//! The credential configuration selection in the OID4VCI flow (the Go
//! engine's `awaitCredentialSelection`, docs/engine-parity.md §2's
//! gap B1): the auto-selection of a single-configuration offer, the
//! `awaiting_selection` progress and the host ask of a
//! multi-configuration one, and the constraint that what is issued is
//! what the offer put on the table — the invariant the entitlement
//! check (ARF 6.6.2.3) rests on.

use std::sync::{Arc, Mutex};

use engine_core::oid4vci::Oid4vciFlow;
use engine_core::runtime::{FlowContext, FlowHandler};
use engine_core::Ports;
use engine_ports::{
    Clock, ConsentParams, ConsentResult, CredentialSelectionParams, CredentialSelectionResult,
    EntitlementDecision, EvaluationRequest, EvaluationResponse, Host, HostError, HttpClient,
    HttpError, HttpRequest, HttpResponse, KeyValue, KeyValueEntry, MatchResult, Pdp, PdpError,
    ResolveRequest, ResolveResponse, Rng, SignParams, SignResult,
};
use wmp_core::methods::{FlowActionParams, FlowStartParams};

// ─── The harness ─────────────────────────────────────────────────────────

/// The issuer metadata: two configurations with display entries, the
/// shape the `available_credentials` progress carries.
const TWO_CONFIGURATION_METADATA: &str = r#"{
    "credential_issuer": "https://issuer.example",
    "credential_endpoint": "https://issuer.example/credential",
    "token_endpoint": "https://issuer.example/token",
    "authorization_servers": ["https://as.example"],
    "credential_configurations_supported": {
        "UniversityDegree": {
            "format": "dc+sd-jwt",
            "vct": "https://vc.siros.example/degree",
            "scope": "openid credential",
            "display": [
                {"name": "University Degree", "locale": "en-US"}
            ]
        },
        "Mdl": {
            "format": "mso_mdoc",
            "doctype": "org.iso.18013.5.1.mDL",
            "display": [{"name": "Driving Licence"}]
        },
        "Passport": {
            "format": "dc+sd-jwt",
            "vct": "https://vc.siros.example/passport"
        }
    }
}"#;

/// The scripted HTTP: dispatches by URL, recording the credential
/// requests.
struct ScriptedHttp {
    credential_requests: Mutex<Vec<Vec<u8>>>,
}

#[async_trait::async_trait]
impl HttpClient for ScriptedHttp {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, HttpError> {
        let body = match request.url.as_str() {
            "https://issuer.example/.well-known/openid-credential-issuer" => {
                TWO_CONFIGURATION_METADATA.to_owned()
            }
            "https://as.example/.well-known/oauth-authorization-server" => serde_json::json!({
                "issuer": "https://as.example",
                "authorization_endpoint": "https://as.example/authorize",
                "token_endpoint": "https://as.example/token",
                "pushed_authorization_request_endpoint": "https://as.example/par",
                "require_pushed_authorization_requests": false,
            })
            .to_string(),
            "https://as.example/par" => {
                serde_json::json!({ "request_uri": "urn:ietf:params:oauth:request_uri:par-1" })
                    .to_string()
            }
            "https://as.example/token" => {
                let form = String::from_utf8_lossy(&request.body).into_owned();
                if form.contains("grant_type=authorization_code") {
                    assert!(form.contains("code_verifier="));
                } else {
                    // The pre-authorized grant.
                    assert!(form.contains(
                        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code"
                    ));
                    assert!(form.contains("pre-authorized_code=code-1"));
                }
                serde_json::json!({
                    "access_token": "at-1", "token_type": "Bearer", "expires_in": 3600,
                    "c_nonce": "nonce-1"
                })
                .to_string()
            }
            "https://issuer.example/credential" => {
                // The credential request: the configuration id rides
                // its `credential_configuration_id` member.
                let form = String::from_utf8_lossy(&request.body).into_owned();
                self.credential_requests
                    .lock()
                    .expect("lock")
                    .push(form.into_bytes());
                serde_json::json!({ "credential": "credential-jwt-1" }).to_string()
            }
            "https://issuer.example/token" => serde_json::json!({
                "access_token": "at-1", "token_type": "Bearer", "expires_in": 3600,
                "c_nonce": "nonce-1"
            })
            .to_string(),
            other => panic!("unexpected fetch: {other}"),
        };
        Ok(HttpResponse {
            status: 200,
            headers: Vec::new(),
            body: body.into_bytes(),
        })
    }
}

/// A deterministic Rng: bytes i, i+1, i+2... — the state and the PKCE
/// verifier are computable in the test.
struct FakeRng;

impl Rng for FakeRng {
    fn fill(&self, buf: &mut [u8]) -> bool {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = i as u8;
        }
        true
    }
}

struct FakeClock;

#[async_trait::async_trait]
impl Clock for FakeClock {
    fn now_unix(&self) -> i64 {
        1_000
    }
    async fn sleep(&self, _duration_ms: u64) {}
}

struct TrustedPdp;

#[async_trait::async_trait]
impl Pdp for TrustedPdp {
    async fn evaluate(&self, _request: EvaluationRequest) -> Result<EvaluationResponse, PdpError> {
        Ok(EvaluationResponse {
            trusted: true,
            decision: None,
                context: None,
        })
    }
    async fn resolve(&self, _request: ResolveRequest) -> Result<ResolveResponse, PdpError> {
        Ok(ResolveResponse {
            metadata: Vec::new(),
            trust_info: None,
        })
    }
    async fn evaluate_entitlement(
        &self,
        _request: engine_ports::EntitlementRequest,
    ) -> Result<EntitlementDecision, PdpError> {
        Err(PdpError::NotImplemented)
    }
}

/// The in-memory KeyValue: the authorization-code stash has to survive
/// between the flow's two calls.
struct MemKv(Mutex<rustc_hash::FxHashMap<String, Vec<u8>>>);
#[async_trait::async_trait]
impl KeyValue for MemKv {
    async fn get(&self, key: &str) -> Option<KeyValueEntry> {
        self.0.lock().ok()?.get(key).map(|value| KeyValueEntry {
            value: value.clone(),
            ttl_secs: None,
        })
    }
    async fn put(&self, key: &str, entry: KeyValueEntry) {
        self.0
            .lock()
            .map(|mut map| map.insert(key.to_owned(), entry.value))
            .ok();
    }
    async fn delete(&self, key: &str) {
        self.0.lock().map(|mut map| map.remove(key)).ok();
    }
}

struct NoopTelemetry;

impl engine_ports::Telemetry for NoopTelemetry {
    fn event(&self, _event: engine_ports::TelemetryEvent) {}
}

/// The host that answers the ask chain and records the selection
/// asks: the answer is scripted, the asks recorded.
struct SelectingHost {
    answer: Option<CredentialSelectionResult>,
    asks: Mutex<Vec<CredentialSelectionParams>>,
}

#[async_trait::async_trait]
impl Host for SelectingHost {
    async fn request_sign(&self, _p: SignParams) -> Result<SignResult, HostError> {
        Ok(SignResult {
            signature: vec![1, 2, 3, 4],
        })
    }
    async fn request_match(
        &self,
        _params: engine_ports::MatchParams,
    ) -> Result<MatchResult, HostError> {
        Ok(MatchResult::default())
    }
    async fn request_consent(&self, _p: ConsentParams) -> Result<ConsentResult, HostError> {
        Ok(ConsentResult { consented: true })
    }
    async fn request_tx_code(&self, _f: &str) -> Result<String, HostError> {
        Ok("1234".to_owned())
    }
    async fn open_authorization(&self, _f: &str, _url: &str) -> Result<(), HostError> {
        Ok(())
    }
    async fn request_credential_selection(
        &self,
        params: CredentialSelectionParams,
    ) -> Result<CredentialSelectionResult, HostError> {
        self.asks.lock().expect("lock").push(params);
        match &self.answer {
            Some(result) => Ok(result.clone()),
            // The older host: no selection support at all.
            None => Err(HostError::Cannot("no selection".to_owned())),
        }
    }
    fn progress(&self, _f: &str, _s: &str, _d: Option<String>) {}
}

/// The transport that captures what the peer writes.
struct CaptureTransport {
    written: Mutex<Vec<Vec<u8>>>,
}

impl wmp_core::transport::Transport for CaptureTransport {
    fn read_message(&self) -> Result<Vec<u8>, wmp_core::transport::TransportError> {
        Err(wmp_core::transport::TransportError::Closed)
    }
    fn write_message(&self, data: &[u8]) -> Result<(), wmp_core::transport::TransportError> {
        self.written.lock().expect("lock").push(data.to_vec());
        Ok(())
    }
    fn close(&self) -> Result<(), wmp_core::transport::TransportError> {
        Ok(())
    }
}

/// The flow context over scripted ports.
fn test_context(
    host: Arc<SelectingHost>,
) -> (FlowContext, Arc<ScriptedHttp>, Arc<CaptureTransport>) {
    let store = Arc::new(wmp_core::session::MemorySessionStore::new());
    let handler = Arc::new(wmp_core::sessionservice::SessionHandler::new(
        Arc::new(
            wmp_core::sessionservice::SessionService::new(
                wmp_core::sessionservice::SessionServiceConfig {
                    store: Some(store.clone()),
                    entropy: Some(Arc::new(|bytes: &mut [u8]| {
                        for (i, b) in bytes.iter_mut().enumerate() {
                            *b = i as u8;
                        }
                        true
                    })),
                    ..wmp_core::sessionservice::SessionServiceConfig::default()
                },
            )
            .unwrap_or_else(|_| panic!("session service")),
        ),
        Arc::new(|| 0),
    ));
    let transport = Arc::new(CaptureTransport {
        written: Mutex::new(Vec::new()),
    });
    let peer = wmp_core::peer::PeerBuilder::new(handler)
        .session_store(store)
        .transport(transport.clone())
        .build();
    let http = Arc::new(ScriptedHttp {
        credential_requests: Mutex::new(Vec::new()),
    });
    let ctx = FlowContext {
        flow_id: "flow-1".to_owned(),
        flow_type: "oid4vci".to_owned(),
        session: None,
        ports: Arc::new(Ports {
            http: http.clone(),
            clock: Arc::new(FakeClock),
            rng: Arc::new(FakeRng),
            host,
            pdp: Arc::new(TrustedPdp),
            kv: Arc::new(MemKv(Mutex::new(rustc_hash::FxHashMap::default()))),
            telemetry: Arc::new(NoopTelemetry),
            consent_check: engine_ports::ConsentCheckMode::Warn,
            notifications: std::sync::Arc::new(
                engine_core::oid4vci::notification::NotificationContexts::default(),
            ),
        }),
        peer,
        request_context: wmp_core::context::RequestContext::default(),
    };
    (ctx, http, transport)
}

/// The flow start params: the offer by value, the configurations named
/// by the caller, the pre-authorized grant.
fn start_params(ids: &[&str]) -> FlowStartParams {
    FlowStartParams {
        wmp: wmp_core::types::Metadata::default(),
        flow_id: "flow-1".to_owned(),
        flow_type: "oid4vci".to_owned(),
        params: serde_json::value::RawValue::from_string(
            serde_json::json!({
                "credential_issuer": "https://issuer.example",
                "credential_configuration_ids": ids,
                "grants": {
                    "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                        "pre-authorized_code": "code-1"
                    }
                },
                "redirect_uri": "https://wallet.example/cb",
                "client_id": "client-1"
            })
            .to_string(),
        )
        .ok(),
        timeout: None,
    }
}

/// The `awaiting_selection` progress payloads the transport captured.
fn awaiting_selection_payloads(transport: &CaptureTransport) -> Vec<serde_json::Value> {
    transport
        .written
        .lock()
        .expect("lock")
        .iter()
        .filter_map(|raw| serde_json::from_slice::<serde_json::Value>(raw).ok())
        .filter(|message| {
            message.get("method").and_then(|m| m.as_str()) == Some("wmp.flow.progress")
        })
        .filter_map(|message| {
            let step = message
                .pointer("/params/step")
                .and_then(|s| s.as_str())
                .unwrap_or_default();
            (step == "awaiting_selection").then(|| {
                message
                    .pointer("/params/payload")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null)
            })
        })
        .collect()
}

/// The configuration id the credential request named, if it happened.
fn requested_configuration_id(http: &ScriptedHttp) -> Option<String> {
    let requests = http.credential_requests.lock().expect("lock");
    let body = String::from_utf8(requests.first()?.clone()).ok()?;
    // The request is JSON: the member names the configuration.
    let value: serde_json::Value = serde_json::from_str(&body).ok()?;
    value
        .get("credential_configuration_id")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
}

// ─── The guarantees ──────────────────────────────────────────────────────

/// A single-configuration offer auto-selects: no `awaiting_selection`
/// progress, no ask — the configuration is not a choice (the Go rule) —
/// and the credential request names it.
#[tokio::test]
async fn a_single_configuration_offer_auto_selects() {
    let host = Arc::new(SelectingHost {
        answer: None,
        asks: Mutex::new(Vec::new()),
    });
    let (ctx, http, transport) = test_context(host.clone());
    let flow = Oid4vciFlow;

    flow.start_flow(&ctx, &start_params(&["UniversityDegree"]))
        .await
        .expect("the flow completes");

    assert!(
        awaiting_selection_payloads(&transport).is_empty(),
        "no selection progress for a single configuration"
    );
    assert!(
        host.asks.lock().expect("lock").is_empty(),
        "no selection ask for a single configuration"
    );
    assert_eq!(
        requested_configuration_id(&http).as_deref(),
        Some("UniversityDegree"),
        "the auto-selected configuration is the one requested"
    );
}

/// A multi-configuration offer is the user's choice: the
/// `awaiting_selection` progress carries the `available_credentials`
/// with the Go wire names (the id, the display, the format, the vct),
/// in the offer's order, and the host's answer selects.
#[tokio::test]
async fn a_multi_configuration_offer_asks_with_the_available_credentials() {
    let host = Arc::new(SelectingHost {
        answer: Some(CredentialSelectionResult {
            credential_configuration_id: "Mdl".to_owned(),
        }),
        asks: Mutex::new(Vec::new()),
    });
    let (ctx, http, transport) = test_context(host.clone());
    let flow = Oid4vciFlow;

    flow.start_flow(&ctx, &start_params(&["UniversityDegree", "Mdl"]))
        .await
        .expect("the flow completes");

    // The progress: one, with the available credentials.
    let payloads = awaiting_selection_payloads(&transport);
    assert_eq!(payloads.len(), 1, "one awaiting_selection progress");
    let available = payloads[0]
        .get("available_credentials")
        .and_then(|v| v.as_array())
        .expect("the available_credentials array");
    assert_eq!(
        available.len(),
        2,
        "both configurations, in the offer's order"
    );
    assert_eq!(available[0]["id"], "UniversityDegree");
    assert_eq!(available[0]["format"], "dc+sd-jwt");
    assert_eq!(available[0]["vct"], "https://vc.siros.example/degree");
    assert_eq!(
        available[0]["display"]["name"], "University Degree",
        "the display entry rides raw: the first entry, an object (the Go Display *CredentialDisplay)"
    );
    assert_eq!(available[1]["id"], "Mdl");
    assert_eq!(available[1]["format"], "mso_mdoc");

    // The ask: the same available credentials.
    let asks = host.asks.lock().expect("lock");
    assert_eq!(asks.len(), 1, "one selection ask");
    assert_eq!(asks[0].available.len(), 2);
    assert_eq!(asks[0].available[0].id, "UniversityDegree");
    assert_eq!(asks[0].available[1].id, "Mdl");

    // The answer selected: the credential request names it.
    assert_eq!(
        requested_configuration_id(&http).as_deref(),
        Some("Mdl"),
        "the answer's configuration is the one requested"
    );
}

/// The answer is constrained to the offer: an id the issuer metadata
/// defines but the offer never named refuses — what is issued is what
/// the entitlement check evaluated, never a configuration the offer
/// did not put on the table (the stronger rule this core keeps).
#[tokio::test]
async fn an_answer_outside_the_offer_refuses() {
    // The offer names both displayed configurations; the answer names
    // the metadata's third — defined by the issuer, offered by no one.
    let host = Arc::new(SelectingHost {
        answer: Some(CredentialSelectionResult {
            credential_configuration_id: "Passport".to_owned(),
        }),
        asks: Mutex::new(Vec::new()),
    });
    let (ctx, http, _transport) = test_context(host);
    let flow = Oid4vciFlow;

    let refusal = flow
        .start_flow(&ctx, &start_params(&["UniversityDegree", "Mdl"]))
        .await
        .expect_err("the unoffered answer refuses the flow");
    let wmp_core::handler::HandlerError::Rpc(rpc) = refusal else {
        panic!("the refusal is an Rpc error");
    };
    // The Go engine's message for a selection it cannot act on.
    let reason = rpc
        .data
        .as_ref()
        .and_then(|data| serde_json::from_str::<serde_json::Value>(data.get()).ok())
        .and_then(|data| {
            data.get("reason")
                .and_then(|v| v.as_str())
                .map(str::to_owned)
        });
    assert_eq!(
        reason.as_deref(),
        Some("invalid credential configuration"),
        "the refusal names the class"
    );
    // Nothing was issued.
    assert!(
        http.credential_requests.lock().expect("lock").is_empty(),
        "no credential request for a refused selection"
    );
}

/// The older host — one that cannot answer a selection ask, the default
/// every pre-selection host inherits — fails closed on a
/// multi-configuration offer: never the first configuration unasked.
#[tokio::test]
async fn an_older_host_fails_closed_on_a_multi_configuration_offer() {
    let host = Arc::new(SelectingHost {
        answer: None,
        asks: Mutex::new(Vec::new()),
    });
    let (ctx, http, _transport) = test_context(host.clone());
    let flow = Oid4vciFlow;

    let refusal = flow
        .start_flow(&ctx, &start_params(&["UniversityDegree", "Mdl"]))
        .await
        .expect_err("the older host refuses the multi-configuration offer");
    let wmp_core::handler::HandlerError::Rpc(_) = refusal else {
        panic!("the refusal is an Rpc error");
    };
    assert!(
        !host.asks.lock().expect("lock").is_empty(),
        "the ask was made (the default refused it)"
    );
    assert!(
        http.credential_requests.lock().expect("lock").is_empty(),
        "nothing issued unasked"
    );
}

/// The authorization-code resume requests the stashed configuration —
/// the user's choice made before the redirect, not a re-derivation
/// (and never a second ask) after the browser roundtrip.
#[tokio::test]
async fn the_resume_requests_the_stashed_configuration() {
    // The authorization-code offer, multi-configuration: the host
    // selects the mDL.
    let host = Arc::new(SelectingHost {
        answer: Some(CredentialSelectionResult {
            credential_configuration_id: "Mdl".to_owned(),
        }),
        asks: Mutex::new(Vec::new()),
    });
    let (ctx, http, _transport) = test_context(host.clone());
    let flow = Oid4vciFlow;

    let params = FlowStartParams {
        wmp: wmp_core::types::Metadata::default(),
        flow_id: "flow-1".to_owned(),
        flow_type: "oid4vci".to_owned(),
        params: serde_json::value::RawValue::from_string(
            serde_json::json!({
                "credential_issuer": "https://issuer.example",
                "credential_configuration_ids": ["UniversityDegree", "Mdl"],
                "grants": {
                    "authorization_code": { "issuer_state": "session-1" }
                },
                "redirect_uri": "https://wallet.example/cb",
                "client_id": "client-1"
            })
            .to_string(),
        )
        .ok(),
        timeout: None,
    };

    // The first call: the authorization handoff. The selection was
    // asked (the multi-configuration offer) and stashed.
    flow.start_flow(&ctx, &params).await.expect("the handoff");
    assert_eq!(host.asks.lock().expect("lock").len(), 1);

    // The second call: the redirect's answer, with the state the Rng
    // port produced (bytes 0..16).
    let expected_state = engine_core::oid4vci::auth_code::generate_state(&FakeRng).expect("state");
    let action = FlowActionParams {
        wmp: wmp_core::types::Metadata::default(),
        flow_id: "flow-1".to_owned(),
        action: "authorization_complete".to_owned(),
        params: serde_json::value::RawValue::from_string(
            serde_json::json!({ "code": "auth-code-1", "state": expected_state }).to_string(),
        )
        .ok(),
    };
    flow.handle_action(&ctx, &action).await.expect("the resume");

    // The resume requested the stashed configuration, and no second
    // selection ask was made.
    assert_eq!(
        requested_configuration_id(&http).as_deref(),
        Some("Mdl"),
        "the resume requests the stashed configuration"
    );
    assert_eq!(
        host.asks.lock().expect("lock").len(),
        1,
        "no second selection ask after the redirect"
    );
}
