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
/// requests. `credential_fail_from` (0-based) makes every credential
/// request from that index answer 500 — the partial-failure tests'
/// knob; `None` never fails.
struct ScriptedHttp {
    credential_requests: Mutex<Vec<Vec<u8>>>,
    credential_fail_from: Option<usize>,
    token_requests: Mutex<usize>,
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
                *self.token_requests.lock().expect("lock") += 1;
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
                let mut requests = self.credential_requests.lock().expect("lock");
                let index = requests.len();
                requests.push(form.into_bytes());
                if self.credential_fail_from.is_some_and(|from| index >= from) {
                    return Ok(HttpResponse {
                        status: 500,
                        headers: Vec::new(),
                        body: serde_json::json!({ "error": "server_error" })
                            .to_string()
                            .into_bytes(),
                    });
                }
                serde_json::json!({ "credential": format!("credential-jwt-{index}") }).to_string()
            }
            "https://issuer.example/token" => {
                *self.token_requests.lock().expect("lock") += 1;
                serde_json::json!({
                    "access_token": "at-1", "token_type": "Bearer", "expires_in": 3600,
                    "c_nonce": "nonce-1"
                })
                .to_string()
            }
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
    test_context_with_failures(host, None)
}

/// test_context with the credential-failure knob (#28's partial-failure
/// tests).
fn test_context_with_failures(
    host: Arc<SelectingHost>,
    credential_fail_from: Option<usize>,
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
        credential_fail_from,
        token_requests: Mutex::new(0),
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
            require_authorization_response_issuer: false,
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
    start_params_with(ids, serde_json::json!({}))
}

/// The flow start params with extra members merged in (#28: the flow
/// start's `selected_credential_configuration_ids` set and the
/// `issuance_selection_policy` knob ride here).
fn start_params_with(ids: &[&str], extra: serde_json::Value) -> FlowStartParams {
    let mut params = serde_json::json!({
        "credential_issuer": "https://issuer.example",
        "credential_configuration_ids": ids,
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": "code-1"
            }
        },
        "redirect_uri": "https://wallet.example/cb",
        "client_id": "client-1"
    });
    if let (Some(object), Some(members)) = (params.as_object_mut(), extra.as_object()) {
        for (key, value) in members {
            object.insert(key.clone(), value.clone());
        }
    }
    FlowStartParams {
        wmp: wmp_core::types::Metadata::default(),
        flow_id: "flow-1".to_owned(),
        flow_type: "oid4vci".to_owned(),
        params: serde_json::value::RawValue::from_string(params.to_string()).ok(),
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

/// Every configuration id the credential requests named, in order (#28:
/// one request per selected configuration).
fn requested_configuration_ids(http: &ScriptedHttp) -> Vec<String> {
    let requests = http.credential_requests.lock().expect("lock");
    requests
        .iter()
        .filter_map(|body| String::from_utf8(body.clone()).ok())
        .filter_map(|body| serde_json::from_str::<serde_json::Value>(&body).ok())
        .filter_map(|value| {
            value
                .get("credential_configuration_id")
                .and_then(|v| v.as_str())
                .map(str::to_owned)
        })
        .collect()
}

/// The completion's result payload, if the flow completed.
fn completion_result(transport: &CaptureTransport) -> Option<serde_json::Value> {
    transport
        .written
        .lock()
        .expect("lock")
        .iter()
        .filter_map(|raw| serde_json::from_slice::<serde_json::Value>(raw).ok())
        .filter(|message| {
            message.get("method").and_then(|m| m.as_str()) == Some("wmp.flow.complete")
        })
        .map(|message| {
            message
                .pointer("/params/result")
                .cloned()
                .unwrap_or(serde_json::Value::Null)
        })
        .next()
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

/// Under the `user_selects` policy a multi-configuration offer is the
/// user's choice: the `awaiting_selection` progress carries the
/// `available_credentials` with the Go wire names (the id, the
/// display, the format, the vct), in the offer's order, and the host's
/// answer selects — the legacy single-id answer accepted as the
/// one-element set (the pre-#28 host's shape).
#[tokio::test]
async fn a_user_selects_offer_asks_and_the_legacy_single_answer_selects() {
    let host = Arc::new(SelectingHost {
        answer: Some(CredentialSelectionResult {
            credential_configuration_id: Some("Mdl".to_owned()),
            credential_configuration_ids: Vec::new(),
        }),
        asks: Mutex::new(Vec::new()),
    });
    let (ctx, http, transport) = test_context(host.clone());
    let flow = Oid4vciFlow;

    flow.start_flow(
        &ctx,
        &start_params_with(
            &["UniversityDegree", "Mdl"],
            serde_json::json!({ "issuance_selection_policy": "user_selects" }),
        ),
    )
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
            credential_configuration_id: None,
            credential_configuration_ids: vec!["Passport".to_owned()],
        }),
        asks: Mutex::new(Vec::new()),
    });
    let (ctx, http, _transport) = test_context(host);
    let flow = Oid4vciFlow;

    let refusal = flow
        .start_flow(
            &ctx,
            &start_params_with(
                &["UniversityDegree", "Mdl"],
                serde_json::json!({ "issuance_selection_policy": "user_selects" }),
            ),
        )
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
/// multi-configuration offer under `user_selects`: never a
/// configuration unasked.
#[tokio::test]
async fn an_older_host_fails_closed_on_a_user_selects_offer() {
    let host = Arc::new(SelectingHost {
        answer: None,
        asks: Mutex::new(Vec::new()),
    });
    let (ctx, http, _transport) = test_context(host.clone());
    let flow = Oid4vciFlow;

    let refusal = flow
        .start_flow(
            &ctx,
            &start_params_with(
                &["UniversityDegree", "Mdl"],
                serde_json::json!({ "issuance_selection_policy": "user_selects" }),
            ),
        )
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
            credential_configuration_id: Some("Mdl".to_owned()),
            credential_configuration_ids: Vec::new(),
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
                "issuance_selection_policy": "user_selects",
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

// ─── #28 / go-wallet-backend#549: the selected SET ─────────────────────────

/// The `issue_all` default: a multi-configuration offer issues EVERY
/// offered configuration with no selection step at all — no ask, no
/// `awaiting_selection` progress — one token for the whole set, one
/// credential request per configuration, and a completion carrying
/// every result, each paired with its configuration id.
#[tokio::test]
async fn a_multi_configuration_offer_issues_every_configuration_by_default() {
    let host = Arc::new(SelectingHost {
        answer: None,
        asks: Mutex::new(Vec::new()),
    });
    let (ctx, http, transport) = test_context(host.clone());
    let flow = Oid4vciFlow;

    flow.start_flow(&ctx, &start_params(&["UniversityDegree", "Mdl"]))
        .await
        .expect("the flow completes");

    assert!(
        host.asks.lock().expect("lock").is_empty(),
        "no selection ask under the issue_all default"
    );
    assert!(
        awaiting_selection_payloads(&transport).is_empty(),
        "no awaiting_selection progress under the issue_all default"
    );
    assert_eq!(
        requested_configuration_ids(&http),
        vec!["UniversityDegree".to_owned(), "Mdl".to_owned()],
        "one credential request per offered configuration, in the offer's order"
    );
    assert_eq!(
        *http.token_requests.lock().expect("lock"),
        1,
        "one token exchange for the whole set"
    );

    // The completion: every configuration's result, each paired with its
    // configuration id (the renewal pairing).
    let completion = completion_result(&transport).expect("the flow completed");
    let credentials = completion
        .get("credentials")
        .and_then(|v| v.as_array())
        .expect("the credentials array");
    assert_eq!(credentials.len(), 2, "one entry per configuration");
    assert_eq!(
        credentials[0]["credential_configuration_id"],
        "UniversityDegree"
    );
    assert_eq!(credentials[1]["credential_configuration_id"], "Mdl");
    assert_eq!(credentials[0]["credential"], "credential-jwt-0");
    assert_eq!(credentials[1]["credential"], "credential-jwt-1");
    assert!(
        completion.get("failures").is_none(),
        "no failures member when everything issued"
    );
    // The legacy single-configuration view keeps the first entry's.
    assert_eq!(completion["credential"], "credential-jwt-0");
}

/// The flow-start set (`selected_credential_configuration_ids`) IS the
/// selection: no ask runs, whatever the deployment's policy — the user
/// already chose before the flow started.
#[tokio::test]
async fn the_flow_start_set_is_the_selection_under_both_policies() {
    for policy in [None, Some("user_selects")] {
        let host = Arc::new(SelectingHost {
            answer: None,
            asks: Mutex::new(Vec::new()),
        });
        let (ctx, http, _transport) = test_context(host.clone());
        let flow = Oid4vciFlow;
        let mut extra = serde_json::json!({
            "selected_credential_configuration_ids": ["Mdl"]
        });
        if let Some(policy) = policy {
            extra["issuance_selection_policy"] = serde_json::Value::String(policy.to_owned());
        }

        flow.start_flow(
            &ctx,
            &start_params_with(&["UniversityDegree", "Mdl"], extra),
        )
        .await
        .expect("the flow completes");

        assert!(
            host.asks.lock().expect("lock").is_empty(),
            "the flow-start set is the selection: no ask"
        );
        assert_eq!(
            requested_configuration_ids(&http),
            vec!["Mdl".to_owned()],
            "only the chosen subset issues"
        );
    }
}

/// A flow-start set naming an id the offer never carried refuses: never
/// a silent fall-back to issuing configurations nobody chose.
#[tokio::test]
async fn the_flow_start_set_refuses_an_id_outside_the_offer() {
    let host = Arc::new(SelectingHost {
        answer: None,
        asks: Mutex::new(Vec::new()),
    });
    let (ctx, http, _transport) = test_context(host);
    let flow = Oid4vciFlow;

    let refusal = flow
        .start_flow(
            &ctx,
            &start_params_with(
                &["UniversityDegree", "Mdl"],
                serde_json::json!({
                    "selected_credential_configuration_ids": ["Mdl", "Passport"]
                }),
            ),
        )
        .await
        .expect_err("the unoffered flow-start id refuses the flow");
    let wmp_core::handler::HandlerError::Rpc(rpc) = refusal else {
        panic!("the refusal is an Rpc error");
    };
    let reason = rpc
        .data
        .as_ref()
        .and_then(|data| serde_json::from_str::<serde_json::Value>(data.get()).ok())
        .and_then(|data| {
            data.get("reason")
                .and_then(|v| v.as_str())
                .map(str::to_owned)
        });
    assert_eq!(reason.as_deref(), Some("invalid credential configuration"));
    assert!(
        http.credential_requests.lock().expect("lock").is_empty(),
        "nothing issued for a refused flow-start set"
    );
}

/// The `user_selects` answer with the SET member selects the subset.
#[tokio::test]
async fn a_user_selects_answer_with_the_set_selects_the_subset() {
    let host = Arc::new(SelectingHost {
        answer: Some(CredentialSelectionResult {
            credential_configuration_id: None,
            credential_configuration_ids: vec!["Mdl".to_owned()],
        }),
        asks: Mutex::new(Vec::new()),
    });
    let (ctx, http, _transport) = test_context(host);
    let flow = Oid4vciFlow;

    flow.start_flow(
        &ctx,
        &start_params_with(
            &["UniversityDegree", "Mdl"],
            serde_json::json!({ "issuance_selection_policy": "user_selects" }),
        ),
    )
    .await
    .expect("the flow completes");

    assert_eq!(
        requested_configuration_ids(&http),
        vec!["Mdl".to_owned()],
        "the answer's set is the selection"
    );
}

/// A partial failure completes: the configuration that failed does not
/// abort the other — the completion carries the success AND the
/// per-configuration failure report (which configuration, why).
#[tokio::test]
async fn a_partial_failure_completes_with_the_failure_reported() {
    let host = Arc::new(SelectingHost {
        answer: None,
        asks: Mutex::new(Vec::new()),
    });
    let (ctx, http, transport) = test_context_with_failures(host, Some(1));
    let flow = Oid4vciFlow;

    flow.start_flow(&ctx, &start_params(&["UniversityDegree", "Mdl"]))
        .await
        .expect("one or more successes complete the flow");

    assert_eq!(
        requested_configuration_ids(&http).len(),
        2,
        "the failed configuration did not abort the other's request"
    );

    let completion = completion_result(&transport).expect("the flow completed");
    let credentials = completion
        .get("credentials")
        .and_then(|v| v.as_array())
        .expect("the credentials array");
    assert_eq!(
        credentials.len(),
        1,
        "the successful configuration's result"
    );
    assert_eq!(
        credentials[0]["credential_configuration_id"],
        "UniversityDegree"
    );
    let failures = completion
        .get("failures")
        .and_then(|v| v.as_array())
        .expect("the failures report");
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0]["credential_configuration_id"], "Mdl");
    assert!(
        !failures[0]["error"].as_str().unwrap_or_default().is_empty(),
        "the failure's reason rides the report"
    );
}

/// Zero successes fail the flow: exactly ONE error — the first
/// failure's reason — never one per configuration.
#[tokio::test]
async fn zero_successes_fail_the_flow_with_one_error() {
    let host = Arc::new(SelectingHost {
        answer: None,
        asks: Mutex::new(Vec::new()),
    });
    let (ctx, _http, transport) = test_context_with_failures(host, Some(0));
    let flow = Oid4vciFlow;

    let refusal = flow
        .start_flow(&ctx, &start_params(&["UniversityDegree", "Mdl"]))
        .await
        .expect_err("nothing issued: the flow fails");
    let wmp_core::handler::HandlerError::Rpc(rpc) = refusal else {
        panic!("the refusal is an Rpc error");
    };
    let data = rpc
        .data
        .as_ref()
        .and_then(|data| serde_json::from_str::<serde_json::Value>(data.get()).ok());
    assert_eq!(
        data.as_ref()
            .and_then(|data| data.get("reason"))
            .and_then(|v| v.as_str()),
        Some("oid4vci: credential endpoint answered 500"),
        "the single error carries the first failure's reason"
    );
    assert!(
        completion_result(&transport).is_none(),
        "no completion on zero successes"
    );
}
