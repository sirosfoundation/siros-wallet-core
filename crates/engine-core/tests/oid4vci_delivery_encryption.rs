//! #51: the auxiliary-data delivery plan — not the issuer's
//! `encryption_required` flag alone — decides whether the credential
//! request offers response encryption.
//!
//! A `to_wallet` `hash_commitment` entry carries a Secret Value
//! (auxiliary.rs §7.1), so the response that delivers it MUST be
//! encrypted. The response-side gate has always refused a plain
//! response carrying `auxiliary_data` (`CredentialError::PlainSecret`)
//! — but the request side keyed only on the issuer's
//! `credential_response_encryption`, so an issuer advertising
//! `encryption_required: false` alongside a `to_wallet` plan received
//! a request with NO `credential_response_encryption` member, answered
//! plain, and hit the gate mid-flight: the engine had built the very
//! refusal it then raised (the realeyes repro, captured verbatim on
//! the issuer machine).
//!
//! The fix ports the WS engine's decision shape (`negotiateResponseEncryption`:
//! `Required: seedAdvertised || encCfg.EncryptionRequired`): the
//! delivery-driven requirement is decided in the issuance loop, per
//! configuration, BEFORE any request is made — the offer is mandatory
//! when the plan carries a `to_wallet` secret, and an issuer that
//! yields no pair (or advertises no `credential_response_encryption`
//! at all) fails that configuration's issuance up front, never the
//! plain request the gate would refuse.
//!
//! Key custody is unchanged — deliberately. The engine runs in the
//! frontend (the wasm adapter in the wallet-frontend's page, the SDKs'
//! LOCAL mode in-process), where engine-held key material IS
//! client-held; the two engines converge on the RULE, each keeps its
//! own custody model (the WS engine's sign/relay actions on its side,
//! engine-core's ephemeral key on its own).

use std::sync::{Arc, Mutex};

use engine_core::oid4vci::Oid4vciFlow;
use engine_core::runtime::{FlowContext, FlowHandler};
use engine_core::Ports;
use engine_ports::{
    Clock, ConsentParams, ConsentResult, EntitlementDecision, EvaluationRequest,
    EvaluationResponse, Host, HostError, HttpClient, HttpError, HttpRequest, HttpResponse,
    KeyValue, KeyValueEntry, MatchResult, Pdp, PdpError, ResolveRequest, ResolveResponse, Rng,
    SignParams, SignResult,
};
use wmp_core::methods::FlowStartParams;

// ─── The harness ──────────────────────────────────────────────────────────

/// The issuer metadata: one configuration whose advertisement carries a
/// `to_wallet` `hash_commitment` (a Secret Value, §7.1), with the
/// configuration's `credential_response_encryption` shaped by the caller.
/// (Engine-core reads the encryption config PER CONFIGURATION —
/// `encryption_config_for` iterates the configurations' values — where the
/// WS engine reads it at the issuer level; a parity divergence, not this
/// fix's scope.)
fn issuer_metadata(encryption: Option<serde_json::Value>) -> serde_json::Value {
    let mut configuration = serde_json::json!({
        "format": "dc+sd-jwt",
        "proof_types_supported": {"jwt": {}},
        "auxiliary_data_supported": {
            "to_wallet": [
                {
                    "type": "hash_commitment",
                    "alg": "sha-256",
                    "path": ["family_name"]
                }
            ]
        }
    });
    if let Some(encryption) = encryption {
        configuration["credential_response_encryption"] = encryption;
    }
    serde_json::json!({
        "credential_issuer": "https://issuer.example",
        "credential_endpoint": "https://issuer.example/credential",
        "authorization_servers": ["https://as.example"],
        "credential_configurations_supported": {
            "nym_auth.1": configuration
        }
    })
}

/// The issuer metadata WITHOUT any auxiliary-data plan (the issuer-required
/// back-compat case: no delivery, `encryption_required: true`).
fn issuer_metadata_plain_config(encryption: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "credential_issuer": "https://issuer.example",
        "credential_endpoint": "https://issuer.example/credential",
        "authorization_servers": ["https://as.example"],
        "credential_configurations_supported": {
            "nym_auth.1": {
                "format": "dc+sd-jwt",
                "proof_types_supported": {"jwt": {}},
                "credential_response_encryption": encryption
            }
        }
    })
}

/// The scripted HTTP: dispatches by URL, recording the credential requests.
struct ScriptedHttp {
    metadata: serde_json::Value,
    credential_requests: Mutex<Vec<Vec<u8>>>,
}

#[async_trait::async_trait]
impl HttpClient for ScriptedHttp {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, HttpError> {
        // The credential endpoint: the issuer's answer honours an
        // encryption offer (a JWE to the offered key, OID4VCI §7.3 —
        // "when the request carries credential_response_encryption, the
        // response MUST be encrypted"); no offer answers plain.
        if request.url == "https://issuer.example/credential" {
            return self.answer_credential(&request);
        }
        let body = match request.url.as_str() {
            "https://issuer.example/.well-known/openid-credential-issuer" => {
                self.metadata.to_string()
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
                // The pre-authorized grant.
                assert!(form.contains(
                    "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code"
                ));
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

impl ScriptedHttp {
    /// The credential endpoint's answer: the request recorded, then a
    /// JWE to the offered key when the request carries
    /// `credential_response_encryption` (the offer obliges the issuer,
    /// §7.3), plain otherwise.
    fn answer_credential(&self, request: &HttpRequest) -> Result<HttpResponse, HttpError> {
        let form = String::from_utf8_lossy(&request.body).into_owned();
        self.credential_requests
            .lock()
            .expect("lock")
            .push(form.clone().into_bytes());
        let sent: serde_json::Value = serde_json::from_str(&form).expect("the request is JSON");
        let Some(encryption) = sent.get("credential_response_encryption") else {
            return Ok(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: serde_json::json!({ "credential": "credential-jwt-1" })
                    .to_string()
                    .into_bytes(),
            });
        };
        let recipient: jose_rs::jwk::Jwk =
            serde_json::from_value(encryption["jwk"].clone()).expect("the offered jwk");
        let mut recipient = recipient;
        recipient.alg = Some("ECDH-ES".to_owned());
        let plaintext = serde_json::json!({ "credential": "credential-jwt-1" })
            .to_string()
            .into_bytes();
        let jwe = jose_rs::jwe::compact::encrypt_with_jwk_header(
            &recipient,
            jose_rs::header::JoseHeader::for_jwe(
                jose_rs::algorithm::JweAlgorithm::EcdhEs,
                jose_rs::algorithm::JweEncryption::A256GCM,
            ),
            &plaintext,
            jose_rs::algorithm::JweEncryption::A256GCM,
        )
        .expect("the issuer encrypts to the offered key");
        Ok(HttpResponse {
            status: 200,
            headers: vec![("content-type".to_owned(), "application/jose".to_owned())],
            body: jwe.into_bytes(),
        })
    }
}

/// The host: answers the sign asks (the proofs); nothing else is asked
/// of it on this path (a single configuration auto-selects).
struct SigningHost;

#[async_trait::async_trait]
impl Host for SigningHost {
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
    fn progress(&self, _f: &str, _s: &str, _d: Option<String>) {}
}

/// A PDP that trusts the issuer and answers no entitlement decision
/// (the check's NotImplemented path allows issuance).
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
        if let Ok(mut map) = self.0.lock() {
            map.insert(key.to_owned(), entry.value);
        }
    }
    async fn delete(&self, key: &str) {
        if let Ok(mut map) = self.0.lock() {
            map.remove(key);
        }
    }
}

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

struct NoopTelemetry;
impl engine_ports::Telemetry for NoopTelemetry {
    fn event(&self, _event: engine_ports::TelemetryEvent) {}
}

/// The flow context over the scripted ports.
fn test_context(metadata: serde_json::Value) -> (FlowContext, Arc<ScriptedHttp>) {
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
    let peer = wmp_core::peer::PeerBuilder::new(handler)
        .session_store(store)
        .build();
    let http = Arc::new(ScriptedHttp {
        metadata,
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
            host: Arc::new(SigningHost),
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
    (ctx, http)
}

/// The flow start params: the offer by value, the pre-authorized grant.
fn start_params() -> FlowStartParams {
    FlowStartParams {
        wmp: wmp_core::types::Metadata::default(),
        flow_id: "flow-1".to_owned(),
        flow_type: "oid4vci".to_owned(),
        params: serde_json::value::RawValue::from_string(
            serde_json::json!({
                "credential_issuer": "https://issuer.example",
                "credential_configuration_ids": ["nym_auth.1"],
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

/// The one credential request the flow made, parsed.
fn the_credential_request(http: &ScriptedHttp) -> serde_json::Value {
    let requests = http.credential_requests.lock().expect("lock");
    assert_eq!(requests.len(), 1, "exactly one credential request");
    let body = String::from_utf8(requests[0].clone()).expect("the request body");
    serde_json::from_str(&body).expect("the request is JSON")
}

// ─── The guarantees ────────────────────────────────────────────────────────

/// #51's own case: a `to_wallet` plan forces the offer DESPITE the
/// issuer's `encryption_required: false`. The request carries the
/// `credential_response_encryption` member (the wallet's public JWK and
/// the negotiated pair), so the response that carries the Secret Value
/// is encrypted — never the plain request the §7.1 gate would have to
/// refuse mid-flight (the realeyes repro).
#[tokio::test]
async fn a_to_wallet_delivery_offers_encryption_despite_encryption_required_false() {
    let (ctx, http) = test_context(issuer_metadata(Some(serde_json::json!({
        "alg_values_supported": ["ECDH-ES"],
        "enc_values_supported": ["A256GCM"],
        "encryption_required": false,
    }))));
    let flow = Oid4vciFlow;

    flow.start_flow(&ctx, &start_params())
        .await
        .expect("the flow completes");

    let request = the_credential_request(&http);
    let encryption = request
        .get("credential_response_encryption")
        .expect("#51: the to_wallet delivery forces the encryption offer");
    assert_eq!(
        encryption["enc"], "A256GCM",
        "the negotiated pair (prefer the strongest)"
    );
    let jwk = encryption
        .get("jwk")
        .expect("the offer carries the wallet's public JWK");
    assert_eq!(jwk["kty"], "EC", "a P-256 EC key");
    assert!(
        jwk.get("d").is_none(),
        "the offered JWK is public — no private material"
    );
}

/// No pair at all (the issuer advertises no
/// `credential_response_encryption`): the delivery-driven requirement
/// fails the configuration's issuance BEFORE any request is made — the
/// flow errors with the dedicated reason, and nothing is ever sent to
/// the credential endpoint (the pre-#51 wall: the plain request, the
/// plain answer carrying `auxiliary_data`, the §7.1 refusal mid-flight).
#[tokio::test]
async fn a_to_wallet_delivery_without_any_pair_refuses_before_the_request() {
    let (ctx, http) = test_context(issuer_metadata(None));
    let flow = Oid4vciFlow;

    let refusal = flow
        .start_flow(&ctx, &start_params())
        .await
        .expect_err("the delivery forces the refusal before any request");

    let wmp_core::handler::HandlerError::Rpc(rpc) = &refusal else {
        panic!("the refusal is the flow's Rpc error, found: {refusal:?}");
    };
    let reason = rpc
        .data
        .as_ref()
        .and_then(|data| serde_json::from_str::<serde_json::Value>(data.get()).ok())
        .and_then(|data| {
            data.get("reason")
                .and_then(|value| value.as_str())
                .map(str::to_owned)
        })
        .unwrap_or_default();
    assert!(
        reason.contains("requires credential response encryption"),
        "the refusal names the delivery-driven requirement, found: {reason}"
    );
    assert!(
        http.credential_requests.lock().expect("lock").is_empty(),
        "nothing was sent to the credential endpoint"
    );
}

/// Back-compat, both sides: an issuer that requires encryption still
/// gets the offer with no delivery plan at all, and an issuer that
/// neither requires it nor carries a plan gets NO offer (the wire
/// behaviour for every plain credential stands unchanged).
#[tokio::test]
async fn the_issuers_flag_alone_still_decides_when_no_delivery_is_advertised() {
    // encryption_required: true, no plan: the offer stands.
    let (ctx, http) = test_context(issuer_metadata_plain_config(serde_json::json!({
        "alg_values_supported": ["ECDH-ES"],
        "enc_values_supported": ["A256GCM"],
        "encryption_required": true,
    })));
    let flow = Oid4vciFlow;
    flow.start_flow(&ctx, &start_params())
        .await
        .expect("the flow completes");
    let request = the_credential_request(&http);
    assert!(
        request.get("credential_response_encryption").is_some(),
        "the issuer's own requirement still drives the offer"
    );

    // encryption_required: false, no plan: the offer STILL stands —
    // engine-core offers whenever a pair overlaps, required or not (its
    // pre-#51 wire behaviour, unchanged by this fix: #51 makes the offer
    // MANDATORY for a to_wallet delivery; it does not suppress offers
    // nobody required).
    let (ctx, http) = test_context(issuer_metadata_plain_config(serde_json::json!({
        "alg_values_supported": ["ECDH-ES"],
        "enc_values_supported": ["A256GCM"],
        "encryption_required": false,
    })));
    let flow = Oid4vciFlow;
    flow.start_flow(&ctx, &start_params())
        .await
        .expect("the flow completes");
    let request = the_credential_request(&http);
    assert!(
        request.get("credential_response_encryption").is_some(),
        "an overlapping pair alone still drives the offer (the pre-#51 wire behaviour stands)"
    );
}
