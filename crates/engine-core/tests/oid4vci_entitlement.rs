//! The issuer entitlement check in the OID4VCI flow (ARF 6.6.2.3): the
//! request the PDP receives, the additive findings progress, the
//! `-31020` refusal, and the ordering that never answers both a trust
//! refusal and an entitlement refusal for one flow.
//!
//! The reference is the Go engine
//! (`go-wallet-backend`, branch `feat/issuer-entitlement-in-evaluate`:
//! `checkIssuerEntitlement`, `failNotEntitled`) and its WMP mapping
//! (`feat/wmp-issuer-entitlement-mapping`: `ISSUER_NOT_ENTITLED` →
//! `-31020`).

use std::sync::{Arc, Mutex};

use engine_core::oid4vci::entitlement::{check_entitlement, not_entitled_data};
use engine_core::oid4vci::types::MetadataType;
use engine_core::oid4vci::{issuer, Oid4vciFlow};
use engine_core::runtime::{FlowContext, FlowHandler};
use engine_core::Ports;
use engine_ports::{
    Clock, ConsentParams, ConsentResult, EntitlementCode, EntitlementDecision, EntitlementFinding,
    EntitlementMode, EntitlementOffer, EntitlementRequest, Host, HostError, HttpClient, HttpError,
    HttpRequest, HttpResponse, KeyValue, KeyValueEntry, MatchParams, MatchResult, Pdp, PdpError,
    ResolveRequest, ResolveResponse, Rng, SignParams, SignResult, Telemetry, TelemetryEvent,
};
use wmp_core::error::ERR_ISSUER_NOT_ENTITLED;

/// The issuer metadata document, as the resolver serves it: two
/// configurations (an mdoc and an SD-JWT VC), and the `issuer_info`
/// array the entitlement evaluator reads the registration certificate
/// from (ETSI TS 119 472-3) — a member this core does not model, so it
/// rides the raw document.
const ISSUER_METADATA: &str = r#"{
    "credential_issuer": "https://issuer.example",
    "credential_endpoint": "https://issuer.example/credential",
    "token_endpoint": "https://issuer.example/token",
    "authorization_servers": ["https://as.example"],
    "credential_configurations": {
        "degree_sdjwt": {
            "format": "dc+sd-jwt",
            "vct": "https://vc.siros.example/degree",
            "jwks": {"keys": [{"kty": "EC", "crv": "P-256", "x": "bJM", "y": "L0Z"}]}
        },
        "edu_mdoc": {"format": "mso_mdoc", "doctype": "org.iso.18013.5.1.mDL"}
    },
    "issuer_info": [
        {"format": "registration_cert", "data": "eyJhbGciOiJFUzIuIn0.payload.sig"}
    ]
}"#;

/// The AS metadata document the resolver serves.
const AS_METADATA: &str = r#"{
    "issuer": "https://as.example",
    "token_endpoint": "https://as.example/token"
}"#;

// ─── The harness ─────────────────────────────────────────────────────────

/// Serves the issuer and AS metadata documents.
struct ScriptedHttp;

#[async_trait::async_trait]
impl HttpClient for ScriptedHttp {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, HttpError> {
        let body = match request.url.as_str() {
            "https://issuer.example/.well-known/openid-credential-issuer" => ISSUER_METADATA,
            "https://as.example/.well-known/oauth-authorization-server" => AS_METADATA,
            _ => {
                return Err(HttpError::Transport(format!(
                    "no fixture for {}",
                    request.url
                )))
            }
        };
        Ok(HttpResponse {
            status: 200,
            headers: vec![("content-type".to_owned(), "application/json".to_owned())],
            body: body.as_bytes().to_vec(),
        })
    }
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

struct FakeClock;

#[async_trait::async_trait]
impl Clock for FakeClock {
    fn now_unix(&self) -> i64 {
        1_000
    }
    async fn sleep(&self, _duration_ms: u64) {}
}

struct FakeRng;

impl Rng for FakeRng {
    fn fill(&self, _buf: &mut [u8]) -> bool {
        true
    }
}

/// The host the flows never reach: every ask declines.
struct NoopHost;

#[async_trait::async_trait]
impl Host for NoopHost {
    async fn request_sign(&self, _params: SignParams) -> Result<SignResult, HostError> {
        Err(HostError::Cannot("no host in the test".to_owned()))
    }
    async fn request_match(&self, _params: MatchParams) -> Result<MatchResult, HostError> {
        Err(HostError::Cannot("no host in the test".to_owned()))
    }
    async fn request_consent(&self, _params: ConsentParams) -> Result<ConsentResult, HostError> {
        Err(HostError::Cannot("no host in the test".to_owned()))
    }
    async fn request_tx_code(&self, _flow_id: &str) -> Result<String, HostError> {
        Err(HostError::Cannot("no host in the test".to_owned()))
    }
    async fn open_authorization(&self, _flow_id: &str, _url: &str) -> Result<(), HostError> {
        Ok(())
    }
    fn progress(&self, _flow_id: &str, _step: &str, _detail: Option<String>) {}
}

struct NoopKv;

#[async_trait::async_trait]
impl KeyValue for NoopKv {
    async fn get(&self, _key: &str) -> Option<KeyValueEntry> {
        None
    }
    async fn put(&self, _key: &str, _entry: KeyValueEntry) {}
    async fn delete(&self, _key: &str) {}
}

struct NoopTelemetry;

impl Telemetry for NoopTelemetry {
    fn event(&self, _event: TelemetryEvent) {}
}

/// The request the scripted PDP received, for the assertions.
type Recorded = Arc<Mutex<Option<EntitlementRequest>>>;

/// A PDP the test scripts: trusted for the trust decision, with the
/// entitlement answer the test needs. `None` leaves the operation to
/// the trait's default (`NotImplemented`).
struct ScriptedPdp {
    answer: Option<EntitlementDecision>,
    recorded: Recorded,
}

impl ScriptedPdp {
    fn refusing() -> (Arc<Self>, Recorded) {
        Self::new(Some(EntitlementDecision {
            allowed: false,
            mode: EntitlementMode::Fail,
            evaluated: true,
            findings: vec![EntitlementFinding {
                code: EntitlementCode::NoRegistrationCertificate,
                message: "the metadata carries no registration certificate".to_owned(),
                credential_type: None,
            }],
            findings_truncated: false,
        }))
    }

    fn findings() -> (Arc<Self>, Recorded) {
        Self::new(Some(EntitlementDecision {
            allowed: true,
            mode: EntitlementMode::Warn,
            evaluated: true,
            findings: vec![EntitlementFinding {
                code: EntitlementCode::TypeNotRegistered,
                message: "the offered type is not registered".to_owned(),
                credential_type: Some("org.iso.18013.5.1.mDL".to_owned()),
            }],
            findings_truncated: false,
        }))
    }

    fn minimal() -> (Arc<Self>, Recorded) {
        Self::new(None)
    }

    fn new(answer: Option<EntitlementDecision>) -> (Arc<Self>, Recorded) {
        let recorded: Recorded = Arc::new(Mutex::new(None));
        (
            Arc::new(Self {
                answer,
                recorded: recorded.clone(),
            }),
            recorded,
        )
    }
}

#[async_trait::async_trait]
impl Pdp for ScriptedPdp {
    async fn evaluate(
        &self,
        _request: engine_ports::EvaluationRequest,
    ) -> Result<engine_ports::EvaluationResponse, PdpError> {
        Ok(engine_ports::EvaluationResponse {
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
        request: EntitlementRequest,
    ) -> Result<EntitlementDecision, PdpError> {
        *self.recorded.lock().expect("lock") = Some(request);
        match self.answer.clone() {
            Some(decision) => Ok(decision),
            None => Err(PdpError::NotImplemented),
        }
    }
}

/// The flow context the tests run in, with the transport capturing
/// what the peer writes.
fn test_context(pdp: Arc<dyn Pdp>) -> (FlowContext, Arc<CaptureTransport>) {
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
    let ctx = FlowContext {
        flow_id: "flow-1".to_owned(),
        flow_type: "oid4vci".to_owned(),
        session: None,
        ports: Arc::new(Ports {
            http: Arc::new(ScriptedHttp),
            clock: Arc::new(FakeClock),
            rng: Arc::new(FakeRng),
            host: Arc::new(NoopHost),
            pdp,
            kv: Arc::new(NoopKv),
            telemetry: Arc::new(NoopTelemetry),
            consent_check: engine_ports::ConsentCheckMode::Warn,
            notifications: std::sync::Arc::new(
                engine_core::oid4vci::notification::NotificationContexts::default(),
            ),
        }),
        peer,
        request_context: wmp_core::context::RequestContext::default(),
    };
    (ctx, transport)
}

/// The offer the flow starts from, by value (no offer fetch): both
/// configurations, the pre-authorized grant.
fn start_params() -> wmp_core::methods::FlowStartParams {
    wmp_core::methods::FlowStartParams {
        wmp: wmp_core::types::Metadata::default(),
        flow_id: "flow-1".to_owned(),
        flow_type: "oid4vci".to_owned(),
        params: serde_json::value::RawValue::from_string(
            serde_json::json!({
                "credential_issuer": "https://issuer.example",
                "credential_configuration_ids": ["edu_mdoc", "degree_sdjwt"],
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

/// The issuer metadata, resolved the way the flow resolves it.
async fn resolved_metadata() -> engine_core::oid4vci::types::IssuerMetadata {
    issuer::resolve_issuer_metadata(
        &ScriptedHttp,
        "https://issuer.example",
        MetadataType::PreferSigned,
        false,
    )
    .await
    .expect("the issuer metadata resolves")
}

/// The `trust_evaluated` progress notifications the transport captured,
/// as JSON payload values.
fn trust_evaluated_progresses(transport: &CaptureTransport) -> Vec<serde_json::Value> {
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
            (step == "trust_evaluated").then(|| {
                message
                    .pointer("/params/payload")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null)
            })
        })
        .collect()
}

// ─── The guarantees ─────────────────────────────────────────────────────

/// The flow refuses when the PDP refuses: `-31020`
/// (`wmp.ErrIssuerNotEntitled`) with the issuer and the bounded
/// decision as the data — the Go `failNotEntitled` shape.
#[tokio::test]
async fn a_refused_entitlement_fails_the_flow_with_issuer_not_entitled() {
    let (pdp, _recorded) = ScriptedPdp::refusing();
    let (ctx, _transport) = test_context(pdp);
    let flow = Oid4vciFlow;

    let refusal = flow
        .start_flow(&ctx, &start_params())
        .await
        .expect_err("the refusal refuses the flow");
    let rpc = match refusal {
        wmp_core::handler::HandlerError::Rpc(rpc) => rpc,
        other => panic!("the refusal is an Rpc error, not {other:?}"),
    };

    // The code: go-wmp's ErrIssuerNotEntitled.
    assert_eq!(rpc.code, ERR_ISSUER_NOT_ENTITLED);

    // The data: the issuer and the bounded decision, as the Go
    // NewIssuerNotEntitledData shape carries them.
    let data = rpc.data.expect("the refusal carries the decision");
    let data: serde_json::Value = serde_json::from_str(data.get()).expect("the data is JSON");
    assert_eq!(data["issuer"], "https://issuer.example");
    assert_eq!(data["issuer_entitlement"]["allowed"], false);
    assert_eq!(data["issuer_entitlement"]["mode"], "fail");
    assert_eq!(data["issuer_entitlement"]["evaluated"], true);
    assert_eq!(
        data["issuer_entitlement"]["findings"][0]["code"],
        "no_registration_certificate"
    );
    assert_eq!(data["issuer_entitlement"]["findings_truncated"], false);
}

/// The trust refusal wins: an untrusted issuer answers `-31006` with
/// the `untrusted_issuer` reason, never the entitlement's `-31020` —
/// never both refusals for one flow.
#[tokio::test]
async fn the_trust_refusal_wins_over_the_entitlement_refusal() {
    /// Untrusted for the trust decision, so the flow answers the trust
    /// refusal alone.
    struct UntrustedPdp;

    #[async_trait::async_trait]
    impl Pdp for UntrustedPdp {
        async fn evaluate(
            &self,
            _request: engine_ports::EvaluationRequest,
        ) -> Result<engine_ports::EvaluationResponse, PdpError> {
            Ok(engine_ports::EvaluationResponse {
                trusted: false,
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
    }

    let (ctx, _transport) = test_context(Arc::new(UntrustedPdp));
    let flow = Oid4vciFlow;

    let refusal = flow
        .start_flow(&ctx, &start_params())
        .await
        .expect_err("the untrusted issuer refuses the flow");
    let rpc = match refusal {
        wmp_core::handler::HandlerError::Rpc(rpc) => rpc,
        other => panic!("the refusal is an Rpc error, not {other:?}"),
    };
    // The trust refusal: the flow error (-31006) with the
    // untrusted_issuer reason, never -31020.
    assert_eq!(rpc.code, wmp_core::error::ERR_FLOW_ERROR);
    let data: serde_json::Value =
        serde_json::from_str(rpc.data.expect("the typed data").get()).expect("the data is JSON");
    assert_eq!(data["reason"], "untrusted_issuer");
}

/// The evaluator receives the raw document — the `issuer_info` array
/// riding it, unmodelled — the signing key material as the trust
/// decision received it, and the offers with the type each format
/// counts (the Go `OfferFor`: `mso_mdoc` reads its `doctype`, the
/// SD-JWT formats their `vct`).
#[tokio::test]
async fn the_evaluator_receives_the_document_and_the_offers() {
    let (pdp, recorded) = ScriptedPdp::findings();
    let (ctx, _transport) = test_context(pdp);
    let metadata = resolved_metadata().await;

    let decision = check_entitlement(
        &ctx,
        "https://issuer.example",
        &metadata,
        &["edu_mdoc".to_owned(), "degree_sdjwt".to_owned()],
    )
    .await;
    assert!(decision.allowed, "the scripted answer allows");

    let recorded = recorded
        .lock()
        .expect("lock")
        .clone()
        .expect("the check called the PDP");

    // The issuer, as the flow received it.
    assert_eq!(recorded.issuer, "https://issuer.example");

    // The raw document, byte for byte the resolver's — the
    // `issuer_info` member rides it for the evaluator to read.
    assert_eq!(
        recorded.metadata,
        ISSUER_METADATA.as_bytes(),
        "the raw document as published, issuer_info and all"
    );

    // The signing key material, as the trust decision received it:
    // the inline jwks of the configuration carrying one.
    let key_material: serde_json::Value =
        serde_json::from_str(&String::from_utf8(recorded.key_material).expect("the jwks is text"))
            .expect("the jwks is JSON");
    assert_eq!(
        key_material,
        serde_json::json!({"keys": [{"kty": "EC", "crv": "P-256", "x": "bJM", "y": "L0Z"}]}),
        "the jwks, as Pdp::evaluate received it"
    );

    // The offers, in the offer's order, each with the type its format
    // counts (the Go OfferFor).
    assert_eq!(
        recorded.offers,
        vec![
            EntitlementOffer {
                format: "mso_mdoc".to_owned(),
                credential_type: "org.iso.18013.5.1.mDL".to_owned()
            },
            EntitlementOffer {
                format: "dc+sd-jwt".to_owned(),
                credential_type: "https://vc.siros.example/degree".to_owned()
            },
        ]
    );
}

/// The findings ride an additive `trust_evaluated` progress: it names
/// `issuer_entitlement_evaluated`, never `issuer_trust_evaluated`
/// (the SDKs key their trust report on that member, so the findings
/// can never read as a trust decision), and it carries the bounded
/// decision.
#[tokio::test]
async fn the_findings_ride_the_additive_trust_evaluated_progress() {
    let (pdp, _recorded) = ScriptedPdp::findings();
    let (ctx, transport) = test_context(pdp);
    let metadata = resolved_metadata().await;

    let decision = check_entitlement(
        &ctx,
        "https://issuer.example",
        &metadata,
        &["edu_mdoc".to_owned()],
    )
    .await;
    assert!(decision.allowed);

    let progresses = trust_evaluated_progresses(&transport);
    assert_eq!(progresses.len(), 1, "one findings progress");
    let payload = &progresses[0];

    // The additive marker, and never the trust marker.
    assert_eq!(payload["issuer_entitlement_evaluated"], true);
    assert!(
        payload.get("issuer_trust_evaluated").is_none(),
        "the findings progress is not a trust decision"
    );
    assert_eq!(payload["issuer"], "https://issuer.example");

    // The bounded decision rides it.
    assert_eq!(payload["issuer_entitlement"]["allowed"], true);
    assert_eq!(payload["issuer_entitlement"]["mode"], "warn");
    assert_eq!(payload["issuer_entitlement"]["evaluated"], true);
    assert_eq!(
        payload["issuer_entitlement"]["findings"][0]["code"],
        "attestation_type_not_registered"
    );
    assert_eq!(
        payload["issuer_entitlement"]["findings"][0]["credential_type"],
        "org.iso.18013.5.1.mDL"
    );
    assert_eq!(payload["issuer_entitlement"]["findings_truncated"], false);
}

/// A PDP without the operation answers "not evaluated": the flow
/// proceeds (the ARF's 24-month grace), no findings arise, and no
/// progress rides.
#[tokio::test]
async fn an_unimplemented_check_leaves_the_flow_unevaluated() {
    let (pdp, _recorded) = ScriptedPdp::minimal();
    let (ctx, transport) = test_context(pdp);
    let metadata = resolved_metadata().await;

    let decision = check_entitlement(
        &ctx,
        "https://issuer.example",
        &metadata,
        &["edu_mdoc".to_owned()],
    )
    .await;

    // Not evaluated, and allowed: "not checked" never reads as
    // "checked and fine", and never refuses the flow.
    assert!(decision.allowed);
    assert!(!decision.evaluated);
    assert!(decision.findings.is_empty());

    // Nothing rides: the grace is silence.
    assert!(
        trust_evaluated_progresses(&transport).is_empty(),
        "no findings, no progress"
    );
}

/// The refusal's data is the bounded decision: the caps of the relay
/// (16 findings) hold in the `-31020` data too.
#[tokio::test]
async fn the_refusal_data_carries_the_bounded_decision() {
    let findings: Vec<EntitlementFinding> = (0..20)
        .map(|_| EntitlementFinding {
            code: EntitlementCode::TypeNotRegistered,
            message: "not registered".to_owned(),
            credential_type: Some("https://vc.siros.example/degree".to_owned()),
        })
        .collect();
    let decision = EntitlementDecision {
        allowed: false,
        mode: EntitlementMode::Fail,
        evaluated: true,
        findings,
        findings_truncated: false,
    };

    let rpc = not_entitled_data("https://issuer.example", &decision);
    assert_eq!(rpc.code, ERR_ISSUER_NOT_ENTITLED);
    let data: serde_json::Value =
        serde_json::from_str(rpc.data.expect("the data").get()).expect("the data is JSON");
    let summary = &data["issuer_entitlement"];
    assert_eq!(summary["findings"].as_array().map(Vec::len), Some(16));
    assert_eq!(summary["findings_truncated"], true);
}
