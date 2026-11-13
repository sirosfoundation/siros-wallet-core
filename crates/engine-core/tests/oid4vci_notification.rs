//! The credential_notification flow (WMP OpenID4x 3.4) and the
//! notification context store (#527/#528): the single-use context
//! bound to its session, the TTL, the spend-after-contact rule, the
//! forward (the DPoP proof over the endpoint without query and
//! fragment), and the registration the issuance completion carries.
//!
//! The references are the Go engine (`go-wallet-backend`, branch
//! `feat/wmp-notification`: `notification.go`, `wmp_notification.go`)
//! and go-wmp's `openid4x/notification.go` (OpenID4x 3.4), whose
//! bounds and reasons are the contract here.

use std::sync::{Arc, Mutex};

use engine_core::oid4vci::notification::{
    self, CredentialNotificationFlow, NotificationContext, NotificationContexts,
    MAX_CONCURRENT_FORWARDS, MAX_ID_LEN, REASON_BUSY, REASON_CONTEXT_UNAVAILABLE,
    REASON_SIGNING_FAILED, STATUS_FORWARDED,
};
use engine_core::oid4vci::Oid4vciFlow;
use engine_core::runtime::{FlowContext, FlowHandler};
use engine_core::Ports;
use engine_ports::{
    Clock, ConsentParams, ConsentResult, CredentialSelectionParams, CredentialSelectionResult,
    DpopProofParams, DpopProofResult, EntitlementDecision, EvaluationRequest, EvaluationResponse,
    Host, HostError, HttpClient, HttpError, HttpRequest, HttpResponse, KeyValue, KeyValueEntry,
    Pdp, PdpError, ResolveRequest, ResolveResponse, Rng, SignParams, SignResult,
};
use wmp_core::handler::HandlerError;
use wmp_core::methods::FlowStartParams;

/// The issuer metadata of a notifying issuer: the endpoint the
/// notification POSTs to, with a query the DPoP htu must drop.
const NOTIFICATION_ENDPOINT: &str = "https://issuer.example/notification?source=test";

// ─── The harness ─────────────────────────────────────────────────────────

/// The HTTP that records what it served, answering 204 (OID4VCI §10).
struct RecordingHttp {
    served: Mutex<Vec<HttpRequest>>,
    /// The status the notification endpoint answers.
    status: u16,
}

#[async_trait::async_trait]
impl HttpClient for RecordingHttp {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, HttpError> {
        self.served.lock().expect("lock").push(request.clone());
        if request
            .url
            .starts_with("https://issuer.example/notification")
        {
            return Ok(HttpResponse {
                status: self.status,
                headers: Vec::new(),
                body: Vec::new(),
            });
        }
        // The issuance path's fetches.
        match request.url.as_str() {
            "https://issuer.example/.well-known/openid-credential-issuer" => {
                Ok(HttpResponse {
                    status: 200,
                    headers: vec![(
                        "content-type".to_owned(),
                        "application/json".to_owned(),
                    )],
                    body: br#"{
                        "credential_issuer": "https://issuer.example",
                        "credential_endpoint": "https://issuer.example/credential",
                        "token_endpoint": "https://issuer.example/token",
                        "notification_endpoint": "https://issuer.example/notification?source=test",
                        "credential_configurations_supported": {
                            "UniversityDegree": {"format": "dc+sd-jwt", "vct": "https://vc.example/degree"}
                        }
                    }"#
                    .to_vec(),
                })
            }
            "https://issuer.example/.well-known/oauth-authorization-server" => {
                Ok(HttpResponse {
                    status: 200,
                    headers: vec![(
                        "content-type".to_owned(),
                        "application/json".to_owned(),
                    )],
                    body: br#"{
                        "issuer": "https://issuer.example",
                        "token_endpoint": "https://issuer.example/token"
                    }"#
                    .to_vec(),
                })
            }
            "https://issuer.example/token" => {
                Ok(HttpResponse {
                    status: 200,
                    headers: vec![(
                        "content-type".to_owned(),
                        "application/json".to_owned(),
                    )],
                    body: br#"{
                        "access_token": "at-issuance",
                        "token_type": "Bearer",
                        "expires_in": 3600
                    }"#
                    .to_vec(),
                })
            }
            "https://issuer.example/credential" => Ok(HttpResponse {
                status: 200,
                headers: vec![(
                    "content-type".to_owned(),
                    "application/json".to_owned(),
                )],
                // OID4VCI §11.1: the notification_id the wallet must echo.
                body: br#"{"credential": "credential-jwt-1", "notification_id": "nid-1"}"#
                    .to_vec(),
            }),
            _ => Ok(HttpResponse {
                status: 404,
                headers: Vec::new(),
                body: Vec::new(),
            }),
        }
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
    fn fill(&self, buf: &mut [u8]) -> bool {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = i as u8;
        }
        true
    }
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

impl engine_ports::Telemetry for NoopTelemetry {
    fn event(&self, _event: engine_ports::TelemetryEvent) {}
}

/// The host whose DPoP-proof answer is scripted (settable between
/// calls, so one flow context can serve a refusal and its retry):
/// `None` refuses (the wallet did not provide a proof), `Some(proof)`
/// answers and records the ask.
struct ProofHost {
    answer: Mutex<Option<String>>,
    asks: Mutex<Vec<DpopProofParams>>,
}

impl ProofHost {
    /// The refusing host.
    fn refusing() -> Arc<Self> {
        Arc::new(Self {
            answer: Mutex::new(None),
            asks: Mutex::new(Vec::new()),
        })
    }

    /// The proving host.
    fn proving(proof: &str) -> Arc<Self> {
        Arc::new(Self {
            answer: Mutex::new(Some(proof.to_owned())),
            asks: Mutex::new(Vec::new()),
        })
    }

    /// Sets the answer the next proof ask returns.
    fn set_answer(&self, proof: Option<&str>) {
        *self.answer.lock().expect("lock") = proof.map(str::to_owned);
    }
}

#[async_trait::async_trait]
impl Host for ProofHost {
    async fn request_sign(&self, _p: SignParams) -> Result<SignResult, HostError> {
        Ok(SignResult {
            signature: vec![1, 2, 3, 4],
        })
    }
    async fn request_dpop_proof(
        &self,
        params: DpopProofParams,
    ) -> Result<DpopProofResult, HostError> {
        self.asks.lock().expect("lock").push(params);
        match self.answer.lock().expect("lock").clone() {
            Some(proof) => Ok(DpopProofResult { proof }),
            None => Err(HostError::Cannot("no proof".to_owned())),
        }
    }
    async fn request_match(
        &self,
        _params: engine_ports::MatchParams,
    ) -> Result<engine_ports::MatchResult, HostError> {
        Ok(engine_ports::MatchResult::default())
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
        _params: CredentialSelectionParams,
    ) -> Result<CredentialSelectionResult, HostError> {
        Err(HostError::Cannot("no selection".to_owned()))
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
    host: Arc<ProofHost>,
    http: Arc<RecordingHttp>,
) -> (FlowContext, Arc<CaptureTransport>) {
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
        flow_id: "notif-1".to_owned(),
        flow_type: "credential_notification".to_owned(),
        session: None,
        ports: Arc::new(Ports {
            http,
            clock: Arc::new(FakeClock),
            rng: Arc::new(FakeRng),
            host,
            pdp: Arc::new(TrustedPdp),
            kv: Arc::new(NoopKv),
            telemetry: Arc::new(NoopTelemetry),
            consent_check: engine_ports::ConsentCheckMode::Warn,
            notifications: Arc::new(NotificationContexts::default()),
        }),
        peer,
        request_context: wmp_core::context::RequestContext::default(),
    };
    (ctx, transport)
}

/// A registered context, the Go test fixture's shape: a Bearer
/// (or DPoP) token, the endpoint with its query, one known id.
fn context(notification_id: &str, token_type: &str) -> NotificationContext {
    NotificationContext::new(
        NOTIFICATION_ENDPOINT.to_owned(),
        "at-issuance".to_owned(),
        token_type.to_owned(),
        "https://issuer.example".to_owned(),
        // No engine-held key: the proofs come from the host (the
        // client-held mode the flow is about).
        None,
        Some("device-key-1".to_owned()),
        None,
        Some(notification_id.to_owned()),
        String::new(),
    )
}

/// The start params of a notification flow (OpenID4x 3.4.1).
fn start_params(issuance: &str, id: &str, event: &str) -> FlowStartParams {
    FlowStartParams {
        wmp: wmp_core::types::Metadata::default(),
        flow_id: "notif-1".to_owned(),
        flow_type: "credential_notification".to_owned(),
        params: serde_json::value::RawValue::from_string(
            serde_json::json!({
                "issuance_flow_id": issuance,
                "notification_id": id,
                "event": event,
            })
            .to_string(),
        )
        .ok(),
        timeout: None,
    }
}

/// The flow error of a refused start: the code, and the typed data.
fn refused(error: &HandlerError) -> (i32, serde_json::Value) {
    match error {
        HandlerError::Rpc(rpc) => {
            let data: serde_json::Value = rpc
                .data
                .as_ref()
                .and_then(|data| serde_json::from_str(data.get()).ok())
                .unwrap_or(serde_json::Value::Null);
            (rpc.code, data)
        }
        other => panic!("the refusal is an Rpc error, not {other:?}"),
    }
}

/// The completions the transport captured.
fn completions(transport: &CaptureTransport) -> Vec<serde_json::Value> {
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
        .collect()
}

// ─── The start's validation (OpenID4x 3.4.1) ──────────────────────────────

/// The params' bounds and members, as go-wmp's
/// `ParseCredentialNotificationStart` enforces them: the first
/// offending member, in the section's order — a name, never a value.
#[test]
fn the_start_names_the_first_offending_member() {
    let valid = serde_json::json!({
        "issuance_flow_id": "issu-1",
        "notification_id": "nid-1",
        "event": "credential_accepted",
        "event_description": "the wallet accepted it",
    });
    let raw = serde_json::value::RawValue::from_string(valid.to_string()).expect("raw");
    assert!(notification::parse_start(&Some(raw)).is_ok());

    let offending = |value: serde_json::Value, member: &str| {
        let raw = serde_json::value::RawValue::from_string(value.to_string()).expect("raw");
        assert_eq!(
            notification::parse_start(&Some(raw)).expect_err("refused"),
            member
        );
    };
    // The order: issuance_flow_id, notification_id, event,
    // event_description (the section's order).
    offending(
        serde_json::json!({"notification_id": "nid-1", "event": "credential_accepted"}),
        "issuance_flow_id",
    );
    offending(
        serde_json::json!({"issuance_flow_id": "issu-1", "event": "credential_accepted"}),
        "notification_id",
    );
    offending(
        serde_json::json!({"issuance_flow_id": "issu-1", "notification_id": "nid-1"}),
        "event",
    );
    // Not an event the profile defines.
    offending(
        serde_json::json!({
            "issuance_flow_id": "issu-1", "notification_id": "nid-1",
            "event": "credential_deleted"
        }),
        "event",
    );
    // Beyond the schema's maxLengths (Unicode scalar values).
    offending(
        serde_json::json!({
            "issuance_flow_id": "x".repeat(MAX_ID_LEN + 1),
            "notification_id": "nid-1", "event": "credential_accepted"
        }),
        "issuance_flow_id",
    );
    // Not printable ASCII.
    offending(
        serde_json::json!({
            "issuance_flow_id": "issu-1", "notification_id": "nid-1",
            "event": "credential_accepted", "event_description": "not\u{00e9}"
        }),
        "event_description",
    );
    // Absent params are the issuance_flow_id's complaint.
    assert_eq!(
        notification::parse_start(&None).expect_err("refused"),
        "issuance_flow_id"
    );
}

// ─── The store's semantics ───────────────────────────────────────────────

/// The claim is single use, bound to the session, and expires (the
/// Go `useLocked`, `claim` and `take`): each id once, the context of
/// another session not at all, nothing past the TTL.
#[test]
fn the_claim_is_single_use_bound_and_ttl_limited() {
    let store = NotificationContexts::default();
    store.put("issu-1", context("nid-1", "Bearer"), 1_000);

    // The same id twice: the second claim finds nothing.
    assert!(
        store.claim("issu-1", "", "nid-1", 1_000).is_some(),
        "the first claim takes the context"
    );
    assert!(
        store.claim("issu-1", "", "nid-1", 1_000).is_none(),
        "its one id is used: the context is gone"
    );

    // A second issuance's id stays usable: each response's id is its
    // own single use.
    store.put("issu-2", context("nid-2", "Bearer"), 1_000);
    assert!(store.claim("issu-2", "", "nid-2", 1_000).is_some());
    assert!(store.claim("issu-2", "", "nid-2", 1_000).is_none());

    // The TTL: past it, nothing.
    store.put("issu-3", context("nid-3", "Bearer"), 1_000);
    assert!(
        store
            .claim(
                "issu-3",
                "",
                "nid-3",
                1_000 + notification::CONTEXT_TTL_SECS + 1
            )
            .is_none(),
        "the context is gone past its TTL"
    );
    assert_eq!(
        store.endpoint_for("issu-3", 1_000 + notification::CONTEXT_TTL_SECS + 1),
        "",
        "the completion's endpoint is gone with it"
    );
}

/// The session binding: a context retained for a session is not
/// claimable from another one (the Go principal binding).
#[test]
fn the_context_is_bound_to_its_session() {
    let store = NotificationContexts::default();
    let mut context = context("nid-1", "Bearer");
    context.session_id = "ses-issuance".to_owned();
    store.put("issu-1", context, 1_000);

    assert!(
        store.claim("issu-1", "ses-other", "nid-1", 1_000).is_none(),
        "another session cannot claim it"
    );
    assert!(
        store
            .claim("issu-1", "ses-issuance", "nid-1", 1_000)
            .is_some(),
        "its own session can"
    );
}

/// The unspend (#528): an id whose notification never reached the
/// issuer goes back — with the original expiry, never past it — and a
/// superseded registration owns the flow id, so an unspend of an old
/// context revives nothing.
#[test]
fn an_unspent_id_goes_back_with_its_expiry() {
    let store = NotificationContexts::default();
    store.put("issu-1", context("nid-1", "Bearer"), 1_000);

    let claimed = store
        .claim("issu-1", "", "nid-1", 1_000)
        .expect("the first claim takes it");
    // Nothing was sent: the id goes back.
    store.unspend("issu-1", &claimed, "nid-1", 1_000);
    assert!(
        store.claim("issu-1", "", "nid-1", 1_000).is_some(),
        "the retry may claim the same id"
    );

    // But never past the original expiry: the unspend keeps it.
    store.put("issu-2", context("nid-2", "Bearer"), 1_000);
    let claimed = store.claim("issu-2", "", "nid-2", 1_000).expect("claimed");
    store.unspend(
        "issu-2",
        &claimed,
        "nid-2",
        1_000 + notification::CONTEXT_TTL_SECS + 1,
    );
    assert!(
        store
            .claim(
                "issu-2",
                "",
                "nid-2",
                1_000 + notification::CONTEXT_TTL_SECS + 1
            )
            .is_none(),
        "an expired context is not revived"
    );

    // A newer registration owns the flow id: the old context's unspend
    // revives nothing (the Go seq check).
    store.put("issu-3", context("nid-3", "Bearer"), 1_000);
    let claimed = store.claim("issu-3", "", "nid-3", 1_000).expect("claimed");
    store.put("issu-3", context("nid-4", "Bearer"), 1_000);
    store.unspend("issu-3", &claimed, "nid-3", 1_000);
    assert!(
        store.claim("issu-3", "", "nid-3", 1_000).is_none(),
        "a superseded context is not revived"
    );
    assert!(
        store.claim("issu-3", "", "nid-4", 1_000).is_some(),
        "the newer registration answers the flow id"
    );
}

// ─── The flow ────────────────────────────────────────────────────────────

/// The flow forwards the notification: the §10 request body to the
/// full endpoint, authorized with the retained token, and — when the
/// token is DPoP-bound — proofed over the endpoint **without query and
/// fragment** (OpenID4x 3.4.3: the only htu a wallet signs), the
/// completion carrying the forwarded status.
#[tokio::test]
async fn the_flow_forwards_over_the_stripped_htu() {
    let host = ProofHost::proving("proof-1");
    let http = Arc::new(RecordingHttp {
        served: Mutex::new(Vec::new()),
        status: 204,
    });
    let (ctx, transport) = test_context(host.clone(), http.clone());
    ctx.ports
        .notifications
        .put("issu-1", context("nid-1", "DPoP"), 1_000);

    let flow = CredentialNotificationFlow;
    flow.start_flow(
        &ctx,
        &start_params("issu-1", "nid-1", "credential_accepted"),
    )
    .await
    .expect("the notification forwards");

    // The DPoP proof was asked over the endpoint without query and
    // fragment (RFC 9449 §4.2, OpenID4x 3.4.3), with the token's ath.
    let asks = host.asks.lock().expect("lock");
    assert_eq!(asks.len(), 1, "one proof ask");
    assert_eq!(asks[0].htu, "https://issuer.example/notification");
    assert_eq!(asks[0].htm, "POST");
    assert_eq!(asks[0].key_id.as_deref(), Some("device-key-1"));
    assert_eq!(asks[0].access_token, "at-issuance");

    // The request went to the FULL endpoint, with the §10 body and
    // the DPoP scheme.
    let served = http.served.lock().expect("lock");
    let post = &served[0];
    assert_eq!(post.url, NOTIFICATION_ENDPOINT);
    assert!(post
        .headers
        .iter()
        .any(|(name, value)| { name == "authorization" && value == "DPoP at-issuance" }));
    assert!(post
        .headers
        .iter()
        .any(|(name, value)| { name == "DPoP" && value == "proof-1" }));
    let body: serde_json::Value = serde_json::from_slice(&post.body).expect("the §10 body");
    assert_eq!(body["notification_id"], "nid-1");
    assert_eq!(body["event"], "credential_accepted");

    // The completion: the forwarded status (OpenID4x 3.4.2).
    let completions = completions(&transport);
    assert_eq!(completions.len(), 1);
    assert_eq!(completions[0]["status"], STATUS_FORWARDED);
    assert_eq!(completions[0]["notification_id"], "nid-1");
}

/// #528, through the flow: a DPoP proof the wallet did not provide
/// sends nothing, so the id is not spent — the wallet retries the
/// same notification, and the retry forwards. The issuer was never
/// contacted between the two.
#[tokio::test]
async fn a_failed_signing_spends_nothing_and_the_retry_forwards() {
    let refusing = ProofHost::refusing();
    let http = Arc::new(RecordingHttp {
        served: Mutex::new(Vec::new()),
        status: 204,
    });
    let (ctx, transport) = test_context(refusing.clone(), http.clone());
    ctx.ports
        .notifications
        .put("issu-1", context("nid-1", "DPoP"), 1_000);

    let flow = CredentialNotificationFlow;
    let error = flow
        .start_flow(
            &ctx,
            &start_params("issu-1", "nid-1", "credential_accepted"),
        )
        .await
        .expect_err("the refusing wallet's flow refuses");
    let (code, data) = refused(&error);
    // The flow error (-31006) with the signing reason, not retryable
    // as a *notification* retry from the engine's side (the wallet
    // may re-ask, the same id, until the TTL).
    assert_eq!(code, wmp_core::error::ERR_FLOW_ERROR);
    assert_eq!(data["reason"], REASON_SIGNING_FAILED);

    // Nothing was sent to the issuer.
    assert!(
        http.served.lock().expect("lock").is_empty(),
        "a failed proof sent nothing"
    );

    // The retry, on the SAME engine and store: the wallet provides
    // the proof now, and the same id — unspent, its context back with
    // its original expiry — forwards.
    refusing.set_answer(Some("proof-2"));
    let flow = CredentialNotificationFlow;
    flow.start_flow(
        &ctx,
        &start_params("issu-1", "nid-1", "credential_accepted"),
    )
    .await
    .expect("the retry forwards the same id");
    assert_eq!(completions(&transport).len(), 1);
    assert_eq!(completions(&transport)[0]["status"], STATUS_FORWARDED);
}

/// No usable context: absent, consumed, another session's, or an id
/// that does not match — the reason does not say which (OpenID4x
/// 3.4.2), and nothing is sent.
#[tokio::test]
async fn no_usable_context_refuses_without_saying_which() {
    let host = ProofHost::proving("proof-1");
    let http = Arc::new(RecordingHttp {
        served: Mutex::new(Vec::new()),
        status: 204,
    });
    let (ctx, _transport) = test_context(host.clone(), http.clone());
    ctx.ports
        .notifications
        .put("issu-1", context("nid-1", "DPoP"), 1_000);

    let flow = CredentialNotificationFlow;
    // An id the context does not know.
    let error = flow
        .start_flow(
            &ctx,
            &start_params("issu-1", "nid-other", "credential_accepted"),
        )
        .await
        .expect_err("an unknown id refuses");
    let (code, data) = refused(&error);
    assert_eq!(code, wmp_core::error::ERR_FLOW_ERROR);
    assert_eq!(data["reason"], REASON_CONTEXT_UNAVAILABLE);
    assert_eq!(data["retryable"], false);

    // A flow with no context at all: the same reason.
    let error = flow
        .start_flow(
            &ctx,
            &start_params("issu-none", "nid-1", "credential_accepted"),
        )
        .await
        .expect_err("no context refuses");
    let (_, data) = refused(&error);
    assert_eq!(data["reason"], REASON_CONTEXT_UNAVAILABLE);

    // Nothing was sent for either.
    assert!(http.served.lock().expect("lock").is_empty());
}

/// The forwarding limit (the Go backpressure): at
/// [`MAX_CONCURRENT_FORWARDS`] in flight, a notification is turned
/// away busy, its context and id kept for the wallet's retry.
#[tokio::test]
async fn the_forwarding_limit_turns_a_notification_away_busy() {
    let host = ProofHost::proving("proof-1");
    let http = Arc::new(RecordingHttp {
        served: Mutex::new(Vec::new()),
        status: 204,
    });
    let (ctx, _transport) = test_context(host, http.clone());
    ctx.ports
        .notifications
        .put("issu-1", context("nid-1", "DPoP"), 1_000);

    // Hold every forwarding slot.
    for _ in 0..MAX_CONCURRENT_FORWARDS {
        assert!(ctx.ports.notifications.try_begin_forward());
    }

    let flow = CredentialNotificationFlow;
    let error = flow
        .start_flow(
            &ctx,
            &start_params("issu-1", "nid-1", "credential_accepted"),
        )
        .await
        .expect_err("the limit refuses");
    let (_, data) = refused(&error);
    assert_eq!(data["reason"], REASON_BUSY);
    assert_eq!(data["retryable"], true);
    // The context and the id were kept for the retry.
    assert!(
        ctx.ports
            .notifications
            .claim("issu-1", "", "nid-1", 1_000)
            .is_some(),
        "a busy notification keeps its id"
    );
}

// ─── The issuance completion registers ───────────────────────────────────

/// The issuance completion tells the wallet what it needs to start a
/// notification (the `notification_endpoint` and the issuer's
/// `notification_id`), and the notification flow forwards from the
/// context that same completion registered — the end to end, one
/// engine, one store: the §10 POST the issuer expects, authorized with
/// the issuance's own token.
#[tokio::test]
async fn the_issuance_completion_registers_and_the_flow_forwards() {
    let host = ProofHost::proving("proof-1");
    let http = Arc::new(RecordingHttp {
        served: Mutex::new(Vec::new()),
        status: 204,
    });
    let (ctx, transport) = test_context(host, http.clone());
    let issuance_ctx = FlowContext {
        flow_id: "issu-1".to_owned(),
        flow_type: "oid4vci".to_owned(),
        session: None,
        ports: ctx.ports.clone(),
        peer: ctx.peer.clone(),
        request_context: wmp_core::context::RequestContext::default(),
    };

    // The pre-authorized issuance, against the notifying issuer.
    let flow = Oid4vciFlow;
    flow.start_flow(
        &issuance_ctx,
        &FlowStartParams {
            wmp: wmp_core::types::Metadata::default(),
            flow_id: "issu-1".to_owned(),
            flow_type: "oid4vci".to_owned(),
            params: serde_json::value::RawValue::from_string(
                serde_json::json!({
                    "credential_issuer": "https://issuer.example",
                    "credential_configuration_ids": ["UniversityDegree"],
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
        },
    )
    .await
    .expect("the issuance completes");

    // The completion carries the notification members (#527).
    let completions = completions(&transport);
    assert!(!completions.is_empty(), "the issuance completes");
    let issuance = &completions[0];
    assert_eq!(
        issuance["notification_endpoint"],
        "https://issuer.example/notification?source=test"
    );
    assert_eq!(issuance["notification_id"], "nid-1");

    // The notification flow, on the same engine: the context the
    // completion registered is the one it forwards from.
    let flow = CredentialNotificationFlow;
    flow.start_flow(
        &ctx,
        &start_params("issu-1", "nid-1", "credential_accepted"),
    )
    .await
    .expect("the notification forwards");

    // The §10 POST went to the issuer, authorized with the
    // issuance's own token.
    let served = http.served.lock().expect("lock");
    let post = served
        .iter()
        .find(|request| {
            request.method == "POST"
                && request
                    .url
                    .starts_with("https://issuer.example/notification")
        })
        .expect("the notification POST");
    let body: serde_json::Value = serde_json::from_slice(&post.body).expect("the §10 body");
    assert_eq!(body["notification_id"], "nid-1");
    assert_eq!(body["event"], "credential_accepted");
}
