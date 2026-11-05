//! The OID4VP consent component (#525): the DCQL vetting of the
//! host's match answer — `oid4vp::consent` — under the deployment's
//! mode, and the flow that refuses on it.
//!
//! The reference is the Go engine (branch `feat/consent-component` of
//! `go-wallet-backend`): `consentPolicy.Decide` and
//! `checkConsentAgainstDCQL`, whose test table
//! (`oid4vp_consent_test.go`) is the fixture truth here, ported case
//! for case.

use std::sync::{Arc, Mutex};

use engine_core::oid4vp::consent::{
    self, REASON_CLAIM_OUTSIDE, REASON_DUPLICATE, REASON_OUTSIDE_QUERY, REASON_UNPARSEABLE,
};
use engine_core::oid4vp::Oid4vpFlow;
use engine_core::runtime::{FlowContext, FlowHandler};
use engine_core::Ports;
use engine_ports::{
    Clock, ConsentCheckMode, ConsentParams, ConsentResult, EntitlementDecision, EvaluationRequest,
    EvaluationResponse, Host, HostError, HttpClient, HttpError, HttpRequest, HttpResponse,
    KeyValue, KeyValueEntry, MatchParams, MatchResult, Pdp, PdpError, ResolveRequest,
    ResolveResponse, Rng, SignParams, SignResult, Telemetry, TelemetryEvent, VpParams, VpResult,
    VpSelection,
};
use wmp_core::methods::FlowStartParams;

/// The DCQL query the Go fixture table vets against
/// (`consentTestQuery`): four credential shapes — a PID with nested
/// and wildcard paths, claim sets, an mdoc with a dotted namespace, a
/// query with no claims, and a `multiple` query.
const GO_FIXTURE_QUERY: &str = r#"{
 "credentials":[
  {"id":"pid","format":"dc+sd-jwt","claims":[
     {"id":"a","path":["given_name"]},{"id":"b","path":["family_name"]},
     {"id":"c","path":["address","street"]},{"id":"d","path":["nationalities",null,"code"]}]},
  {"id":"pid_sets","claims":[{"id":"x","path":["a"]},{"id":"y","path":["b"]},{"id":"z","path":["c"]}],
     "claim_sets":[["x","y"],["z"]]},
  {"id":"mdl","format":"mso_mdoc","claims":[{"path":["org.iso.18013.5.1","family_name"]},{"path":["org.iso.18013.5.1","portrait"]}]},
  {"id":"noclaims","format":"dc+sd-jwt"},
  {"id":"multi","multiple":true}
 ]}"#;

// ─── The harness ─────────────────────────────────────────────────────────

/// The telemetry that records what the core reports: the violation
/// records, with their fields.
#[derive(Default)]
struct RecordingTelemetry {
    events: Mutex<Vec<TelemetryEvent>>,
}

impl Telemetry for RecordingTelemetry {
    fn event(&self, event: TelemetryEvent) {
        self.events.lock().expect("lock").push(event);
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

struct TrustedPdp;

#[async_trait::async_trait]
impl Pdp for TrustedPdp {
    async fn evaluate(&self, _request: EvaluationRequest) -> Result<EvaluationResponse, PdpError> {
        Ok(EvaluationResponse {
            trusted: true,
            decision: None,
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

/// The host that answers the whole ask chain and records what it was
/// asked: the match answer is scripted, the consent consents, the VP
/// ask is recorded.
struct ScriptedHost {
    answer: MatchResult,
    consents: bool,
    vps: Mutex<Vec<VpParams>>,
    consents_asked: Mutex<usize>,
}

#[async_trait::async_trait]
impl Host for ScriptedHost {
    async fn request_sign(&self, _params: SignParams) -> Result<SignResult, HostError> {
        Err(HostError::Cannot("no plain sign in the test".to_owned()))
    }
    async fn request_match(&self, _params: MatchParams) -> Result<MatchResult, HostError> {
        Ok(self.answer.clone())
    }
    async fn request_consent(&self, _params: ConsentParams) -> Result<ConsentResult, HostError> {
        *self.consents_asked.lock().expect("lock") += 1;
        Ok(ConsentResult {
            consented: self.consents,
        })
    }
    async fn request_vp(&self, params: VpParams) -> Result<VpResult, HostError> {
        self.vps.lock().expect("lock").push(params);
        Ok(VpResult {
            vp_token: "token-1".to_owned(),
            refusal: None,
        })
    }
    async fn request_tx_code(&self, _flow_id: &str) -> Result<String, HostError> {
        Err(HostError::Cannot("no tx code in the test".to_owned()))
    }
    async fn open_authorization(&self, _flow_id: &str, _url: &str) -> Result<(), HostError> {
        Ok(())
    }
    fn progress(&self, _flow_id: &str, _step: &str, _detail: Option<String>) {}
}

/// The HTTP that records the verifier response POSTs.
struct RecordingHttp {
    posts: Mutex<Vec<(String, Vec<u8>)>>,
}

#[async_trait::async_trait]
impl HttpClient for RecordingHttp {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, HttpError> {
        if request.method == "POST" {
            self.posts
                .lock()
                .expect("lock")
                .push((request.url, request.body));
        }
        Ok(HttpResponse {
            status: 200,
            headers: Vec::new(),
            body: br#"{"redirect_uri":"https://verifier.example/after"}"#.to_vec(),
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

/// The flow context under a consent mode, with the telemetry recorded.
fn vet_context(mode: ConsentCheckMode, telemetry: Arc<RecordingTelemetry>) -> FlowContext {
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
        .transport(transport)
        .build();
    FlowContext {
        flow_id: "flow-vp-1".to_owned(),
        flow_type: "oid4vp".to_owned(),
        session: None,
        ports: Arc::new(Ports {
            http: Arc::new(RecordingHttp {
                posts: Mutex::new(Vec::new()),
            }),
            clock: Arc::new(FakeClock),
            rng: Arc::new(FakeRng),
            host: Arc::new(ScriptedHost {
                answer: MatchResult::default(),
                consents: true,
                vps: Mutex::new(Vec::new()),
                consents_asked: Mutex::new(0),
            }),
            pdp: Arc::new(TrustedPdp),
            kv: Arc::new(NoopKv),
            telemetry,
            consent_check: mode,
        }),
        peer,
        request_context: wmp_core::context::RequestContext::default(),
    }
}

/// The flow context for a full presentation, under a consent mode.
/// Returns the context, the HTTP that recorded the verifier POSTs, and
/// the transport that captured the peer's completions.
fn flow_context(
    mode: ConsentCheckMode,
    host: Arc<ScriptedHost>,
) -> (FlowContext, Arc<RecordingHttp>, Arc<CaptureTransport>) {
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
    let http = Arc::new(RecordingHttp {
        posts: Mutex::new(Vec::new()),
    });
    let telemetry = Arc::new(RecordingTelemetry::default());
    let ctx = FlowContext {
        flow_id: "flow-vp-1".to_owned(),
        flow_type: "oid4vp".to_owned(),
        session: None,
        ports: Arc::new(Ports {
            http: http.clone(),
            clock: Arc::new(FakeClock),
            rng: Arc::new(FakeRng),
            host,
            pdp: Arc::new(TrustedPdp),
            kv: Arc::new(NoopKv),
            telemetry,
            consent_check: mode,
        }),
        peer,
        request_context: wmp_core::context::RequestContext::default(),
    };
    (ctx, http, transport)
}

/// The completions the transport captured, as JSON values.
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

/// One selection, the Go fixture's `sel`.
fn sel(query: &str, claims: &[&str]) -> VpSelection {
    VpSelection {
        credential_query_id: query.to_owned(),
        credential_id: "cred-1".to_owned(),
        disclosed_claims: claims.iter().map(|c| c.to_string()).collect(),
    }
}

/// The flow start params, with a DCQL request whose pid query carries
/// the claims the fixture table vets.
fn dcql_start_params() -> FlowStartParams {
    FlowStartParams {
        wmp: wmp_core::types::Metadata::default(),
        flow_id: "flow-vp-1".to_owned(),
        flow_type: "oid4vp".to_owned(),
        params: serde_json::value::RawValue::from_string(
            serde_json::json!({
                "client_id": "https://verifier.example",
                "nonce": "nonce-vp-1",
                "response_uri": "https://verifier.example/response",
                "response_mode": "direct_post",
                "state": "state-vp-1",
                "dcql_query": {
                    "credentials": [
                        {
                            "id": "pid-query",
                            "meta": {"vct_values": ["urn:pid"]},
                            "claims": [
                                {"id": "a", "path": ["given_name"]},
                                {"id": "c", "path": ["address", "street"]},
                                {"id": "d", "path": ["nationalities", null, "code"]}
                            ]
                        }
                    ]
                }
            })
            .to_string(),
        )
        .ok(),
        timeout: None,
    }
}

// ─── The vetting table (the Go fixture, case for case) ───────────────────

/// The Go fixture table (`TestCheckConsentAgainstDCQL`), ported case
/// for case: the bare and joined spellings clients use, the wildcards,
/// the always-disclosed top-levels, the claim-set combinations, the
/// mdoc namespace, the duplicates, and the refusals' reason classes
/// and query ids. Each case carries its own query — the fixture's
/// where the case belongs to it, the Go table's per-case query
/// otherwise.
#[tokio::test]
async fn the_go_fixture_table_vets_case_for_case() {
    let fixture: serde_json::Value =
        serde_json::from_str(GO_FIXTURE_QUERY).expect("the fixture query parses");
    let in_options = serde_json::json!({
        "credentials": [{"id": "a"}, {"id": "b"}, {"id": "c"}],
        "credential_sets": [{"options": [["a"], ["b"]]}]
    });
    // (name, query, selections, expected reason, expected query id)
    let cases: Vec<(&str, serde_json::Value, Vec<VpSelection>, &str, &str)> = vec![
        (
            "valid bare names",
            fixture.clone(),
            vec![sel("pid", &["given_name", "family_name"])],
            "",
            "",
        ),
        (
            "valid joined path",
            fixture.clone(),
            vec![sel("pid", &["given_name", "address.street"])],
            "",
            "",
        ),
        (
            "valid bare last element of nested",
            fixture.clone(),
            vec![sel("pid", &["street"])],
            "",
            "",
        ),
        (
            "wildcard joined index",
            fixture.clone(),
            vec![sel("pid", &["nationalities.0.code"])],
            "",
            "",
        ),
        (
            "wildcard joined empty",
            fixture.clone(),
            vec![sel("pid", &["nationalities..code"])],
            "",
            "",
        ),
        (
            "child of requested path",
            fixture.clone(),
            vec![sel("pid", &["address.street.name"])],
            "",
            "",
        ),
        (
            "always disclosed",
            fixture.clone(),
            vec![sel("pid", &["vct", "given_name"])],
            "",
            "",
        ),
        (
            "empty disclosed",
            fixture.clone(),
            vec![sel("pid", &[])],
            "",
            "",
        ),
        // a client-supplied id is kept out of the violation
        (
            "unknown query id",
            fixture.clone(),
            vec![sel("other", &["given_name"])],
            REASON_OUTSIDE_QUERY,
            "",
        ),
        (
            "empty query id",
            fixture.clone(),
            vec![sel("", &["given_name"])],
            REASON_OUTSIDE_QUERY,
            "",
        ),
        (
            "claim outside query",
            fixture.clone(),
            vec![sel("pid", &["given_name", "birth_date"])],
            REASON_CLAIM_OUTSIDE,
            "pid",
        ),
        (
            "parent of requested path is a superset",
            fixture.clone(),
            vec![sel("pid", &["address"])],
            REASON_CLAIM_OUTSIDE,
            "pid",
        ),
        (
            "claim of another query",
            fixture.clone(),
            vec![sel("pid", &["portrait"])],
            REASON_CLAIM_OUTSIDE,
            "pid",
        ),
        (
            "claim_sets first combo",
            fixture.clone(),
            vec![sel("pid_sets", &["a", "b"])],
            "",
            "",
        ),
        (
            "claim_sets second combo",
            fixture.clone(),
            vec![sel("pid_sets", &["c"])],
            "",
            "",
        ),
        (
            "claim_sets subset of one combo",
            fixture.clone(),
            vec![sel("pid_sets", &["a"])],
            "",
            "",
        ),
        (
            "claim_sets mixed combos",
            fixture.clone(),
            vec![sel("pid_sets", &["a", "c"])],
            REASON_CLAIM_OUTSIDE,
            "pid_sets",
        ),
        (
            "mdoc namespace joined",
            fixture.clone(),
            vec![sel("mdl", &["org.iso.18013.5.1.family_name"])],
            "",
            "",
        ),
        (
            "mdoc element only",
            fixture.clone(),
            vec![sel("mdl", &["portrait"])],
            "",
            "",
        ),
        (
            "mdoc wrong namespace",
            fixture.clone(),
            vec![sel("mdl", &["org.other.family_name"])],
            REASON_CLAIM_OUTSIDE,
            "mdl",
        ),
        (
            "mdoc extra element",
            fixture.clone(),
            vec![sel("mdl", &["birth_date"])],
            REASON_CLAIM_OUTSIDE,
            "mdl",
        ),
        (
            "no-claims query, empty disclosed",
            fixture.clone(),
            vec![sel("noclaims", &[])],
            "",
            "",
        ),
        (
            "no-claims query, claims disclosed",
            fixture.clone(),
            vec![sel("noclaims", &["given_name"])],
            REASON_CLAIM_OUTSIDE,
            "noclaims",
        ),
        (
            "duplicate query id",
            fixture.clone(),
            vec![sel("pid", &["given_name"]), sel("pid", &["given_name"])],
            REASON_DUPLICATE,
            "pid",
        ),
        (
            "duplicate allowed with multiple",
            fixture.clone(),
            vec![sel("multi", &[]), sel("multi", &[])],
            "",
            "",
        ),
        (
            "two different queries",
            fixture.clone(),
            vec![sel("pid", &["given_name"]), sel("mdl", &["portrait"])],
            "",
            "",
        ),
        (
            "credential_sets: known option ids",
            in_options.clone(),
            vec![sel("a", &[])],
            "",
            "",
        ),
        (
            "credential_sets: id in no option",
            in_options,
            vec![sel("c", &[])],
            REASON_OUTSIDE_QUERY,
            "c",
        ),
        (
            "integer path element",
            serde_json::json!({"credentials":[{"id":"a","claims":[{"path":["list",1]}]}]}),
            vec![sel("a", &["list.1"])],
            "",
            "",
        ),
        (
            "integer path element mismatch",
            serde_json::json!({"credentials":[{"id":"a","claims":[{"path":["list",1,"x"]}]}]}),
            vec![sel("a", &["list.2.x"])],
            REASON_CLAIM_OUTSIDE,
            "a",
        ),
        (
            "trailing wildcard allows any bare name",
            serde_json::json!({"credentials":[{"id":"a","claims":[{"path":["address",null]}]}]}),
            vec![sel("a", &["street"])],
            "",
            "",
        ),
        (
            "values constraint does not affect path",
            serde_json::json!({"credentials":[{"id":"a","claims":[{"path":["age_over_18"],"values":[true]}]}]}),
            vec![sel("a", &["age_over_18"])],
            "",
            "",
        ),
        (
            "credential_sets: several sets combined",
            serde_json::json!({"credentials":[{"id":"a"},{"id":"b"},{"id":"c"}],
                "credential_sets":[{"options":[["a"]]},{"options":[["b","c"]],"required":false}]}),
            vec![sel("a", &[]), sel("b", &[]), sel("c", &[])],
            "",
            "",
        ),
    ];

    for (name, query, selections, reason, query_id) in cases {
        let telemetry = Arc::new(RecordingTelemetry::default());
        let ctx = vet_context(ConsentCheckMode::Enforce, telemetry);
        let violation = consent::vet(&ctx, Some(&query), &selections).await;
        if reason.is_empty() {
            assert!(
                violation.is_none(),
                "{name}: expected a fit, got {violation:?}"
            );
        } else {
            let violation = violation.unwrap_or_else(|| panic!("{name}: expected a refusal"));
            assert_eq!(violation.reason, reason, "{name}");
            assert_eq!(violation.query_id, query_id, "{name}");
        }
    }
}

/// The queries that cannot be interpreted, refused as violations:
/// `not json`, an empty object, a query with no credentials (the Go
/// `TestCheckConsentAgainstDCQL_Unparseable`). "Cannot compare" never
/// means "allowed".
#[tokio::test]
async fn an_uninterpretable_query_is_a_violation() {
    for query in ["not json", "{}", r#"{"credentials":[]}"#] {
        let value: serde_json::Value =
            serde_json::from_str(query).unwrap_or(serde_json::Value::Null);
        let telemetry = Arc::new(RecordingTelemetry::default());
        let ctx = vet_context(ConsentCheckMode::Enforce, telemetry.clone());
        let violation = consent::vet(&ctx, Some(&value), &[sel("a", &[])]).await;
        assert!(
            matches!(
                violation,
                Some(v) if v.reason == REASON_UNPARSEABLE
            ),
            "{query}: a query that cannot be interpreted is a violation"
        );
        // The record was made, with the unparseable reason class.
        let events = telemetry.events.lock().expect("lock");
        assert_eq!(events.len(), 1, "{query}: one violation record");
        assert_eq!(events[0].fields[1].1, REASON_UNPARSEABLE, "{query}");
    }
}

/// The modes: `warn` records the violation (telemetry: the reason
/// class and the query id alone) and proceeds; `enforce` refuses on
/// it; `off` compares nothing and records nothing (the Go
/// `TestConsentPolicy_Decide` "modes").
#[tokio::test]
async fn the_modes_record_and_refuse() {
    let query: serde_json::Value =
        serde_json::from_str(GO_FIXTURE_QUERY).expect("the fixture query parses");
    let violating = vec![sel("not-in-query", &[])];

    // Warn: recorded, proceeded. The record is read in a block, so
    // the guard drops before the next await.
    let telemetry = Arc::new(RecordingTelemetry::default());
    let ctx = vet_context(ConsentCheckMode::Warn, telemetry.clone());
    assert!(consent::vet(&ctx, Some(&query), &violating).await.is_none());
    {
        let events = telemetry.events.lock().expect("lock");
        assert_eq!(events.len(), 1, "warn records the violation");
        assert_eq!(events[0].name, "oid4vp_consent_violation");
        let fields: Vec<_> = events[0]
            .fields
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        assert!(fields.contains(&("mode", "warn")));
        assert!(fields.contains(&("reason", REASON_OUTSIDE_QUERY)));
        // The client-supplied id never rides the record.
        assert!(!fields.iter().any(|(_, v)| v.contains("not-in-query")));
    }

    // Enforce: recorded, refused.
    let telemetry = Arc::new(RecordingTelemetry::default());
    let ctx = vet_context(ConsentCheckMode::Enforce, telemetry);
    assert!(consent::vet(&ctx, Some(&query), &violating).await.is_some());

    // Off: nothing compared, nothing recorded.
    let telemetry = Arc::new(RecordingTelemetry::default());
    let ctx = vet_context(ConsentCheckMode::Off, telemetry.clone());
    assert!(consent::vet(&ctx, Some(&query), &violating).await.is_none());
    assert!(telemetry.events.lock().expect("lock").is_empty());

    // No query (a scope-only request): nothing to compare with, in
    // every mode.
    let telemetry = Arc::new(RecordingTelemetry::default());
    let ctx = vet_context(ConsentCheckMode::Enforce, telemetry);
    assert!(consent::vet(&ctx, None, &violating).await.is_none());
}

/// A violation's record never carries a claim name or value (the Go
/// "a refusal never carries a claim name"): the reason class and the
/// query id alone.
#[tokio::test]
async fn the_record_never_carries_a_claim_name() {
    let query: serde_json::Value =
        serde_json::from_str(GO_FIXTURE_QUERY).expect("the fixture query parses");
    let violating = vec![sel("pid", &["SECRET_CLAIM_NAME"])];
    let telemetry = Arc::new(RecordingTelemetry::default());
    let ctx = vet_context(ConsentCheckMode::Warn, telemetry.clone());
    let violation = consent::vet(&ctx, Some(&query), &violating).await;
    assert!(violation.is_none(), "warn proceeds");
    let events = telemetry.events.lock().expect("lock");
    let recorded = serde_json::to_string(&*events).expect("the record serialises");
    assert!(
        !recorded.contains("SECRET_CLAIM_NAME"),
        "a claim name never reaches the record"
    );
}

// ─── The flow ────────────────────────────────────────────────────────────

/// An `enforce` deployment refuses the presentation on a violating
/// match answer: the verifier is answered `access_denied` (as a decline
/// is), the consent UI is never asked, and the flow completes with the
/// refusal's reason class (the Go `refuseConsent`).
#[tokio::test]
async fn an_enforced_violation_refuses_the_presentation() {
    let host = Arc::new(ScriptedHost {
        answer: MatchResult {
            selections: vec![sel("pid-query", &["SECRET_CLAIM_NAME"])],
            handle: None,
        },
        consents: true,
        vps: Mutex::new(Vec::new()),
        consents_asked: Mutex::new(0),
    });
    let (ctx, http, transport) = flow_context(ConsentCheckMode::Enforce, host.clone());
    let flow = Oid4vpFlow;
    // The flow completes (the graceful refusal shape, as a decline):
    // the verifier was answered, the client sees the completion.
    flow.start_flow(&ctx, &dcql_start_params())
        .await
        .expect("the refusal completes the flow");

    // The verifier: access_denied, the same description as every
    // refusal (the verifier cannot tell them apart).
    let posts = http.posts.lock().expect("lock");
    assert_eq!(posts.len(), 1, "one response POST");
    let body = String::from_utf8(posts[0].1.clone()).expect("the response body is text");
    assert!(body.contains("error=access_denied"), "{body}");

    // The consent UI was never asked: the refusal answers before it.
    assert_eq!(*host.consents_asked.lock().expect("lock"), 0);
    // Nothing was signed: no VP ask.
    assert!(host.vps.lock().expect("lock").is_empty());
    // The completion carries the refusal's reason class.
    let completions = completions(&transport);
    assert_eq!(completions.len(), 1);
    assert_eq!(completions[0]["refused"], true);
    assert_eq!(completions[0]["reason"], REASON_CLAIM_OUTSIDE);
}

/// The transport's selection handle rides the match answer into the
/// presentation ask, unchanged (WMP OpenID4x 3.2.3.1): what the host
/// returns as its answer's handle is what the sign ask carries.
#[tokio::test]
async fn the_selection_handle_rides_into_the_presentation_ask() {
    let host = Arc::new(ScriptedHost {
        answer: MatchResult {
            selections: vec![sel("pid-query", &["given_name"])],
            handle: Some("selection-handle-7".to_owned()),
        },
        consents: true,
        vps: Mutex::new(Vec::new()),
        consents_asked: Mutex::new(0),
    });
    let (ctx, _http, _transport) = flow_context(ConsentCheckMode::Enforce, host.clone());
    let flow = Oid4vpFlow;
    flow.start_flow(&ctx, &dcql_start_params())
        .await
        .expect("the presentation completes");

    let vps = host.vps.lock().expect("lock");
    assert_eq!(vps.len(), 1, "one presentation ask");
    assert_eq!(
        vps[0].selection_handle.as_deref(),
        Some("selection-handle-7"),
        "the handle rides unchanged"
    );
}
