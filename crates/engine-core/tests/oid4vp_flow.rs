//! The OpenID4VP flow handler end to end on scripted ports: the
//! presentation, the untrusted-verifier refusal, and the sign-stage
//! refusal.

use engine_core::oid4vp::Oid4vpFlow;
use wmp_core::handler::HandlerError;
use wmp_core::methods::*;

/// Percent-decoding of a form value.
fn percent_decode(value: &str) -> String {
    let mut out = Vec::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            continue;
        }
        let hex: String = chars.by_ref().take(2).collect();
        let byte = u8::from_str_radix(&hex, 16).expect("a two-digit percent escape");
        out.push(byte);
    }
    String::from_utf8(out).expect("the decoded value is UTF-8")
}

mod presentation_flow_tests {
    //! The presentation flow, end to end on scripted ports: the request,
    //! the trust evaluation, the match with the DCQL query and the
    //! verifier, the consent, the host-constructed VP token, the DCQL
    //! assembly, and the submission.

    use super::*;
    use engine_core::runtime::{FlowContext, FlowHandler};
    use engine_core::Ports;
    use engine_ports::{
        AttestationParams, AttestationResult, ConsentParams, ConsentResult, DpopProofParams,
        DpopProofResult, EvaluationRequest, EvaluationResponse, Host, HostError, HttpClient,
        HttpError, HttpRequest, HttpResponse, KeyValue, KeyValueEntry, MatchParams, MatchResult,
        Pdp, PdpError, ResolveRequest, ResolveResponse, Rng, SignParams, SignResult, VpParams,
        VpResult, VpSelection,
    };
    use std::sync::{Arc, Mutex};

    struct TrustedPdp;
    #[async_trait::async_trait]
    impl Pdp for TrustedPdp {
        async fn evaluate(
            &self,
            _request: EvaluationRequest,
        ) -> Result<EvaluationResponse, PdpError> {
            Ok(EvaluationResponse {
                trusted: true,
                decision: Some("in the registry".to_owned()),
                context: None,
            })
        }
        async fn resolve(&self, _request: ResolveRequest) -> Result<ResolveResponse, PdpError> {
            Err(PdpError::NotImplemented)
        }
    }

    /// The host that answers the whole ask chain and records what it
    /// was asked.
    struct RecordingHost {
        matches: Mutex<Vec<MatchParams>>,
        vps: Mutex<Vec<VpParams>>,
    }

    #[async_trait::async_trait]
    impl Host for RecordingHost {
        async fn request_sign(&self, _params: SignParams) -> Result<SignResult, HostError> {
            Err(HostError::Cannot(
                "no plain sign in the presentation test".to_owned(),
            ))
        }
        async fn request_match(&self, params: MatchParams) -> Result<MatchResult, HostError> {
            self.matches.lock().map(|mut m| m.push(params)).ok();
            Ok(MatchResult {
                selections: vec![
                    VpSelection {
                        credential_query_id: "pid-query".to_owned(),
                        credential_id: "cred-pid".to_owned(),
                        disclosed_claims: vec!["given_name".to_owned()],
                    },
                    VpSelection {
                        credential_query_id: "degree-query".to_owned(),
                        credential_id: "cred-degree".to_owned(),
                        disclosed_claims: Vec::new(),
                    },
                ],
                handle: None,
            })
        }
        async fn request_consent(
            &self,
            _params: ConsentParams,
        ) -> Result<ConsentResult, HostError> {
            Ok(ConsentResult { consented: true })
        }
        async fn request_tx_code(&self, _flow_id: &str) -> Result<String, HostError> {
            Err(HostError::Cannot("no tx code".to_owned()))
        }
        async fn open_authorization(&self, _flow_id: &str, _url: &str) -> Result<(), HostError> {
            Ok(())
        }
        async fn request_vp(&self, params: VpParams) -> Result<VpResult, HostError> {
            self.vps.lock().map(|mut v| v.push(params)).ok();
            Ok(VpResult {
                vp_token: "token-pid\ntoken-degree".to_owned(),
                refusal: None,
            })
        }
        async fn request_dpop_proof(
            &self,
            _params: DpopProofParams,
        ) -> Result<DpopProofResult, HostError> {
            Err(HostError::Cannot("no client-held dpop".to_owned()))
        }
        async fn request_attestation(
            &self,
            _params: AttestationParams,
        ) -> Result<AttestationResult, HostError> {
            Err(HostError::Cannot("no attestation".to_owned()))
        }
        fn progress(&self, _flow_id: &str, _step: &str, _detail: Option<String>) {}
    }

    /// The scripted HTTP: one answer per URL.
    struct ScriptedHttp {
        answers: Mutex<Vec<(String, HttpResponse)>>,
        seen: Mutex<Vec<HttpRequest>>,
    }

    impl ScriptedHttp {
        fn new(answers: Vec<(String, HttpResponse)>) -> Self {
            Self {
                answers: Mutex::new(answers),
                seen: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl HttpClient for ScriptedHttp {
        async fn send(&self, request: HttpRequest) -> Result<HttpResponse, HttpError> {
            self.seen.lock().map(|mut s| s.push(request.clone())).ok();
            let answer = self.answers.lock().ok().and_then(|mut a| {
                a.iter()
                    .position(|(url, _)| *url == request.url)
                    .map(|index| a.remove(index).1)
            });
            Ok(answer.unwrap_or(HttpResponse {
                status: 404,
                headers: Vec::new(),
                body: Vec::new(),
            }))
        }
    }

    fn test_context(host: Arc<RecordingHost>, http: Arc<ScriptedHttp>) -> FlowContext {
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
        FlowContext {
            flow_id: "flow-vp-1".to_owned(),
            flow_type: "oid4vp".to_owned(),
            session: None,
            ports: Arc::new(Ports {
                http,
                clock: Arc::new(FixedClock),
                rng: Arc::new(FakeRng),
                host,
                pdp: Arc::new(TrustedPdp),
                kv: Arc::new(MemKv(Mutex::new(rustc_hash::FxHashMap::default()))),
                telemetry: Arc::new(NoTelemetry),
                consent_check: engine_ports::ConsentCheckMode::Warn,
                notifications: std::sync::Arc::new(
                    engine_core::oid4vci::notification::NotificationContexts::default(),
                ),
            }),
            peer,
            request_context: wmp_core::context::RequestContext::default(),
        }
    }

    pub(super) struct FixedClock;
    #[async_trait::async_trait]
    impl engine_ports::Clock for FixedClock {
        fn now_unix(&self) -> i64 {
            1_000
        }
        async fn sleep(&self, _duration_ms: u64) {}
    }

    pub(super) struct FakeRng;
    impl Rng for FakeRng {
        fn fill(&self, buf: &mut [u8]) -> bool {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = i as u8;
            }
            true
        }
    }

    pub(super) struct MemKv(pub(super) Mutex<rustc_hash::FxHashMap<String, Vec<u8>>>);
    #[async_trait::async_trait]
    impl KeyValue for MemKv {
        async fn get(&self, key: &str) -> Option<KeyValueEntry> {
            self.0.lock().ok()?.get(key).map(|v| KeyValueEntry {
                value: v.clone(),
                ttl_secs: None,
            })
        }
        async fn put(&self, key: &str, entry: KeyValueEntry) {
            self.0
                .lock()
                .map(|mut m| m.insert(key.to_owned(), entry.value))
                .ok();
        }
        async fn delete(&self, key: &str) {
            self.0.lock().map(|mut m| m.remove(key)).ok();
        }
    }

    pub(super) struct NoTelemetry;
    impl engine_ports::Telemetry for NoTelemetry {
        fn event(&self, _event: engine_ports::TelemetryEvent) {}
    }

    /// A params Box<RawValue> from a JSON value.
    pub(super) fn raw_value(value: serde_json::Value) -> Option<Box<serde_json::value::RawValue>> {
        serde_json::value::RawValue::from_string(value.to_string()).ok()
    }

    /// The refusal tests' request: a redirect_uri-scheme request (no
    /// signed form needed — the refusal is at the sign stage).
    pub(super) fn refusal_request_json() -> serde_json::Value {
        serde_json::json!({
            "client_id": "https://verifier.example",
            "nonce": "nonce-refusal-1",
            "response_uri": "https://verifier.example/response",
            "response_mode": "direct_post",
            "state": "state-refusal-1",
            "dcql_query": {"credentials": [
                {"id": "pid-query", "meta": {"vct_values": ["urn:pid"]}}
            ]},
        })
    }

    pub(super) fn start_params() -> FlowStartParams {
        FlowStartParams {
            wmp: wmp_core::types::Metadata::default(),
            flow_id: "flow-vp-1".to_owned(),
            flow_type: "oid4vp".to_owned(),
            params: raw_value(serde_json::json!({
                // The redirect_uri scheme: the x509_san_dns scheme now
                // requires the signed request form (§5), which the plain
                // params cannot carry.
                "client_id": "https://verifier.example",
                "nonce": "nonce-vp-1",
                "response_uri": "https://verifier.example/response",
                "response_mode": "direct_post",
                "state": "state-vp-1",
                "dcql_query": {
                    "credentials": [
                        { "id": "pid-query", "meta": { "vct_values": ["urn:pid"] } },
                        { "id": "degree-query", "meta": { "vct_values": ["urn:degree"] } }
                    ]
                }
            })),
            timeout: None,
        }
    }

    #[tokio::test]
    async fn the_presentation_flow_matches_consents_and_presents() {
        let host = Arc::new(RecordingHost {
            matches: Mutex::new(Vec::new()),
            vps: Mutex::new(Vec::new()),
        });
        let http = Arc::new(ScriptedHttp::new(vec![(
            "https://verifier.example/response".to_owned(),
            HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: br#"{"redirect_uri":"https://verifier.example/done"}"#.to_vec(),
            },
        )]));
        let ctx = test_context(host.clone(), http.clone());

        Oid4vpFlow
            .start_flow(&ctx, &start_params())
            .await
            .expect("the presentation flow completes");

        // The match ask carried the DCQL query and the verifier.
        let matches = host.matches.lock().expect("lock");
        assert_eq!(matches.len(), 1);
        assert!(matches[0].dcql_query.is_some());
        assert_eq!(matches[0].verifier.client_id, "https://verifier.example");
        assert!(matches[0].verifier.trusted);
        drop(matches);

        // The VP ask carried the audience, the nonce, both selections,
        // and the response endpoint; no thumbprint for direct_post.
        let vps = host.vps.lock().expect("lock");
        assert_eq!(vps.len(), 1);
        assert_eq!(vps[0].audience, "https://verifier.example");
        assert_eq!(vps[0].nonce, "nonce-vp-1");
        assert_eq!(vps[0].response_uri, "https://verifier.example/response");
        assert_eq!(vps[0].selections.len(), 2);
        assert_eq!(vps[0].selections[0].credential_query_id, "pid-query");
        assert_eq!(vps[0].verifier_jwk_thumbprint, "");
        drop(vps);

        // The submission: the vp_token restructured into the DCQL
        // object keyed by query id.
        let seen = http.seen.lock().expect("lock");
        assert_eq!(seen.len(), 1);
        let body = String::from_utf8_lossy(&seen[0].body).into_owned();
        assert!(body.contains("vp_token="));
        let vp_token = body
            .strip_prefix("vp_token=")
            .and_then(|rest| rest.split('&').next())
            .unwrap_or_default();
        let decoded = percent_decode(vp_token).into_bytes();
        let parsed: serde_json::Value =
            serde_json::from_slice(&decoded).expect("the restructured vp_token is JSON");
        assert_eq!(parsed["pid-query"], serde_json::json!(["token-pid"]));
        assert_eq!(parsed["degree-query"], serde_json::json!(["token-degree"]));
    }

    #[tokio::test]
    async fn an_empty_match_ends_the_flow_without_presenting() {
        struct EmptyMatchHost;
        #[async_trait::async_trait]
        impl Host for EmptyMatchHost {
            async fn request_sign(&self, _params: SignParams) -> Result<SignResult, HostError> {
                Err(HostError::Cannot("no".to_owned()))
            }
            async fn request_match(&self, _params: MatchParams) -> Result<MatchResult, HostError> {
                Ok(MatchResult {
                    selections: Vec::new(),
                    handle: None,
                })
            }
            async fn request_consent(
                &self,
                _params: ConsentParams,
            ) -> Result<ConsentResult, HostError> {
                Err(HostError::Cannot("never asked".to_owned()))
            }
            async fn request_tx_code(&self, _flow_id: &str) -> Result<String, HostError> {
                Err(HostError::Cannot("no".to_owned()))
            }
            async fn open_authorization(
                &self,
                _flow_id: &str,
                _url: &str,
            ) -> Result<(), HostError> {
                Ok(())
            }
            fn progress(&self, _flow_id: &str, _step: &str, _detail: Option<String>) {}
        }

        let http = Arc::new(ScriptedHttp::new(Vec::new()));
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
        let ctx = FlowContext {
            flow_id: "flow-vp-1".to_owned(),
            flow_type: "oid4vp".to_owned(),
            session: None,
            ports: Arc::new(Ports {
                http: http.clone(),
                clock: Arc::new(FixedClock),
                rng: Arc::new(FakeRng),
                host: Arc::new(EmptyMatchHost),
                pdp: Arc::new(TrustedPdp),
                kv: Arc::new(MemKv(Mutex::new(rustc_hash::FxHashMap::default()))),
                telemetry: Arc::new(NoTelemetry),
                consent_check: engine_ports::ConsentCheckMode::Warn,
                notifications: std::sync::Arc::new(
                    engine_core::oid4vci::notification::NotificationContexts::default(),
                ),
            }),
            peer,
            request_context: wmp_core::context::RequestContext::default(),
        };

        Oid4vpFlow
            .start_flow(&ctx, &start_params())
            .await
            .expect("the empty match ends the flow, it is not an error");

        // The DCQL contract (OID4VP 1.0 §6.2, §6.4.2): the required
        // queries the wallet cannot satisfy answer with access_denied —
        // one error POST, no vp_token.
        let seen = http.seen.lock().expect("lock").clone();
        assert_eq!(seen.len(), 1, "exactly the access_denied submission");
        let body = String::from_utf8_lossy(&seen[0].body).into_owned();
        assert!(
            body.contains("error=access_denied"),
            "the access_denied error response: {body}"
        );
        assert!(!body.contains("vp_token="));
    }
}

mod untrusted_flow_tests {
    //! The untrusted-verifier refusal at the flow level: the typed -31006
    //! data (go-wmp's NewUntrustedVerifierData shape) rides the flow
    //! error — the class reason, the refused verifier, the PDP's detail,
    //! and the retryable flag. The ports are the presentation flow's own
    //! test fakes, reached through the parent module's re-exports.

    use super::presentation_flow_tests::{FakeRng, FixedClock, MemKv, NoTelemetry};
    use super::*;
    use engine_core::runtime::{FlowContext, FlowHandler};
    use engine_core::Ports;
    use engine_ports::{
        EvaluationRequest, EvaluationResponse, Host, HostError, HttpClient, HttpError, HttpRequest,
        HttpResponse, MatchParams, MatchResult, Pdp, PdpError, ResolveRequest, ResolveResponse,
        SignParams, SignResult,
    };
    use std::sync::{Arc, Mutex};

    /// The PDP that answers untrusted, with its reason.
    struct UntrustedPdp;

    #[async_trait::async_trait]
    impl Pdp for UntrustedPdp {
        async fn evaluate(
            &self,
            _request: EvaluationRequest,
        ) -> Result<EvaluationResponse, PdpError> {
            Ok(EvaluationResponse {
                trusted: false,
                decision: Some("not in the registry".to_owned()),
                context: None,
            })
        }
        async fn resolve(&self, _request: ResolveRequest) -> Result<ResolveResponse, PdpError> {
            Err(PdpError::NotImplemented)
        }
    }

    /// A host that answers nothing: the refusal happens before any ask.
    struct SilentHost;

    #[async_trait::async_trait]
    impl Host for SilentHost {
        async fn request_sign(&self, _params: SignParams) -> Result<SignResult, HostError> {
            Err(HostError::Cannot("silent".to_owned()))
        }
        async fn request_match(&self, _params: MatchParams) -> Result<MatchResult, HostError> {
            Err(HostError::Cannot("silent".to_owned()))
        }
        async fn request_consent(
            &self,
            _params: engine_ports::ConsentParams,
        ) -> Result<engine_ports::ConsentResult, HostError> {
            Err(HostError::Cannot("silent".to_owned()))
        }
        async fn request_tx_code(&self, _flow_id: &str) -> Result<String, HostError> {
            Err(HostError::Cannot("silent".to_owned()))
        }
        async fn open_authorization(&self, _flow_id: &str, _url: &str) -> Result<(), HostError> {
            Err(HostError::Cannot("silent".to_owned()))
        }
        fn progress(&self, _flow_id: &str, _step: &str, _detail: Option<String>) {}
    }

    struct EmptyHttp;

    #[async_trait::async_trait]
    impl HttpClient for EmptyHttp {
        async fn send(&self, _request: HttpRequest) -> Result<HttpResponse, HttpError> {
            Err(HttpError::Refused)
        }
    }

    #[tokio::test]
    async fn the_untrusted_verifier_refusal_carries_the_typed_flow_error_data() {
        let store = std::sync::Arc::new(wmp_core::session::MemorySessionStore::new());
        let _ = &store; // used by the session_store call below
        let peer = wmp_core::peer::PeerBuilder::new(Arc::new(
            wmp_core::sessionservice::SessionHandler::new(
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
            ),
        ))
        .session_store(store)
        .build();
        let ctx = FlowContext {
            flow_id: "flow-untrusted-1".to_owned(),
            flow_type: "oid4vp".to_owned(),
            session: None,
            ports: Arc::new(Ports {
                http: Arc::new(EmptyHttp),
                clock: Arc::new(FixedClock),
                rng: Arc::new(FakeRng),
                host: Arc::new(SilentHost),
                pdp: Arc::new(UntrustedPdp),
                kv: Arc::new(MemKv(Mutex::new(rustc_hash::FxHashMap::default()))),
                telemetry: Arc::new(NoTelemetry),
                consent_check: engine_ports::ConsentCheckMode::Warn,
                notifications: std::sync::Arc::new(
                    engine_core::oid4vci::notification::NotificationContexts::default(),
                ),
            }),
            peer,
            request_context: wmp_core::context::RequestContext::default(),
        };
        let flow = Oid4vpFlow;
        let params = super::presentation_flow_tests::start_params();
        let err = flow
            .start_flow(&ctx, &params)
            .await
            .expect_err("the untrusted verifier refuses");
        // The flow error: -31006 with the typed data.
        let HandlerError::Rpc(rpc) = &err else {
            panic!("the refusal is a flow error: {err:?}");
        };
        assert_eq!(rpc.code, wmp_core::error::ERR_FLOW_ERROR);
        let data: serde_json::Value = {
            let raw = rpc.data.as_ref().expect("the typed data rides the error");
            serde_json::from_str(raw.get()).expect("the data is JSON")
        };
        assert_eq!(
            data.get("reason").and_then(serde_json::Value::as_str),
            Some("untrusted_verifier"),
            "the class reason: {data}"
        );
        assert_eq!(
            data.get("verifier").and_then(serde_json::Value::as_str),
            Some("https://verifier.example"),
            "the refused verifier: {data}"
        );
        assert_eq!(
            data.get("detail").and_then(serde_json::Value::as_str),
            Some("not in the registry"),
            "the PDP's detail: {data}"
        );
        assert_eq!(
            data.get("retryable").and_then(serde_json::Value::as_bool),
            Some(false),
            "never retryable: {data}"
        );
    }
}

mod sign_refusal_tests {
    //! The sign-stage refusal (#472): a host that refuses at `request_vp`
    //! — by the user's decline, or by the answer's refusal code — answers
    //! the verifier `access_denied` at once and completes the flow with
    //! the decline, never a partial vp_token.

    use super::*;
    use engine_core::runtime::{FlowContext, FlowHandler};
    use engine_core::Ports;
    use engine_ports::{
        ConsentParams, ConsentResult, EvaluationRequest, EvaluationResponse, Host, HostError,
        HttpClient, HttpError, HttpRequest, HttpResponse, MatchParams, MatchResult, Pdp, PdpError,
        ResolveRequest, ResolveResponse, SignParams, SignResult, VpParams, VpResult, VpSelection,
    };
    use std::sync::{Arc, Mutex};

    /// A PDP that trusts everything.
    struct TrustedPdp;
    #[async_trait::async_trait]
    impl Pdp for TrustedPdp {
        async fn evaluate(
            &self,
            _request: EvaluationRequest,
        ) -> Result<EvaluationResponse, PdpError> {
            Ok(EvaluationResponse {
                trusted: true,
                decision: None,
                context: None,
            })
        }
        async fn resolve(&self, _request: ResolveRequest) -> Result<ResolveResponse, PdpError> {
            Err(PdpError::NotImplemented)
        }
    }

    /// The recording HTTP: the verifier's error POST lands here.
    struct RecordingHttp {
        posts: Mutex<Vec<(String, Vec<u8>)>>,
    }
    #[async_trait::async_trait]
    impl HttpClient for RecordingHttp {
        async fn send(&self, request: HttpRequest) -> Result<HttpResponse, HttpError> {
            if request.method == "POST" {
                self.posts
                    .lock()
                    .map(|mut p| p.push((request.url, request.body)))
                    .ok();
            }
            Ok(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: br#"{"redirect_uri":"https://verifier.example/after"}"#.to_vec(),
            })
        }
    }

    /// A host that refuses the VP ask: by the user's decline (an
    /// `Err`), or by the answer's refusal code (an `Ok` with
    /// `refusal` set).
    struct RefusingHost {
        by_error: bool,
    }
    #[async_trait::async_trait]
    impl Host for RefusingHost {
        async fn request_sign(&self, _p: SignParams) -> Result<SignResult, HostError> {
            Err(HostError::Cannot("refusing".to_owned()))
        }
        async fn request_match(&self, _params: MatchParams) -> Result<MatchResult, HostError> {
            Ok(MatchResult {
                selections: vec![VpSelection {
                    credential_query_id: "pid-query".to_owned(),
                    credential_id: "cred-pid-001".to_owned(),
                    disclosed_claims: Vec::new(),
                }],
                handle: None,
            })
        }
        async fn request_consent(&self, _p: ConsentParams) -> Result<ConsentResult, HostError> {
            Ok(ConsentResult { consented: true })
        }
        async fn request_tx_code(&self, _f: &str) -> Result<String, HostError> {
            Ok("1234".to_owned())
        }
        async fn open_authorization(&self, _f: &str, _u: &str) -> Result<(), HostError> {
            Ok(())
        }
        async fn request_vp(&self, _params: VpParams) -> Result<VpResult, HostError> {
            if self.by_error {
                // The user's decline at the sign stage.
                Err(HostError::Declined)
            } else {
                // The answer's refusal code (#472's
                // sign_response.error_code).
                Ok(VpResult {
                    vp_token: String::new(),
                    refusal: Some(engine_ports::SignRefusal::sign_refused()),
                })
            }
        }
        fn progress(&self, _f: &str, _s: &str, _d: Option<String>) {}
    }

    fn refusal_context(host: Arc<RefusingHost>, http: Arc<RecordingHttp>) -> FlowContext {
        let store = Arc::new(wmp_core::session::MemorySessionStore::new());
        let peer = wmp_core::peer::PeerBuilder::new(Arc::new(
            wmp_core::sessionservice::SessionHandler::new(
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
            ),
        ))
        .session_store(store)
        .build();
        FlowContext {
            flow_id: "flow-refusal-1".to_owned(),
            flow_type: "oid4vp".to_owned(),
            session: None,
            ports: Arc::new(Ports {
                http,
                clock: Arc::new(super::presentation_flow_tests::FixedClock),
                rng: Arc::new(super::presentation_flow_tests::FakeRng),
                host,
                pdp: Arc::new(TrustedPdp),
                kv: Arc::new(super::presentation_flow_tests::MemKv(
                    std::sync::Mutex::new(rustc_hash::FxHashMap::default()),
                )),
                telemetry: Arc::new(super::presentation_flow_tests::NoTelemetry),
                consent_check: engine_ports::ConsentCheckMode::Warn,
                notifications: std::sync::Arc::new(
                    engine_core::oid4vci::notification::NotificationContexts::default(),
                ),
            }),
            peer,
            request_context: wmp_core::context::RequestContext::default(),
        }
    }

    fn refusal_start_params() -> FlowStartParams {
        FlowStartParams {
            wmp: wmp_core::types::Metadata::default(),
            flow_id: "flow-refusal-1".to_owned(),
            flow_type: "oid4vp".to_owned(),
            params: super::presentation_flow_tests::raw_value(
                super::presentation_flow_tests::refusal_request_json(),
            ),
            timeout: None,
        }
    }

    #[tokio::test]
    async fn a_users_decline_at_the_sign_stage_answers_the_verifier_access_denied() {
        let host = Arc::new(RefusingHost { by_error: true });
        let http = Arc::new(RecordingHttp {
            posts: Mutex::new(Vec::new()),
        });
        let ctx = refusal_context(host, http.clone());
        let flow = Oid4vpFlow;
        // The flow completes (not errors): the refusal is a completion
        // with declined:true, the verifier answered.
        flow.start_flow(&ctx, &refusal_start_params())
            .await
            .expect("the refusal completes the flow");
        // The verifier was POSTed the access_denied.
        let posts = http.posts.lock().expect("lock");
        assert!(
            posts
                .iter()
                .any(|(_, body)| String::from_utf8_lossy(body).contains("error=access_denied")),
            "the verifier got the access_denied: {posts:?}"
        );
    }

    #[tokio::test]
    async fn a_sign_refusal_code_answers_the_verifier_access_denied() {
        let host = Arc::new(RefusingHost { by_error: false });
        let http = Arc::new(RecordingHttp {
            posts: Mutex::new(Vec::new()),
        });
        let ctx = refusal_context(host, http.clone());
        let flow = Oid4vpFlow;
        flow.start_flow(&ctx, &refusal_start_params())
            .await
            .expect("the refusal completes the flow");
        let posts = http.posts.lock().expect("lock");
        assert!(
            posts
                .iter()
                .any(|(_, body)| String::from_utf8_lossy(body).contains("error=access_denied")),
            "the verifier got the access_denied: {posts:?}"
        );
    }
}
