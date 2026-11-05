//! The OID4VCI flow handler, end to end on fake ports.

mod auth_code_flow_tests {
    //! The two-call authorization-code flow, end to end on fake ports:
    //! start_flow builds the authorization request (PKCE, PAR) and hands
    //! the URL over; the redirect's answer arrives as wmp.flow.action,
    //! and the resume exchanges, re-resolves, and delivers.

    use engine_core::oid4vci::*;
    use engine_core::runtime::{FlowContext, FlowHandler};
    use engine_core::Ports;
    use engine_ports::{
        ConsentParams, ConsentResult, EvaluationRequest, EvaluationResponse, Host, HostError,
        HttpClient, HttpError, HttpRequest, HttpResponse, KeyValue, KeyValueEntry, MatchResult,
        Pdp, PdpError, ResolveRequest, ResolveResponse, Rng, SignParams, SignResult, VpSelection,
    };
    use std::sync::{Arc, Mutex};
    use wmp_core::methods::{FlowActionParams, FlowStartParams};

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

    /// An in-memory KeyValue.
    struct MemKv(Mutex<rustc_hash::FxHashMap<String, Vec<u8>>>);
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
            })
        }
        async fn resolve(&self, _request: ResolveRequest) -> Result<ResolveResponse, PdpError> {
            Err(PdpError::NotImplemented)
        }
    }

    pub(super) struct FakeHost {
        pub(super) authorization_urls: Mutex<Vec<String>>,
        pub(super) sign_key_ids: Mutex<Vec<Option<String>>>,
    }
    #[async_trait::async_trait]
    impl Host for FakeHost {
        async fn request_sign(&self, p: SignParams) -> Result<SignResult, HostError> {
            // The key id each sign ask named — the RFC 7523
            // assertion's registered kid, when the AS demands the
            // method.
            self.sign_key_ids
                .lock()
                .map(|mut ids| ids.push(p.key_id))
                .ok();
            Ok(SignResult {
                signature: vec![1, 2, 3, 4],
            })
        }
        async fn request_match(
            &self,
            _params: engine_ports::MatchParams,
        ) -> Result<MatchResult, HostError> {
            Ok(MatchResult {
                selections: vec![VpSelection {
                    credential_query_id: String::new(),
                    credential_id: "cred-1".to_owned(),
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
        async fn open_authorization(&self, _f: &str, url: &str) -> Result<(), HostError> {
            self.authorization_urls
                .lock()
                .map(|mut u| u.push(url.to_owned()))
                .ok();
            Ok(())
        }
        fn progress(&self, _f: &str, _s: &str, _d: Option<String>) {}
    }

    /// The scripted HTTP: dispatches by URL.
    struct ScriptedHttp {
        credential_requests: Mutex<Vec<Vec<u8>>>,
        /// The AS metadata's `token_endpoint_auth_methods_supported`
        /// (OpenID4VCI 1.0 §5.1) — the private_key_jwt variant the
        /// code-for-token exchange answers with the RFC 7523
        /// assertion.
        token_auth_methods: Vec<String>,
    }
    #[async_trait::async_trait]
    impl HttpClient for ScriptedHttp {
        async fn send(&self, request: HttpRequest) -> Result<HttpResponse, HttpError> {
            let body = match request.url.as_str() {
                "https://issuer.example/.well-known/openid-credential-issuer" => {
                    serde_json::json!({
                        "credential_issuer": "https://issuer.example",
                        "authorization_servers": ["https://as.example"],
                        "credential_configurations_supported": {
                            "UniversityDegree": { "scope": "openid credential", "format": "sd_jwt" }
                        }
                    })
                    .to_string()
                }
                "https://as.example/.well-known/oauth-authorization-server" => serde_json::json!({
                    "issuer": "https://as.example",
                    "authorization_endpoint": "https://as.example/authorize",
                    "token_endpoint": "https://as.example/token",
                    "pushed_authorization_request_endpoint": "https://as.example/par",
                    "require_pushed_authorization_requests": false,
                    "challenge_endpoint": "https://as.example/attestation/challenge",
                    "token_endpoint_auth_methods_supported": &self.token_auth_methods,
                })
                .to_string(),
                "https://as.example/par" => {
                    // The PAR push: assert the parameters arrived.
                    let form = String::from_utf8_lossy(&request.body).into_owned();
                    assert!(
                        form.contains("grant_type=authorization_code")
                            || form.contains("response_type=code")
                    );
                    assert!(form.contains("code_challenge_method=S256"));
                    assert!(form.contains("code_challenge="));
                    assert!(form.contains("issuer_state=session-1"));
                    assert!(form.contains("resource=https%3A%2F%2Fissuer.example"));
                    serde_json::json!({ "request_uri": "urn:ietf:params:oauth:request_uri:par-1" })
                        .to_string()
                }
                "https://as.example/token" => {
                    let form = String::from_utf8_lossy(&request.body).into_owned();
                    if form.contains("grant_type=authorization_code") {
                        assert!(form.contains("code_verifier="));
                        assert!(form.contains("resource=https%3A%2F%2Fissuer.example"));
                        // The RFC 7523 assertion, when the AS names the
                        // method: the type and the value ride the form
                        // (RFC 7523 §2.2).
                        if self
                            .token_auth_methods
                            .iter()
                            .any(|m| m == "private_key_jwt")
                        {
                            assert!(form.contains(
                                "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer"
                            ));
                            assert!(form.contains("client_assertion="));
                        }
                    } else {
                        // The renewal grant.
                        assert!(form.contains("grant_type=refresh_token"));
                        assert!(form.contains("refresh_token=rt-1"));
                    }
                    serde_json::json!({
                        "access_token": "at-1", "token_type": "Bearer", "expires_in": 3600,
                        "c_nonce": "nonce-1",
                        "refresh_token": "rt-2"
                    })
                    .to_string()
                }
                "https://issuer.example/credential" => {
                    self.credential_requests
                        .lock()
                        .map(|mut r| r.push(request.body.clone()))
                        .ok();
                    serde_json::json!({ "credential": "credential-jwt-1" }).to_string()
                }
                "https://issuer.example/notification" => "{}".to_owned(),
                other => panic!("unexpected fetch: {other}"),
            };
            Ok(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: body.into_bytes(),
            })
        }
    }

    pub(super) fn test_context(http: Arc<dyn HttpClient>, host: Arc<FakeHost>) -> FlowContext {
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
            flow_id: "flow-1".to_owned(),
            flow_type: "oid4vci".to_owned(),
            session: None,
            ports: Arc::new(Ports {
                http,
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
        }
    }

    struct FakeClock;
    #[async_trait::async_trait]
    impl engine_ports::Clock for FakeClock {
        fn now_unix(&self) -> i64 {
            1_000
        }
        async fn sleep(&self, _duration_ms: u64) {}
    }

    struct NoopTelemetry;
    impl engine_ports::Telemetry for NoopTelemetry {
        fn event(&self, _event: engine_ports::TelemetryEvent) {}
    }

    fn start_params() -> FlowStartParams {
        FlowStartParams {
            wmp: wmp_core::types::Metadata::default(),
            flow_id: "flow-1".to_owned(),
            flow_type: "oid4vci".to_owned(),
            params: raw_value(serde_json::json!({
                "credential_issuer": "https://issuer.example",
                "credential_configuration_ids": ["UniversityDegree"],
                "grants": {
                    "authorization_code": { "issuer_state": "session-1" }
                },
                "redirect_uri": "https://wallet.example/cb",
                "client_id": "client-1"
            })),
            timeout: None,
        }
    }

    /// A params Box<RawValue> from a JSON value.
    pub(super) fn raw_value(value: serde_json::Value) -> Option<Box<serde_json::value::RawValue>> {
        serde_json::value::RawValue::from_string(value.to_string()).ok()
    }

    #[tokio::test]
    async fn the_authorization_code_flow_spans_start_and_action() {
        let http = Arc::new(ScriptedHttp {
            credential_requests: Mutex::new(Vec::new()),
            token_auth_methods: Vec::new(),
        });
        let host = Arc::new(FakeHost {
            authorization_urls: Mutex::new(Vec::new()),
            sign_key_ids: Mutex::new(Vec::new()),
        });
        let ctx = test_context(http.clone() as Arc<dyn HttpClient>, host.clone());
        let flow = Oid4vciFlow;

        // ── The first call: the authorization request ──────────────────
        let result = flow.start_flow(&ctx, &start_params()).await.expect("start");
        assert_eq!(result.flow_id, "flow-1");

        // The handoff: the authorization URL carries the PAR request_uri
        // and only client_id beside it. The guard is block-scoped: the
        // lock must not live across the resume's await.
        {
            let urls = host.authorization_urls.lock().expect("lock");
            assert_eq!(urls.len(), 1);
            assert!(urls[0].starts_with("https://as.example/authorize?"));
            assert!(
                urls[0].contains("request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Apar-1")
            );
            assert!(urls[0].contains("client_id=client-1"));
            // The pushed parameters are NOT in the URL (PAR: server-side).
            assert!(!urls[0].contains("code_challenge="));
        }

        // ── The second call: the redirect's answer ─────────────────────
        // The state the Rng port produced (bytes 0..16).
        let expected_state = auth_code::generate_state(&FakeRng).expect("state");
        let action = FlowActionParams {
            wmp: wmp_core::types::Metadata::default(),
            flow_id: "flow-1".to_owned(),
            action: "authorization_complete".to_owned(),
            params: raw_value(
                serde_json::json!({ "code": "auth-code-1", "state": expected_state }),
            ),
        };
        let result = flow.handle_action(&ctx, &action).await.expect("resume");
        assert_eq!(result.status, "completed");

        // The credential request happened, with the proof.
        let requests = http.credential_requests.lock().expect("lock");
        assert_eq!(requests.len(), 1);
        let body: serde_json::Value = serde_json::from_slice(&requests[0]).expect("json");
        assert_eq!(body["credential_configuration_id"], "UniversityDegree");
        assert!(body["proofs"]["jwt"][0]
            .as_str()
            .is_some_and(|j| !j.is_empty()));
    }

    #[tokio::test]
    async fn the_resume_carries_the_private_key_jwt_assertion_with_the_registered_kid() {
        let http = Arc::new(ScriptedHttp {
            credential_requests: Mutex::new(Vec::new()),
            // The AS names the method (OpenID4VCI 1.0 §5.1): the
            // code-for-token POST must carry the RFC 7523 assertion.
            token_auth_methods: vec!["private_key_jwt".to_owned()],
        });
        let host = Arc::new(FakeHost {
            authorization_urls: Mutex::new(Vec::new()),
            sign_key_ids: Mutex::new(Vec::new()),
        });
        let ctx = test_context(http.clone() as Arc<dyn HttpClient>, host.clone());
        let flow = Oid4vciFlow;

        // The flow start carries the registered kid: the stash keeps
        // the offer params across the reload (the stateless resume).
        let params = FlowStartParams {
            wmp: wmp_core::types::Metadata::default(),
            flow_id: "flow-1".to_owned(),
            flow_type: "oid4vci".to_owned(),
            params: raw_value(serde_json::json!({
                "credential_issuer": "https://issuer.example",
                "credential_configuration_ids": ["UniversityDegree"],
                "grants": {
                    "authorization_code": { "issuer_state": "session-1" }
                },
                "redirect_uri": "https://wallet.example/cb",
                "client_id": "client-1",
                "client_key_kid": "client-key-1"
            })),
            timeout: None,
        };
        flow.start_flow(&ctx, &params).await.expect("start");

        // The redirect's answer, with the state the Rng port produced.
        let expected_state = auth_code::generate_state(&FakeRng).expect("state");
        let action = FlowActionParams {
            wmp: wmp_core::types::Metadata::default(),
            flow_id: "flow-1".to_owned(),
            action: "authorization_complete".to_owned(),
            params: raw_value(
                serde_json::json!({ "code": "auth-code-1", "state": expected_state }),
            ),
        };
        let result = flow.handle_action(&ctx, &action).await.expect("resume");
        assert_eq!(result.status, "completed");

        // The assertion's sign ask named the registered kid — the
        // stash relayed it across the reload, and the scripted token
        // handler asserts the form members the assertion rides.
        let key_ids = host.sign_key_ids.lock().expect("lock");
        assert!(
            key_ids
                .iter()
                .any(|id| id.as_deref() == Some("client-key-1")),
            "the sign asks carried the registered kid: {key_ids:?}"
        );
    }

    #[tokio::test]
    async fn a_state_mismatch_refuses_the_resume() {
        let http = Arc::new(ScriptedHttp {
            credential_requests: Mutex::new(Vec::new()),
            token_auth_methods: Vec::new(),
        });
        let host = Arc::new(FakeHost {
            authorization_urls: Mutex::new(Vec::new()),
            sign_key_ids: Mutex::new(Vec::new()),
        });
        let ctx = test_context(http.clone() as Arc<dyn HttpClient>, host.clone());
        let flow = Oid4vciFlow;

        flow.start_flow(&ctx, &start_params()).await.expect("start");

        // A state that is not the stashed one: the CSRF refusal.
        let action = FlowActionParams {
            wmp: wmp_core::types::Metadata::default(),
            flow_id: "flow-1".to_owned(),
            action: "authorization_complete".to_owned(),
            params: raw_value(serde_json::json!({ "code": "auth-code-1", "state": "wrong-state" })),
        };
        assert!(flow.handle_action(&ctx, &action).await.is_err());
        // Nothing reached the credential endpoint.
        assert!(http.credential_requests.lock().expect("lock").is_empty());
    }
}

mod renewal_flow_tests {
    //! The renewal relay, end to end: the flow start carries the
    //! refresh_token, the DPoP key the token was bound to, and the
    //! reissuance kid — the same key re-signs the proof, and the
    //! completion relays the new refresh token and key forward.

    use engine_core::oid4vci::*;
    use engine_core::runtime::{FlowContext, FlowHandler};
    use engine_core::Ports;
    use engine_ports::{
        ConsentParams, ConsentResult, EvaluationRequest, EvaluationResponse, Host, HostError,
        HttpClient, HttpError, HttpRequest, HttpResponse, MatchParams, MatchResult, Pdp, PdpError,
        ResolveRequest, ResolveResponse, Rng, SignParams, SignResult,
    };
    use std::sync::{Arc, Mutex};
    use wmp_core::methods::FlowStartParams;

    struct TrustedPdp;
    #[async_trait::async_trait]
    impl Pdp for TrustedPdp {
        async fn evaluate(&self, _r: EvaluationRequest) -> Result<EvaluationResponse, PdpError> {
            Ok(EvaluationResponse {
                trusted: true,
                decision: None,
            })
        }
        async fn resolve(&self, _r: ResolveRequest) -> Result<ResolveResponse, PdpError> {
            Err(PdpError::NotImplemented)
        }
    }

    /// The host that records the sign ask's key id.
    struct RenewalHost {
        sign_key_ids: Mutex<Vec<Option<String>>>,
    }

    #[async_trait::async_trait]
    impl Host for RenewalHost {
        async fn request_sign(&self, p: SignParams) -> Result<SignResult, HostError> {
            self.sign_key_ids
                .lock()
                .map(|mut k| k.push(p.key_id.clone()))
                .ok();
            Ok(SignResult {
                signature: vec![9, 8, 7, 6],
            })
        }
        async fn request_match(&self, _p: MatchParams) -> Result<MatchResult, HostError> {
            Err(HostError::Cannot("no match".to_owned()))
        }
        async fn request_consent(&self, _p: ConsentParams) -> Result<ConsentResult, HostError> {
            Err(HostError::Cannot("no consent".to_owned()))
        }
        async fn request_tx_code(&self, _f: &str) -> Result<String, HostError> {
            Err(HostError::Cannot("no tx code".to_owned()))
        }
        async fn open_authorization(&self, _f: &str, _u: &str) -> Result<(), HostError> {
            Ok(())
        }
        fn progress(&self, _f: &str, _s: &str, _d: Option<String>) {}
    }

    struct RenewalHttp {
        token_requests: Mutex<Vec<Vec<u8>>>,
    }

    #[async_trait::async_trait]
    impl HttpClient for RenewalHttp {
        async fn send(&self, request: HttpRequest) -> Result<HttpResponse, HttpError> {
            let body = match request.url.as_str() {
                "https://issuer.example/.well-known/openid-credential-issuer" => {
                    serde_json::json!({
                        "credential_issuer": "https://issuer.example",
                        "authorization_servers": ["https://as.example"],
                        "credential_configurations_supported": {
                            "UniversityDegree": { "scope": "openid", "format": "sd_jwt" }
                        }
                    })
                    .to_string()
                }
                "https://as.example/.well-known/oauth-authorization-server" => serde_json::json!({
                    "issuer": "https://as.example",
                    "token_endpoint": "https://as.example/token"
                })
                .to_string(),
                "https://as.example/token" => {
                    self.token_requests
                        .lock()
                        .map(|mut r| r.push(request.body.clone()))
                        .ok();
                    serde_json::json!({
                        "access_token": "at-renewed", "token_type": "Bearer",
                        "refresh_token": "rt-2"
                    })
                    .to_string()
                }
                "https://issuer.example/credential" => {
                    serde_json::json!({ "credential": "credential-renewed" }).to_string()
                }
                "https://issuer.example/notification" => "{}".to_owned(),
                other => panic!("unexpected fetch: {other}"),
            };
            Ok(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: body.into_bytes(),
            })
        }
    }

    struct FixedClock;
    #[async_trait::async_trait]
    impl engine_ports::Clock for FixedClock {
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

    struct MemKv(Mutex<rustc_hash::FxHashMap<String, Vec<u8>>>);
    #[async_trait::async_trait]
    impl engine_ports::KeyValue for MemKv {
        async fn get(&self, key: &str) -> Option<engine_ports::KeyValueEntry> {
            self.0
                .lock()
                .ok()?
                .get(key)
                .map(|v| engine_ports::KeyValueEntry {
                    value: v.clone(),
                    ttl_secs: None,
                })
        }
        async fn put(&self, key: &str, entry: engine_ports::KeyValueEntry) {
            self.0
                .lock()
                .map(|mut m| m.insert(key.to_owned(), entry.value))
                .ok();
        }
        async fn delete(&self, key: &str) {
            self.0.lock().map(|mut m| m.remove(key)).ok();
        }
    }

    struct NoTelemetry;
    impl engine_ports::Telemetry for NoTelemetry {
        fn event(&self, _e: engine_ports::TelemetryEvent) {}
    }

    #[tokio::test]
    async fn the_renewal_reuses_the_dpop_key_and_the_reissuance_kid() {
        // The key the original issuance bound the refresh token to.
        let dpop_key = dpop::DpopKey::generate().expect("keygen");
        let relay = dpop_key.private_jwk_json().expect("relay");

        let http = Arc::new(RenewalHttp {
            token_requests: Mutex::new(Vec::new()),
        });
        let host = Arc::new(RenewalHost {
            sign_key_ids: Mutex::new(Vec::new()),
        });

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
            flow_id: "flow-renewal-1".to_owned(),
            flow_type: "oid4vci".to_owned(),
            session: None,
            ports: Arc::new(Ports {
                http: http.clone(),
                clock: Arc::new(FixedClock),
                rng: Arc::new(FakeRng),
                host: host.clone(),
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

        let start = FlowStartParams {
            wmp: wmp_core::types::Metadata::default(),
            flow_id: "flow-renewal-1".to_owned(),
            flow_type: "oid4vci".to_owned(),
            params: serde_json::value::RawValue::from_string(
                serde_json::json!({
                    "credential_issuer": "https://issuer.example",
                    "selected_credential_configuration_id": "UniversityDegree",
                    "refresh_token": "rt-1",
                    "dpop_jwk": relay,
                    "reissuance_kid": "kid-original"
                })
                .to_string(),
            )
            .ok(),
            timeout: None,
        };

        Oid4vciFlow
            .start_flow(&ctx, &start)
            .await
            .expect("the renewal completes");

        // The refresh grant went to the token endpoint.
        let token_requests = http.token_requests.lock().expect("lock");
        assert_eq!(token_requests.len(), 1);
        let form = String::from_utf8_lossy(&token_requests[0]).into_owned();
        assert!(form.contains("grant_type=refresh_token"));
        assert!(form.contains("refresh_token=rt-1"));

        // The proof was signed with the EXISTING key the issuer knows.
        let key_ids = host.sign_key_ids.lock().expect("lock");
        assert_eq!(key_ids.as_slice(), [Some("kid-original".to_owned())]);
    }
}

mod as_selection_tests {
    //! #511: the offer's `authorization_server` hint — the grant-level
    //! hint selects the AS; a mismatch fails closed; no hint keeps the
    //! first-advertised choice.

    use super::auth_code_flow_tests::{raw_value, test_context, FakeHost};
    use engine_core::oid4vci::*;
    use engine_core::runtime::FlowHandler;
    use engine_ports::{HttpClient, HttpError, HttpRequest, HttpResponse};
    use std::sync::{Arc, Mutex};
    use wmp_core::methods::FlowStartParams;

    const ISSUER_METADATA_URL: &str = "https://issuer.example/.well-known/openid-credential-issuer";
    const AS_METADATA_PATH: &str = "/.well-known/oauth-authorization-server";

    /// Serves the issuer metadata advertising `servers`, records every
    /// other fetch (the AS discovery), and answers it 500, which ends
    /// the flow.
    struct AsRecordingHttp {
        servers: Vec<String>,
        as_fetches: Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl HttpClient for AsRecordingHttp {
        async fn send(&self, request: HttpRequest) -> Result<HttpResponse, HttpError> {
            if request.url == ISSUER_METADATA_URL {
                let body = serde_json::json!({
                    "credential_issuer": "https://issuer.example",
                    "authorization_servers": self.servers,
                    "credential_configurations_supported": {
                        "UniversityDegree": { "format": "sd_jwt" }
                    }
                });
                return Ok(HttpResponse {
                    status: 200,
                    headers: Vec::new(),
                    body: body.to_string().into_bytes(),
                });
            }
            self.as_fetches
                .lock()
                .map(|mut fetches| fetches.push(request.url.clone()))
                .ok();
            Ok(HttpResponse {
                status: 500,
                headers: Vec::new(),
                body: Vec::new(),
            })
        }
    }

    /// The AS the flow started with the offer `grants` discovers, given
    /// the issuer metadata's `authorization_servers`; `None` when the
    /// flow refuses before any AS discovery.
    async fn select_as_url(grants: serde_json::Value, servers: &[&str]) -> Option<String> {
        let http = Arc::new(AsRecordingHttp {
            servers: servers.iter().map(|s| s.to_string()).collect(),
            as_fetches: Mutex::new(Vec::new()),
        });
        let host = Arc::new(FakeHost {
            authorization_urls: Mutex::new(Vec::new()),
            sign_key_ids: Mutex::new(Vec::new()),
        });
        let ctx = test_context(http.clone() as Arc<dyn HttpClient>, host);
        let params = FlowStartParams {
            wmp: wmp_core::types::Metadata::default(),
            flow_id: "flow-1".to_owned(),
            flow_type: "oid4vci".to_owned(),
            params: raw_value(serde_json::json!({
                "credential_issuer": "https://issuer.example",
                "credential_configuration_ids": ["UniversityDegree"],
                "grants": grants,
            })),
            timeout: None,
        };
        assert!(
            Oid4vciFlow.start_flow(&ctx, &params).await.is_err(),
            "the flow ends at the AS discovery or before"
        );
        let fetches = http.as_fetches.lock().expect("fetches").clone();
        fetches.first().map(|url| {
            url.strip_suffix(AS_METADATA_PATH)
                .expect("the RFC 8414 discovery URL comes first")
                .to_owned()
        })
    }

    #[tokio::test]
    async fn a_matching_hint_selects_the_hinted_as() {
        let grants = serde_json::json!({
            "authorization_code": {"authorization_server": "https://as-2.example"}
        });
        assert_eq!(
            select_as_url(grants, &["https://as-1.example", "https://as-2.example"]).await,
            Some("https://as-2.example".to_owned()),
            "the hint selects, not the first"
        );
    }

    #[tokio::test]
    async fn a_mismatched_hint_fails_closed() {
        // OpenID4VCI 1.0/1.1: the wallet MUST NOT proceed when the hint
        // matches no advertised entry.
        let grants = serde_json::json!({
            "authorization_code": {"authorization_server": "https://evil.example"}
        });
        assert!(
            select_as_url(grants, &["https://as-1.example"])
                .await
                .is_none(),
            "the mismatch fails closed"
        );
    }

    #[tokio::test]
    async fn an_exact_match_is_required() {
        // The match is an exact string comparison: a trailing slash or a
        // scheme difference is a mismatch.
        let grants = serde_json::json!({
            "authorization_code": {"authorization_server": "https://as-1.example/"}
        });
        assert!(select_as_url(grants, &["https://as-1.example"])
            .await
            .is_none());
    }

    #[tokio::test]
    async fn no_hint_keeps_the_first_advertised() {
        let grants = serde_json::json!({
            "authorization_code": {"issuer_state": "x"}
        });
        assert_eq!(
            select_as_url(
                grants.clone(),
                &["https://as-1.example", "https://as-2.example"]
            )
            .await,
            Some("https://as-1.example".to_owned())
        );
        // And no advertised servers at all: the credential issuer itself.
        assert_eq!(
            select_as_url(grants, &[]).await,
            Some("https://issuer.example".to_owned())
        );
    }

    #[tokio::test]
    async fn the_hint_is_read_from_either_grant() {
        // The pre-authorized grant carries it too.
        let grants = serde_json::json!({
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": "x",
                "authorization_server": "https://as-2.example"
            }
        });
        assert_eq!(
            select_as_url(grants, &["https://as-1.example", "https://as-2.example"]).await,
            Some("https://as-2.example".to_owned())
        );
    }
}
