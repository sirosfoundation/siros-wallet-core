//! The flow runtime: the registration, the dispatch of a second family
//! through the same seam, the capability refusal, and the in-flight and
//! stateless resolution of a flow's family.

use std::sync::Arc;

use engine_core::runtime::{FlowContext, FlowHandler, FlowRuntime};
use engine_core::Ports;
use rustc_hash::FxHashMap;
use wmp_core::context::RequestContext;
use wmp_core::error::ERR_CAPABILITY_NOT_SUPPORTED;
use wmp_core::handler::HandlerError;
use wmp_core::methods::*;
/// A trivial flow family unrelated to OpenID4: the S0 second-flow
/// proof, mirroring the spec's requirement ("a second, trivial flow
/// type unrelated to OpenID4 through the same trait; if that needs any
/// change to the runtime, the seam is wrong").
struct EchoFlow;

#[async_trait::async_trait]
impl FlowHandler for EchoFlow {
    fn flow_types(&self) -> Vec<String> {
        vec!["echo".to_owned()]
    }

    async fn start_flow(
        &self,
        ctx: &FlowContext,
        params: &FlowStartParams,
    ) -> Result<FlowStartResult, HandlerError> {
        // Echo the flow_id back as the result: the seam works.
        let _ = ctx;
        Ok(FlowStartResult {
            wmp: wmp_core::types::Metadata::default(),
            flow_id: params.flow_id.clone(),
            flow_type: params.flow_type.clone(),
        })
    }

    async fn handle_action(
        &self,
        _ctx: &FlowContext,
        params: &FlowActionParams,
    ) -> Result<FlowActionResult, HandlerError> {
        Ok(FlowActionResult {
            wmp: wmp_core::types::Metadata::default(),
            flow_id: params.flow_id.clone(),
            action: params.action.clone(),
            status: "accepted".to_owned(),
        })
    }

    async fn handle_progress(&self, _ctx: &FlowContext, _params: &FlowProgressParams) {}
    async fn handle_complete(&self, _ctx: &FlowContext, _params: &FlowCompleteParams) {}
    async fn handle_error(&self, _ctx: &FlowContext, _params: &FlowErrorParams) {}
    async fn handle_cancel(
        &self,
        _ctx: &FlowContext,
        _params: &FlowCancelParams,
    ) -> Result<bool, HandlerError> {
        Ok(true)
    }
}

fn test_runtime() -> FlowRuntime {
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
            .unwrap_or_else(|_| panic!("config")),
        ),
        Arc::new(|| 0),
    ));
    let peer = wmp_core::peer::PeerBuilder::new(handler)
        .session_store(store.clone())
        .build();
    FlowRuntime::new(Arc::new(noop_ports()), peer)
}

fn noop_ports() -> Ports {
    struct NoopHttp;
    #[async_trait::async_trait]
    impl engine_ports::HttpClient for NoopHttp {
        async fn send(
            &self,
            _request: engine_ports::HttpRequest,
        ) -> Result<engine_ports::HttpResponse, engine_ports::HttpError> {
            Err(engine_ports::HttpError::Transport("noop".to_owned()))
        }
    }
    struct NoopClock;
    #[async_trait::async_trait]
    impl engine_ports::Clock for NoopClock {
        fn now_unix(&self) -> i64 {
            0
        }
        async fn sleep(&self, _duration_ms: u64) {}
    }
    struct NoopRng;
    impl engine_ports::Rng for NoopRng {
        fn fill(&self, _buf: &mut [u8]) -> bool {
            false
        }
    }
    struct NoopHost;
    #[async_trait::async_trait]
    impl engine_ports::Host for NoopHost {
        async fn request_sign(
            &self,
            _params: engine_ports::SignParams,
        ) -> Result<engine_ports::SignResult, engine_ports::HostError> {
            Err(engine_ports::HostError::Cannot("noop".to_owned()))
        }
        async fn request_match(
            &self,
            _params: engine_ports::MatchParams,
        ) -> Result<engine_ports::MatchResult, engine_ports::HostError> {
            Err(engine_ports::HostError::Cannot("noop".to_owned()))
        }
        async fn request_consent(
            &self,
            _params: engine_ports::ConsentParams,
        ) -> Result<engine_ports::ConsentResult, engine_ports::HostError> {
            Err(engine_ports::HostError::Cannot("noop".to_owned()))
        }
        async fn request_tx_code(&self, _flow_id: &str) -> Result<String, engine_ports::HostError> {
            Err(engine_ports::HostError::Cannot("noop".to_owned()))
        }
        async fn open_authorization(
            &self,
            _flow_id: &str,
            _url: &str,
        ) -> Result<(), engine_ports::HostError> {
            Err(engine_ports::HostError::Cannot("noop".to_owned()))
        }
        fn progress(&self, _flow_id: &str, _step: &str, _detail: Option<String>) {}
    }
    struct NoopPdp;
    #[async_trait::async_trait]
    impl engine_ports::Pdp for NoopPdp {
        async fn evaluate(
            &self,
            _request: engine_ports::EvaluationRequest,
        ) -> Result<engine_ports::EvaluationResponse, engine_ports::PdpError> {
            Err(engine_ports::PdpError::NotImplemented)
        }
        async fn resolve(
            &self,
            _request: engine_ports::ResolveRequest,
        ) -> Result<engine_ports::ResolveResponse, engine_ports::PdpError> {
            Err(engine_ports::PdpError::NotImplemented)
        }
    }
    /// The in-memory KV the runtime tests run on — the stateless
    /// resume's registry reads and writes through it, exactly as a
    /// browser's localStorage-backed KV would.
    struct MemoryKv(parking_lot::Mutex<FxHashMap<String, Vec<u8>>>);
    #[async_trait::async_trait]
    impl engine_ports::KeyValue for MemoryKv {
        async fn get(&self, key: &str) -> Option<engine_ports::KeyValueEntry> {
            self.0
                .lock()
                .get(key)
                .map(|value| engine_ports::KeyValueEntry {
                    value: value.clone(),
                    ttl_secs: None,
                })
        }
        async fn put(&self, key: &str, entry: engine_ports::KeyValueEntry) {
            self.0.lock().insert(key.to_owned(), entry.value);
        }
        async fn delete(&self, key: &str) {
            self.0.lock().remove(key);
        }
    }
    struct NoopTelemetry;
    impl engine_ports::Telemetry for NoopTelemetry {
        fn event(&self, _event: engine_ports::TelemetryEvent) {}
    }
    Ports {
        http: Arc::new(NoopHttp),
        clock: Arc::new(NoopClock),
        rng: Arc::new(NoopRng),
        host: Arc::new(NoopHost),
        pdp: Arc::new(NoopPdp),
        kv: Arc::new(MemoryKv(parking_lot::Mutex::new(FxHashMap::default()))),
        telemetry: Arc::new(NoopTelemetry),
        consent_check: engine_ports::ConsentCheckMode::Warn,
    }
}

#[tokio::test]
async fn the_second_flow_proves_the_seam() {
    let runtime = test_runtime();
    runtime
        .register(Arc::new(EchoFlow))
        .expect("register the echo family");

    let params = FlowStartParams {
        wmp: wmp_core::types::Metadata::default(),
        flow_type: "echo".to_owned(),
        flow_id: "flow-echo-1".to_owned(),
        params: None,
        timeout: None,
    };
    let result = runtime
        .start_flow(&RequestContext::default(), &params)
        .await
        .expect("the echo flow starts");
    assert_eq!(result.flow_id, "flow-echo-1");
    assert_eq!(result.flow_type, "echo");
}

#[tokio::test]
async fn an_unregistered_flow_type_answers_31005() {
    let runtime = test_runtime();
    let params = FlowStartParams {
        wmp: wmp_core::types::Metadata::default(),
        flow_type: "nonesuch".to_owned(),
        flow_id: "flow-x".to_owned(),
        params: None,
        timeout: None,
    };
    let err = runtime
        .start_flow(&RequestContext::default(), &params)
        .await
        .expect_err("the unregistered type refuses");
    assert!(
        matches!(
            &err,
            HandlerError::Rpc(rpc)
                if rpc.code == ERR_CAPABILITY_NOT_SUPPORTED
        ),
        "the refusal is -31005: {err}"
    );
}

#[tokio::test]
async fn a_duplicate_registration_refuses() {
    let runtime = test_runtime();
    runtime
        .register(Arc::new(EchoFlow))
        .expect("first registration");
    assert!(
        runtime.register(Arc::new(EchoFlow)).is_err(),
        "the second registration of the same flow type refuses"
    );
}

#[tokio::test]
async fn a_flow_started_elsewhere_resolves_its_family_from_the_kv() {
    // The stateless resume: the start registers the flow in the KV
    // registry, a fresh runtime (the page reloaded) resolves the
    // family from it and the action reaches the flow.
    let runtime = test_runtime();
    runtime.register(Arc::new(EchoFlow)).expect("register");

    let ctx = RequestContext {
        principal: Some(wmp_core::principal::Principal::new("runtime-test", "")),
        ..RequestContext::default()
    };
    runtime
        .start_flow(
            &ctx,
            &FlowStartParams {
                wmp: wmp_core::types::Metadata::default(),
                flow_type: "echo".to_owned(),
                flow_id: "flow-elsewhere-1".to_owned(),
                params: None,
                timeout: None,
            },
        )
        .await
        .expect("start");

    // A fresh runtime over the SAME ports (the KV survived the
    // reload): empty in-memory registry.
    let peer =
        wmp_core::peer::PeerBuilder::new(Arc::new(wmp_core::sessionservice::SessionHandler::new(
            Arc::new(
                wmp_core::sessionservice::SessionService::new(
                    wmp_core::sessionservice::SessionServiceConfig {
                        store: Some(Arc::new(wmp_core::session::MemorySessionStore::new())),
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
        )))
        .build();
    let fresh = FlowRuntime::new(runtime.ports(), peer);
    fresh.register(Arc::new(EchoFlow)).expect("register");

    let action = fresh
        .handle_action(
            &ctx,
            &FlowActionParams {
                wmp: wmp_core::types::Metadata::default(),
                flow_id: "flow-elsewhere-1".to_owned(),
                action: "go".to_owned(),
                params: None,
            },
        )
        .await
        .expect("the stateless resume resolves the family");
    assert_eq!(action.status, "accepted");
}

#[tokio::test]
async fn an_in_flight_flow_resolves_its_family_for_the_action() {
    // The two-call shape the authorization-code grant needs: a
    // start that returns without completing keeps the flow
    // registered, the action reaches the family, and the completion
    // unregisters.
    let runtime = test_runtime();
    runtime.register(Arc::new(EchoFlow)).expect("register");

    let ctx = RequestContext {
        principal: Some(wmp_core::principal::Principal::new("runtime-test", "")),
        ..RequestContext::default()
    };
    let start = runtime
        .start_flow(
            &ctx,
            &FlowStartParams {
                wmp: wmp_core::types::Metadata::default(),
                flow_type: "echo".to_owned(),
                flow_id: "flow-9".to_owned(),
                params: None,
                timeout: None,
            },
        )
        .await
        .expect("start");
    assert_eq!(start.flow_id, "flow-9");

    // The action resolves the family through the in-flight map.
    let action = runtime
        .handle_action(
            &ctx,
            &FlowActionParams {
                wmp: wmp_core::types::Metadata::default(),
                flow_id: "flow-9".to_owned(),
                action: "go".to_owned(),
                params: None,
            },
        )
        .await
        .expect("action");
    assert_eq!(action.status, "accepted");

    // The completion unregisters: a later action finds no flow.
    runtime
        .handle_complete(
            &ctx,
            &FlowCompleteParams {
                wmp: wmp_core::types::Metadata::default(),
                flow_id: "flow-9".to_owned(),
                result: None,
            },
        )
        .await;
    assert!(runtime
        .handle_action(
            &ctx,
            &FlowActionParams {
                wmp: wmp_core::types::Metadata::default(),
                flow_id: "flow-9".to_owned(),
                action: "go".to_owned(),
                params: None,
            },
        )
        .await
        .is_err());
}
