//! The flow runtime: the registry that dispatches flow starts to the
//! families that own them, the capability gate, and the context the
//! families run in.
//!
//! This is the engine's S0 shape: the seam the engine spec demands, with
//! the second non-OpenID4 flow provable through it. The flow families
//! (OpenID4VCI, OpenID4VP) register through the [`FlowHandler`] trait; the
//! runtime supplies the ports and the flow context; a family never reaches
//! into the runtime's internals.

use std::sync::Arc;

use rustc_hash::FxHashMap;

use crate::Ports;

use wmp_core::context::RequestContext;
use wmp_core::error::{RpcError, ERR_CAPABILITY_NOT_SUPPORTED};
use wmp_core::handler::HandlerError;
use wmp_core::methods::*;
use wmp_core::session::Session;

/// A flow family: the handler plus its registration.
///
/// A family is identified by its flow types (`oid4vci`, `oid4vp`, a future
/// `qerds` or an MCP flow). The runtime registers handlers by flow type,
/// gates them on the session's negotiated capabilities, and routes
/// sub-flow requests through the flow context. A family never reaches
/// into the runtime's internals.
///
/// Adding a family takes: its parameter and result schemas in the WMP
/// spec with vectors, a handler module, and new ports only if the family
/// needs effects the existing ports do not cover. **No change to this
/// runtime.**
#[async_trait::async_trait]
pub trait FlowHandler: Send + Sync {
    /// The flow type identifiers this handler manages.
    fn flow_types(&self) -> Vec<String>;

    /// The capability that must have been negotiated before a flow of
    /// `flow_type` may start (core §6.5 item 2, §10.3). An empty string
    /// means no capability is required.
    fn required_capability(&self, flow_type: &str) -> String {
        let _ = flow_type;
        String::new()
    }

    /// `wmp.flow.start` for a flow type this handler owns.
    async fn start_flow(
        &self,
        ctx: &FlowContext,
        params: &FlowStartParams,
    ) -> Result<FlowStartResult, HandlerError>;

    /// `wmp.flow.action` on a flow this handler owns.
    async fn handle_action(
        &self,
        ctx: &FlowContext,
        params: &FlowActionParams,
    ) -> Result<FlowActionResult, HandlerError>;

    /// `wmp.flow.progress` on a flow this handler owns.
    async fn handle_progress(&self, ctx: &FlowContext, params: &FlowProgressParams);

    /// `wmp.flow.complete` on a flow this handler owns.
    async fn handle_complete(&self, ctx: &FlowContext, params: &FlowCompleteParams);

    /// `wmp.flow.error` on a flow this handler owns.
    async fn handle_error(&self, ctx: &FlowContext, params: &FlowErrorParams);

    /// `wmp.flow.cancel` for a flow this handler owns: `Ok(true)` when the
    /// handler stopped a flow, `Ok(false)` when it did not.
    async fn handle_cancel(
        &self,
        ctx: &FlowContext,
        params: &FlowCancelParams,
    ) -> Result<bool, HandlerError>;
}

/// What a flow's handler runs with: the ports, the session, the flow's
/// identity, and the WMP peer it sends through.
pub struct FlowContext {
    /// The flow's identifier.
    pub flow_id: String,
    /// The flow's type.
    pub flow_type: String,
    /// The session the flow belongs to, when there is one.
    pub session: Option<Session>,
    /// The ports the flow runs on.
    pub ports: Arc<Ports>,
    /// The WMP peer the flow sends notifications through.
    pub peer: Arc<wmp_core::peer::Peer>,
    /// The request context the flow was started in.
    pub request_context: RequestContext,
}

impl FlowContext {
    /// Sends a `wmp.flow.progress` notification through the peer.
    pub async fn progress(
        &self,
        step: &str,
        payload: &impl serde::Serialize,
    ) -> Result<(), HandlerError> {
        let payload = serde_json::to_value(payload)
            .map_err(|_| HandlerError::Rpc(RpcError::code(wmp_core::error::ERR_INTERNAL_ERROR)))?;
        let params = FlowProgressParams {
            wmp: wmp_core::types::Metadata {
                session_id: self
                    .session
                    .as_ref()
                    .map_or_else(String::new, |s| s.id.clone()),
                ..wmp_core::types::Metadata::default()
            },
            flow_id: self.flow_id.clone(),
            step: step.to_owned(),
            payload: serde_json::to_string(&payload)
                .ok()
                .and_then(|s| serde_json::value::RawValue::from_string(s).ok()),
        };
        let value = serde_json::to_value(&params)
            .map_err(|_| HandlerError::Rpc(RpcError::code(wmp_core::error::ERR_INTERNAL_ERROR)))?;
        self.peer
            .notify(&self.request_context, METHOD_FLOW_PROGRESS, &value)
    }

    /// Sends a `wmp.flow.complete` notification through the peer.
    pub async fn complete(&self, result: &impl serde::Serialize) -> Result<(), HandlerError> {
        let result = serde_json::to_value(result)
            .map_err(|_| HandlerError::Rpc(RpcError::code(wmp_core::error::ERR_INTERNAL_ERROR)))?;
        let params = FlowCompleteParams {
            wmp: wmp_core::types::Metadata {
                session_id: self
                    .session
                    .as_ref()
                    .map_or_else(String::new, |s| s.id.clone()),
                ..wmp_core::types::Metadata::default()
            },
            flow_id: self.flow_id.clone(),
            result: serde_json::to_string(&result)
                .ok()
                .and_then(|s| serde_json::value::RawValue::from_string(s).ok()),
        };
        let value = serde_json::to_value(&params)
            .map_err(|_| HandlerError::Rpc(RpcError::code(wmp_core::error::ERR_INTERNAL_ERROR)))?;
        self.peer
            .notify(&self.request_context, METHOD_FLOW_COMPLETE, &value)
    }

    /// Sends a `wmp.flow.error` notification through the peer.
    pub async fn error(&self, code: i64, message: &str) -> Result<(), HandlerError> {
        let params = FlowErrorParams {
            wmp: wmp_core::types::Metadata {
                session_id: self
                    .session
                    .as_ref()
                    .map_or_else(String::new, |s| s.id.clone()),
                ..wmp_core::types::Metadata::default()
            },
            flow_id: self.flow_id.clone(),
            code,
            message: message.to_owned(),
            data: None,
        };
        let value = serde_json::to_value(&params)
            .map_err(|_| HandlerError::Rpc(RpcError::code(wmp_core::error::ERR_INTERNAL_ERROR)))?;
        self.peer
            .notify(&self.request_context, METHOD_FLOW_ERROR, &value)
    }

    /// The HTTP port the flow fetches through.
    pub fn http(&self) -> &Arc<dyn engine_ports::HttpClient> {
        &self.ports.http
    }

    /// The clock the flow reads.
    pub fn clock(&self) -> &Arc<dyn engine_ports::Clock> {
        &self.ports.clock
    }

    /// The host the flow asks for sign, consent and selection.
    pub fn host(&self) -> &Arc<dyn engine_ports::Host> {
        &self.ports.host
    }

    /// The PDP the flow evaluates trust through.
    pub fn pdp(&self) -> &Arc<dyn engine_ports::Pdp> {
        &self.ports.pdp
    }

    /// The randomness the flow samples (the OAuth state, the PKCE
    /// verifier — the core's own random choices).
    pub fn rng(&self) -> &Arc<dyn engine_ports::Rng> {
        &self.ports.rng
    }

    /// The persistence the flow stashes its cross-call state in (the
    /// authorization-code resume: the verifier, the state, the offer).
    pub fn kv(&self) -> &Arc<dyn engine_ports::KeyValue> {
        &self.ports.kv
    }
}

/// An in-flight flow: the family that owns it, and its type.
type InFlight = (Arc<dyn FlowHandler>, String);

/// The flow runtime: the registry that dispatches flow starts to the
/// families that own them, and the capability gate that refuses a flow
/// type whose capability was not negotiated (core §10.3).
pub struct FlowRuntime {
    handlers: parking_lot::RwLock<FxHashMap<String, Arc<dyn FlowHandler>>>,
    /// The in-flight flows: the flow id to the family that owns it and
    /// the flow's type. A start registers; a completion, an error or a
    /// cancel unregisters. The authorization-code grant spans two WMP
    /// calls on the strength of this map.
    flows: parking_lot::RwLock<FxHashMap<String, InFlight>>,
    ports: Arc<Ports>,
    peer: Arc<wmp_core::peer::Peer>,
}

impl FlowRuntime {
    /// An empty runtime over the given ports and peer.
    pub fn new(ports: Arc<Ports>, peer: Arc<wmp_core::peer::Peer>) -> Self {
        Self {
            handlers: parking_lot::RwLock::new(FxHashMap::default()),
            flows: parking_lot::RwLock::new(FxHashMap::default()),
            ports,
            peer,
        }
    }

    /// Registers a flow family. Errors when one of its flow types is
    /// already registered.
    pub fn register(&self, handler: Arc<dyn FlowHandler>) -> Result<(), HandlerError> {
        let mut handlers = self.handlers.write();
        for flow_type in handler.flow_types() {
            if handlers.contains_key(&flow_type) {
                return Err(HandlerError::Rpc(RpcError::new(
                    wmp_core::error::ERR_INTERNAL_ERROR,
                    Some(
                        serde_json::json!({ "reason": format!("flow type {flow_type:?} already registered") }),
                    ),
                )));
            }
        }
        for flow_type in handler.flow_types() {
            handlers.insert(flow_type, handler.clone());
        }
        Ok(())
    }

    /// Handles a `wmp.flow.start`: finds the family, checks the capability
    /// gate, and runs the start.
    pub async fn start_flow(
        &self,
        ctx: &RequestContext,
        params: &FlowStartParams,
    ) -> Result<FlowStartResult, HandlerError> {
        let handler = self.lookup(&params.flow_type).ok_or_else(|| {
            // Nobody here implements this flow type: an unsupported
            // capability (core §10.3), not an unknown method.
            HandlerError::Rpc(RpcError::new(
                ERR_CAPABILITY_NOT_SUPPORTED,
                Some(serde_json::json!({ "unsupported": params.flow_type })),
            ))
        })?;

        // Core §10.3: a flow type whose capability was not negotiated is
        // refused with -31005 before the family sees it. With no session
        // resolvable, nothing counts as negotiated: a family that declares
        // a requirement fails closed.
        let need = handler.required_capability(&params.flow_type);
        if !need.is_empty() {
            let negotiated = ctx
                .session
                .as_ref()
                .is_some_and(|session| session.has_capability(&need));
            if !negotiated {
                return Err(HandlerError::Rpc(RpcError::new(
                    ERR_CAPABILITY_NOT_SUPPORTED,
                    Some(serde_json::json!({
                        "unsupported": params.flow_type,
                        "capability": need,
                    })),
                )));
            }
        }

        let flow_ctx = FlowContext {
            flow_id: params.flow_id.clone(),
            flow_type: params.flow_type.clone(),
            session: ctx.session.clone(),
            ports: self.ports.clone(),
            peer: self.peer.clone(),
            request_context: ctx.clone(),
        };
        let result = handler.start_flow(&flow_ctx, params).await?;

        // The flow is in flight: the action, progress, complete and
        // cancel calls resolve the family through this map. A flow the
        // family completed inside the start (the pre-authorized grant)
        // is unregistered by the complete handler below — a start that
        // returns without completing (the authorization-code handoff)
        // stays registered for the redirect's action.
        self.flows
            .write()
            .insert(params.flow_id.clone(), (handler, params.flow_type.clone()));

        Ok(result)
    }

    /// Handles a `wmp.flow.action`.
    pub async fn handle_action(
        &self,
        ctx: &RequestContext,
        params: &FlowActionParams,
    ) -> Result<FlowActionResult, HandlerError> {
        let flow_ctx = self.context_of(ctx, &params.flow_id);
        let handler = self.handler_of_flow(ctx, &params.flow_id).ok_or_else(|| {
            HandlerError::Rpc(RpcError::new(
                wmp_core::error::ERR_FLOW_ERROR,
                Some(
                    serde_json::json!({ "reason": format!("flow not found: {}", params.flow_id) }),
                ),
            ))
        })?;
        handler.handle_action(&flow_ctx, params).await
    }

    /// Handles a `wmp.flow.progress`.
    pub async fn handle_progress(&self, ctx: &RequestContext, params: &FlowProgressParams) {
        if let Some(handler) = self.handler_of_flow(ctx, &params.flow_id) {
            let flow_ctx = self.context_of(ctx, &params.flow_id);
            handler.handle_progress(&flow_ctx, params).await;
        }
    }

    /// Handles a `wmp.flow.complete`.
    pub async fn handle_complete(&self, ctx: &RequestContext, params: &FlowCompleteParams) {
        if let Some(handler) = self.handler_of_flow(ctx, &params.flow_id) {
            let flow_ctx = self.context_of(ctx, &params.flow_id);
            handler.handle_complete(&flow_ctx, params).await;
            // The flow is done: unregister it.
            self.flows.write().remove(&params.flow_id);
        }
    }

    /// Handles a `wmp.flow.error`.
    pub async fn handle_error(&self, ctx: &RequestContext, params: &FlowErrorParams) {
        if let Some(handler) = self.handler_of_flow(ctx, &params.flow_id) {
            let flow_ctx = self.context_of(ctx, &params.flow_id);
            handler.handle_error(&flow_ctx, params).await;
            // The flow is dead: unregister it.
            self.flows.write().remove(&params.flow_id);
        }
    }

    /// Handles a `wmp.flow.cancel`.
    pub async fn handle_cancel(
        &self,
        ctx: &RequestContext,
        params: &FlowCancelParams,
    ) -> Result<FlowCancelResult, HandlerError> {
        let Some(handler) = self.handler_of_flow(ctx, &params.flow_id) else {
            return Err(HandlerError::Rpc(RpcError::new(
                wmp_core::error::ERR_FLOW_ERROR,
                Some(
                    serde_json::json!({ "reason": format!("flow not found: {}", params.flow_id) }),
                ),
            )));
        };
        let flow_ctx = self.context_of(ctx, &params.flow_id);
        let stopped = handler.handle_cancel(&flow_ctx, params).await?;
        if stopped {
            // The flow is cancelled: unregister it.
            self.flows.write().remove(&params.flow_id);
        }
        Ok(FlowCancelResult {
            wmp: wmp_core::types::Metadata::default(),
            flow_id: params.flow_id.clone(),
            status: if stopped { "cancelled" } else { "active" }.to_owned(),
        })
    }

    fn lookup(&self, flow_type: &str) -> Option<Arc<dyn FlowHandler>> {
        self.handlers.read().get(flow_type).cloned()
    }

    /// The handler of a flow the context names, resolving the flow's type
    /// from the session's or the request's flow registry. For now, the
    /// handler is found by the flow type the request carries; a
    /// flow-instance-to-handler map (what wmp-core's registry does) arrives
    /// with the flow families.
    fn handler_of_flow(
        &self,
        _ctx: &RequestContext,
        flow_id: &str,
    ) -> Option<Arc<dyn FlowHandler>> {
        self.flows
            .read()
            .get(flow_id)
            .map(|(handler, _)| handler.clone())
    }

    fn context_of(&self, ctx: &RequestContext, flow_id: &str) -> FlowContext {
        let flow_type = self
            .flows
            .read()
            .get(flow_id)
            .map(|(_, flow_type)| flow_type.clone())
            .unwrap_or_default();
        FlowContext {
            flow_id: flow_id.to_owned(),
            flow_type,
            session: ctx.session.clone(),
            ports: self.ports.clone(),
            peer: self.peer.clone(),
            request_context: ctx.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            async fn request_tx_code(
                &self,
                _flow_id: &str,
            ) -> Result<String, engine_ports::HostError> {
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
        struct NoopKv;
        #[async_trait::async_trait]
        impl engine_ports::KeyValue for NoopKv {
            async fn get(&self, _key: &str) -> Option<engine_ports::KeyValueEntry> {
                None
            }
            async fn put(&self, _key: &str, _entry: engine_ports::KeyValueEntry) {}
            async fn delete(&self, _key: &str) {}
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
            kv: Arc::new(NoopKv),
            telemetry: Arc::new(NoopTelemetry),
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
}
