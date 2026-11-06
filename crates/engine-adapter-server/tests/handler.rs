//! The engine handler's flow-start TAC gate (the Go engine's
//! `requiredTACForProtocol`) and its OpenID4x action translation (WMP OpenID4x
//! 3.1.2/3.2.2), driven through the `Handler` trait over a family that echoes
//! what reaches it.

use std::sync::Arc;

use engine_adapter_server::config::Config;
use engine_adapter_server::handler::EngineHandler;
use engine_adapter_server::host_bridge::FlowSessions;
use engine_adapter_server::EngineServer;
use engine_core::runtime::{FlowContext, FlowHandler, FlowRuntime};
use wmp_core::context::RequestContext;
use wmp_core::handler::{Handler, HandlerError};
use wmp_core::methods::*;
use wmp_core::principal::Principal;
use wmp_core::types::Metadata;

/// Accepts every start and answers each action with the name it received.
struct EchoFlow;

#[async_trait::async_trait]
impl FlowHandler for EchoFlow {
    fn flow_types(&self) -> Vec<String> {
        ["oid4vp", "oid4vci", "vctm", "anything-else"]
            .map(str::to_owned)
            .to_vec()
    }

    async fn start_flow(
        &self,
        _ctx: &FlowContext,
        params: &FlowStartParams,
    ) -> Result<FlowStartResult, HandlerError> {
        Ok(FlowStartResult {
            wmp: Metadata::default(),
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
            wmp: Metadata::default(),
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

/// An engine handler whose runtime holds only [`EchoFlow`], on the server's
/// ports and peer.
fn echo_handler() -> Arc<EngineHandler> {
    let config = Config::default();
    let server = EngineServer::new(config.clone());
    let runtime = Arc::new(FlowRuntime::new(
        server.runtime.ports(),
        server.runtime.peer(),
    ));
    runtime
        .register(Arc::new(EchoFlow))
        .expect("the echo family registers");
    EngineHandler::new(
        &config,
        &server.store,
        runtime,
        server.outbox.clone(),
        FlowSessions::new(),
    )
}

fn context_of(principal: Principal) -> RequestContext {
    RequestContext {
        principal: Some(principal),
        ..RequestContext::default()
    }
}

fn start(handler: &EngineHandler, ctx: &RequestContext, flow_type: &str) -> bool {
    let params = FlowStartParams {
        wmp: Metadata::default(),
        flow_type: flow_type.to_owned(),
        flow_id: "flow-1".to_owned(),
        params: None,
        timeout: None,
    };
    match handler.flow_start(ctx, &params) {
        Ok(result) => {
            assert_eq!(result.flow_type, flow_type);
            true
        }
        Err(HandlerError::Rpc(err)) if err.code == -31002 => false,
        Err(err) => panic!("the gate answers a grant or -31002: {err:?}"),
    }
}

/// Whether the handler starts `flow_type` for a principal carrying `tac`.
fn tac_grants(handler: &EngineHandler, tac: &str, flow_type: &str) -> bool {
    let principal = Principal::with_token("alice", "acme", "jti", tac);
    start(handler, &context_of(principal), flow_type)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_openid4x_actions_map_to_the_engine_actions() {
    let handler = echo_handler();
    let ctx = context_of(Principal::new("alice", "acme"));
    assert!(start(&handler, &ctx, "anything-else"));
    for (client, engine) in [
        ("authorize", "authorization_complete"),
        ("select_credentials", "select_credential"),
        ("provide_tx_code", "provide_pin"),
        ("accept_offer", "consent"),
        // Unknown actions pass through: the flow families decide what they
        // answer.
        ("consent", "consent"),
        ("decline", "decline"),
        ("credentials_matched", "credentials_matched"),
    ] {
        let params = FlowActionParams {
            wmp: Metadata::default(),
            flow_id: "flow-1".to_owned(),
            action: client.to_owned(),
            params: None,
        };
        let result = handler
            .flow_action(&ctx, &params)
            .expect("the family answers");
        assert_eq!(result.action, engine, "the client sent {client}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_flow_types_carry_their_required_tacs() {
    let handler = echo_handler();
    // OID4VP shares an existing credential (read).
    assert!(tac_grants(&handler, "r", "oid4vp"));
    assert!(!tac_grants(&handler, "i", "oid4vp"));
    // OID4VCI receives a new one (insert).
    assert!(tac_grants(&handler, "i", "oid4vci"));
    assert!(!tac_grants(&handler, "r", "oid4vci"));
    // Other flow types require nothing: a TAC with neither permission starts
    // them.
    assert!(tac_grants(&handler, "x", "vctm"));
    assert!(tac_grants(&handler, "x", "anything-else"));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_principal_tac_gates_the_flow_types() {
    let handler = echo_handler();
    // `ri` grants both engine flows.
    assert!(tac_grants(&handler, "ri", "oid4vp"));
    assert!(tac_grants(&handler, "ri", "oid4vci"));
    // `r` alone grants only the presentation.
    assert!(tac_grants(&handler, "r", "oid4vp"));
    assert!(!tac_grants(&handler, "r", "oid4vci"));
    // The gate does not apply to the legacy principal's empty TAC.
    let legacy = Principal::new("alice", "acme");
    assert!(legacy.tac.is_empty());
    let ctx = context_of(legacy);
    assert!(start(&handler, &ctx, "oid4vp"));
    assert!(start(&handler, &ctx, "oid4vci"));
}
