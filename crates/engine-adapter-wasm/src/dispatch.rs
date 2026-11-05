//! The JSON-RPC dispatcher: the WMP surface the browser drives — the
//! session methods and the flow methods, routed to the SessionService
//! and the FlowRuntime the same way the server adapter's EngineHandler
//! routes them, but native-async (the browser has no `block_in_place`
//! to bridge through).
//!
//! The dispatcher is plain Rust over `serde_json::Value` — no wasm
//! types — so the routing, the capability gate, and the session
//! plumbing are testable on the host target exactly as they run in the
//! browser.

use std::sync::Arc;

use wmp_core::context::RequestContext;
use wmp_core::error::RpcError;
use wmp_core::handler::{Handler, HandlerError};
use wmp_core::methods::*;
use wmp_core::session::SessionStore;
use wmp_core::sessionservice::{SessionService, SessionServiceConfig};

use engine_core::runtime::FlowRuntime;

/// The session methods' principal: the page's wallet. WMP requires an
/// authenticated principal to own a session; the browser wallet is it.
const PRINCIPAL: &str = "wasm-wallet";

/// The engine behind the JS surface: the session service, the runtime
/// with both flow families registered, and the session store they
/// share.
pub struct Dispatcher {
    sessions: Arc<wmp_core::sessionservice::SessionHandler>,
    runtime: Arc<FlowRuntime>,
    store: Arc<dyn SessionStore>,
}

impl Dispatcher {
    /// Builds the dispatcher over the given ports, with the page's
    /// clock and entropy closures (the browser's `Date.now` and
    /// `crypto.getRandomValues`; the tests inject fixed ones). The
    /// session store is the in-memory one — a page reload is a new
    /// wallet session; the resumption path is the client's to persist.
    pub fn new(
        ports: Arc<engine_core::Ports>,
        clock: wmp_core::sessionservice::Clock,
        entropy: wmp_core::sessionservice::EntropyFn,
    ) -> Result<Self, String> {
        let store: Arc<dyn SessionStore> = Arc::new(wmp_core::session::MemorySessionStore::new());

        let service = SessionService::new(SessionServiceConfig {
            store: Some(store.clone()),
            // The browser wallet offers the flows capability; the
            // engine's families gate on it.
            supported: flows_capability(16)?,
            entropy: Some(entropy),
            ..SessionServiceConfig::default()
        })
        .map_err(|err| format!("the session service config: {err}"))?;

        let service = Arc::new(service);

        let session_handler = Arc::new(wmp_core::sessionservice::SessionHandler::new(
            service.clone(),
            clock.clone(),
        ));
        let peer = wmp_core::peer::PeerBuilder::new(session_handler.clone())
            .session_store(store.clone())
            .build();

        let runtime = Arc::new(FlowRuntime::new(ports, peer));
        runtime
            .register(Arc::new(engine_core::oid4vci::Oid4vciFlow))
            .map_err(|err| format!("register the oid4vci family: {err}"))?;
        runtime
            .register(Arc::new(engine_core::oid4vp::Oid4vpFlow))
            .map_err(|err| format!("register the oid4vp family: {err}"))?;
        runtime
            .register(Arc::new(
                engine_core::oid4vci::notification::CredentialNotificationFlow,
            ))
            .map_err(|err| format!("register the credential_notification family: {err}"))?;

        let _ = clock.clone();
        Ok(Self {
            sessions: session_handler,
            runtime,
            store,
        })
    }

    /// Handles one JSON-RPC message: the params as the caller sends
    /// them (the `params` member of the envelope), the method name,
    /// and the raw envelope's session for the request context. The
    /// answer is the JSON-RPC result value, or the error the method
    /// refused with.
    pub async fn request(
        &self,
        method: &str,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, DispatchError> {
        let ctx = self.context_for(params);

        match method {
            "wmp.session.create" => {
                let params: SessionCreateParams = Self::typed(params)?;
                self.sessions
                    .session_create(&ctx, &params)
                    .map(|result| serde_json::to_value(&result).unwrap_or_default())
                    .map_err(DispatchError::from)
            }
            "wmp.session.resume" => {
                let params: SessionResumeParams = Self::typed(params)?;
                self.sessions
                    .session_resume(&ctx, &params)
                    .map(|result| serde_json::to_value(&result).unwrap_or_default())
                    .map_err(DispatchError::from)
            }
            "wmp.session.close" => {
                let params: SessionCloseParams = Self::typed(params)?;
                self.sessions.session_close(&ctx, &params);
                Ok(serde_json::Value::Null)
            }
            "wmp.session.authenticate" => {
                let params: SessionAuthenticateParams = Self::typed(params)?;
                self.sessions
                    .session_authenticate(&ctx, &params)
                    .map(|result| serde_json::to_value(&result).unwrap_or_default())
                    .map_err(DispatchError::from)
            }
            "wmp.flow.start" => {
                let params: FlowStartParams = Self::typed(params)?;
                self.runtime
                    .start_flow(&ctx, &params)
                    .await
                    .map(|result| serde_json::to_value(&result).unwrap_or_default())
                    .map_err(DispatchError::from)
            }
            "wmp.flow.action" => {
                let params: FlowActionParams = Self::typed(params)?;
                self.runtime
                    .handle_action(&ctx, &params)
                    .await
                    .map(|result| serde_json::to_value(&result).unwrap_or_default())
                    .map_err(DispatchError::from)
            }
            "wmp.flow.cancel" => {
                let params: FlowCancelParams = Self::typed(params)?;
                self.runtime
                    .handle_cancel(&ctx, &params)
                    .await
                    .map(|result| serde_json::to_value(&result).unwrap_or_default())
                    .map_err(DispatchError::from)
            }
            // The notifications the wallet host sends back: no result,
            // and the flow registry's hygiene (a completion, an error
            // or a cancel unregisters the flow).
            "wmp.flow.progress" => {
                let params: FlowProgressParams = Self::typed(params)?;
                self.runtime.handle_progress(&ctx, &params).await;
                Ok(serde_json::Value::Null)
            }
            "wmp.flow.complete" => {
                let params: FlowCompleteParams = Self::typed(params)?;
                self.runtime.handle_complete(&ctx, &params).await;
                Ok(serde_json::Value::Null)
            }
            "wmp.flow.error" => {
                let params: FlowErrorParams = Self::typed(params)?;
                self.runtime.handle_error(&ctx, &params).await;
                Ok(serde_json::Value::Null)
            }
            other => Err(DispatchError::MethodNotFound(other.to_owned())),
        }
    }

    /// Deserializes the typed params, refusing malformed input the way
    /// the peer does.
    fn typed<T: serde::de::DeserializeOwned>(
        params: &serde_json::Value,
    ) -> Result<T, DispatchError> {
        serde_json::from_value(params.clone())
            .map_err(|err| DispatchError::InvalidParams(err.to_string()))
    }

    /// The request context: the wallet's principal, with the session
    /// resolved from the envelope the way the peer resolves it —
    /// everything the capability gate needs.
    fn context_for(&self, params: &serde_json::Value) -> RequestContext {
        let mut ctx = RequestContext {
            principal: Some(wmp_core::principal::Principal::new(PRINCIPAL, "")),
            ..RequestContext::default()
        };
        if let Some(session_id) = params
            .get("wmp")
            .and_then(|wmp| wmp.get("session_id"))
            .and_then(|id| id.as_str())
        {
            if !session_id.is_empty() {
                if let Some(session) = self.store.get(session_id) {
                    ctx.session = Some(session);
                }
            }
        }
        ctx
    }
}

/// Why a dispatch refused.
#[derive(Debug, thiserror::Error)]
pub enum DispatchError {
    /// An unknown method.
    #[error("wmp: method not found: {0}")]
    MethodNotFound(String),
    /// Malformed params.
    #[error("wmp: invalid params: {0}")]
    InvalidParams(String),
    /// The handler refused: the WMP error to answer with.
    #[error("{0}")]
    Handler(#[from] HandlerError),
}

impl DispatchError {
    /// The JSON-RPC error object the refusal answers with.
    pub fn to_rpc(&self) -> RpcError {
        match self {
            Self::MethodNotFound(_) => RpcError::code(wmp_core::error::ERR_METHOD_NOT_FOUND),
            Self::InvalidParams(reason) => RpcError::new(
                wmp_core::error::ERR_INVALID_PARAMS,
                Some(serde_json::json!({ "reason": reason })),
            ),
            Self::Handler(err) => err.to_rpc(),
        }
    }
}

/// The flows capability the dispatcher grants.
fn flows_capability(max_concurrent: i64) -> Result<wmp_core::types::Capabilities, String> {
    // The credential_notification capability (WMP OpenID4x 2.4): the
    // events the engine forwards and the TTL of the context it
    // retains. A wallet that wants to run the flow offers it; a
    // session that did not negotiate it refuses the flow (-31005,
    // core 10.3).
    serde_json::from_value(serde_json::json!({
        "flows": { "max_concurrent": max_concurrent },
        "credential_notification": {
            "events": ["credential_accepted", "credential_failure"],
            "context_ttl_seconds": 300,
        },
    }))
    .map_err(|err| format!("the flows capability does not serialize: {err}"))
}
