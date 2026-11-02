//! Profiles: the pluggable extension seam of WMP.
//!
//! A profile adds capabilities, flow types, resolve handlers and custom
//! methods to a [`crate::Peer`]. go-wmp discovers a profile's optional roles
//! by type assertion (`FlowHandler`, `MethodHandler`, `ResolveHandler`,
//! `SessionHook`, `IdentifierResolver`, `CapabilityRequirer`,
//! `FlowCanceller`, `routeManager`); Rust has no cross-trait downcast, so
//! every role is a default method on [`Profile`] or the trait it refines —
//! override what you implement, leave the rest defaulted.

use std::sync::Arc;

use crate::context::RequestContext;
use crate::error::{RpcError, ERR_METHOD_NOT_FOUND};
use crate::handler::HandlerError;
use crate::methods::*;
use crate::session::Session;
use crate::types::Capabilities;

/// The result of a dispatch: an optional result value (absent for
/// notification-style methods) or the error to send.
pub type DispatchResult = Result<Option<serde_json::Value>, HandlerError>;

/// One step of the middleware chain: it receives the next step as a value it
/// can call, or short-circuits by returning without calling it.
pub type ChainStep =
    Arc<dyn Fn(&RequestContext, &str, &serde_json::Value) -> DispatchResult + Send + Sync>;

/// Middleware intercepts incoming requests before they reach the handler.
///
/// Call `next` to pass control to the next middleware or the final handler;
/// return early without calling it to short-circuit processing.
pub type Middleware = Arc<
    dyn Fn(&RequestContext, &str, &serde_json::Value, &ChainStep) -> DispatchResult + Send + Sync,
>;

/// A pluggable extension to WMP. Register profiles with
/// [`crate::Peer::use_profile`] before serving.
pub trait Profile: Send + Sync {
    /// The profile identifier (for example `openid4x`, `evidence`).
    fn name(&self) -> String;

    /// The capability names this profile provides, used during session
    /// negotiation to determine which profiles are active for a session.
    fn capabilities(&self) -> Vec<String>;

    /// Called when the profile is registered with a peer. The profile
    /// receives a [`PeerContext`] for sending outgoing messages and holds
    /// it as long as it is registered.
    fn init(&self, ctx: Arc<dyn PeerContext>) -> Result<(), HandlerError>;

    /// The flow types this profile handles. A profile that handles none
    /// returns an empty slice and is never dispatched flows.
    fn flow_types(&self) -> Vec<String> {
        Vec::new()
    }

    /// `wmp.flow.start` for a flow type in [`Profile::flow_types`].
    fn start_flow(
        &self,
        _ctx: &RequestContext,
        _params: &FlowStartParams,
    ) -> Result<FlowStartResult, HandlerError> {
        Err(RpcError::code(ERR_METHOD_NOT_FOUND).into())
    }

    /// `wmp.flow.action` on a flow this profile manages.
    fn handle_action(
        &self,
        _ctx: &RequestContext,
        _params: &FlowActionParams,
    ) -> Result<FlowActionResult, HandlerError> {
        Err(RpcError::code(ERR_METHOD_NOT_FOUND).into())
    }

    /// `wmp.flow.progress` on a flow this profile manages.
    fn handle_progress(&self, _ctx: &RequestContext, _params: &FlowProgressParams) {}

    /// `wmp.flow.complete` on a flow this profile manages.
    fn handle_complete(&self, _ctx: &RequestContext, _params: &FlowCompleteParams) {}

    /// `wmp.flow.error` on a flow this profile manages.
    fn handle_error(&self, _ctx: &RequestContext, _params: &FlowErrorParams) {}

    /// The custom methods this profile handles, in its own namespace (for
    /// example `oid4vci.offer.parse`).
    fn methods(&self) -> Vec<String> {
        Vec::new()
    }

    /// A custom method from [`Profile::methods`]. The params arrive as a
    /// parsed JSON value (go-wmp passes raw bytes; the mirror parses once,
    /// at the dispatch boundary).
    fn handle_method(
        &self,
        _ctx: &RequestContext,
        _method: &str,
        _params: &serde_json::Value,
    ) -> DispatchResult {
        Err(RpcError::code(ERR_METHOD_NOT_FOUND).into())
    }

    /// The resolution types this profile handles for `wmp.resolve`.
    fn resolve_types(&self) -> Vec<String> {
        Vec::new()
    }

    /// A resolve for a type from [`Profile::resolve_types`].
    fn handle_resolve(
        &self,
        _ctx: &RequestContext,
        _params: &ResolveParams,
    ) -> Result<ResolveResult, HandlerError> {
        Err(RpcError::code(ERR_METHOD_NOT_FOUND).into())
    }

    /// The identifier scheme prefixes this profile resolves (for example
    /// `did:`), consulted when the well-known mechanism fails.
    fn identifier_schemes(&self) -> Vec<String> {
        Vec::new()
    }

    /// Resolves an identifier of a scheme from [`Profile::identifier_schemes`]
    /// to a WMP endpoint: `Ok(None)` when this resolver cannot handle the
    /// identifier, an error only for transient failures.
    fn resolve_identifier(
        &self,
        _ctx: &RequestContext,
        _identifier: &str,
    ) -> Result<Option<DiscoveredEndpoint>, HandlerError> {
        Ok(None)
    }

    /// Called after a session is created but before the response is sent.
    /// The hook can modify the session or reject the creation with an error.
    ///
    /// A profile that overrides this must also override
    /// [`Profile::has_session_hooks`] — the registry cannot see overrides,
    /// where go-wmp sees the `SessionHook` interface.
    fn on_session_create(
        &self,
        _ctx: &RequestContext,
        _session: &mut Session,
        _params: &SessionCreateParams,
    ) -> Result<(), HandlerError> {
        Ok(())
    }

    /// Whether this profile carries session hooks (go-wmp's `SessionHook`
    /// type assertion, made explicit because Rust cannot detect overrides).
    fn has_session_hooks(&self) -> bool {
        false
    }

    /// Runs after a resume is validated and the token rotated; an error
    /// rejects the resume. The session is a private copy for authorisation
    /// and observation: changes are not persisted. Because the presented
    /// token is already spent, a rejected session cannot be resumed again
    /// and the client must create a new one (core §4.5.4).
    ///
    /// A profile that overrides this must also override
    /// [`Profile::has_resume_hooks`].
    fn on_session_resume(
        &self,
        _ctx: &RequestContext,
        _session: &Session,
        _params: &SessionResumeParams,
    ) -> Result<(), HandlerError> {
        Ok(())
    }

    /// Whether this profile is a resume hook (go-wmp's `SessionResumer`
    /// type assertion, made explicit).
    fn has_resume_hooks(&self) -> bool {
        false
    }

    /// Called when a session is being closed.
    fn on_session_close(
        &self,
        _ctx: &RequestContext,
        _session: &Session,
        _params: &SessionCloseParams,
    ) {
    }

    /// The capability that must have been negotiated before a flow of
    /// `flow_type` may start (core §6.5 item 2, §10.3). A flow type that
    /// needs no capability returns an empty string.
    ///
    /// A peer refuses `wmp.flow.start` for a flow type whose capability is
    /// not negotiated with `-31005` and data naming the flow type and the
    /// capability, before the profile's [`Profile::start_flow`] runs. With no
    /// session resolvable, nothing counts as negotiated: a profile that
    /// declares a requirement fails closed.
    fn required_capability(&self, _flow_type: &str) -> String {
        String::new()
    }

    /// Whether this profile ends the route of each flow it runs itself
    /// (go-wmp's `routeManager` marker). For any other profile the peer ends
    /// the route when the flow sends its terminal notification.
    fn manages_flow_routes(&self) -> bool {
        false
    }

    /// `wmp.flow.cancel` for a flow this profile owns: `Ok(true)` when the
    /// profile stopped a flow of its own (the peer answers "cancelled"),
    /// `Ok(false)` when it did not, an error when it cannot stop the flow
    /// (for example `-31006` already terminal). A profile that overrides
    /// this must also override [`Profile::is_flow_canceller`].
    fn handle_cancel(
        &self,
        _ctx: &RequestContext,
        _params: &FlowCancelParams,
    ) -> Result<bool, HandlerError> {
        Ok(false)
    }

    /// Whether this profile cancels flows it owns (go-wmp's `FlowCanceller`
    /// type assertion, made explicit because Rust cannot detect overrides).
    fn is_flow_canceller(&self) -> bool {
        false
    }
}

/// Provides profiles with the ability to send messages and access session
/// state. Passed to [`Profile::init`].
///
/// Parameters arrive as JSON values, not as `impl Serialize`: the trait must
/// stay dyn-compatible, and go-wmp's marshalling moves to the caller.
pub trait PeerContext: Send + Sync {
    /// Sends a JSON-RPC 2.0 notification.
    fn notify(
        &self,
        ctx: &RequestContext,
        method: &str,
        params: &serde_json::Value,
    ) -> Result<(), HandlerError>;

    /// Sends a JSON-RPC 2.0 request and waits for the response.
    fn call(
        &self,
        ctx: &RequestContext,
        method: &str,
        params: &serde_json::Value,
    ) -> DispatchResult;

    /// The session with this identifier, if the peer holds one.
    fn session(&self, id: &str) -> Option<Session>;

    /// The session the peer's static identity names, which stamps the
    /// messages that name none (go-wmp reaches this by interface
    /// assertion); empty when the peer has no identity session.
    fn default_session_id(&self) -> String {
        String::new()
    }

    /// The protocol version negotiated for a session (go-wmp reaches this
    /// through an unexported interface assertion on the peer); the default
    /// is the crate's version.
    fn version_for(&self, _session_id: &str) -> String {
        crate::types::VERSION.to_owned()
    }

    /// The capabilities this profile provides to a session, as negotiated.
    /// Profiles that offer none return an empty set.
    fn capabilities(&self) -> Capabilities {
        Capabilities::default()
    }
}

/// The result of identifier resolution: a WMP endpoint URL and optional
/// pre-fetched capabilities.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct DiscoveredEndpoint {
    /// The WMP endpoint URL (for example `wss://relay.example.com/wmp`).
    pub endpoint: String,
    /// Optional pre-fetched capabilities from the discovery source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<serde_json::Value>,
    /// The optional relay endpoint for this identifier.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub relay: String,
    /// The optional URL for MLS key packages.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mls_key_packages: String,
}

/// Lets a profile receive the progress, completion and error messages of a
/// flow it started itself (a sub-flow), which the peer would otherwise hand to
/// the handler because no handler started that flow identifier.
pub trait FlowRouter: Send + Sync {
    /// Routes `wmp.flow.progress`, `wmp.flow.complete` and `wmp.flow.error`
    /// of `flow_id` to the profile, but only when they name `session_id` in
    /// their `wmp` metadata (any session when it is empty).
    ///
    /// Returns `None`, and routes nothing, when the flow identifier is
    /// already routed or a `wmp.flow.start` of it is running. A claim is not
    /// ended by a completion or error, nor taken by the peer's own
    /// `wmp.flow.start`: only the returned release ends it — call it exactly
    /// once; dropping it also releases.
    fn claim_flow(
        &self,
        flow_id: &str,
        session_id: &str,
        handler: Arc<dyn Profile>,
    ) -> Option<Claim>;
}

/// The release of a [`FlowRouter::claim_flow`]. Call [`Claim::release`] once;
/// dropping the guard releases too.
pub struct Claim {
    registry: std::sync::Arc<crate::registry::Registry>,
    flow_id: String,
    gen: u64,
}

impl Claim {
    /// A claim the registry holds; internal to the crate.
    pub(crate) fn new(
        registry: std::sync::Arc<crate::registry::Registry>,
        flow_id: String,
        gen: u64,
    ) -> Self {
        Self {
            registry,
            flow_id,
            gen,
        }
    }

    /// Ends this claim. Idempotent.
    pub fn release(self) {
        self.registry.release(&self.flow_id, self.gen);
    }
}

impl Drop for Claim {
    fn drop(&mut self) {
        self.registry.release(&self.flow_id, self.gen);
    }
}
