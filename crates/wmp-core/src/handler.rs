//! The trait an application implements to handle WMP method calls.

use crate::context::RequestContext;
use crate::error::{RpcError, ERR_INTERNAL_ERROR, ERR_METHOD_NOT_FOUND};
use crate::methods::*;

/// What a handler returned instead of a result.
///
/// go-wmp sends an `*RPCError` as the JSON-RPC error response and turns any
/// other error into an internal error; the mirror keeps the same split.
#[derive(Debug, thiserror::Error)]
pub enum HandlerError {
    /// The error to send as the JSON-RPC error response.
    #[error("{0}")]
    Rpc(#[from] RpcError),
    /// An unexpected failure, sent as `-32603` with no detail.
    #[error("wmp: internal handler error")]
    Internal(#[source] Box<dyn std::error::Error + Send + Sync>),
}

impl HandlerError {
    /// The error response to send: a [`HandlerError::Rpc`] unchanged, an
    /// [`HandlerError::Internal`] as a bare internal error.
    pub fn to_rpc(&self) -> RpcError {
        match self {
            Self::Rpc(err) => err.clone(),
            Self::Internal(_) => RpcError::code(ERR_INTERNAL_ERROR),
        }
    }
}

/// Processes incoming WMP method calls; implement this for your application.
///
/// Every method has a default implementation: request methods answer
/// `-32601` (method not found) — mirroring go-wmp's `BaseHandler`, which an
/// implementer embeds to override only what it needs — and notifications are
/// no-ops. Override the methods you handle.
///
/// go-wmp keeps `CredentialNotification` in a separate optional interface to
/// avoid breaking existing consumers; in a fresh API it is simply another
/// default no-op here.
pub trait Handler: Send + Sync {
    /// The session store the handler owns, when it owns one
    /// (go-wmp's `SessionStoreProvider` interface, a default here): the peer
    /// uses it for session lookups when no store was set on the peer
    /// directly, so capability gating and the per-session versions work with
    /// the store the handler actually writes to.
    fn session_store(&self) -> Option<std::sync::Arc<dyn crate::session::SessionStore>> {
        None
    }

    /// The protocol versions this handler negotiates against
    /// (go-wmp's `VersionProvider` interface, a default here). A service
    /// configured with different versions also works through a peer.
    fn supported_versions(&self) -> Vec<String> {
        crate::types::SUPPORTED_VERSIONS
            .iter()
            .copied()
            .map(str::to_owned)
            .collect()
    }

    /// `wmp.session.create`
    fn session_create(
        &self,
        _ctx: &RequestContext,
        _params: &SessionCreateParams,
    ) -> Result<SessionCreateResult, HandlerError> {
        Err(RpcError::code(ERR_METHOD_NOT_FOUND).into())
    }

    /// `wmp.session.resume`
    fn session_resume(
        &self,
        _ctx: &RequestContext,
        _params: &SessionResumeParams,
    ) -> Result<SessionResumeResult, HandlerError> {
        Err(RpcError::code(ERR_METHOD_NOT_FOUND).into())
    }

    /// `wmp.session.close` (notification; the error is for logging only).
    fn session_close(&self, _ctx: &RequestContext, _params: &SessionCloseParams) {}

    /// `wmp.session.authenticate`
    fn session_authenticate(
        &self,
        _ctx: &RequestContext,
        _params: &SessionAuthenticateParams,
    ) -> Result<SessionAuthenticateResult, HandlerError> {
        Err(RpcError::code(ERR_METHOD_NOT_FOUND).into())
    }

    /// `wmp.message.deliver` (notification; the error is for logging only).
    fn message_deliver(&self, _ctx: &RequestContext, _params: &MessageDeliverParams) {}

    /// `wmp.message.ack` (notification; the error is for logging only).
    fn message_ack(&self, _ctx: &RequestContext, _params: &MessageAckParams) {}

    /// `wmp.message.status` (notification; the error is for logging only).
    fn message_status(&self, _ctx: &RequestContext, _params: &MessageStatusParams) {}

    /// `wmp.message.poll`
    fn message_poll(
        &self,
        _ctx: &RequestContext,
        _params: &MessagePollParams,
    ) -> Result<MessagePollResult, HandlerError> {
        Err(RpcError::code(ERR_METHOD_NOT_FOUND).into())
    }

    /// `wmp.capability.update`
    fn capability_update(
        &self,
        _ctx: &RequestContext,
        _params: &CapabilityUpdateParams,
    ) -> Result<CapabilityUpdateResult, HandlerError> {
        Err(RpcError::code(ERR_METHOD_NOT_FOUND).into())
    }

    /// `wmp.capability.list`
    fn capability_list(
        &self,
        _ctx: &RequestContext,
        _params: &CapabilityListParams,
    ) -> Result<CapabilityListResult, HandlerError> {
        Err(RpcError::code(ERR_METHOD_NOT_FOUND).into())
    }

    /// `wmp.flow.start`
    fn flow_start(
        &self,
        _ctx: &RequestContext,
        _params: &FlowStartParams,
    ) -> Result<FlowStartResult, HandlerError> {
        Err(RpcError::code(ERR_METHOD_NOT_FOUND).into())
    }

    /// `wmp.flow.progress` (notification; the error is for logging only).
    fn flow_progress(&self, _ctx: &RequestContext, _params: &FlowProgressParams) {}

    /// `wmp.flow.action`
    fn flow_action(
        &self,
        _ctx: &RequestContext,
        _params: &FlowActionParams,
    ) -> Result<FlowActionResult, HandlerError> {
        Err(RpcError::code(ERR_METHOD_NOT_FOUND).into())
    }

    /// `wmp.flow.complete` (notification; the error is for logging only).
    fn flow_complete(&self, _ctx: &RequestContext, _params: &FlowCompleteParams) {}

    /// `wmp.flow.error` (notification; the error is for logging only).
    fn flow_error(&self, _ctx: &RequestContext, _params: &FlowErrorParams) {}

    /// `wmp.flow.cancel`
    fn flow_cancel(
        &self,
        _ctx: &RequestContext,
        _params: &FlowCancelParams,
    ) -> Result<FlowCancelResult, HandlerError> {
        Err(RpcError::code(ERR_METHOD_NOT_FOUND).into())
    }

    /// `wmp.resolve`
    fn resolve(
        &self,
        _ctx: &RequestContext,
        _params: &ResolveParams,
    ) -> Result<ResolveResult, HandlerError> {
        Err(RpcError::code(ERR_METHOD_NOT_FOUND).into())
    }

    /// `wmp.credential.notification` (notification; the error is for logging
    /// only). An OID4VCI §10 credential lifecycle event, carried from the
    /// client to the server.
    fn credential_notification(
        &self,
        _ctx: &RequestContext,
        _params: &CredentialNotificationParams,
    ) {
    }
}
