//! The peer: one side of a WMP connection. It dispatches incoming messages
//! to a [`Handler`] and profiles, and sends outgoing messages.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};

use rustc_hash::FxHashMap;
use serde_json::value::RawValue;

use crate::context::RequestContext;
use crate::error::{
    RpcError, ERR_CAPABILITY_NOT_SUPPORTED, ERR_FLOW_ERROR, ERR_INTERNAL_ERROR, ERR_INVALID_PARAMS,
    ERR_INVALID_REQUEST, ERR_METHOD_NOT_FOUND, ERR_NOT_AUTHORIZED, ERR_PARSE_ERROR,
    ERR_PARTICIPANT_NOT_FOUND, ERR_SESSION_EXPIRED,
};
use crate::handler::{Handler, HandlerError};
use crate::jsonrpc::{
    decode_message, new_error_response, new_response, DecodeOptions, Request, Response,
};
use crate::methods::*;
use crate::profile::{ChainStep, DispatchResult, Middleware, Profile};
use crate::registry::{DeferKind, Registry, StartOutcome};
use crate::session::{Session, SessionStore, StoreError};
use crate::sessionservice::METADATA_KEY_VERSION;
use crate::token::RESUMPTION_TOKEN_BYTES;
use crate::types::VERSION;
use crate::version::{negotiate_version, version_rejection};

/// An optional hook that validates incoming JSON-RPC params before dispatch.
pub trait Validator: Send + Sync {
    /// Validates the params of `method`; an error message rejects the
    /// request with `-32602` and that reason.
    fn validate_method(&self, method: &str, data: &[u8]) -> Result<(), String>;
}

/// An optional hook that decides whether an incoming request or notification
/// may proceed.
pub trait Authorizer: Send + Sync {
    /// Whether the request is allowed.
    fn authorize(&self, ctx: &RequestContext, method: &str, params: &serde_json::Value) -> bool;
}

/// An observer of the inbound `wmp.message.*` methods an orchestrator peer
/// intercepts. Must not block.
pub trait InboundMessageObserver: Send + Sync {
    /// `method` is one of the message methods; `refused` is true when the
    /// peer answered the message with an error (a deliver request), false
    /// when it was only logged and dropped.
    fn observe_inbound_message(&self, ctx: &RequestContext, method: &str, refused: bool);
}

/// Configures the orchestrator behaviour of [`PeerBuilder::orchestrator_messages`].
#[derive(Default)]
pub struct OrchestratorMessageOptions {
    /// Optional; called once per intercepted message.
    pub observer: Option<Arc<dyn InboundMessageObserver>>,
}

/// The session identity outbound messages are stamped with.
struct SessionIdentity {
    session_id: String,
    sender: String,
}

/// One side of a WMP connection. Handles incoming messages by dispatching to
/// a [`Handler`] and the registered profiles, and sends outgoing messages.
///
/// The mirror's divergences from go-wmp, all consequences of the
/// no-ambient-state rule: there is no logger (telemetry is an adapter
/// concern); the peer takes the current time and an entropy source from its
/// callers; the request context is an explicit [`RequestContext`] rather
/// than `context.Context`; and params pass through the middleware chain and
/// the dispatch table as parsed JSON values, not raw bytes.
pub struct Peer {
    transport: Option<Arc<dyn crate::transport::Transport>>,
    handler: Arc<dyn Handler>,
    registry: Arc<Registry>,
    sessions: Option<Arc<dyn SessionStore>>,
    validator: Option<Arc<dyn Validator>>,
    authorizer: Option<Arc<dyn Authorizer>>,
    identity: Option<SessionIdentity>,
    orchestrator: Option<OrchestratorMessageOptions>,
    max_message_size: usize,
    entropy: Option<crate::sessionservice::EntropyFn>,
    versions: Mutex<FxHashMap<String, String>>,
    pending: Mutex<FxHashMap<String, mpsc::Sender<Response>>>,
    closed: AtomicBool,
}

/// Builds a [`Peer`] — the mirror of go-wmp's `PeerOption` functions, which
/// can propagate registration errors instead of logging them away.
pub struct PeerBuilder {
    handler: Arc<dyn Handler>,
    registry: Registry,
    transport: Option<Arc<dyn crate::transport::Transport>>,
    validator: Option<Arc<dyn Validator>>,
    authorizer: Option<Arc<dyn Authorizer>>,
    sessions: Option<Arc<dyn SessionStore>>,
    identity: Option<SessionIdentity>,
    orchestrator: Option<OrchestratorMessageOptions>,
    max_message_size: usize,
    entropy: Option<crate::sessionservice::EntropyFn>,
}

impl PeerBuilder {
    /// A peer dispatching to `handler`.
    pub fn new(handler: Arc<dyn Handler>) -> Self {
        Self {
            handler,
            registry: Registry::new(),
            transport: None,
            validator: None,
            authorizer: None,
            sessions: None,
            identity: None,
            orchestrator: None,
            max_message_size: crate::jsonrpc::DEFAULT_MAX_MESSAGE_SIZE,
            entropy: None,
        }
    }

    /// Sets the transport outgoing messages are written to.
    /// [`Peer::handle_request_sync`] needs none.
    pub fn transport(mut self, transport: Arc<dyn crate::transport::Transport>) -> Self {
        self.transport = Some(transport);
        self
    }

    /// Sets the maximum incoming message size in bytes (default 1 MiB).
    pub fn max_message_size(mut self, size: usize) -> Self {
        self.max_message_size = size;
        self
    }

    /// Sets a validator for incoming JSON-RPC request parameters.
    pub fn validator(mut self, validator: Arc<dyn Validator>) -> Self {
        self.validator = Some(validator);
        self
    }

    /// Sets an authorization hook for incoming requests.
    pub fn authorizer(mut self, authorizer: Arc<dyn Authorizer>) -> Self {
        self.authorizer = Some(authorizer);
        self
    }

    /// Sets the session store used for session context enrichment and
    /// [`Peer::session`]. The store cannot change after the build (go-wmp's
    /// `SetSessionStore`): a peer is shared behind an `Arc`.
    pub fn session_store(mut self, store: Arc<dyn SessionStore>) -> Self {
        self.sessions = Some(store);
        self
    }

    /// Makes every outbound notification and call carry the `wmp` metadata
    /// object: the negotiated protocol version, session id and sender (core
    /// §2.2.3 requires `wmp.version` on all messages). Metadata the caller
    /// already set is never overwritten; only empty members are filled.
    /// Empty arguments are simply not stamped.
    pub fn session_identity(mut self, session_id: &str, sender: &str) -> Self {
        self.identity = Some(SessionIdentity {
            session_id: session_id.to_owned(),
            sender: sender.to_owned(),
        });
        self
    }

    /// Sets the entropy source the peer generates request ids from; without
    /// one, [`Peer::call`] answers an internal error instead of drawing
    /// randomness (go-wmp samples `crypto/rand` itself).
    pub fn entropy(mut self, entropy: crate::sessionservice::EntropyFn) -> Self {
        self.entropy = Some(entropy);
        self
    }

    /// Makes the peer behave as a tls-mode orchestrator (a party that runs
    /// flows and relays nothing) for inbound `wmp.message.*`: a deliver
    /// request is answered with `-31008`, and acks and statuses are observed,
    /// never routed to the handler. Without this option the peer is
    /// peer-to-peer: all three are dispatched to the handler.
    pub fn orchestrator_messages(mut self, opts: OrchestratorMessageOptions) -> Self {
        self.orchestrator = Some(opts);
        self
    }

    /// Registers a profile with the peer, initialising it immediately.
    pub fn profile(self, profile: Arc<dyn Profile>) -> Result<Self, HandlerError> {
        self.registry.register(profile)?;
        Ok(self)
    }

    /// Adds middleware to the processing chain, called in registration order
    /// for every incoming request.
    pub fn middleware(self, mw: Middleware) -> Self {
        self.registry.add_middleware(mw);
        self
    }

    /// Builds the peer behind an `Arc`: the middleware chain and the flow
    /// deferrals hold on to it.
    pub fn build(self) -> Arc<Peer> {
        Arc::new(Peer {
            transport: self.transport,
            handler: self.handler,
            registry: Arc::new(self.registry),
            sessions: self.sessions,
            validator: self.validator,
            authorizer: self.authorizer,
            identity: self.identity,
            orchestrator: self.orchestrator,
            max_message_size: self.max_message_size,
            entropy: self.entropy,
            versions: Mutex::new(FxHashMap::default()),
            pending: Mutex::new(FxHashMap::default()),
            closed: AtomicBool::new(false),
        })
    }
}

impl Peer {
    /// Handles one raw JSON-RPC message synchronously, without a transport —
    /// the entry the conformance harness drives and an in-process caller
    /// uses.
    ///
    /// Returns the response bytes, `None` for a notification (which never
    /// gets a response).
    pub fn handle_request_sync(
        self: &Arc<Self>,
        ctx: &RequestContext,
        data: &[u8],
    ) -> Result<Option<Vec<u8>>, HandlerError> {
        if data.len() > self.max_message_size {
            return self.respond(&new_error_response(
                None,
                RpcError::new(
                    ERR_INVALID_REQUEST,
                    Some(serde_json::json!({ "reason": "message too large" })),
                ),
            ));
        }
        let options = DecodeOptions {
            max_size: Some(self.max_message_size),
            max_depth: None,
        };
        let msg = match decode_message(data, options) {
            Ok(msg) => msg,
            Err(_) => {
                return self.respond(&new_error_response(None, RpcError::code(ERR_PARSE_ERROR)));
            }
        };
        if msg.is_response() {
            self.handle_response(&msg.as_response());
            return Ok(None);
        }
        let request = msg.as_request();
        let ctx = RequestContext {
            is_notification: request.is_notification(),
            ..ctx.clone()
        };
        if let Some(authorizer) = &self.authorizer {
            if !authorizer.authorize(&ctx, &request.method, &params_value(&request)?) {
                return self.respond(&new_error_response(
                    request.id.clone(),
                    RpcError::code(ERR_NOT_AUTHORIZED),
                ));
            }
        }
        if let Some(validator) = &self.validator {
            if let Err(reason) = validator.validate_method(&request.method, data) {
                return self.respond(&new_error_response(
                    request.id.clone(),
                    RpcError::new(
                        ERR_INVALID_PARAMS,
                        Some(serde_json::json!({ "reason": reason })),
                    ),
                ));
            }
        }
        // Enrich the context with the (unauthenticated) sender and session
        // claims; callers verify identity assertions and ownership.
        let ctx = self.enrich_context(&ctx, &request);
        let params = params_value(&request)?;
        let this = self.clone();
        let final_step: ChainStep =
            Arc::new(move |ctx, method, params| this.dispatch_method_internal(ctx, method, params));
        let result = self
            .registry
            .run_middleware(&ctx, &request.method, &params, final_step);
        if request.is_notification() {
            return Ok(None);
        }
        let id = request.id.clone();
        match result {
            Ok(Some(value)) => {
                let resp = new_response(id, &value).map_err(internal)?;
                self.respond(&resp)
            }
            Ok(None) => {
                let resp = new_response(id, &serde_json::json!({})).map_err(internal)?;
                self.respond(&resp)
            }
            Err(err) => self.respond(&new_error_response(id, err.to_rpc())),
        }
    }

    fn respond(&self, resp: &Response) -> Result<Option<Vec<u8>>, HandlerError> {
        Ok(Some(serde_json::to_vec(resp).map_err(|_| {
            HandlerError::Rpc(RpcError::code(ERR_INTERNAL_ERROR))
        })?))
    }

    /// Registers a profile with this peer, initialising it immediately.
    pub fn use_profile(&self, profile: Arc<dyn Profile>) -> Result<(), HandlerError> {
        self.registry.register(profile)
    }

    /// Adds middleware to the processing chain.
    pub fn use_middleware(&self, mw: Middleware) {
        self.registry.add_middleware(mw);
    }

    /// The session with this identifier, if the peer holds one.
    pub fn session(&self, id: &str) -> Option<Session> {
        self.store().and_then(|store| store.get(id))
    }

    /// The store: the builder's, else the handler's, else none.
    fn store(&self) -> Option<Arc<dyn SessionStore>> {
        self.sessions
            .clone()
            .or_else(|| self.handler.session_store())
    }

    /// Adds the sender and the session named in the request's `wmp`
    /// metadata to the context. These are unauthenticated claims.
    fn enrich_context(&self, ctx: &RequestContext, request: &Request) -> RequestContext {
        let params = match params_value(request) {
            Ok(params) => params,
            Err(_) => return ctx.clone(),
        };
        let mut ctx = ctx.clone();
        if let Some(wmp) = params.get("wmp") {
            if let Some(sender) = wmp.get("sender").and_then(|s| s.as_str()) {
                if !sender.is_empty() {
                    ctx.sender = sender.to_owned();
                }
            }
            if let Some(session_id) = wmp.get("session_id").and_then(|s| s.as_str()) {
                if !session_id.is_empty() {
                    if let Some(store) = self.store() {
                        if let Some(session) = store.get(session_id) {
                            ctx.session = Some(session);
                        }
                    }
                }
            }
        }
        ctx
    }

    /// Routes an inbound response to a pending [`Peer::call`].
    fn handle_response(&self, response: &Response) {
        let Some(id) = response.id.as_ref() else {
            return;
        };
        let Ok(mut pending) = self.pending.lock() else {
            return;
        };
        if let Some(sender) = pending.remove(id.get()) {
            let _ = sender.send(response.clone());
        }
    }

    /// Sends a JSON-RPC 2.0 notification (no response expected), stamped
    /// with the peer's session identity.
    pub fn notify(
        &self,
        _ctx: &RequestContext,
        method: &str,
        params: &impl serde::Serialize,
    ) -> Result<(), HandlerError> {
        let params = self.stamp(method, params)?;
        let request = crate::jsonrpc::new_notification(method, &params).map_err(internal)?;
        let data = serde_json::to_vec(&request).map_err(internal)?;
        self.write_outgoing(&data)
    }

    /// Sends a JSON-RPC 2.0 request and waits for the response.
    pub fn call(
        &self,
        _ctx: &RequestContext,
        method: &str,
        params: &impl serde::Serialize,
    ) -> DispatchResult {
        let id = self.new_request_id()?;
        let params = self.stamp(method, params)?;
        let request = crate::jsonrpc::new_request(Some(&id), method, &params).map_err(internal)?;
        let (sender, receiver) = mpsc::channel();
        {
            let Ok(mut pending) = self.pending.lock() else {
                return Err(HandlerError::Rpc(RpcError::code(ERR_INTERNAL_ERROR)));
            };
            pending.insert(id.clone(), sender);
        }
        let data = serde_json::to_vec(&request).map_err(internal)?;
        self.write_outgoing(&data)?;
        match receiver.recv() {
            Ok(response) => match response.result {
                Some(result) => Ok(Some(serde_json::from_str(result.get()).map_err(internal)?)),
                None => match response.error {
                    Some(error) => Err(HandlerError::Rpc(error)),
                    None => Ok(None),
                },
            },
            Err(_) => {
                if let Ok(mut pending) = self.pending.lock() {
                    pending.remove(&id);
                }
                Err(HandlerError::Rpc(RpcError::code(ERR_INTERNAL_ERROR)))
            }
        }
    }

    /// Writes to the transport, which the peer must have.
    fn write_outgoing(&self, data: &[u8]) -> Result<(), HandlerError> {
        let transport = self
            .transport
            .as_ref()
            .ok_or_else(|| HandlerError::Rpc(RpcError::code(ERR_INTERNAL_ERROR)))?;
        transport
            .write_message(data)
            .map_err(|_| HandlerError::Rpc(RpcError::code(ERR_INTERNAL_ERROR)))
    }

    /// A fresh request identifier: `req-` plus 128 entropy bits, base64url
    /// unpadded. go-wmp samples `crypto/rand`; the mirror takes its entropy
    /// from the builder.
    fn new_request_id(&self) -> Result<String, HandlerError> {
        let entropy = self
            .entropy
            .as_ref()
            .ok_or_else(|| HandlerError::Rpc(RpcError::code(ERR_INTERNAL_ERROR)))?;
        let mut bytes = [0u8; RESUMPTION_TOKEN_BYTES];
        if !entropy(&mut bytes) {
            return Err(HandlerError::Rpc(RpcError::code(ERR_INTERNAL_ERROR)));
        }
        let sixteen: Vec<u8> = bytes.iter().take(16).copied().collect();
        Ok(format!(
            "req-{}",
            crate::token::base64url_unpadded(&sixteen)
        ))
    }

    /// Closes the peer and its underlying transport. Idempotent.
    pub fn close(&self) -> Result<(), HandlerError> {
        if self
            .closed
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            if let Some(transport) = &self.transport {
                transport
                    .close()
                    .map_err(|_| HandlerError::Rpc(RpcError::code(ERR_INTERNAL_ERROR)))?;
            }
        }
        Ok(())
    }

    /// The session a flow started by this request belongs to: the
    /// store-resolved one when there is one, else the one the request names,
    /// else the peer's own identity's.
    fn flow_session(&self, ctx: &RequestContext, named: &str) -> String {
        if let Some(session) = &ctx.session {
            return session.id.clone();
        }
        if !named.is_empty() {
            return named.to_owned();
        }
        self.identity
            .as_ref()
            .map_or_else(String::new, |id| id.session_id.clone())
    }

    /// The version set this peer negotiates against.
    fn supported_versions(&self) -> Vec<String> {
        self.handler.supported_versions()
    }

    /// Selects a version against the supported set, or rejects with
    /// `-31013` carrying `supported_versions`.
    fn negotiate_or_reject(&self, offered: &str) -> Result<String, HandlerError> {
        let supported = self.supported_versions();
        let supported_refs: Vec<&str> = supported.iter().map(String::as_str).collect();
        negotiate_version(offered, &supported_refs)
            .map(str::to_owned)
            .ok_or_else(|| version_rejection(Some(offered), &supported_refs).into())
    }

    /// The negotiated version of the session, or [`VERSION`].
    fn version_for(&self, session_id: &str) -> String {
        self.recorded_version(&self.version_key(session_id))
            .unwrap_or_else(|| VERSION.to_owned())
    }

    fn version_key(&self, session_id: &str) -> String {
        if session_id.is_empty() {
            if let Some(identity) = &self.identity {
                return identity.session_id.clone();
            }
        }
        session_id.to_owned()
    }

    /// The version on record for a session: the store's, else the cache's.
    fn recorded_version(&self, key: &str) -> Option<String> {
        if let Some(version) = self.stored_version(key) {
            return Some(version);
        }
        self.versions.lock().ok()?.get(key).cloned()
    }

    /// The version recorded in the session store, if any.
    fn stored_version(&self, key: &str) -> Option<String> {
        if key.is_empty() {
            return None;
        }
        let session = self.store()?.get(key)?;
        let version = session.metadata.get(METADATA_KEY_VERSION)?.clone();
        (!version.is_empty()).then_some(version)
    }

    /// Remembers the version negotiated for a session, so messages of one
    /// session never carry the version negotiated for another. When the
    /// session store already holds the version nothing is cached: the store
    /// is authoritative and its expiry also ends the entry.
    fn record_version(&self, session_id: &str, version: &str) {
        if version.is_empty() {
            return;
        }
        let key = self.version_key(session_id);
        if self.stored_version(&key).is_some() {
            return;
        }
        if let Ok(mut versions) = self.versions.lock() {
            versions.insert(key, version.to_owned());
        }
    }

    /// Drops the cached version of a session that is gone. A close the
    /// handler refused (the session still exists) keeps its version.
    fn forget_version(&self, session_id: &str) {
        let key = self.version_key(session_id);
        if let Some(store) = self.store() {
            if store.get(&key).is_some() {
                return;
            }
        }
        if let Ok(mut versions) = self.versions.lock() {
            versions.remove(&key);
        }
    }

    /// Handles an inbound `wmp.message.*` for an orchestrator peer.
    /// Reports `handled` false when the option is off.
    fn intercept_message(&self, ctx: &RequestContext, method: &str) -> Result<bool, HandlerError> {
        let Some(orchestrator) = &self.orchestrator else {
            return Ok(false);
        };
        let refused = method == METHOD_MESSAGE_DELIVER && !ctx.is_notification;
        if let Some(observer) = &orchestrator.observer {
            observer.observe_inbound_message(ctx, method, refused);
        }
        if refused {
            return Err(RpcError::code(ERR_PARTICIPANT_NOT_FOUND).into());
        }
        Ok(true)
    }

    /// The dispatch table: one method at a time, mirroring go-wmp's
    /// `dispatchMethodInternal`.
    fn dispatch_method_internal(
        &self,
        ctx: &RequestContext,
        method: &str,
        params: &serde_json::Value,
    ) -> DispatchResult {
        macro_rules! params_of {
            ($t:ty) => {
                serde_json::from_value::<$t>(params.clone()).map_err(invalid_params)?
            };
        }
        macro_rules! value_of {
            ($result:expr) => {
                serde_json::to_value($result).map_err(internal)?
            };
        }
        match method {
            METHOD_SESSION_CREATE => {
                let ps: SessionCreateParams = params_of!(SessionCreateParams);
                Ok(Some(self.dispatch_session_create(ctx, &ps)?))
            }
            METHOD_SESSION_RESUME => {
                let ps: SessionResumeParams = params_of!(SessionResumeParams);
                Ok(Some(self.dispatch_session_resume(ctx, &ps)?))
            }
            METHOD_SESSION_CLOSE => {
                let ps: SessionCloseParams = params_of!(SessionCloseParams);
                self.run_session_close_hooks(ctx, &ps);
                self.handler.session_close(ctx, &ps);
                self.forget_version(&ps.wmp.session_id);
                Ok(None)
            }
            METHOD_SESSION_AUTHENTICATE => {
                let ps: SessionAuthenticateParams = params_of!(SessionAuthenticateParams);
                Ok(Some(value_of!(self
                    .handler
                    .session_authenticate(ctx, &ps)?)))
            }
            METHOD_MESSAGE_DELIVER => {
                let ps: MessageDeliverParams = params_of!(MessageDeliverParams);
                if self.intercept_message(ctx, METHOD_MESSAGE_DELIVER)? {
                    return Ok(None);
                }
                self.handler.message_deliver(ctx, &ps);
                Ok(None)
            }
            METHOD_MESSAGE_ACK => {
                let ps: MessageAckParams = params_of!(MessageAckParams);
                if self.intercept_message(ctx, METHOD_MESSAGE_ACK)? {
                    return Ok(None);
                }
                self.handler.message_ack(ctx, &ps);
                Ok(None)
            }
            METHOD_MESSAGE_STATUS => {
                let ps: MessageStatusParams = params_of!(MessageStatusParams);
                if self.intercept_message(ctx, METHOD_MESSAGE_STATUS)? {
                    return Ok(None);
                }
                self.handler.message_status(ctx, &ps);
                Ok(None)
            }
            METHOD_MESSAGE_POLL => {
                let ps: MessagePollParams = params_of!(MessagePollParams);
                Ok(Some(value_of!(self.handler.message_poll(ctx, &ps)?)))
            }
            METHOD_CAPABILITY_UPDATE => {
                let ps: CapabilityUpdateParams = params_of!(CapabilityUpdateParams);
                Ok(Some(value_of!(self.handler.capability_update(ctx, &ps)?)))
            }
            METHOD_CAPABILITY_LIST => {
                let ps: CapabilityListParams = params_of!(CapabilityListParams);
                Ok(Some(value_of!(self.handler.capability_list(ctx, &ps)?)))
            }
            METHOD_FLOW_START => {
                let ps: FlowStartParams = params_of!(FlowStartParams);
                self.dispatch_flow_start(ctx, &ps)
            }
            METHOD_FLOW_PROGRESS => {
                let ps: FlowProgressParams = params_of!(FlowProgressParams);
                let (flow_id, session_id) = (ps.flow_id.clone(), ps.wmp.session_id.clone());
                self.deliver_flow(
                    &flow_id,
                    &session_id,
                    DeferKind::Progress,
                    FlowMessage::Progress(ctx.clone(), ps),
                );
                Ok(None)
            }
            METHOD_FLOW_ACTION => {
                let ps: FlowActionParams = params_of!(FlowActionParams);
                self.dispatch_flow_action(ctx, &ps)
            }
            METHOD_FLOW_COMPLETE => {
                let ps: FlowCompleteParams = params_of!(FlowCompleteParams);
                let (flow_id, session_id) = (ps.flow_id.clone(), ps.wmp.session_id.clone());
                self.deliver_flow(
                    &flow_id,
                    &session_id,
                    DeferKind::Terminal,
                    FlowMessage::Complete(ctx.clone(), ps),
                );
                Ok(None)
            }
            METHOD_FLOW_ERROR => {
                let ps: FlowErrorParams = params_of!(FlowErrorParams);
                let (flow_id, session_id) = (ps.flow_id.clone(), ps.wmp.session_id.clone());
                self.deliver_flow(
                    &flow_id,
                    &session_id,
                    DeferKind::Terminal,
                    FlowMessage::Error(ctx.clone(), ps),
                );
                Ok(None)
            }
            METHOD_FLOW_CANCEL => {
                let ps: FlowCancelParams = params_of!(FlowCancelParams);
                self.dispatch_flow_cancel(ctx, &ps)
            }
            METHOD_RESOLVE => {
                let ps: ResolveParams = params_of!(ResolveParams);
                if let Some(resolver) = self.registry.lookup_resolver(&ps.r#type) {
                    return Ok(Some(value_of!(resolver.handle_resolve(ctx, &ps)?)));
                }
                Ok(Some(value_of!(self.handler.resolve(ctx, &ps)?)))
            }
            METHOD_CREDENTIAL_NOTIFICATION => {
                let ps: CredentialNotificationParams = params_of!(CredentialNotificationParams);
                if let Err(err) = validate_credential_notification(&ps) {
                    // A real request gets the fast, synchronous rejection
                    // this validation exists for. A notification can never
                    // receive it back, so returning here would silently drop
                    // the message instead of giving the handler a chance to
                    // see it at all.
                    if !ctx.is_notification {
                        return Err(err.into());
                    }
                }
                self.handler.credential_notification(ctx, &ps);
                Ok(None)
            }
            other => {
                if let Some(handler) = self.registry.lookup_method(other) {
                    return handler.handle_method(ctx, other, params);
                }
                Err(HandlerError::Rpc(RpcError::code(ERR_METHOD_NOT_FOUND)))
            }
        }
    }

    /// Negotiates the version, calls the handler, runs the create hooks and
    /// only then commits the negotiated version for the session.
    fn dispatch_session_create(
        &self,
        ctx: &RequestContext,
        ps: &SessionCreateParams,
    ) -> Result<serde_json::Value, HandlerError> {
        let selected = self.negotiate_or_reject(&ps.wmp.version)?;
        let mut result = self.handler.session_create(ctx, ps)?;
        if result.wmp.version.is_empty() {
            result.wmp.version = selected.clone();
        }
        if self.store().is_some() && !result.wmp.session_id.is_empty() {
            self.run_create_hooks(ctx, ps, &mut result)?;
        }
        self.record_version(&result.wmp.session_id, &result.wmp.version);
        serde_json::to_value(result).map_err(internal)
    }

    /// Runs the registered session-create hooks on the stored or a fresh
    /// session, persisting what the hooks produced and answering the client
    /// with exactly that.
    fn run_create_hooks(
        &self,
        ctx: &RequestContext,
        ps: &SessionCreateParams,
        result: &mut SessionCreateResult,
    ) -> Result<(), HandlerError> {
        let Some(store) = self.store() else {
            return Ok(());
        };
        // A handler that owns the session lifecycle (the session service)
        // has already stored the session with its owner and token expiry;
        // never replace that record with a bare copy.
        let existing = store.get(&result.wmp.session_id);
        if self.handler.session_store().is_some() && existing.is_none() {
            // The handler persists its own sessions and the record is gone
            // (it expired and was swept meanwhile). Recreating a bare copy
            // would lose owner and expiry.
            return Err(RpcError::code(ERR_SESSION_EXPIRED).into());
        }
        let mut session = match &existing {
            Some(session) => session.clone(),
            None => Session {
                id: result.wmp.session_id.clone(),
                participants: ps.participants.clone(),
                capabilities: result.capabilities.clone(),
                security: result.security.clone(),
                resumption_token: result.resumption_token.clone(),
                metadata: [(METADATA_KEY_VERSION.to_owned(), result.wmp.version.clone())]
                    .into_iter()
                    .collect(),
                ..Session::default()
            },
        };
        self.registry
            .run_session_create_hooks(ctx, &mut session, ps)?;
        let write = match existing {
            Some(_) => update_if_present(&store, session.clone()),
            None => store.create(session.clone()),
        };
        match write {
            Ok(()) => {}
            Err(StoreError::NoSuchSession) => {
                // The session was removed (expired and swept) while the
                // hooks ran: writing it back would resurrect it.
                return Err(RpcError::code(ERR_SESSION_EXPIRED).into());
            }
            Err(_) => {
                // The hook's changes (or the record itself) were not
                // persisted and the client would hold a session the server
                // cannot honour.
                let _ = store.delete(&session.id);
                return Err(RpcError::code(ERR_INTERNAL_ERROR).into());
            }
        }
        // What was persisted is what the client is told.
        result.capabilities = session.capabilities.clone();
        result.security = session.security.clone();
        result.resumption_token = session.resumption_token.clone();
        Ok(())
    }

    /// Negotiates the version, calls the handler, runs the resume hooks and
    /// commits the version only for a successful resume.
    fn dispatch_session_resume(
        &self,
        ctx: &RequestContext,
        ps: &SessionResumeParams,
    ) -> Result<serde_json::Value, HandlerError> {
        let selected = self.negotiate_or_reject(&ps.wmp.version)?;
        let mut result = self.handler.session_resume(ctx, ps)?;
        if !result.resumed {
            if result.wmp.version.is_empty() {
                result.wmp.version = selected;
            }
            return serde_json::to_value(result).map_err(internal);
        }
        if result.wmp.version.is_empty() {
            // A session keeps the version negotiated at create (core
            // §2.2.3). Checked only after the handler authorised the
            // resume, so a version error cannot reveal that a session
            // exists.
            result.wmp.version = self.resume_version(ps, &selected)?;
        }
        self.run_resume_hooks(ctx, ps)?;
        self.record_version(&ps.session_id, &result.wmp.version);
        serde_json::to_value(result).map_err(internal)
    }

    /// The resume hooks on a private copy of the session. Without a session
    /// to show them, the resume is refused: resume authorisation must not
    /// be bypassed. The token has already been rotated, so a rejecting hook
    /// ends this session's resumability (core §4.5.4).
    fn run_resume_hooks(
        &self,
        ctx: &RequestContext,
        ps: &SessionResumeParams,
    ) -> Result<(), HandlerError> {
        if !self.registry.has_resumers() {
            return Ok(());
        }
        let session = self
            .store()
            .and_then(|store| store.get(&ps.session_id))
            .ok_or_else(|| HandlerError::Rpc(RpcError::code(ERR_INTERNAL_ERROR)))?;
        self.registry.run_session_resumers(ctx, &session, ps)
    }

    /// The version for a resume whose handler named none: the session's
    /// recorded one if the client still offers at least that, else the
    /// freshly negotiated one.
    fn resume_version(
        &self,
        ps: &SessionResumeParams,
        negotiated: &str,
    ) -> Result<String, HandlerError> {
        let Some(recorded) = self.recorded_version(&self.version_key(&ps.session_id)) else {
            return Ok(negotiated.to_owned());
        };
        // The recorded version must still be supported; never advertise one
        // that is not.
        let supported = self.supported_versions();
        if !supported.contains(&recorded) {
            let refs: Vec<&str> = supported.iter().map(String::as_str).collect();
            return Err(version_rejection(Some(&ps.wmp.version), &refs).into());
        }
        let pinned = [recorded.as_str()];
        negotiate_version(&ps.wmp.version, &pinned)
            .map(str::to_owned)
            .ok_or_else(|| version_rejection(Some(&ps.wmp.version), &pinned).into())
    }

    /// Adds the session identity to the `wmp` object of outbound params.
    /// Params that are not a JSON object are returned as is.
    fn stamp(
        &self,
        method: &str,
        params: &impl serde::Serialize,
    ) -> Result<serde_json::Value, HandlerError> {
        let Some(identity) = &self.identity else {
            return serde_json::to_value(params).map_err(internal);
        };
        let mut value = serde_json::to_value(params).map_err(internal)?;
        let Some(obj) = value.as_object_mut() else {
            return Ok(value);
        };
        let mut meta = obj
            .get("wmp")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();
        // Patch only missing or empty members; everything else the caller
        // put in the envelope stays as it is.
        let mut session_id = string_member(&meta, "session_id");
        if session_id.is_empty() && method == METHOD_SESSION_RESUME {
            // A resume names its target session at the top level, not in
            // wmp.
            session_id = obj
                .get("session_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_owned();
        }
        if session_id.is_empty() {
            session_id = identity.session_id.clone();
        }
        fill_member(&mut meta, "session_id", &session_id)?;
        fill_member(&mut meta, "version", &self.version_for(&session_id))?;
        fill_member(&mut meta, "sender", &identity.sender)?;
        obj.insert("wmp".to_owned(), serde_json::Value::Object(meta));
        Ok(value)
    }

    // --- Flow dispatch ---

    /// Routes a `wmp.flow.start` to the profile that owns its flow type, or
    /// to the handler.
    fn dispatch_flow_start(&self, ctx: &RequestContext, ps: &FlowStartParams) -> DispatchResult {
        // A flow_id that is routed (a claim for a sub-flow of this peer, or
        // a flow still running) or being started is not available to the
        // remote peer's start. Reserving it before the handler runs keeps a
        // claim made meanwhile from being overwritten.
        let session = self.flow_session(ctx, &ps.wmp.session_id);
        let start_id = start_identity(ps);
        match self.registry.begin_start(&ps.flow_id, &session, start_id) {
            StartOutcome::Refused => {
                return Err(RpcError::new(
                    ERR_FLOW_ERROR,
                    Some(serde_json::json!({ "reason": "flow_id in use" })),
                )
                .into());
            }
            StartOutcome::Duplicate => {
                // The same start again (a re-issue after a resume): the flow
                // exists, and a second worker is not launched.
                return Ok(Some(serde_json::json!({
                    "wmp": {
                        "version": self.version_for(&session),
                        "session_id": session,
                    },
                    "flow_id": ps.flow_id,
                    "flow_type": ps.flow_type,
                })));
            }
            StartOutcome::Reserved => {}
        }
        let handler = match self.registry.lookup_flow_handler(&ps.flow_type) {
            Some(handler) => handler,
            None => {
                return match self.handler.flow_start(ctx, ps) {
                    Err(err) if is_method_not_found(&err) => {
                        // Nobody here implements this flow type: that is an
                        // unsupported capability (core §10.3), not an
                        // unknown method.
                        self.registry.discard_start(&ps.flow_id);
                        Err(new_unsupported_error(&ps.flow_type, None).into())
                    }
                    Ok(result) => {
                        self.finish_start(&ps.flow_id, true);
                        Ok(Some(serde_json::to_value(result).map_err(internal)?))
                    }
                    Err(err) => {
                        self.finish_start(&ps.flow_id, false);
                        Err(err)
                    }
                };
            }
        };
        // Core §10.3: a flow type whose capability was not negotiated is
        // refused with -31005 before the profile sees it.
        let need = handler.required_capability(&ps.flow_type);
        if !need.is_empty() {
            let negotiated = ctx
                .session
                .as_ref()
                .is_some_and(|session| session.has_capability(&need));
            if !negotiated {
                self.registry.discard_start(&ps.flow_id);
                return Err(new_unsupported_error(
                    &ps.flow_type,
                    Some(serde_json::json!({ "capability": need })),
                )
                .into());
            }
        }
        // Route the flow's messages before its worker can run, under a
        // generation of its own: a worker that finishes first releases
        // exactly this route, and messages that arrive while the start runs
        // are held until it returns.
        let Some((gen, replaced)) =
            self.registry
                .route(&ps.flow_id, &session, handler.clone(), start_id)
        else {
            return Err(HandlerError::Rpc(RpcError::code(ERR_INTERNAL_ERROR)));
        };
        // The route handle the profile's start receives: the generation and
        // the functions that end exactly this route.
        let (release_flow, release_gen) = (ps.flow_id.clone(), gen);
        let release_registry = self.registry.clone();
        let release: Arc<dyn Fn() + Send + Sync> =
            Arc::new(move || release_registry.release(&release_flow, release_gen));
        let (terminal_flow, terminal_gen) = (ps.flow_id.clone(), gen);
        let terminal_registry = self.registry.clone();
        let terminal: Arc<dyn Fn() + Send + Sync> =
            Arc::new(move || terminal_registry.mark_terminal(&terminal_flow, terminal_gen));
        let route_ctx = RequestContext {
            flow_gen: Some(gen),
            flow_route: Some(crate::context::FlowRouteHandle {
                gen,
                release,
                terminal,
            }),
            ..ctx.clone()
        };
        match handler.start_flow(&route_ctx, ps) {
            Ok(result) => {
                self.finish_start(&ps.flow_id, true);
                Ok(Some(serde_json::to_value(result).map_err(internal)?))
            }
            Err(err) => {
                // The flow did not start: its route goes, and the one it was
                // to replace (an ordinary handler's earlier flow) is routed
                // again.
                self.registry.abandon_route(&ps.flow_id, gen, replaced);
                self.registry.discard_start(&ps.flow_id);
                Err(err)
            }
        }
    }

    /// Ends the reservation of a start whose handler has returned. A start
    /// that succeeded applies what was held for it, in order, before
    /// anything newer is dispatched; one that failed drops it.
    fn finish_start(&self, flow_id: &str, succeeded: bool) {
        if !succeeded {
            self.registry.discard_start(flow_id);
            return;
        }
        loop {
            let (ops, done) = self.registry.take_deferred(flow_id);
            if done {
                return;
            }
            for op in ops {
                op();
            }
        }
    }

    /// Hands a progress, completion or error message to the route of its
    /// flow: now, or after the flow's start has returned when that is still
    /// running (held within the registry's limits). A message for a flow no
    /// route exists for goes to the handler, as does one that was held for
    /// a start that published no route. A message from another session than
    /// the flow's is dropped.
    fn deliver_flow(&self, flow_id: &str, session: &str, kind: DeferKind, msg: FlowMessage) {
        if let Some(start_session) = self.registry.starting_session(flow_id) {
            if !start_session.is_empty() && start_session != session {
                return;
            }
            let registry = self.registry.clone();
            let handler = self.handler.clone();
            let flow_id_arg = flow_id.to_owned();
            let session = session.to_owned();
            let msg = msg.clone();
            let op = move || deliver_once(&registry, &handler, &flow_id_arg, &session, &msg);
            if self
                .registry
                .defer_while_starting(flow_id, kind, Box::new(op))
            {
                return;
            }
        }
        deliver_once(&self.registry, &self.handler, flow_id, session, &msg);
    }

    /// Routes a `wmp.flow.action` to its flow.
    fn dispatch_flow_action(&self, ctx: &RequestContext, ps: &FlowActionParams) -> DispatchResult {
        match self.registry.lookup_flow(&ps.flow_id) {
            None => {
                // A flow whose start is running and has published no route
                // cannot take the action yet: refused, for the starting
                // session only, to be repeated.
                if let Some(start_session) = self.registry.starting_session(&ps.flow_id) {
                    if !start_session.is_empty() && start_session != ps.wmp.session_id {
                        return Err(RpcError::code(ERR_NOT_AUTHORIZED).into());
                    }
                    return Err(RpcError::new(
                        ERR_FLOW_ERROR,
                        Some(serde_json::json!({ "reason": "flow is still starting" })),
                    )
                    .into());
                }
                let result = self.handler.flow_action(ctx, ps)?;
                Ok(Some(serde_json::to_value(result).map_err(internal)?))
            }
            Some(entry) => {
                if !entry.session.is_empty() && entry.session != ps.wmp.session_id {
                    return Err(RpcError::code(ERR_NOT_AUTHORIZED).into());
                }
                // A route that is published (its start is running) is
                // dispatched to at once: a worker that asked for an action
                // before the start returned must get it, and waiting for the
                // start would deadlock a start that itself waits for the
                // action.
                if let Some(current) = self.registry.acquire(&ps.flow_id, entry.gen) {
                    let gen_ctx = RequestContext {
                        flow_gen: Some(entry.gen),
                        ..ctx.clone()
                    };
                    let result = current.handler.handle_action(&gen_ctx, ps);
                    self.registry.done(&ps.flow_id, entry.gen);
                    return Ok(Some(
                        serde_json::to_value(result.map_err(internal)?).map_err(internal)?,
                    ));
                }
                let result = self.handler.flow_action(ctx, ps)?;
                Ok(Some(serde_json::to_value(result).map_err(internal)?))
            }
        }
    }

    /// Routes a `wmp.flow.cancel` to its flow.
    fn dispatch_flow_cancel(&self, ctx: &RequestContext, ps: &FlowCancelParams) -> DispatchResult {
        let entry = self.registry.lookup_flow(&ps.flow_id);
        let starting = self.registry.starting_session(&ps.flow_id);
        if let Some(entry) = &entry {
            if !entry.session.is_empty() && entry.session != ps.wmp.session_id {
                return Err(RpcError::code(ERR_NOT_AUTHORIZED).into());
            }
        }
        if entry.is_none() {
            if let Some(start_session) = &starting {
                if !start_session.is_empty() && *start_session != ps.wmp.session_id {
                    return Err(RpcError::code(ERR_NOT_AUTHORIZED).into());
                }
            }
        }
        let cancelled = serde_json::json!({
            "wmp": {
                "version": self.version_for(&ps.wmp.session_id),
                "session_id": ps.wmp.session_id,
            },
            "flow_id": ps.flow_id,
            "status": "cancelled",
        });
        if starting.is_some() {
            // A cancel of a flow whose start is running is applied the
            // moment the flow exists, but only when it can then be honoured:
            // the route is published and its handler stops flows. Anything
            // else is refused, not acknowledged.
            if let Some(entry) = &entry {
                if entry.handler.is_flow_canceller() {
                    let registry = self.registry.clone();
                    let ps = ps.clone();
                    let flow_id = ps.flow_id.clone();
                    let entry = entry.clone();
                    let ctx = ctx.clone();
                    let op = move || {
                        let _ = apply_cancel(&registry, &ctx, &entry, &ps);
                    };
                    if self
                        .registry
                        .defer_while_starting(&flow_id, DeferKind::Cancel, Box::new(op))
                    {
                        return Ok(Some(cancelled));
                    }
                }
            }
            return Err(RpcError::new(
                ERR_FLOW_ERROR,
                Some(serde_json::json!({ "reason": "flow is still starting" })),
            )
            .into());
        }
        let Some(entry) = entry else {
            let result = self.handler.flow_cancel(ctx, ps)?;
            return Ok(Some(serde_json::to_value(result).map_err(internal)?));
        };
        let stopped = apply_cancel(&self.registry, ctx, &entry, ps);
        match stopped {
            Ok(true) => Ok(Some(cancelled)),
            Ok(false) if entry.managed || entry.claimed => {
                let result = self.handler.flow_cancel(ctx, ps)?;
                Ok(Some(serde_json::to_value(result).map_err(internal)?))
            }
            Ok(false) => {
                // An ordinary handler's flow that has no canceller: the
                // handler answers, and the route goes only if it accepted.
                let result = self.handler.flow_cancel(ctx, ps)?;
                self.registry.release(&ps.flow_id, entry.gen);
                Ok(Some(serde_json::to_value(result).map_err(internal)?))
            }
            Err(err) => Err(err),
        }
    }

    /// The session-close hooks, run on the session the request names.
    fn run_session_close_hooks(&self, ctx: &RequestContext, ps: &SessionCloseParams) {
        let Some(store) = self.store() else {
            return;
        };
        let Some(session) = store.get(&ps.wmp.session_id) else {
            return;
        };
        self.registry.run_session_close_hooks(ctx, &session, ps);
    }

    /// Resolves a WMP identifier to an endpoint using the registered
    /// identifier resolvers, tried in registration order; the first `Some`
    /// result wins. `Ok(None)` when no resolver can handle the identifier —
    /// the caller falls back to well-known configuration or session
    /// parameters.
    pub fn resolve_identifier(
        &self,
        ctx: &RequestContext,
        identifier: &str,
    ) -> Result<Option<crate::profile::DiscoveredEndpoint>, HandlerError> {
        self.registry.resolve_identifier(ctx, identifier)
    }
}

impl crate::profile::FlowRouter for Peer {
    fn claim_flow(
        &self,
        flow_id: &str,
        session_id: &str,
        handler: Arc<dyn Profile>,
    ) -> Option<crate::profile::Claim> {
        self.registry.claim_flow(flow_id, session_id, handler)
    }
}

/// One delivery through a route: acquire, deliver, done — the mirror of
/// go-wmp's `viaRoute`.
fn deliver_once(
    registry: &Arc<Registry>,
    handler: &Arc<dyn Handler>,
    flow_id: &str,
    session: &str,
    msg: &FlowMessage,
) {
    match registry.lookup_flow(flow_id) {
        Some(entry) => {
            if entry.session.is_empty() || entry.session == session {
                if let Some(current) = registry.acquire(flow_id, entry.gen) {
                    deliver_to_profile(registry, &current, &msg.with_gen(entry.gen));
                    registry.done(flow_id, entry.gen);
                }
            }
            // A message from another session than the flow's is dropped.
        }
        None => deliver_to_handler(handler, msg),
    }
}

/// Applies a cancel to the authorized route `entry`, and reports whether it
/// stopped the flow, or the error that says it cannot (already terminal).
/// Only the route's own generation is acted on: if that flow has ended and
/// the id was reused, the cancel is not applied to the replacement.
fn apply_cancel(
    registry: &Arc<Registry>,
    ctx: &RequestContext,
    entry: &crate::registry::FlowEntry,
    ps: &FlowCancelParams,
) -> Result<bool, HandlerError> {
    let Some(current) = registry.acquire(&entry.flow_id, entry.gen) else {
        return Ok(false);
    };
    let gen_ctx = RequestContext {
        flow_gen: Some(entry.gen),
        ..ctx.clone()
    };
    let result = current.handler.handle_cancel(&gen_ctx, ps);
    registry.done(&entry.flow_id, entry.gen);
    let stopped = matches!(result, Ok(true));
    // The route of an ordinary handler's flow ends only once the handler
    // stopped it; one that refused keeps it.
    if stopped && !current.managed {
        registry.release(&entry.flow_id, entry.gen);
    }
    result
}

fn deliver_to_profile(
    registry: &Arc<Registry>,
    entry: &crate::registry::FlowEntry,
    msg: &FlowMessage,
) {
    let end_route = |entry: &crate::registry::FlowEntry| {
        // The route of an ordinary handler's flow ends with its terminal
        // notification; a claim's claimant and a route-managing handler end
        // their own.
        if !entry.claimed && !entry.managed {
            registry.release(&entry.flow_id, entry.gen);
        }
    };
    match msg {
        FlowMessage::Progress(ctx, ps) => entry.handler.handle_progress(ctx, ps),
        FlowMessage::Complete(ctx, ps) => {
            entry.handler.handle_complete(ctx, ps);
            end_route(entry);
        }
        FlowMessage::Error(ctx, ps) => {
            entry.handler.handle_error(ctx, ps);
            end_route(entry);
        }
    }
}

fn deliver_to_handler(handler: &Arc<dyn Handler>, msg: &FlowMessage) {
    match msg {
        FlowMessage::Progress(ctx, ps) => handler.flow_progress(ctx, ps),
        FlowMessage::Complete(ctx, ps) => handler.flow_complete(ctx, ps),
        FlowMessage::Error(ctx, ps) => handler.flow_error(ctx, ps),
    }
}

/// The flow messages routed to a handler, with the context they arrived in.
#[derive(Clone)]
enum FlowMessage {
    /// A `wmp.flow.progress`.
    Progress(RequestContext, FlowProgressParams),
    /// A `wmp.flow.complete`.
    Complete(RequestContext, FlowCompleteParams),
    /// A `wmp.flow.error`.
    Error(RequestContext, FlowErrorParams),
}

impl FlowMessage {
    /// The message with the route's generation set on its context.
    fn with_gen(&self, gen: u64) -> FlowMessage {
        match self {
            Self::Progress(ctx, ps) => Self::Progress(
                RequestContext {
                    flow_gen: Some(gen),
                    ..ctx.clone()
                },
                ps.clone(),
            ),
            Self::Complete(ctx, ps) => Self::Complete(
                RequestContext {
                    flow_gen: Some(gen),
                    ..ctx.clone()
                },
                ps.clone(),
            ),
            Self::Error(ctx, ps) => Self::Error(
                RequestContext {
                    flow_gen: Some(gen),
                    ..ctx.clone()
                },
                ps.clone(),
            ),
        }
    }
}

/// The params of a request as a parsed value.
fn params_value(request: &Request) -> Result<serde_json::Value, HandlerError> {
    match &request.params {
        Some(params) => serde_json::from_str(params.get()).map_err(invalid_params),
        None => Ok(serde_json::Value::Null),
    }
}

/// Whether an error answers `-32601`.
fn is_method_not_found(err: &HandlerError) -> bool {
    matches!(err, HandlerError::Rpc(rpc) if rpc.code == ERR_METHOD_NOT_FOUND)
}

/// The `-31005` error whose data names the unsupported item.
fn new_unsupported_error(unsupported: &str, extra: Option<serde_json::Value>) -> RpcError {
    let mut data = extra.unwrap_or_else(|| serde_json::json!({}));
    if let Some(map) = data.as_object_mut() {
        map.insert(
            "unsupported".to_owned(),
            serde_json::Value::String(unsupported.to_owned()),
        );
    }
    RpcError::new(ERR_CAPABILITY_NOT_SUPPORTED, Some(data))
}

fn invalid_params<E>(_err: E) -> HandlerError {
    HandlerError::Rpc(RpcError::code(ERR_INVALID_PARAMS))
}

fn internal<E>(_err: E) -> HandlerError {
    HandlerError::Rpc(RpcError::code(ERR_INTERNAL_ERROR))
}

/// `meta[key]` as a string, empty when absent or not a string.
fn string_member(meta: &serde_json::Map<String, serde_json::Value>, key: &str) -> String {
    meta.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned()
}

/// Sets `meta[key]` to `value` unless it already holds a non-empty string or
/// the value is empty.
fn fill_member(
    meta: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    value: &str,
) -> Result<(), HandlerError> {
    if value.is_empty() || !string_member(meta, key).is_empty() {
        return Ok(());
    }
    meta.insert(key.to_owned(), serde_json::Value::String(value.to_owned()));
    Ok(())
}

/// The identity of a `wmp.flow.start`: what it asks for — the flow type, its
/// timeout and its params, the params compared as canonical JSON — so the
/// same start sent again is recognised.
fn start_identity(ps: &FlowStartParams) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(ps.flow_type.as_bytes());
    hasher.update([0]);
    hasher.update(ps.timeout.unwrap_or_default().to_string().as_bytes());
    hasher.update([0]);
    hasher.update(canonical_json(ps.params.as_deref()));
    hasher.finalize().into()
}

/// Re-encodes raw JSON with sorted object members and no insignificant
/// whitespace; raw JSON that does not parse is returned as is.
fn canonical_json(raw: Option<&RawValue>) -> Vec<u8> {
    let Some(raw) = raw else {
        return Vec::new();
    };
    match serde_json::from_str::<serde_json::Value>(raw.get()) {
        Ok(value) => serde_json::to_vec(&value).unwrap_or_else(|_| raw.get().as_bytes().to_vec()),
        Err(_) => raw.get().as_bytes().to_vec(),
    }
}

/// go-wmp's `updateIfPresent` helper: the store's atomic
/// update-if-present, else a non-atomic read followed by an update.
fn update_if_present(store: &Arc<dyn SessionStore>, session: Session) -> Result<(), StoreError> {
    match store.update_if_present(session.clone()) {
        Err(StoreError::Unsupported) => {}
        other => return other,
    }
    if store.get(&session.id).is_none() {
        return Err(StoreError::NoSuchSession);
    }
    store.update(session)
}
