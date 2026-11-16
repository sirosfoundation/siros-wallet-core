//! The async flow driver: a [`FlowContext`] for a flow's worker, and
//! [`AsyncFlowProfile`], the profile that runs flow functions as threads —
//! the mirror of go-wmp's `FlowContext` and `AsyncFlowProfile`.
//!
//! go-wmp leans on goroutines, channels and `context` cancellation. The
//! mirror keeps the semantics on `std` primitives: a cancellation token for
//! the flow's context, a signalled queue for actions, a signalled terminal
//! flag for the flow's end, and one thread per flow. wasm32 has no threads;
//! a browser driver arrives with the adapter that needs it.
//!
//! Divergences from go-wmp, recorded here: a profile's flows are keyed by
//! flow id alone, not by the dispatching peer (a profile shared by several
//! peers needs the peer in the key; no adapter here does that yet), and the
//! peer's `Lifetime` watcher is not ported (the mirror's peer has no
//! lifetime broadcast). `RequestSubFlow` — go-wmp's `subflow.go` — is the
//! remaining piece of this stage; see `docs/wmp-core-port.md`.

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::Duration;

use rustc_hash::FxHashMap;
use serde_json::value::RawValue;

use crate::context::{FlowRouteHandle, RequestContext};
use crate::error::{RpcError, ERR_CAPABILITY_NOT_SUPPORTED, ERR_FLOW_ERROR, ERR_INTERNAL_ERROR};
use crate::handler::HandlerError;
use crate::methods::*;
use crate::profile::{PeerContext, Profile};
use crate::subflow::{Outcome, SubFlow, SubFlowError};
use crate::types::Metadata;
use crate::version::VERSION;

/// A flow's worker: runs in its own thread and uses the [`FlowContext`] to
/// communicate with the remote peer. Returns `Ok` on success.
pub type FlowFunc =
    Arc<dyn Fn(&CancelToken, &Arc<FlowContext>) -> Result<(), HandlerError> + Send + Sync>;

/// A cancellation token — the mirror of the `context.WithCancel` the flow's
/// worker runs under. The sub-flow machinery extends it with causes when it
/// arrives.
#[derive(Default)]
pub struct CancelToken {
    state: Mutex<bool>,
    signal: Condvar,
}

impl CancelToken {
    /// A token that is not cancelled.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Cancels the token. Idempotent; wakes every waiter.
    pub fn cancel(&self) {
        if let Ok(mut state) = self.state.lock() {
            *state = true;
        }
        self.signal.notify_all();
    }

    /// Whether the token is cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.state.lock().is_ok_and(|state| *state)
    }

    /// Waits until the token is cancelled.
    pub fn wait(&self) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        while !*state {
            match self.signal.wait(state) {
                Ok(guard) => state = guard,
                Err(_) => return,
            }
        }
    }
}

/// The flow's action queue and terminal flag, signalled together: a waiter
/// wakes for an action, the flow's end, or its timeout.
#[derive(Default)]
struct Actions {
    state: Mutex<(VecDeque<FlowActionParams>, bool)>,
    signal: Condvar,
}

impl Actions {
    fn deliver(&self, params: FlowActionParams) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        if state.1 {
            return false; // the flow is terminal
        }
        state.0.push_back(params);
        self.signal.notify_one();
        true
    }

    fn wait(&self, timeout: Duration) -> Option<FlowActionParams> {
        let deadline = std::time::Instant::now() + timeout;
        let Ok(mut state) = self.state.lock() else {
            return None;
        };
        loop {
            if let Some(action) = state.0.pop_front() {
                return Some(action);
            }
            if state.1 {
                return None;
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return None;
            }
            let Ok((guard, waited)) = self.signal.wait_timeout(state, remaining) else {
                return None;
            };
            state = guard;
            if waited.timed_out() {
                return None;
            }
        }
    }

    fn terminate(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.1 = true;
        }
        self.signal.notify_all();
    }
}

/// What a flow's worker drives it with: send progress notifications, request
/// actions from the remote peer, and complete or cancel the flow. It bridges
/// the WMP call-return model with a thread-per-flow model.
pub struct FlowContext {
    /// The flow's identifier.
    pub flow_id: String,
    /// The flow's type.
    pub flow_type: String,
    /// The flow-type-specific parameters the flow started with.
    pub params: Option<Box<RawValue>>,

    /// The session the flow was started in; every notification the flow
    /// sends carries it, whatever session the peer's static identity
    /// names.
    session_id: String,
    peer: Mutex<Option<Arc<dyn PeerContext>>>,
    actions: Actions,
    /// The generation of the flow's route, and the handles that end it.
    gen: u64,
    route: Option<FlowRouteHandle>,
    /// The profile that runs the flow: sub-flows route their messages
    /// through it.
    profile: Mutex<Weak<AsyncFlowProfile>>,
    /// Cancels the context the flow's worker runs under — the same token
    /// the worker holds (go-wmp's `fc.stop`).
    stop: Arc<CancelToken>,
}

impl FlowContext {
    /// Sends a `wmp.flow.progress` notification to the remote peer.
    pub fn progress(
        &self,
        step: &str,
        payload: &impl serde::Serialize,
    ) -> Result<(), HandlerError> {
        let params = FlowProgressParams {
            wmp: self.meta(),
            flow_id: self.flow_id.clone(),
            step: step.to_owned(),
            payload: raw_of(payload),
        };
        self.notify_peer(METHOD_FLOW_PROGRESS, &params)
    }

    /// Sends a `wmp.flow.progress` with the given step, then waits for a
    /// matching `wmp.flow.action` from the remote peer. This is the primary
    /// request/response pattern for flow workers.
    pub fn request_action(
        &self,
        step: &str,
        payload: &impl serde::Serialize,
        timeout: Duration,
    ) -> Result<Option<FlowActionParams>, HandlerError> {
        self.progress(step, payload)?;
        self.wait_for_action(timeout)
    }

    /// Waits for the next `wmp.flow.action` for this flow, until `timeout`
    /// or the flow's end.
    pub fn wait_for_action(
        &self,
        timeout: Duration,
    ) -> Result<Option<FlowActionParams>, HandlerError> {
        Ok(self.actions.wait(timeout))
    }

    /// Sends a `wmp.flow.complete` notification and marks the flow as done.
    pub fn complete(&self, result: &impl serde::Serialize) -> Result<(), HandlerError> {
        let params = FlowCompleteParams {
            wmp: self.meta(),
            flow_id: self.flow_id.clone(),
            result: raw_of(result),
        };
        let sent = self.notify_peer(METHOD_FLOW_COMPLETE, &params);
        if sent.is_ok() {
            self.cancel(); // the flow is terminal: its context ends
        }
        sent
    }

    /// Sends a `wmp.flow.error` notification and marks the flow as failed.
    pub fn error(
        &self,
        code: i64,
        message: &str,
        data: &impl serde::Serialize,
    ) -> Result<(), HandlerError> {
        let params = FlowErrorParams {
            wmp: self.meta(),
            flow_id: self.flow_id.clone(),
            code,
            message: message.to_owned(),
            data: raw_of(data),
        };
        let sent = self.notify_peer(METHOD_FLOW_ERROR, &params);
        if sent.is_ok() {
            self.cancel();
        }
        sent
    }

    /// The session the flow's messages go out under: the flow's own, else
    /// the one the peer's identity names.
    pub fn session_id(&self) -> String {
        if !self.session_id.is_empty() {
            return self.session_id.clone();
        }
        self.peer
            .lock()
            .ok()
            .and_then(|peer| peer.as_ref().map(|p| p.default_session_id()))
            .unwrap_or_default()
    }

    /// Whether the flow has ended: its terminal notification went out, or
    /// it was cancelled.
    pub fn is_terminal(&self) -> bool {
        self.actions
            .state
            .lock()
            .map(|state| state.1)
            .unwrap_or(true)
    }

    /// Ends the flow: terminal, and the worker's context cancelled.
    pub fn cancel(&self) {
        self.actions.terminate();
        if let Some(route) = &self.route {
            (route.terminal)();
        }
        self.stop.cancel();
    }

    /// The cancellation token the flow's worker runs under.
    pub fn worker_token(&self) -> &Arc<CancelToken> {
        &self.stop
    }

    /// The peer the flow sends through.
    pub(crate) fn peer_context(&self) -> Option<Arc<dyn PeerContext>> {
        self.peer.lock().ok().and_then(|peer| peer.clone())
    }

    /// The profile that runs the flow.
    pub(crate) fn profile_context(&self) -> Option<Arc<AsyncFlowProfile>> {
        self.profile.lock().ok().and_then(|weak| weak.upgrade())
    }

    /// The generation of the flow's route.
    pub(crate) fn generation(&self) -> u64 {
        self.gen
    }

    /// The `wmp` object for the flow's messages: the version negotiated for
    /// the flow's session (the crate's version when the peer tracks none)
    /// and the originating session. Set here, not only by the peer's
    /// stamping: a peer without an identity does not stamp, and the message
    /// would then carry an empty `wmp.version`, which core §2.2.3 forbids.
    pub(crate) fn meta(&self) -> Metadata {
        let version = self
            .peer
            .lock()
            .ok()
            .and_then(|peer| peer.as_ref().map(|p| p.version_for(&self.session_id)))
            .unwrap_or_else(|| VERSION.to_string());
        Metadata {
            version,
            session_id: self.session_id(),
            ..Metadata::default()
        }
    }

    /// Routes an incoming flow.action to the waiting worker.
    fn deliver_action(&self, params: FlowActionParams) {
        self.actions.deliver(params);
    }

    fn notify_peer(
        &self,
        method: &str,
        params: &impl serde::Serialize,
    ) -> Result<(), HandlerError> {
        let peer = self.peer.lock().ok().and_then(|peer| peer.clone());
        let Some(peer) = peer else {
            return Err(HandlerError::Rpc(RpcError::code(ERR_INTERNAL_ERROR)));
        };
        let value = serde_json::to_value(params)
            .map_err(|_| HandlerError::Rpc(RpcError::code(ERR_INTERNAL_ERROR)))?;
        peer.notify(&RequestContext::default(), method, &value)
    }
}

/// A profile that runs flow functions as threads. Register a [`FlowFunc`]
/// for each flow type; the profile dispatches incoming flow messages to the
/// worker of the flow they name.
pub struct AsyncFlowProfile {
    name: String,
    handlers: Mutex<FxHashMap<String, FlowFunc>>,
    /// The peer the profile was last initialised with.
    peer: Mutex<Option<Arc<dyn PeerContext>>>,
    /// The running flows, keyed by flow id (see the module's divergences).
    flows: Mutex<FxHashMap<String, Arc<FlowContext>>>,
    /// The sub-flows the profile's flows started, keyed by their flow id.
    pub(crate) children: Mutex<FxHashMap<String, Arc<SubFlow>>>,
    /// The registration order of sub-flows.
    pub(crate) child_seq: std::sync::atomic::AtomicU64,
    /// The profile's own weak reference: the worker thread removes its flow
    /// through it.
    self_ref: Mutex<Weak<AsyncFlowProfile>>,
}

impl AsyncFlowProfile {
    /// A profile that manages async flow workers.
    pub fn new(name: &str) -> Arc<Self> {
        let profile = Arc::new(Self {
            name: name.to_owned(),
            handlers: Mutex::new(FxHashMap::default()),
            peer: Mutex::new(None),
            flows: Mutex::new(FxHashMap::default()),
            children: Mutex::new(FxHashMap::default()),
            child_seq: std::sync::atomic::AtomicU64::new(0),
            self_ref: Mutex::new(Weak::new()),
        });
        if let Ok(mut self_ref) = profile.self_ref.lock() {
            *self_ref = Arc::downgrade(&profile);
        }
        profile
    }

    /// Registers a flow function for a flow type.
    pub fn handle(&self, flow_type: &str, func: FlowFunc) {
        if let Ok(mut handlers) = self.handlers.lock() {
            handlers.insert(flow_type.to_owned(), func);
        }
    }

    /// The flow a message dispatched for generation `gen` is for: a
    /// message for one instance of a flow id never reaches a later
    /// instance.
    fn flow_of(&self, id: &str, gen: u64) -> Option<Arc<FlowContext>> {
        let flow = self.flows.lock().ok()?.get(id).cloned()?;
        if gen != 0 && flow.gen != 0 && flow.gen != gen {
            return None;
        }
        Some(flow)
    }

    /// Cancels the flows with the given id on every peer that runs one.
    /// With a profile shared by several sessions that is rarely what is
    /// wanted: `cancel_session_flow` names the session.
    pub fn cancel_flow(&self, flow_id: &str) {
        let found: Vec<_> = self
            .flows
            .lock()
            .map(|flows| {
                flows
                    .values()
                    .filter(|fc| fc.flow_id == flow_id)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        for flow in found {
            flow.cancel();
        }
    }

    /// Cancels the flow `flow_id` of the session `session_id` only.
    pub fn cancel_session_flow(&self, session_id: &str, flow_id: &str) {
        let found: Vec<_> = self
            .flows
            .lock()
            .map(|flows| {
                flows
                    .values()
                    .filter(|fc| fc.flow_id == flow_id && fc.session_id() == session_id)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        for flow in found {
            flow.cancel();
        }
    }

    /// The number of flows that have not ended. A flow that completed,
    /// failed or was cancelled stays known (and answers "already
    /// terminal") until its worker has exited.
    pub fn active_flows(&self) -> usize {
        self.flows
            .lock()
            .map(|flows| flows.values().filter(|fc| !fc.is_terminal()).count())
            .unwrap_or(0)
    }
}

impl Profile for AsyncFlowProfile {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn capabilities(&self) -> Vec<String> {
        Vec::new()
    }

    fn init(&self, ctx: Arc<dyn PeerContext>) -> Result<(), HandlerError> {
        if let Ok(mut peer) = self.peer.lock() {
            *peer = Some(ctx);
        }
        Ok(())
    }

    fn flow_types(&self) -> Vec<String> {
        self.handlers
            .lock()
            .map(|handlers| handlers.keys().cloned().collect())
            .unwrap_or_default()
    }

    fn manages_flow_routes(&self) -> bool {
        true
    }

    fn start_flow(
        &self,
        ctx: &RequestContext,
        params: &FlowStartParams,
    ) -> Result<FlowStartResult, HandlerError> {
        let func = self
            .handlers
            .lock()
            .ok()
            .and_then(|handlers| handlers.get(&params.flow_type).cloned());
        let Some(func) = func else {
            return Err(HandlerError::Rpc(RpcError::new(
                ERR_CAPABILITY_NOT_SUPPORTED,
                Some(serde_json::json!({ "unsupported": params.flow_type })),
            )));
        };

        // The session the request arrived in: the store-resolved one if
        // known, else the one the request names; a start that names no
        // session belongs to the peer's own.
        let mut session_id = params.wmp.session_id.clone();
        if let Some(session) = &ctx.session {
            session_id = session.id.clone();
        }
        if session_id.is_empty() {
            session_id = self
                .peer
                .lock()
                .ok()
                .and_then(|peer| peer.as_ref().map(|p| p.default_session_id()))
                .unwrap_or_default();
        }
        let peer = self.peer.lock().ok().and_then(|current| current.clone());
        let flow = Arc::new(FlowContext {
            flow_id: params.flow_id.clone(),
            flow_type: params.flow_type.clone(),
            params: params.params.clone(),
            session_id,
            peer: Mutex::new(peer),
            actions: Actions::default(),
            gen: ctx.generation(),
            route: ctx.flow_route.clone(),
            profile: Mutex::new(Weak::new()),
            stop: CancelToken::new(),
        });
        if let Ok(mut profile_ref) = flow.profile.lock() {
            if let Some(profile) = self.self_ref.lock().ok().and_then(|r| r.upgrade()) {
                *profile_ref = Arc::downgrade(&profile);
            }
        }
        if let Ok(mut flows) = self.flows.lock() {
            flows.insert(params.flow_id.clone(), flow.clone());
        }

        // The flow outlives the request that started it. Run the worker in
        // its own thread; when it exits, the flow is removed and — the
        // profile manages its routes — exactly this instance's route ends.
        let self_ref = self.self_ref.lock().ok().map(|r| r.clone());
        let flow_for_worker = flow.clone();
        std::thread::spawn(move || {
            let result = func(flow_for_worker.worker_token(), &flow_for_worker);
            if let Err(err) = result {
                // A flow cancelled (by the remote peer or its profile) is
                // already over: its function returning an error because of
                // that is not a failure to report.
                if !flow_for_worker.worker_token().is_cancelled() && !flow_for_worker.is_terminal()
                {
                    let _ = flow_for_worker.error(
                        ERR_FLOW_ERROR as i64,
                        &err.to_string(),
                        &serde_json::json!({}),
                    );
                }
            }
            flow_for_worker.cancel();
            if let Some(profile) = self_ref.as_ref().and_then(Weak::upgrade) {
                if let Ok(mut flows) = profile.flows.lock() {
                    flows.remove(&flow_for_worker.flow_id);
                }
            }
            if let Some(route) = &flow_for_worker.route {
                (route.release)();
            }
        });

        let version = flow.meta().version;
        Ok(FlowStartResult {
            wmp: Metadata {
                version,
                session_id: flow.session_id(),
                ..Metadata::default()
            },
            flow_id: params.flow_id.clone(),
            flow_type: params.flow_type.clone(),
        })
    }

    fn handle_action(
        &self,
        ctx: &RequestContext,
        params: &FlowActionParams,
    ) -> Result<FlowActionResult, HandlerError> {
        let flow = self.flow_of(&params.flow_id, ctx.generation());
        let Some(flow) = flow else {
            return Err(RpcError::new(
                ERR_FLOW_ERROR,
                Some(
                    serde_json::json!({ "reason": format!("flow not found: {}", params.flow_id) }),
                ),
            )
            .into());
        };
        // A flow that sent its terminal notification takes no more
        // actions, though its worker may still be winding down.
        if flow.is_terminal() {
            return Err(RpcError::new(
                ERR_FLOW_ERROR,
                Some(serde_json::json!({ "reason": "already_terminal" })),
            )
            .into());
        }
        flow.deliver_action(params.clone());
        Ok(FlowActionResult {
            wmp: Metadata::default(),
            flow_id: params.flow_id.clone(),
            action: params.action.clone(),
            status: "accepted".to_owned(),
        })
    }

    fn handle_progress(&self, _ctx: &RequestContext, _params: &FlowProgressParams) {
        // Progress from the remote peer: no routing needed for the
        // server-side flows this profile runs.
    }

    fn handle_complete(&self, ctx: &RequestContext, params: &FlowCompleteParams) {
        if self.deliver_sub_flow(&params.flow_id, Outcome::Result(params.result.clone())) {
            return;
        }
        if let Some(flow) = self.flow_of(&params.flow_id, ctx.generation()) {
            flow.cancel();
        }
    }

    fn handle_error(&self, ctx: &RequestContext, params: &FlowErrorParams) {
        let failure = SubFlowError {
            code: params.code,
            message: params.message.clone(),
            data: params.data.clone(),
        };
        if self.deliver_sub_flow(&params.flow_id, Outcome::Error(failure)) {
            return;
        }
        if let Some(flow) = self.flow_of(&params.flow_id, ctx.generation()) {
            flow.cancel();
        }
    }

    /// A remote `wmp.flow.cancel` ends the flow, and with it the sub-flows
    /// it is waiting for.
    fn handle_cancel(
        &self,
        ctx: &RequestContext,
        params: &FlowCancelParams,
    ) -> Result<bool, HandlerError> {
        let flow = self.flow_of(&params.flow_id, ctx.generation());
        if let Some(flow) = &flow {
            if flow.is_terminal() {
                return Err(RpcError::new(
                    ERR_FLOW_ERROR,
                    Some(serde_json::json!({ "reason": "already_terminal" })),
                )
                .into());
            }
        }
        Ok(flow.is_some_and(|flow| {
            flow.cancel();
            true
        }))
    }

    fn is_flow_canceller(&self) -> bool {
        true
    }
}

/// Serializes a value to raw JSON, when it holds one.
fn raw_of(value: &impl serde::Serialize) -> Option<Box<RawValue>> {
    serde_json::to_string(value)
        .ok()
        .and_then(|s| RawValue::from_string(s).ok())
}
