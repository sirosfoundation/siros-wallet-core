//! Sub-flows: a flow's worker asking the remote peer to run a nested flow
//! and waiting for its result — the mirror of go-wmp's `subflow.go`.

use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use serde_json::value::RawValue;

use crate::flowcontext::{AsyncFlowProfile, FlowContext};
use crate::handler::HandlerError;
use crate::methods::*;
use crate::profile::PeerContext;
use crate::types::Metadata;

/// A failure of a sub-flow: the remote peer refused the `wmp.flow.start`
/// (the JSON-RPC error of its response) or ended the sub-flow with
/// `wmp.flow.error`. Code, message and data are the peer's, with data byte
/// for byte as received.
///
/// Message and data are peer-controlled: neither is part of the `Display`
/// form, so logging the error does not log them. Callers that report the
/// failure onward must not forward them blindly (the OpenID4x profile §3.2.6
/// forwards nothing of a rejected sub-flow).
#[derive(Debug, Clone)]
pub struct SubFlowError {
    /// The peer's error code.
    pub code: i64,
    /// The peer's error message.
    pub message: String,
    /// The peer's error data, byte for byte as received.
    pub data: Option<Box<RawValue>>,
}

impl SubFlowError {
    /// Whether the responder declined the sub-flow rather than failing at
    /// it: code `-31006` with `data.reason` `"rejected"`, the well-known
    /// reason of core §6.2. Every other error is a failure.
    pub fn rejected(&self) -> bool {
        if self.code != crate::error::ERR_FLOW_ERROR as i64 {
            return false;
        }
        let Some(data) = &self.data else {
            return false;
        };
        // The exact member name: a struct decode would also match "Reason".
        let Ok(map) = serde_json::from_str::<serde_json::Value>(data.get()) else {
            return false;
        };
        map.get("reason").and_then(serde_json::Value::as_str) == Some("rejected")
    }
}

impl std::fmt::Display for SubFlowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "wmp: sub-flow failed with code {}", self.code)
    }
}

impl std::error::Error for SubFlowError {}

/// Why a sub-flow request did not produce a result.
#[derive(Debug, thiserror::Error)]
pub enum SubFlowRequestError {
    /// The peer refused the start or ended the sub-flow with
    /// `wmp.flow.error`.
    #[error("{0}")]
    Refused(#[from] SubFlowError),
    /// The sub-flow neither completed nor failed within the timeout.
    #[error("wmp: sub-flow timed out")]
    Timeout,
    /// The parent flow ended (it completed, was cancelled locally or by the
    /// remote peer) while the sub-flow was outstanding.
    #[error("wmp: sub-flow cancelled with its parent flow")]
    CancelledWithParent,
    /// The start could not be sent, and the sub-flow was asked to cancel.
    #[error("wmp: send sub-flow start: {0}")]
    Send(#[from] HandlerError),
    /// The sub-flow could not be routed, identified or serialised.
    #[error("{0}")]
    Unroutable(&'static str),
}

/// A sub-flow whose `wmp.flow.start` was sent and whose result has not
/// arrived.
#[derive(Debug, Clone)]
pub struct PendingSubFlow {
    /// The sub-flow's flow id.
    pub flow_id: String,
    /// The parent flow's id.
    pub parent_flow_id: String,
    /// The sub-flow's type.
    pub flow_type: String,
    /// The params member of the `wmp.flow.start` that was sent,
    /// `parent_flow_id` included. Re-send it with the same flow id to
    /// re-issue the sub-flow.
    pub params: Box<RawValue>,
}

/// One outcome of a sub-flow: its result member, or its failure.
pub(crate) enum Outcome {
    /// The result member of the sub-flow's `wmp.flow.complete`.
    Result(Option<Box<RawValue>>),
    /// The failure of the sub-flow's `wmp.flow.error`, or the refusal of its
    /// start.
    Error(SubFlowError),
}

/// The shared state of one outstanding sub-flow: the outcome the responder
/// sent, the acknowledgement of the start, and whether the outcome was
/// already delivered. One condvar wakes the waiter for any of the three.
pub(crate) struct SubFlow {
    id: String,
    parent_id: String,
    flow_type: String,
    session_id: String,
    params: Box<RawValue>,
    seq: u64,
    parent_gen: u64,
    state: Mutex<SubFlowState>,
    signal: Condvar,
}

#[derive(Default)]
struct SubFlowState {
    /// The first outcome; later ones are dropped.
    outcome: Option<Outcome>,
    /// The answer to the start, until the wait takes it.
    ack: Option<Option<HandlerError>>,
    /// Whether the answer to the start arrived at all — the cancel's
    /// clock starts here, outlasting the wait's consumption of the answer.
    answered: bool,
    /// Whether the outcome was handed to the waiter.
    delivered: bool,
}

impl SubFlow {
    /// Hands an outcome to the waiter; only the first counts. Reports
    /// whether this sub-flow was already known (the addressee).
    pub(crate) fn deliver(&self, outcome: Outcome) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        if state.outcome.is_some() {
            return true; // a later outcome is dropped
        }
        state.outcome = Some(outcome);
        self.signal.notify_all();
        true
    }

    /// Records the answer to the start.
    fn acknowledge(&self, ack: Option<HandlerError>) {
        if let Ok(mut state) = self.state.lock() {
            state.ack = Some(ack);
            state.answered = true;
            self.signal.notify_all();
        }
    }

    /// Takes the outcome, marking it delivered.
    fn take_outcome(&self) -> Option<Outcome> {
        let Ok(mut state) = self.state.lock() else {
            return None;
        };
        let outcome = state.outcome.take();
        if outcome.is_some() {
            state.delivered = true;
        }
        outcome
    }

    /// Whether the answer to the start arrived.
    fn acknowledged(&self) -> bool {
        self.state.lock().is_ok_and(|state| state.answered)
    }

    /// Waits for the outcome or the start's answer, until `deadline`,
    /// watching the parent flow's end every few milliseconds.
    fn wait(&self, parent: &FlowContext, deadline: Instant) -> Arrival {
        const PARENT_TICK: Duration = Duration::from_millis(10);
        let ack_seen = false;
        let Ok(mut state) = self.state.lock() else {
            return Arrival::Wait;
        };
        loop {
            if let Some(outcome) = state.outcome.take() {
                state.delivered = true;
                return Arrival::Outcome(outcome);
            }
            if !ack_seen {
                if let Some(ack) = state.ack.take() {
                    return match ack {
                        None => Arrival::Accepted,
                        Some(err) => Arrival::Refused(err),
                    };
                }
            }
            if parent.is_terminal() {
                return Arrival::ParentEnded;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Arrival::TimedOut;
            }
            let Ok((guard, _)) = self.signal.wait_timeout(state, remaining.min(PARENT_TICK)) else {
                return Arrival::Wait;
            };
            state = guard;
        }
    }
}

/// What a sub-flow's wait returned.
enum Arrival {
    /// A result or a failure arrived.
    Outcome(Outcome),
    /// The start was accepted; only the outcome matters now.
    Accepted,
    /// The start was refused.
    Refused(HandlerError),
    /// The parent flow ended.
    ParentEnded,
    /// The timeout passed.
    TimedOut,
    /// The wait cannot proceed (a poisoned lock).
    Wait,
}

impl FlowContext {
    /// Starts a nested flow of the given type at the remote peer and waits
    /// for its result. It is the orchestrator's side of a sign or match
    /// sub-flow: the flow's worker asks the peer (the wallet) to do
    /// something and carries on with the answer.
    ///
    /// `params` must serialize to a JSON object; the request sets its
    /// `parent_flow_id` member to this flow's id (overwriting any value
    /// there) and sends `wmp.flow.start` with a fresh flow id. The result is
    /// the result member of the sub-flow's `wmp.flow.complete`, unvalidated:
    /// a typed helper validates it for its flow type.
    ///
    /// When it gives up without an outcome it asks the peer to cancel the
    /// sub-flow, so no sub-flow outlives its parent. Only a complete or
    /// error for the sub-flow's own flow id, from the sub-flow's own
    /// session, is accepted as the outcome. It needs no HTTP request: it
    /// works over any peer.
    pub fn request_sub_flow(
        &self,
        flow_type: &str,
        params: &impl serde::Serialize,
        timeout: Duration,
    ) -> Result<Option<Box<RawValue>>, SubFlowRequestError> {
        let peer = self.peer_context();
        let profile = self.profile_context();
        let (Some(peer), Some(profile)) = (peer, profile) else {
            return Err(SubFlowRequestError::Unroutable(
                "wmp: flow context cannot route sub-flow messages (not run by an AsyncFlowProfile on a Peer)",
            ));
        };
        if timeout.is_zero() {
            return Err(SubFlowRequestError::Unroutable(
                "wmp: sub-flow timeout must be positive",
            ));
        }
        // The sub-flow's messages are accepted from one session only: the
        // one the start goes out under. Without one the claim would be open
        // to any.
        let session = self.session_id();
        if session.is_empty() {
            return Err(SubFlowRequestError::Unroutable(
                "wmp: cannot determine the session of the sub-flow",
            ));
        }
        // A parent that is already over starts no child, whatever its
        // worker does next.
        if self.is_terminal() {
            return Err(SubFlowRequestError::CancelledWithParent);
        }
        let body = sub_flow_params(params, &self.flow_id)?;
        let child_id = new_sub_flow_id(&peer, &self.flow_id, flow_type)?;
        let sub = Arc::new(SubFlow {
            id: child_id,
            parent_id: self.flow_id.clone(),
            flow_type: flow_type.to_owned(),
            session_id: session,
            params: body,
            seq: profile.next_child_seq(),
            parent_gen: self.generation(),
            state: Mutex::new(SubFlowState::default()),
            signal: Condvar::new(),
        });

        // Registered before the claim goes in: the first message of the
        // sub-flow may be routed the moment the claim exists.
        let claim = profile
            .register_sub_flow(&peer, &sub)
            .ok_or_else(|| SubFlowRequestError::Unroutable("wmp: sub-flow id is already in use"))?;
        let result = self.run_sub_flow(&peer, &sub, timeout);

        // The claim ends with the request, after any cancel it sent; the
        // child leaves the profile's map either way.
        profile.forget_sub_flow(&sub);
        drop(claim);

        match result {
            SubFlowResult::Outcome(Outcome::Result(result)) => Ok(result),
            SubFlowResult::Outcome(Outcome::Error(err)) => Err(SubFlowRequestError::Refused(err)),
            SubFlowResult::Refused(err) => Err(SubFlowError::of(&err).into()),
            SubFlowResult::Timeout => {
                self.cancel_sub_flow(&peer, &sub);
                Err(SubFlowRequestError::Timeout)
            }
            SubFlowResult::Cancelled => {
                self.cancel_sub_flow(&peer, &sub);
                Err(SubFlowRequestError::CancelledWithParent)
            }
            SubFlowResult::Send(err) => {
                // A transport failure does not say the start was not
                // delivered: cancel, then report.
                self.cancel_sub_flow(&peer, &sub);
                Err(SubFlowRequestError::Send(err))
            }
            SubFlowResult::Wait => Err(SubFlowRequestError::Send(send_failed())),
        }
    }

    /// This flow's own sub-flows that have not completed or failed, oldest
    /// first — after a session resume, a worker can use them to re-issue the
    /// sub-flows whose start or result the interrupted connection may have
    /// lost.
    pub fn pending_sub_flows(&self) -> Vec<PendingSubFlow> {
        let session = self.session_id();
        let Some(profile) = self.profile_context() else {
            return Vec::new();
        };
        if session.is_empty() {
            return Vec::new();
        }
        profile.pending_sub_flows_of(&session, &self.flow_id, self.generation())
    }

    /// Sends the start and waits for the outcome. The send runs apart from
    /// the wait: a stalled transport write cannot hold the request past its
    /// timeout. The start counts as delivered once its answer arrived or an
    /// outcome beat it.
    fn run_sub_flow(
        &self,
        peer: &Arc<dyn PeerContext>,
        sub: &Arc<SubFlow>,
        timeout: Duration,
    ) -> SubFlowResult {
        let mut meta = self.meta_of();
        meta.session_id = sub.session_id.clone();
        let start = FlowStartParams {
            wmp: meta,
            flow_type: sub.flow_type.clone(),
            flow_id: sub.id.clone(),
            params: Some(sub.params.clone()),
            timeout: None,
        };
        let Ok(start_value) = serde_json::to_value(&start) else {
            return SubFlowResult::Send(send_failed());
        };
        let sender_sub = sub.clone();
        let sender_peer = peer.clone();
        std::thread::spawn(move || {
            let answer = sender_peer
                .call(&RequestContext::default(), METHOD_FLOW_START, &start_value)
                .err();
            sender_sub.acknowledge(answer);
        });

        let deadline = Instant::now() + timeout;
        loop {
            match sub.wait(self, deadline) {
                Arrival::Outcome(outcome) => return SubFlowResult::Outcome(outcome),
                Arrival::Accepted => continue,
                Arrival::Refused(err) => {
                    // An outcome already in is the answer, whatever became
                    // of the acknowledgement of the start.
                    if let Some(outcome) = sub.take_outcome() {
                        return SubFlowResult::Outcome(outcome);
                    }
                    if matches!(err, HandlerError::Rpc(_)) {
                        return SubFlowResult::Refused(err);
                    }
                    return SubFlowResult::Send(err);
                }
                Arrival::ParentEnded => {
                    if let Some(outcome) = sub.take_outcome() {
                        return SubFlowResult::Outcome(outcome);
                    }
                    return SubFlowResult::Cancelled;
                }
                Arrival::TimedOut => {
                    if let Some(outcome) = sub.take_outcome() {
                        return SubFlowResult::Outcome(outcome);
                    }
                    return SubFlowResult::Timeout;
                }
                Arrival::Wait => return SubFlowResult::Wait,
            }
        }
    }

    /// Asks the peer to cancel the sub-flow, in the background and best
    /// effort: the peer may be gone, and a sub-flow that already reached a
    /// terminal state answers `-31006` already terminal. It goes out only
    /// after the answer to the start arrived, so the cancel cannot overtake
    /// a start that is still on its way.
    fn cancel_sub_flow(&self, peer: &Arc<dyn PeerContext>, sub: &Arc<SubFlow>) {
        let meta = Metadata {
            session_id: sub.session_id.clone(),
            ..self.meta_of()
        };
        let cancel = FlowCancelParams {
            wmp: meta,
            flow_id: sub.id.clone(),
            reason: CANCEL_REASON_NO_LONGER_NEEDED.to_owned(),
        };
        let Ok(cancel_value) = serde_json::to_value(&cancel) else {
            return;
        };
        let peer = peer.clone();
        let sub = sub.clone();
        std::thread::spawn(move || {
            // The start may be stuck in a write for longer than any cancel
            // timeout; the cancel's own clock starts only when it can follow
            // it. Bounded and best effort.
            let deadline = Instant::now() + Duration::from_secs(30);
            while !sub.acknowledged() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            // A receiver whose start is still running refuses the cancel as
            // "flow is still starting": repeat it, with a short back-off,
            // within the 5 s the cancel has.
            let budget = Instant::now() + Duration::from_secs(5);
            let mut delay = Duration::from_millis(50);
            loop {
                let err = peer
                    .call(
                        &RequestContext::default(),
                        METHOD_FLOW_CANCEL,
                        &cancel_value,
                    )
                    .err();
                match err {
                    Some(err) if still_starting(&err) => {
                        if Instant::now() + delay > budget {
                            return;
                        }
                        std::thread::sleep(delay);
                        delay *= 2;
                    }
                    _ => return,
                }
            }
        });
    }

    fn meta_of(&self) -> Metadata {
        self.meta()
    }
}

enum SubFlowResult {
    Outcome(Outcome),
    Refused(HandlerError),
    Timeout,
    Cancelled,
    Send(HandlerError),
    Wait,
}

impl SubFlowError {
    /// The refusal's shape, from the JSON-RPC error of the start's answer.
    fn of(err: &HandlerError) -> SubFlowError {
        let rpc = err.to_rpc();
        SubFlowError {
            code: rpc.code as i64,
            message: rpc.message,
            data: rpc.data,
        }
    }
}

/// go-wmp's `stillStarting`: the `-31006` "flow is still starting" refusal
/// of a request that arrived before the flow existed.
fn still_starting(err: &HandlerError) -> bool {
    let HandlerError::Rpc(rpc) = err else {
        return false;
    };
    if rpc.code != crate::error::ERR_FLOW_ERROR {
        return false;
    }
    let Some(data) = &rpc.data else {
        return false;
    };
    let Ok(map) = serde_json::from_str::<serde_json::Value>(data.get()) else {
        return false;
    };
    map.get("reason").and_then(serde_json::Value::as_str) == Some("flow is still starting")
}

/// The error a worker sees when its own transport or serialisation failed;
/// distinct from a peer refusal.
fn send_failed() -> HandlerError {
    HandlerError::Rpc(crate::error::RpcError::code(
        crate::error::ERR_INTERNAL_ERROR,
    ))
}

/// Params as a JSON object with `parent_flow_id` set.
fn sub_flow_params(
    params: &impl serde::Serialize,
    parent_id: &str,
) -> Result<Box<RawValue>, SubFlowRequestError> {
    let raw = serde_json::to_value(params)
        .map_err(|_| SubFlowRequestError::Unroutable("wmp: marshal sub-flow params"))?;
    let mut map = match raw {
        serde_json::Value::Object(map) => map,
        serde_json::Value::Null => serde_json::Map::new(),
        _ => {
            return Err(SubFlowRequestError::Unroutable(
                "wmp: sub-flow params must be a JSON object",
            ))
        }
    };
    map.insert(
        "parent_flow_id".to_owned(),
        serde_json::Value::String(parent_id.to_owned()),
    );
    let text = serde_json::to_string(&serde_json::Value::Object(map))
        .map_err(|_| SubFlowRequestError::Unroutable("wmp: marshal sub-flow params"))?;
    RawValue::from_string(text)
        .ok()
        .ok_or_else(|| SubFlowRequestError::Unroutable("wmp: marshal sub-flow params"))
}

/// A fresh, unguessable flow id for a sub-flow, from the peer's entropy:
/// `parent-type-hex`.
fn new_sub_flow_id(
    peer: &Arc<dyn PeerContext>,
    parent_id: &str,
    flow_type: &str,
) -> Result<String, SubFlowRequestError> {
    let entropy = peer.entropy().ok_or(SubFlowRequestError::Unroutable(
        "wmp: no entropy source for the sub-flow id",
    ))?;
    let mut bytes = [0u8; 8];
    if !entropy(&mut bytes) {
        return Err(SubFlowRequestError::Unroutable("wmp: generate sub-flow id"));
    }
    let mut hex = String::with_capacity(16);
    for &b in bytes.iter() {
        hex.push((b'0' + (b >> 4)) as char);
        hex.push((b'0' + (b & 0x0f)) as char);
    }
    Ok(format!("{parent_id}-{flow_type}-{hex}"))
}

impl AsyncFlowProfile {
    /// Registers a sub-flow with this profile and claims its route through
    /// the peer the flow runs on.
    pub(crate) fn register_sub_flow(
        self: &Arc<Self>,
        peer: &Arc<dyn PeerContext>,
        sub: &Arc<SubFlow>,
    ) -> Option<crate::profile::Claim> {
        {
            let Ok(mut children) = self.children.lock() else {
                return None;
            };
            children.insert(sub.id.clone(), sub.clone());
        }
        let profile: Arc<dyn crate::profile::Profile> = self.clone();
        let claim = peer.claim_flow_route(&sub.id, &sub.session_id, profile);
        if claim.is_none() {
            if let Ok(mut children) = self.children.lock() {
                children.remove(&sub.id);
            }
        }
        claim
    }

    /// Forgets a sub-flow; its claim ends when the request drops it.
    pub(crate) fn forget_sub_flow(&self, sub: &Arc<SubFlow>) {
        if let Ok(mut children) = self.children.lock() {
            children.remove(&sub.id);
        }
    }

    /// The profile's view of one session's pending sub-flows of a parent
    /// flow instance.
    fn pending_sub_flows_of(
        &self,
        session: &str,
        parent_id: &str,
        parent_gen: u64,
    ) -> Vec<PendingSubFlow> {
        let mut subs: Vec<Arc<SubFlow>> = self
            .children
            .lock()
            .map(|children| {
                children
                    .values()
                    .filter(|sub| {
                        sub.parent_id == parent_id
                            && sub.parent_gen == parent_gen
                            && !sub.delivered()
                            && sub.session_id == session
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        subs.sort_by_key(|sub| sub.seq);
        subs.into_iter()
            .map(|sub| PendingSubFlow {
                flow_id: sub.id.clone(),
                parent_flow_id: sub.parent_id.clone(),
                flow_type: sub.flow_type.clone(),
                params: sub.params.clone(),
            })
            .collect()
    }

    /// Hands an outcome to the waiter of the sub-flow with this flow id.
    /// Reports whether the id names a sub-flow of this profile.
    pub(crate) fn deliver_sub_flow(&self, flow_id: &str, outcome: Outcome) -> bool {
        let sub = self
            .children
            .lock()
            .ok()
            .and_then(|children| children.get(flow_id).cloned());
        match sub {
            Some(sub) => sub.deliver(outcome),
            None => false,
        }
    }

    /// The next registration order of a sub-flow.
    fn next_child_seq(&self) -> u64 {
        self.child_seq
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1
    }
}

impl SubFlow {
    fn delivered(&self) -> bool {
        self.state
            .lock()
            .map(|state| state.delivered)
            .unwrap_or(true)
    }
}

use crate::context::RequestContext;
