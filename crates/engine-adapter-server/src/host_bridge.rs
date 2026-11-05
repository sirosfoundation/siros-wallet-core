//! The host bridge: the server's `Host` port as WMP sub-flows — the #163
//! bridge's `wmpTransport` piece, the F1 gap in `docs/engine-parity.md`.
//!
//! The engine core's flows ask their sub-flow questions through the
//! [`engine_ports::Host`] port (sign, match, consent, tx_code,
//! presentation, DPoP, attestation, the authorization navigation). On
//! the standalone server the wallet is not in-process — it is the WMP
//! client at the other end of the transport. The bridge turns each ask
//! into a **child flow**: a `wmp.flow.start` for the ask's type, the
//! params the ask carries, routed through the peer's registry so the
//! client's `wmp.flow.complete` (or `error`, or the timeout's `cancel`)
//! reaches the pending ask — exactly the pattern `wmp-core`'s own
//! sub-flow machinery drives for the profiles it runs.
//!
//! The child flow's id is `<parent> :: <type> :: <n>`: it names its
//! parent, so the client's UI can group the asks of one flow, and no
//! two asks of one flow collide.
//!
//! Timeouts: the Go engine's per-ask bounds (sign 3 min, presentation
//! 3 min, match 30 s, the user's consent 5 min, the tx_code 5 min, the
//! authorization navigation 5 min, the DPoP ask 20 s, the attestation
//! ask 10 s). On timeout the bridge cancels the child — the client is
//! told, never left running an ask nobody waits for.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustc_hash::FxHashMap;
use serde_json::value::RawValue;

use wmp_core::context::RequestContext;
use wmp_core::handler::HandlerError;
use wmp_core::methods::*;
use wmp_core::peer::Peer;
use wmp_core::profile::Profile;
use wmp_core::types::{Metadata, VERSION};

/// The Go engine's per-ask timeout bounds (the survey,
/// `docs/engine-parity.md` §6): the sign ask 3 min, the presentation 3
/// min, the match 30 s, the user's consent 5 min, the tx_code 5 min, the
/// authorization navigation 5 min, the DPoP ask 20 s, the attestation
/// ask 10 s.
pub mod ask {
    use std::time::Duration;

    /// The sign ask (and the JWT proof): 3 minutes.
    pub const SIGN: Duration = Duration::from_secs(3 * 60);
    /// The presentation signing ask: 3 minutes (the Go sign_presentation bound).
    pub const PRESENTATION: Duration = Duration::from_secs(3 * 60);
    /// The credential match ask: 30 seconds.
    pub const MATCH: Duration = Duration::from_secs(30);
    /// The user's consent ask: 5 minutes (the user interaction bound).
    pub const CONSENT: Duration = Duration::from_secs(5 * 60);
    /// The transaction code ask: 5 minutes (the user interaction bound).
    pub const TX_CODE: Duration = Duration::from_secs(5 * 60);
    /// The authorization navigation ask: 5 minutes (the redirect round trip).
    pub const AUTHORIZATION: Duration = Duration::from_secs(5 * 60);
    /// The client-held DPoP ask: 20 seconds (the Go sign_client_auth bound).
    pub const DPOP_PROOF: Duration = Duration::from_secs(20);
    /// The client attestation ask: 10 seconds (the Go attestation bound).
    pub const ATTESTATION: Duration = Duration::from_secs(10);
}

/// One child flow's outcome, delivered by the client.
enum Outcome {
    /// The client's `wmp.flow.complete` result.
    Done(Box<RawValue>),
    /// The client's `wmp.flow.error`.
    Failed(i64, String),
    /// The client's `wmp.flow.cancel` — the child stopped.
    Cancelled,
}

/// The flow→session notes: which session each engine flow runs in, so the
/// host bridge starts a flow's asks under the flow's own session. Recorded
/// by the handler at the flow start (the start's `wmp.session_id`); the
/// completion-side forget arrives with the OpenID4x translation (which
/// owns the flow lifecycle events) — until then a cancelled flow's entry
/// goes at its cancel.
#[derive(Default)]
pub struct FlowSessions(std::sync::Mutex<rustc_hash::FxHashMap<String, String>>);

impl FlowSessions {
    /// An empty note.
    pub fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self::default())
    }

    /// Records a flow's session.
    pub fn note(&self, flow_id: &str, session_id: &str) {
        let mut sessions = self.0.lock().unwrap_or_else(|p| p.into_inner());
        sessions.insert(flow_id.to_owned(), session_id.to_owned());
    }

    /// Forgets a flow (its cancel).
    pub fn forget(&self, flow_id: &str) {
        let mut sessions = self.0.lock().unwrap_or_else(|p| p.into_inner());
        sessions.remove(flow_id);
    }

    /// The flow's session, when it was noted.
    pub fn session_of(&self, flow_id: &str) -> Option<String> {
        let sessions = self.0.lock().unwrap_or_else(|p| p.into_inner());
        sessions.get(flow_id).cloned()
    }
}

/// The pending ask: the channel that resolves when the client answers.
struct Pending {
    sender: tokio::sync::oneshot::Sender<Outcome>,
    /// The claim on the child flow's route; held until the ask resolves,
    /// so the completion routes to this bridge.
    #[allow(dead_code)]
    claim: wmp_core::profile::Claim,
}

/// The host bridge: the asks as child flows, the completions routed.
pub struct WmpHostBridge {
    peer: Arc<Peer>,
    pending: Mutex<FxHashMap<String, Pending>>,
    seq: AtomicU64,
}

impl WmpHostBridge {
    /// The bridge over the given peer.
    pub fn new(peer: Arc<Peer>) -> Arc<Self> {
        Arc::new(Self {
            peer,
            pending: Mutex::new(FxHashMap::default()),
            seq: AtomicU64::new(1),
        })
    }

    /// The peer the bridge sends through.
    #[allow(dead_code)]
    pub fn peer(&self) -> &Arc<Peer> {
        &self.peer
    }

    /// Runs one ask as a child flow: claims the child's route, sends the
    /// `wmp.flow.start` with the ask's params, and waits the client's
    /// completion (or its error, or the timeout's cancel).
    ///
    /// `parent` is the asking flow's id, `session` the flow's session,
    /// `flow_type` the ask's type (the client's cue for what to do), and
    /// `params` the ask's parameters. The answer is the client's
    /// completion result, raw.
    pub async fn request(
        self: &Arc<Self>,
        ctx: &RequestContext,
        parent: &str,
        session: &str,
        flow_type: &str,
        params: &impl serde::Serialize,
        timeout: Duration,
    ) -> Result<Box<RawValue>, HostBridgeError> {
        if timeout.is_zero() {
            return Err(HostBridgeError::Invalid(
                "the ask timeout must be positive".to_owned(),
            ));
        }
        let seq = self.seq.fetch_add(1, Ordering::SeqCst);
        let child = format!("{parent}::{flow_type}::{seq}");

        // The route: the child's completion reaches this bridge through
        // the same registry the dispatch routes through.
        let claim = self
            .peer
            .registry()
            .claim_flow(&child, session, self.clone() as Arc<dyn Profile>)
            .ok_or_else(|| HostBridgeError::Invalid("the ask's route is taken".to_owned()))?;

        // The channel, registered before the start goes out: the client's
        // answer may race the notification's tail.
        let (sender, receiver) = tokio::sync::oneshot::channel();
        {
            let mut pending = self.pending.lock().unwrap_or_else(|p| p.into_inner());
            pending.insert(child.clone(), Pending { sender, claim });
        }

        // The start. The wmp envelope names the session; the params are
        // the ask's. Sent as a notification: the answer is the client's
        // own complete, not a reply to this message.
        let start = FlowStartParams {
            wmp: Metadata {
                version: VERSION.to_owned(),
                session_id: session.to_owned(),
                ..Metadata::default()
            },
            flow_id: child.clone(),
            flow_type: flow_type.to_owned(),
            params: raw_of(params),
            timeout: None,
        };
        let start_wmp = start.wmp.clone();
        let sent = self.peer.notify(ctx, METHOD_FLOW_START, &start);
        if sent.is_err() {
            self.take(&child);
            return Err(HostBridgeError::Send);
        }

        // The wait. A timeout cancels the child (the client is told), a
        // completion resolves, an error or cancel refuses.
        match tokio::time::timeout(timeout, receiver).await {
            Ok(Ok(Outcome::Done(result))) => Ok(result),
            Ok(Ok(Outcome::Failed(code, message))) => {
                Err(HostBridgeError::Failed { code, message })
            }
            Ok(Ok(Outcome::Cancelled)) => Err(HostBridgeError::Cancelled),
            Ok(Err(_lost)) => Err(HostBridgeError::Send),
            Err(_elapsed) => {
                // The timeout: cancel the child, then report. The claim
                // ends when the cancel's delivery drops the pending.
                let cancel = FlowCancelParams {
                    wmp: start_wmp,
                    flow_id: child.clone(),
                    reason: "the ask timed out".to_owned(),
                };
                let _ = self.peer.notify(ctx, METHOD_FLOW_CANCEL, &cancel);
                Err(HostBridgeError::Timeout)
            }
        }
    }

    /// Sends the ask's progress notification — fire and forget; the
    /// client's UI hears the step, nobody answers. Synchronous: the
    /// notification rides the transport (the outbox), nothing is awaited.
    pub fn progress(
        &self,
        ctx: &RequestContext,
        flow_id: &str,
        session: &str,
        step: &str,
        detail: Option<String>,
    ) -> Result<(), HandlerError> {
        let params = FlowProgressParams {
            wmp: Metadata {
                version: VERSION.to_owned(),
                session_id: session.to_owned(),
                ..Metadata::default()
            },
            flow_id: flow_id.to_owned(),
            step: step.to_owned(),
            payload: detail.and_then(|text| {
                serde_json::value::RawValue::from_string(
                    serde_json::json!({ "message": text }).to_string(),
                )
                .ok()
            }),
        };
        self.peer.notify(ctx, METHOD_FLOW_PROGRESS, &params)
    }

    /// Takes the pending ask for `child`, ending its route claim.
    fn take(&self, child: &str) -> Option<Pending> {
        let mut pending = self.pending.lock().unwrap_or_else(|p| p.into_inner());
        pending.remove(child)
    }

    /// Delivers an outcome to the pending ask for `child`. A completion
    /// for an ask nobody waits for (a late answer, a cancel after the
    /// timeout) is dropped: the ask already resolved.
    fn deliver(&self, child: &str, outcome: Outcome) {
        if let Some(pending) = self.take(child) {
            let _ = pending.sender.send(outcome);
        }
    }
}

impl Profile for WmpHostBridge {
    fn name(&self) -> String {
        "host-bridge".to_owned()
    }

    fn init(
        &self,
        _ctx: std::sync::Arc<dyn wmp_core::profile::PeerContext>,
    ) -> Result<(), HandlerError> {
        // The bridge needs no peer context: it sends through the peer it
        // was built over, and receives through the registry its claims
        // route to.
        Ok(())
    }

    fn capabilities(&self) -> Vec<String> {
        Vec::new()
    }

    /// The child flow's completion: the ask's answer.
    fn handle_complete(&self, _ctx: &RequestContext, params: &FlowCompleteParams) {
        let outcome = Outcome::Done(params.result.clone().unwrap_or_else(empty_object));
        self.deliver(&params.flow_id, outcome);
    }

    /// The child flow's error: the ask's refusal.
    fn handle_error(&self, _ctx: &RequestContext, params: &FlowErrorParams) {
        let outcome = Outcome::Failed(params.code, params.message.clone());
        self.deliver(&params.flow_id, outcome);
    }

    /// The child flow's cancel: the ask is off — the pending resolves
    /// cancelled, so the asking flow sees its own ask ended rather than
    /// waiting out its timeout.
    fn handle_cancel(
        &self,
        _ctx: &RequestContext,
        params: &FlowCancelParams,
    ) -> Result<bool, HandlerError> {
        self.deliver(&params.flow_id, Outcome::Cancelled);
        Ok(true)
    }
}

/// Why an ask could not be answered.
#[derive(Debug, thiserror::Error)]
pub enum HostBridgeError {
    /// The ask's parameters or its route were invalid.
    #[error("the ask cannot run: {0}")]
    Invalid(String),
    /// The start could not be sent.
    #[error("the ask could not be sent")]
    Send,
    /// The client refused the ask.
    #[error("the ask was refused: {code} {message}")]
    Failed {
        /// The refusal's code.
        code: i64,
        /// The refusal's message.
        message: String,
    },
    /// The client cancelled the ask.
    #[error("the ask was cancelled")]
    Cancelled,
    /// The ask timed out.
    #[error("the ask timed out")]
    Timeout,
}

impl HostBridgeError {
    /// The bridge error as the Host port's error: the refusal keeps the
    /// client's message (the flow's reason names what the wallet said),
    /// the rest are the host's cannot-answer shapes.
    #[must_use]
    pub fn into_host_error(self) -> engine_ports::HostError {
        match self {
            Self::Invalid(reason) => engine_ports::HostError::Cannot(reason),
            Self::Send => engine_ports::HostError::Cannot("the ask could not be sent".to_owned()),
            Self::Failed { code, message } => {
                engine_ports::HostError::Cannot(format!("the ask was refused: {code} {message}"))
            }
            Self::Cancelled => engine_ports::HostError::Cannot("the ask was cancelled".to_owned()),
            Self::Timeout => engine_ports::HostError::Cannot("the ask timed out".to_owned()),
        }
    }
}

/// The empty JSON object, as a raw value: a completion that named no
/// result is an empty answer, not a refusal.
fn empty_object() -> Box<RawValue> {
    serde_json::value::RawValue::from_string("{}".to_owned())
        .unwrap_or_else(|_| Box::<RawValue>::default())
}

/// The raw JSON of a serializable value.
fn raw_of(value: &impl serde::Serialize) -> Option<Box<RawValue>> {
    serde_json::to_string(value)
        .ok()
        .and_then(|text| serde_json::value::RawValue::from_string(text).ok())
}
