//! The shared outbox: the engine's outbound event log behind a trait, so a
//! multi-replica deployment can back it with a shared store (Redis) instead
//! of the per-process memory this crate's [`Outbox`] provides (issue #65).
//!
//! The log's contract is the SSE binding's replay truth (wmp-transport.md
//! §4.3): every session's events, retained up to a window, replayed
//! oldest-first on reconnect, counted by `wmp.session.resume`'s
//! `missed_messages`. The redaction happens **before** the log (the
//! transport's own [`redact`] — a shared store never sees the withheld
//! members), and the client dedupes by event id, so an implementation may
//! redeliver freely.
//!
//! # The failure model (issue #65)
//!
//! - **Replica loss**: the log survives in the shared store; a client
//!   reconnecting to ANY replica replays from its `Last-Event-ID` exactly as
//!   it does today — the log is the truth, no per-replica state exists.
//! - **Resume on another replica**: identical to same-replica (the log is
//!   shared); nothing about a replica's identity rides the protocol.
//! - **Lease/ownership**: none — the log is append-only and per-session;
//!   concurrent appends serialize at the store (the id sequence).
//! - **Duplicate delivery**: unchanged — the client dedupes by event id
//!   (the SDK's `seenEventIds`), exactly as today.
//!
//! # Session affinity (issue #65's interim mitigation)
//!
//! Until every shared state lives behind a store — the flow `Registry`
//! (wmp-core) is process-local by design: a flow's start/complete/cancel all
//! arrive at the instance that owns it — a multi-replica deployment MUST
//! route by session affinity, keyed by the WMP session id. The server warns
//! at startup when more than one replica is configured
//! ([`crate::config::Config::replicas`]).

use std::sync::Arc;

/// One logged outbound event — the outbox's own type (one type, one truth:
/// the in-memory and shared implementations log the same events).
pub use crate::outbox::{LoggedEvent, ReplayGap};

/// The engine's outbound event log: every session's events, written by the
/// transport, read by the SSE route's replay and the resume result's
/// missed-message count (issue #65's shared seam).
///
/// Implementations MUST retain at least [`RETAIN`] events per session,
/// replay them oldest-first, and broadcast live events to the session's
/// subscribers. The [`redact`](super::outbox::redact) filter runs before
/// the log — the store never sees the withheld members.
pub trait SharedOutbox: Send + Sync {
    /// Logs one outbound message under its session (`wmp.session_id` its
    /// params carry, the empty key when none does), broadcasting it to the
    /// live subscribers. The message arrives **already redacted**.
    fn write(&self, session: &str, data: &[u8]) -> LoggedEvent;

    /// The events after `last_id` the session still retains, oldest first.
    /// A client at 0 — a fresh connect, no `Last-Event-ID` — **replays the
    /// whole retained window** (issue #72): a stream that never delivered a
    /// byte carries no `lastEventId` to name what it missed. A client past
    /// 0 replays its gap; a `last_id` below the retained window answers
    /// [`ReplayGap`].
    fn replay(&self, session: &str, last_id: u64) -> Result<Vec<LoggedEvent>, ReplayGap>;

    /// How many events the session sent after `last_id` — the
    /// `wmp.session.resume` result's `missed_messages`. A gap counts as
    /// missed (the answer tells the client it is behind, never caught up).
    fn missed_since(&self, session: &str, last_id: &str) -> i64 {
        let Ok(last) = last_id.parse::<u64>() else {
            return 0;
        };
        match self.replay(session, last) {
            Ok(events) => i64::try_from(events.len()).unwrap_or(i64::MAX),
            Err(ReplayGap) => i64::MAX,
        }
    }

    /// Subscribes to the session's live events. A session with no log yet
    /// subscribes to the log created on its first write.
    fn subscribe(&self, session: &str) -> tokio::sync::broadcast::Receiver<LoggedEvent>;

    /// How many live subscribers the session's log has (issue #72): the
    /// ask's delivery anchor — an ask streamed while this is 0 has no
    /// reader, and its timeout must not burn in the delivery-less window.
    fn subscriber_count(&self, session: &str) -> usize;
}

/// The shared outbox as a factory-configured instance: the deployment's
/// config names the backend (`memory`, `redis`), the constructor builds it.
pub fn shared_outbox(
    backend: &str,
    valkey_url: Option<&str>,
) -> Result<Arc<dyn SharedOutbox>, String> {
    match backend {
        "memory" | "" => Ok(Arc::new(super::outbox::Outbox::new())),
        #[cfg(feature = "valkey")]
        "valkey" => {
            let url = valkey_url.ok_or_else(|| "the valkey backend needs its url".to_owned())?;
            Ok(Arc::new(crate::valkey_outbox::ValkeyOutbox::new(url)?))
        }
        #[cfg(not(feature = "valkey"))]
        "valkey" => Err("the valkey backend needs the valkey feature".to_owned()),
        other => Err(format!("unknown outbox backend: {other}")),
    }
}
