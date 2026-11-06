//! The outbound event log: the transport-side outbox every WMP
//! notification from the engine lands in, keyed by session, with the
//! per-session id sequence the SSE binding replays from.
//!
//! **The SSE binding (wmp-transport.md §4.3):** each outbound message is
//! one event — `id: <n>` (the per-session sequence number), `event: wmp`,
//! `data: {json}`. A client reconnecting with `Last-Event-ID: <n>` gets the
//! events it missed replayed first, then the live stream; a `Last-Event-ID`
//! the log no longer retains answers `410 Gone` (the client must resume the
//! session).
//!
//! **The redaction (go-wmp's replay redaction, #163):** the log withholds
//! `refresh_token`, `dpop_jwk` and `dpop_key_id` from `wmp.flow.complete`
//! results — the renewal relay the client needs on its own side of the
//! boundary never rides a replayable event stream.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use rustc_hash::FxHashMap;
use wmp_core::transport::{Transport, TransportError};

/// How many events each session's log retains for replay. A client whose
/// `Last-Event-ID` falls below the window is answered `410 Gone` (the SSE
/// binding, wmp-transport.md §4.3): it must resume the session.
pub const RETAIN: usize = 1024;

/// One logged outbound event.
#[derive(Debug, Clone)]
pub struct LoggedEvent {
    /// The event's sequence number, per session, starting at 1.
    pub id: u64,
    /// The redacted JSON message.
    pub data: Vec<u8>,
}

/// The `wmp.session.resume` result's missed-message count, answered from
/// the log: one log, one truth — the same events the SSE route replays
/// (go-wmp's replayer contract).
pub struct OutboxReplayer {
    /// The log the count reads.
    pub outbox: std::sync::Arc<Outbox>,
}

impl wmp_core::sessionservice::MessageReplayer for OutboxReplayer {
    fn missed_since(&self, session_id: &str, last_received_id: &str) -> i64 {
        self.outbox.missed_since(session_id, last_received_id)
    }
}

/// A session's event log: the retained events and the live broadcast.
struct SessionLog {
    events: VecDeque<LoggedEvent>,
    next_id: u64,
    broadcast: tokio::sync::broadcast::Sender<LoggedEvent>,
}

impl SessionLog {
    fn new() -> Self {
        let (broadcast, _) = tokio::sync::broadcast::channel(RETAIN);
        Self {
            events: VecDeque::with_capacity(RETAIN),
            next_id: 1,
            broadcast,
        }
    }

    /// Appends one event; drops the oldest when the log is full.
    fn push(&mut self, data: Vec<u8>) -> LoggedEvent {
        let event = LoggedEvent {
            id: self.next_id,
            data,
        };
        self.next_id = self.next_id.saturating_add(1);
        self.events.push_back(event.clone());
        if self.events.len() > RETAIN {
            self.events.pop_front();
        }
        // A subscriber gone is not an error: it reconnects through the log.
        let _ = self.broadcast.send(event.clone());
        event
    }

    /// The oldest retained id; `None` when the log holds nothing yet.
    fn oldest(&self) -> Option<u64> {
        self.events.front().map(|event| event.id)
    }
}

/// The engine's outbound event log: every session's events, fed by the
/// [`OutboxTransport`], read by the SSE route and the resume result's
/// missed-message count.
#[derive(Default)]
pub struct Outbox {
    logs: Mutex<FxHashMap<String, SessionLog>>,
    writes: AtomicU64,
}

impl Outbox {
    /// An empty log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Logs one outbound message under its session, and broadcasts it to the
    /// live subscribers. The message is the full JSON-RPC envelope; the
    /// session is the `wmp.session_id` its params carry, or the empty key
    /// when none does (a message outside any session — logged all the same,
    /// under that key).
    pub fn write(&self, message: &[u8]) -> LoggedEvent {
        self.writes.fetch_add(1, Ordering::SeqCst);
        let redacted = redact(message);
        let session = session_of(message);
        let mut logs = self.logs.lock().unwrap_or_else(|p| p.into_inner());
        let log = logs.entry(session).or_insert_with(SessionLog::new);
        log.push(redacted)
    }

    /// The events after `last_id` the session still retains, oldest first.
    /// A client at 0 — a fresh connect, no `Last-Event-ID` — replays
    /// nothing and goes straight to the live stream. A client past 0
    /// replays its gap; a `last_id` below the retained window answers
    /// [`ReplayGap`] — the SSE binding's `410 Gone`, and the client must
    /// resume the session.
    pub fn replay(&self, session: &str, last_id: u64) -> Result<Vec<LoggedEvent>, ReplayGap> {
        // A fresh connect (no last id) goes live: the replay is the
        // catch-up for a client that was connected, not a start-of-stream
        // dump.
        if last_id == 0 {
            return Ok(Vec::new());
        }
        let logs = self.logs.lock().unwrap_or_else(|p| p.into_inner());
        let Some(log) = logs.get(session) else {
            // No log: nothing was ever sent, and the client claims to have
            // seen something — behind a log that never existed.
            return Err(ReplayGap);
        };
        let Some(oldest) = log.oldest() else {
            // An empty log: the same rule as no log.
            return Err(ReplayGap);
        };
        if last_id + 1 < oldest {
            return Err(ReplayGap);
        }
        Ok(log
            .events
            .iter()
            .filter(|event| event.id > last_id)
            .cloned()
            .collect())
    }

    /// How many events the session sent after `last_id` — the
    /// `wmp.session.resume` result's `missed_messages`, answered from the
    /// same log the SSE route replays (go-wmp's replayer contract).
    pub fn missed_since(&self, session: &str, last_id: &str) -> i64 {
        let Ok(last) = last_id.parse::<u64>() else {
            return 0;
        };
        match self.replay(session, last) {
            Ok(events) => i64::try_from(events.len()).unwrap_or(i64::MAX),
            // A gap counts as missed: the resume answer tells the client
            // it is behind, never that it is caught up.
            Err(ReplayGap) => i64::MAX,
        }
    }

    /// Subscribes to the session's live events. A session with no log yet
    /// subscribes to the log that is created on its first write.
    pub fn subscribe(&self, session: &str) -> tokio::sync::broadcast::Receiver<LoggedEvent> {
        let mut logs = self.logs.lock().unwrap_or_else(|p| p.into_inner());
        let log = logs
            .entry(session.to_owned())
            .or_insert_with(SessionLog::new);
        log.broadcast.subscribe()
    }

    /// The number of writes the log has taken (the tests' probe).
    pub fn write_count(&self) -> u64 {
        self.writes.load(Ordering::SeqCst)
    }
}

/// The log cannot replay from `Last-Event-ID`: the events were dropped by
/// the retention window, or no log exists.
#[derive(Debug, PartialEq, Eq)]
pub struct ReplayGap;

/// The outbox as a [`Transport`]: the peer's outbound messages land in the
/// log, and the SSE route reads them. Inbound never travels through here —
/// the `POST /wmp` route is the inbound path — so reading refuses.
pub struct OutboxTransport {
    outbox: std::sync::Arc<Outbox>,
}

impl OutboxTransport {
    /// The transport over the given log.
    pub fn new(outbox: std::sync::Arc<Outbox>) -> Self {
        Self { outbox }
    }

    /// The log the transport writes to (the routes share the instance).
    pub fn outbox(&self) -> &std::sync::Arc<Outbox> {
        &self.outbox
    }
}

impl Transport for OutboxTransport {
    fn read_message(&self) -> Result<Vec<u8>, TransportError> {
        // The POST route is the inbound path; the transport only writes.
        Err(TransportError::Closed)
    }

    fn write_message(&self, data: &[u8]) -> Result<(), TransportError> {
        self.outbox.write(data);
        Ok(())
    }

    fn close(&self) -> Result<(), TransportError> {
        // The outbox is not a connection: the SSE subscribers close on
        // their own, the log is the durable side.
        Ok(())
    }
}

/// The `wmp.session_id` a JSON-RPC envelope's params carry, or the empty
/// key when none does.
fn session_of(message: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(message)
        .ok()
        .and_then(|value| {
            value
                .pointer("/params/wmp/session_id")
                .and_then(|v| v.as_str())
                .map(str::to_owned)
        })
        .unwrap_or_default()
}

/// The redaction: `wmp.flow.complete` results lose `refresh_token`,
/// `dpop_jwk` and `dpop_key_id` before the log keeps them (go-wmp's
/// replay redaction). Other messages pass through unchanged.
fn redact(message: &[u8]) -> Vec<u8> {
    const WITHHELD: [&str; 3] = ["refresh_token", "dpop_jwk", "dpop_key_id"];
    let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(message) else {
        return message.to_vec();
    };
    let method = value.get("method").and_then(|m| m.as_str());
    if method != Some("wmp.flow.complete") {
        return message.to_vec();
    }
    let Some(result) = value
        .pointer_mut("/params/result")
        .and_then(|r| r.as_object_mut())
    else {
        return message.to_vec();
    };
    for member in WITHHELD {
        result.remove(member);
    }
    serde_json::to_vec(&value).unwrap_or_else(|_| message.to_vec())
}
