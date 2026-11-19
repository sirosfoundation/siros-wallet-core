//! The Valkey-backed shared outbox (issue #65): the engine's outbound event
//! log behind a shared store (a Valkey server — the RESP-compatible open
//! source store, via `fred`, "an async client for Redis and Valkey"), so a
//! multi-replica deployment's SSE replay and resume counts read the same
//! truth from any replica.
//!
//! The layout (one key family per session):
//!
//! - `wmp:outbox:{session}:seq` — the next event id (INCR: concurrent
//!   appends from any replica serialize here);
//! - `wmp:outbox:{session}:log` — a LIST of the retained events;
//! - `wmp:outbox:{session}:ch` — a pub/sub channel for the live tail.
//!
//! The retention window: the write trims the log to [`RETAIN`] entries
//! after each append — the same window the memory log keeps.
//!
//! No lease, no ownership (the trait's documented failure model): the log
//! is append-only and per-session; the client dedupes by event id.

use fred::prelude::*;
use tokio::sync::broadcast;

use crate::outbox::{LoggedEvent, RETAIN};
use crate::shared_outbox::{ReplayGap, SharedOutbox};

/// The Valkey-backed shared outbox.
pub struct ValkeyOutbox {
    client: Client,
    /// The store's URL: the pub/sub listener builds its own dedicated
    /// client from it (a subscribed connection refuses every other
    /// command — the listener can never share the writer's).
    url: String,
    /// The runtime the async client and its pub/sub listener live on: the
    /// trait's methods are sync (the SSE route calls them from its
    /// handler), so they drive the client through this runtime's handle.
    /// The listener (`tokio::spawn`) needs a running reactor, hence the
    /// dedicated one rather than `Handle::try_current` (the caller's
    /// context may have none — a plain `#[test]`).
    runtime: tokio::runtime::Handle,
    /// The live-tail broadcasters, per session: the pub/sub listener feeds
    /// them, the SSE route subscribes.
    channels: dashmap::DashMap<String, broadcast::Sender<LoggedEvent>>,
}

impl ValkeyOutbox {
    /// Connects to the store at `url` (a RESP URL: `valkey://` or
    /// `redis://` — either protocol-identical form) and starts the pub/sub
    /// listener.
    pub fn new(url: &str) -> Result<Self, String> {
        let config =
            Config::from_url(url).map_err(|err| format!("the valkey url does not parse: {err}"))?;
        // A dedicated multi-thread runtime: the client's pub/sub listener
        // spawns on it (`listen`), and the sync trait methods drive the
        // client through its handle.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|err| format!("the valkey runtime failed: {err}"))?;
        let handle = runtime.handle().clone();
        let client = handle
            .block_on(async {
                let client = Client::new(config, None, None, None);
                client.init().await?;
                Ok::<Client, fred::error::Error>(client)
            })
            .map_err(|err| format!("the valkey connection failed: {err}"))?;
        // The runtime never drops: the outbox outlives it, the listener
        // runs on it for the process's life (the engine server is a
        // long-running daemon; a drop would strand the listener mid-task).
        std::mem::forget(runtime);
        let url = url.to_owned();
        let outbox = Self {
            client: client.clone(),
            url: url.clone(),
            runtime: handle.clone(),
            channels: dashmap::DashMap::new(),
        };
        // The listener spawns ON the dedicated runtime (a plain
        // tokio::spawn from this sync context has no reactor; the
        // handle's spawn is the runtime-context call).
        outbox.listen_on(&handle);
        Ok(outbox)
    }

    /// The pub/sub listener: feeds every session's broadcaster from the
    /// store's channel. One pattern subscription (`wmp:outbox:*:ch`) for
    /// every session; a listener failure is a transport failure — the
    /// live tail goes quiet, the replay (the truth) is untouched.
    ///
    /// The spawn goes through an explicit handle: `tokio::spawn` needs a
    /// running reactor, which the dedicated runtime IS even when the
    /// constructor's caller has none (a plain `#[test]`).
    fn listen_on(&self, handle: &tokio::runtime::Handle) {
        let url = self.url.clone();
        let channels = self.channels.clone();
        handle.spawn(async move {
            // A dedicated client: a subscribed connection refuses every
            // other command, so the listener can never share the writer's.
            let Ok(config) = Config::from_url(&url) else {
                return;
            };
            let client = Client::new(config, None, None, None);
            if client.init().await.is_err() {
                return;
            }
            // The pattern channel: every session's events ride
            // `wmp:outbox:*:ch`, the session parsed out of the channel name.
            if client.psubscribe("wmp:outbox:*:ch").await.is_err() {
                return;
            }
            let mut rx = client.message_rx();
            while let Ok(message) = rx.recv().await {
                let channel = message.channel.to_string();
                let Some(session) = channel
                    .strip_prefix("wmp:outbox:")
                    .and_then(|rest| rest.strip_suffix(":ch"))
                else {
                    continue;
                };
                // The payload rides as a bulk string; fred's FromValue
                // (Bytes) carries it.
                let payload: fred::bytes::Bytes =
                    match <_ as fred::types::FromValue>::from_value(message.value) {
                        Ok(payload) => payload,
                        Err(_) => continue,
                    };
                let payload: Vec<u8> = payload.as_ref().to_vec();
                let Some(event) = decode_published(&payload) else {
                    continue;
                };
                if let Some(sender) = channels.get(session) {
                    let _ = sender.send(event);
                }
            }
        });
    }
}

/// One published event's wire form: `id` as a decimal string, `|`, the
/// data — a bulk string. The listener parses it back.
fn encode_published(event: &LoggedEvent) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + event.data.len());
    out.extend_from_slice(event.id.to_string().as_bytes());
    out.push(b'|');
    out.extend_from_slice(&event.data);
    out
}

fn decode_published(payload: &[u8]) -> Option<LoggedEvent> {
    let at = payload.iter().position(|&b| b == b'|')?;
    let id = std::str::from_utf8(payload.get(..at)?).ok()?.parse().ok()?;
    Some(LoggedEvent {
        id,
        data: payload.get(at + 1..)?.to_vec(),
    })
}

fn key_seq(session: &str) -> String {
    format!("wmp:outbox:{session}:seq")
}
fn key_log(session: &str) -> String {
    format!("wmp:outbox:{session}:log")
}
fn key_channel(session: &str) -> String {
    format!("wmp:outbox:{session}:ch")
}

impl SharedOutbox for ValkeyOutbox {
    fn write(&self, session: &str, data: &[u8]) -> LoggedEvent {
        let client = self.client.clone();
        // INCR (the id), RPUSH (the entry), LTRIM (the window), PUBLISH
        // (the live tail): one task, atomic-enough at the store (the id
        // sequence serializes the concurrent appends).
        let id: u64 = self
            .runtime
            .block_on(async {
                let id: u64 = client.incr(&key_seq(session)).await?;
                let entry = encode_published(&LoggedEvent {
                    id,
                    data: data.to_vec(),
                });
                let _: () = client.rpush(&key_log(session), entry.as_slice()).await?;
                // The window: keep the newest RETAIN entries, then the live
                // tail.
                let _: () = client
                    .ltrim(&key_log(session), -(RETAIN as i64), -1)
                    .await?;
                let _: () = client
                    .publish(&key_channel(session), entry.as_slice())
                    .await?;
                Ok::<u64, fred::error::Error>(id)
            })
            .unwrap_or_else(|err| {
                // Issue #65's diagnostics: the store failure rides the
                // log (never the message content).
                eprintln!("engine: valkey outbox write for {session} failed: {err}");
                1
            });
        LoggedEvent {
            id,
            data: data.to_vec(),
        }
    }

    fn replay(&self, session: &str, last_id: u64) -> Result<Vec<LoggedEvent>, ReplayGap> {
        let client = self.client.clone();
        let entries: Vec<Vec<u8>> = self
            .runtime
            .block_on(async { client.lrange::<_, _>(&key_log(session), 0, -1).await })
            .unwrap_or_default();
        let events: Vec<LoggedEvent> = entries.iter().filter_map(|e| decode_published(e)).collect();
        let Some(oldest) = events.first().map(|event| event.id) else {
            // An empty log: a client past 0 claims to have seen something
            // behind it — a gap; a client at 0 missed nothing (the empty
            // session's whole truth is the live stream).
            if last_id == 0 {
                return Ok(Vec::new());
            }
            return Err(ReplayGap);
        };
        if last_id != 0 && last_id + 1 < oldest {
            // Below the retained window: the client must resume the session.
            return Err(ReplayGap);
        }
        // A client at 0 replays the whole retained window (issue #72);
        // past 0, its gap.
        let after = if last_id == 0 {
            oldest.saturating_sub(1)
        } else {
            last_id
        };
        Ok(events
            .into_iter()
            .filter(|event| event.id > after)
            .collect())
    }

    fn subscribe(&self, session: &str) -> broadcast::Receiver<LoggedEvent> {
        let sender = self
            .channels
            .entry(session.to_owned())
            .or_insert_with(|| {
                let (sender, _) = broadcast::channel(RETAIN);
                sender
            })
            .clone();
        sender.subscribe()
    }

    fn subscriber_count(&self, session: &str) -> usize {
        self.channels
            .get(session)
            .map(|sender| sender.receiver_count())
            .unwrap_or(0)
    }
}
