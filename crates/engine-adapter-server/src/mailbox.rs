//! The engine's message mailbox (issue #77): the store `wmp.message.poll`
//! reads from and `wmp.message.deliver` writes into, per session.
//!
//! The delivery model: a `deliver` names its recipients (`to`), each a
//! session id (W2W: the wallet the counterparty's invitation bootstrapped).
//! The message lands in each recipient session's mailbox (ordered, the
//! sender's envelope preserved) AND on its outbox (the SSE stream delivers
//! it live; the replay serves the reconnect) — so a connected wallet
//! receives it pushed, a reconnecting wallet replays it, and a polling
//! wallet pulls it.
//!
//! The ack model: the recipient marks entries by id (`received`/`read`/
//! `processed`/`failed`, the ack statuses). The mailbox keeps the status;
//! `poll` answers only undelivered-but-live entries (the poll is a pull
//! for a wallet without the SSE stream — the same messages the stream
//! already carried).

use std::sync::Mutex;

use rustc_hash::FxHashMap;
use wmp_core::methods::MessageDeliverParams;

/// One mailbox entry: the delivery envelope + the message id + the ack
/// state.
#[derive(Debug, Clone)]
pub struct MailboxEntry {
    /// The message id (the sender's `message_id` or the derived one).
    pub id: String,
    /// The delivered envelope, JSON, sender-preserved.
    pub message: Vec<u8>,
    /// The unix seconds the delivery arrived.
    pub at: i64,
    /// The ack state: `received`/`read`/`processed`/`failed` (wmp-core's
    /// ACK_*), empty until the first ack.
    pub ack: String,
}

/// The per-session mailboxes.
#[derive(Default)]
pub struct Mailbox {
    boxes: Mutex<FxHashMap<String, Vec<MailboxEntry>>>,
}

impl Mailbox {
    /// An empty mailbox.
    pub fn new() -> Self {
        Self::default()
    }

    /// Delivers one message to each recipient session: the mailbox entry
    /// (ordered, appended) per `to`, answering the entries' ids.
    pub fn deliver(
        &self,
        params: &MessageDeliverParams,
        message_id: &str,
        message: &[u8],
        at: i64,
    ) -> Vec<(String, MailboxEntry)> {
        let mut boxes = self.boxes.lock().unwrap_or_else(|p| p.into_inner());
        params
            .to
            .iter()
            .filter(|to| !to.is_empty())
            .map(|to| {
                let entry = MailboxEntry {
                    id: message_id.to_owned(),
                    message: message.to_vec(),
                    at,
                    ack: String::new(),
                };
                boxes.entry(to.clone()).or_default().push(entry.clone());
                (to.clone(), entry)
            })
            .collect()
    }

    /// The entries after `since` (a message id; empty = every entry),
    /// oldest first, up to `limit` (None = the whole box).
    pub fn poll(&self, session: &str, since: &str, limit: Option<i64>) -> Vec<MailboxEntry> {
        let boxes = self.boxes.lock().unwrap_or_else(|p| p.into_inner());
        let Some(entries) = boxes.get(session) else {
            return Vec::new();
        };
        let after = if since.is_empty() {
            0
        } else {
            // The position after the `since` id's last occurrence.
            entries
                .iter()
                .rposition(|entry| entry.id == since)
                .map(|position| position + 1)
                .unwrap_or(0)
        };
        entries
            .iter()
            .skip(after)
            .take(limit.map_or(usize::MAX, |limit| limit.max(0) as usize))
            .cloned()
            .collect()
    }

    /// Marks the entries (by id) with the ack status, answering how many
    /// matched.
    pub fn ack(&self, session: &str, ids: &[String], status: &str) -> usize {
        let mut boxes = self.boxes.lock().unwrap_or_else(|p| p.into_inner());
        let Some(entries) = boxes.get_mut(session) else {
            return 0;
        };
        let marked = entries
            .iter_mut()
            .filter(|entry| ids.contains(&entry.id))
            .map(|entry| {
                entry.ack = status.to_owned();
            })
            .count();
        marked
    }
}
