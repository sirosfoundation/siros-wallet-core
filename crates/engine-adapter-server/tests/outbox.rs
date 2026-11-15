//! The outbound event log: the id sequence, the redaction, the replay and its
//! gap (wmp-transport.md §4.3), the replayer's count, and the live broadcast.

use std::sync::Arc;

use engine_adapter_server::outbox::{Outbox, OutboxReplayer, OutboxTransport, ReplayGap, RETAIN};
use tokio::sync::broadcast::error::TryRecvError;
use wmp_core::sessionservice::MessageReplayer;
use wmp_core::transport::{Transport, TransportError};

fn message(method: &str, session: &str, result: serde_json::Value) -> Vec<u8> {
    serde_json::json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": {
            "wmp": { "session_id": session, "version": "0.1" },
            "result": result,
        }
    })
    .to_string()
    .into_bytes()
}

#[test]
fn write_assigns_per_session_ids_from_one() {
    let outbox = Outbox::new();
    let first = outbox.write(&message(
        "wmp.flow.progress",
        "ses-1",
        serde_json::json!({}),
    ));
    let second = outbox.write(&message(
        "wmp.flow.progress",
        "ses-1",
        serde_json::json!({}),
    ));
    let other = outbox.write(&message(
        "wmp.flow.progress",
        "ses-2",
        serde_json::json!({}),
    ));
    assert_eq!(first.id, 1);
    assert_eq!(second.id, 2);
    assert_eq!(other.id, 1, "each session has its own sequence");
}

#[test]
fn flow_complete_results_lose_the_renewal_relay() {
    let outbox = Outbox::new();
    let event = outbox.write(&message(
        "wmp.flow.complete",
        "ses-1",
        serde_json::json!({
            "credential": "jwt",
            "refresh_token": "rt-secret",
            "dpop_jwk": "{\"kty\":\"EC\"}",
            "dpop_key_id": "key-1",
        }),
    ));
    let logged: serde_json::Value = serde_json::from_slice(&event.data).expect("the event is JSON");
    let result = logged
        .pointer("/params/result")
        .cloned()
        .unwrap_or_default();
    assert!(result.get("credential").is_some(), "the credential stays");
    for withheld in ["refresh_token", "dpop_jwk", "dpop_key_id"] {
        assert!(result.get(withheld).is_none(), "{withheld} is withheld");
    }
}

#[test]
fn other_methods_pass_through_unchanged() {
    let outbox = Outbox::new();
    let body = message(
        "wmp.flow.progress",
        "ses-1",
        serde_json::json!({
            "refresh_token": "rt-rides-a-progress-payload-too",
        }),
    );
    let event = outbox.write(&body);
    assert_eq!(event.data, body, "only flow.complete is redacted");
}

#[test]
fn replay_returns_the_events_after_the_last_id() {
    let outbox = Outbox::new();
    for _ in 0..3 {
        outbox.write(&message(
            "wmp.flow.progress",
            "ses-1",
            serde_json::json!({}),
        ));
    }
    let replayed = outbox.replay("ses-1", 1).expect("the gap fills");
    assert_eq!(
        replayed.iter().map(|event| event.id).collect::<Vec<_>>(),
        [2, 3]
    );
    // A client at the newest id has no gap.
    assert!(outbox.replay("ses-1", 3).expect("at the newest").is_empty());
    // A client ahead of every event has none.
    assert!(outbox.replay("ses-1", 9).expect("ahead").is_empty());
    // A fresh connect at 0 replays nothing, with or without a log.
    assert!(outbox
        .replay("another-session", 0)
        .expect("a fresh session replays nothing")
        .is_empty());
    assert!(outbox
        .replay("ses-1", 0)
        .expect("a fresh connect")
        .is_empty());
}

#[test]
fn replay_behind_the_retention_window_answers_the_gap() {
    let outbox = Outbox::new();
    // Past the retention window by two: the first two events drop.
    for _ in 0..(RETAIN + 2) {
        outbox.write(&message(
            "wmp.flow.progress",
            "ses-1",
            serde_json::json!({}),
        ));
    }
    // The window holds events 3..=(RETAIN+2). A client at 1 is behind it.
    assert!(matches!(outbox.replay("ses-1", 1), Err(ReplayGap)));
    // A fresh connect at 0 replays nothing.
    assert!(outbox
        .replay("ses-1", 0)
        .expect("a fresh connect")
        .is_empty());
    // A client at 2 replays from the window's oldest (3) on.
    let inside = outbox
        .replay("ses-1", 2)
        .expect("the client inside the window replays");
    assert_eq!(inside.len(), RETAIN);
    assert_eq!(
        inside.first().map(|event| event.id),
        Some(3),
        "the replay starts after the last id"
    );
    // No log: a client past 0 is behind a log that never existed.
    assert!(matches!(outbox.replay("never-created", 5), Err(ReplayGap)));
}

#[test]
fn the_replayer_counts_the_missed_events() {
    let outbox = Outbox::new();
    for _ in 0..4 {
        outbox.write(&message(
            "wmp.flow.progress",
            "ses-1",
            serde_json::json!({}),
        ));
    }
    let replayer = OutboxReplayer {
        outbox: Arc::new(outbox),
    };
    assert_eq!(MessageReplayer::missed_since(&replayer, "ses-1", "2"), 2);
    assert_eq!(MessageReplayer::missed_since(&replayer, "ses-1", "4"), 0);
    // An unparsable id counts as none missed.
    assert_eq!(MessageReplayer::missed_since(&replayer, "ses-1", "junk"), 0);
}

#[test]
fn the_transport_writes_and_never_reads() {
    let outbox = Arc::new(Outbox::new());
    let transport = OutboxTransport::new(outbox.clone());
    // A message outside any session logs under the empty key.
    let mut receiver = outbox.subscribe("");
    assert!(transport.write_message(b"{\"x\":1}").is_ok());
    let event = receiver.try_recv().expect("the write logs one event");
    assert_eq!(event.id, 1);
    assert_eq!(
        receiver.try_recv().map(|event| event.id),
        Err(TryRecvError::Empty)
    );
    // The POST route is the inbound path.
    assert_eq!(transport.read_message(), Err(TransportError::Closed));
}

#[tokio::test]
async fn the_live_broadcast_carries_the_write() {
    let outbox = Outbox::new();
    let mut receiver = outbox.subscribe("ses-1");
    outbox.write(&message(
        "wmp.flow.progress",
        "ses-1",
        serde_json::json!({}),
    ));
    let event = tokio::time::timeout(std::time::Duration::from_secs(5), receiver.recv())
        .await
        .expect("the event arrives in time")
        .expect("the channel is live");
    assert_eq!(event.id, 1);
}
