//! The shared-outbox contract (issue #65): the same invariants the memory
//! log's own tests pin, run THROUGH the [`SharedOutbox`] trait against
//! every backend the deployment can pick — the in-memory default always,
//! the Valkey backend when `VALKEY_URL` names a live store.
//!
//! The trait's `write` takes the session and the **already-redacted**
//! bytes (the redaction stays the transport's job; a shared store never
//! sees the withheld members), so these tests feed it plain messages.

use engine_adapter_server::shared_outbox::SharedOutbox;

/// The backends under test: the memory log always; Valkey when its URL is
/// set (the conformance pattern of external-store suites on demand).
fn backends() -> Vec<(&'static str, std::sync::Arc<dyn SharedOutbox>)> {
    let memory: std::sync::Arc<dyn SharedOutbox> =
        std::sync::Arc::new(engine_adapter_server::outbox::Outbox::new());
    let mut out = vec![("memory", memory)];
    if let Ok(url) = std::env::var("VALKEY_URL") {
        match engine_adapter_server::valkey_outbox::ValkeyOutbox::new(&url) {
            Ok(outbox) => {
                let shared: std::sync::Arc<dyn SharedOutbox> = std::sync::Arc::new(outbox);
                out.push(("valkey", shared));
            }
            Err(err) => panic!("VALKEY_URL is set but the store answers: {err}"),
        }
    }
    out
}

fn write(backend: &dyn SharedOutbox, session: &str, method: &str) -> u64 {
    let message = serde_json::json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": {
            "wmp": { "session_id": session, "version": "0.1" },
            "result": {},
        }
    });
    backend.write(session, message.to_string().as_bytes()).id
}

#[test]
fn the_ids_are_per_session_and_start_at_one() {
    for (name, outbox) in backends() {
        assert_eq!(write(outbox.as_ref(), "ses-1", "wmp.flow.progress"), 1);
        assert_eq!(write(outbox.as_ref(), "ses-1", "wmp.flow.progress"), 2);
        assert_eq!(
            write(outbox.as_ref(), "ses-2", "wmp.flow.progress"),
            1,
            "{name}: each session has its own sequence"
        );
    }
}

#[test]
fn a_fresh_stream_replays_the_whole_window() {
    for (name, outbox) in backends() {
        write(outbox.as_ref(), "ses-fresh", "wmp.flow.progress");
        write(outbox.as_ref(), "ses-fresh", "wmp.flow.progress");
        // No Last-Event-ID (last_id 0): the whole retained window replays
        // (issue #72's rule — the black-holed first stream).
        let replayed = outbox
            .replay("ses-fresh", 0)
            .unwrap_or_else(|_| panic!("{name}: a fresh stream replays"));
        assert_eq!(replayed.len(), 2, "{name}: the whole window");
        // Oldest first.
        assert!(replayed[0].id < replayed[1].id, "{name}: oldest first");
    }
}

#[test]
fn a_reconnect_replays_only_its_gap() {
    for (name, outbox) in backends() {
        write(outbox.as_ref(), "ses-gap", "wmp.flow.progress"); // 1
        write(outbox.as_ref(), "ses-gap", "wmp.flow.progress"); // 2
        write(outbox.as_ref(), "ses-gap", "wmp.flow.progress"); // 3
        let replayed = outbox
            .replay("ses-gap", 2)
            .unwrap_or_else(|_| panic!("{name}: the gap replays"));
        assert_eq!(replayed.len(), 1, "{name}: only the missed event");
        assert_eq!(replayed[0].id, 3, "{name}: the event after last_id");
    }
}

#[test]
fn a_missing_log_answers_the_gap_for_a_past_client_and_empty_for_a_fresh_one() {
    for (name, outbox) in backends() {
        assert!(
            outbox.replay("never-written", 0).is_ok(),
            "{name}: a fresh client on an unwritten session misses nothing"
        );
        assert!(
            outbox.replay("never-written", 4).is_err(),
            "{name}: a past client on an unwritten session is behind a log that never existed"
        );
    }
}

#[test]
fn the_missed_count_counts_the_gap() {
    for (name, outbox) in backends() {
        write(outbox.as_ref(), "ses-count", "wmp.flow.progress");
        write(outbox.as_ref(), "ses-count", "wmp.flow.progress");
        assert_eq!(
            outbox.missed_since("ses-count", "1"),
            1,
            "{name}: one missed"
        );
        assert_eq!(
            outbox.missed_since("ses-count", "2"),
            0,
            "{name}: none missed"
        );
        // An unparseable id counts nothing (the parse refuses, the answer 0).
        assert_eq!(
            outbox.missed_since("ses-count", "0-beyond"),
            0,
            "{name}: an unparseable id counts nothing"
        );
    }
}
