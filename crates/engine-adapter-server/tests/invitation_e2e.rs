//! Issue #77 end to end: the invitation flow (create → consume → session)
//! and the message passing between the two wallets (deliver both ways,
//! poll, ack) — the interop tests' prerequisites, rehearsed.
//!
//! The two clients are both unauthenticated `post_wmp` callers (the
//! engine's token validation accepts a plain bearer in the test config —
//! the same shape the e2e suite drives); the invitation's `sender` is
//! whatever the create's principal keys (the token's subject or the
//! fallback).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use engine_adapter_server::config::Config;
use engine_adapter_server::transport::router;
use futures_util::StreamExt;
use tower::ServiceExt;

async fn post_wmp(app: &axum::Router, body: String) -> (StatusCode, serde_json::Value) {
    let request = Request::builder()
        .method("POST")
        .uri("/wmp")
        .header("content-type", "application/json")
        .header("authorization", "Bearer e2e-test")
        .body(Body::from(body))
        .expect("build request");
    let response = app.clone().oneshot(request).await.expect("serve");
    let status = response.status();
    if status == StatusCode::NO_CONTENT {
        return (status, serde_json::Value::Null);
    }
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("read");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

/// The next `data:` JSON message off the SSE stream.
async fn next_message(
    stream: &mut axum::body::BodyDataStream,
    text: &mut String,
) -> Option<serde_json::Value> {
    loop {
        if let Some(at) = text.find("data: ") {
            let after = at + 6;
            if let Some(newline) = text[after..].find('\n') {
                let line_end = after + newline;
                let line = text[after..line_end].to_owned();
                text.drain(..line_end + 1);
                if line.starts_with('{') {
                    if let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) {
                        return Some(value);
                    }
                }
                continue;
            }
        }
        let frame = tokio::time::timeout(std::time::Duration::from_secs(10), stream.next())
            .await
            .expect("the stream stays live")?;
        let Ok(bytes) = frame else {
            return None;
        };
        text.push_str(&String::from_utf8_lossy(&bytes));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_invitation_flow_and_message_passing_end_to_end() {
    // ── The engine, with the invitation endpoint configured ───────────
    let server = Arc::new(engine_adapter_server::EngineServer::new(Config {
        listen_addr: "127.0.0.1:0".to_owned(),
        allow_plaintext: true,
        public_url: "https://wallet.example.com".to_owned(),
        ..Config::default()
    }));
    let app = router(server.clone());

    // ── Part 1: wallet A creates an invitation ────────────────────────
    let (status, created) = {
        let request = Request::builder()
            .method("POST")
            .uri("/wmp/invitation")
            .header("content-type", "application/json")
            .header("authorization", "Bearer e2e-inviter")
            .body(Body::from(
                serde_json::json!({ "ttl_secs": 60 }).to_string(),
            ))
            .expect("build");
        let response = app.clone().oneshot(request).await.expect("serve");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("read");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    };
    assert_eq!(status, StatusCode::OK, "the invitation create: {created}");
    assert!(
        created["invitation"]["nonce"].is_string(),
        "the invitation carries a nonce"
    );
    assert!(
        created["uri"]
            .as_str()
            .unwrap_or_default()
            .starts_with("wmp://invite?data="),
        "the URI is the wmp invite form: {created}"
    );
    assert!(
        created["invitation"]["signature"]
            .as_str()
            .unwrap_or_default()
            .len()
            > 40,
        "the signature is a full JWS compact: {created}"
    );

    // The nonce, for the consume.
    let nonce = created["invitation"]["nonce"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert!(!nonce.is_empty());

    // ── Part 2: wallet B consumes it (the session bootstrap) ───────────
    let (status, session_b) = post_wmp(
        &app,
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": "req-b",
            "method": "wmp.session.create",
            "params": {
                "wmp": { "version": "0.1" },
                "invitation_nonce": nonce,
                "security": { "mode": "tls" }
            }
        })
        .to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the consume: {session_b}");
    assert!(
        session_b.get("error").is_none(),
        "the session bootstraps off the invitation: {session_b}"
    );
    let session_b_id = session_b
        .pointer("/result/wmp/session_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_owned();
    assert!(!session_b_id.is_empty(), "the session id: {session_b}");

    // The single-use: a second consume of the same nonce refuses.
    let (status, refused) = post_wmp(
        &app,
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": "req-b2",
            "method": "wmp.session.create",
            "params": {
                "wmp": { "version": "0.1" },
                "invitation_nonce": nonce,
                "security": { "mode": "tls" }
            }
        })
        .to_string(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the second consume answers: {refused}"
    );
    assert!(
        refused.pointer("/error/code").is_some(),
        "the single-use nonce refuses the second consume: {refused}"
    );

    // ── Part 3: B's SSE stream, before the message ────────────────────
    let sse_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/wmp/events?session_id={session_b_id}"))
                .body(Body::empty())
                .expect("build"),
        )
        .await
        .expect("serve");
    assert_eq!(sse_response.status(), StatusCode::OK);
    let mut stream_b = sse_response.into_body().into_data_stream();
    let mut text_b = String::new();

    // ── Part 4: A (its own session) sends B a message ─────────────────
    let (status, session_a) = post_wmp(
        &app,
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": "req-a",
            "method": "wmp.session.create",
            "params": {
                "wmp": { "version": "0.1" },
                "security": { "mode": "tls" }
            }
        })
        .to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let session_a_id = session_a
        .pointer("/result/wmp/session_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_owned();
    assert!(!session_a_id.is_empty());

    // A's deliver to B: a notification (204), the mailbox + the outbox.
    let (deliver_status, _) = post_wmp(
        &app,
        serde_json::json!({
            "jsonrpc": "2.0",
            "method": "wmp.message.deliver",
            "params": {
                "wmp": { "version": "0.1", "session_id": session_a_id },
                "to": [session_b_id],
                "content_type": "text/plain",
                "body": { "text": "hello from A" }
            }
        })
        .to_string(),
    )
    .await;
    assert_eq!(
        deliver_status,
        StatusCode::NO_CONTENT,
        "the deliver notification"
    );

    // B's SSE stream carries the delivery live (within the next frames).
    let mut delivered = None;
    for _ in 0..16 {
        let Some(message) = next_message(&mut stream_b, &mut text_b).await else {
            break;
        };
        if message.get("method").and_then(serde_json::Value::as_str) == Some("wmp.message.deliver")
        {
            delivered = Some(message);
            break;
        }
    }
    let delivered = delivered.expect("B's stream carried the delivery live");
    assert!(
        delivered
            .pointer("/params/to/0")
            .and_then(serde_json::Value::as_str)
            == Some(session_b_id.as_str()),
        "the delivery names B: {delivered}"
    );

    // ── Part 5: B polls (the pull path) and acks ──────────────────────
    let (status, polled) = post_wmp(
        &app,
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": "req-poll",
            "method": "wmp.message.poll",
            "params": {
                "wmp": { "version": "0.1", "session_id": session_b_id }
            }
        })
        .to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the poll: {polled}");
    assert!(
        polled
            .pointer("/result/messages")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|messages| !messages.is_empty()),
        "the poll answers B's mailbox: {polled}"
    );

    // B's ack (the status surface).
    let message_id = delivered
        .pointer("/params/message_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let (ack_status, _) = post_wmp(
        &app,
        serde_json::json!({
            "jsonrpc": "2.0",
            "method": "wmp.message.ack",
            "params": {
                "wmp": { "version": "0.1", "session_id": session_b_id },
                "message_ids": [message_id],
                "status": "received"
            }
        })
        .to_string(),
    )
    .await;
    assert_eq!(ack_status, StatusCode::NO_CONTENT, "the ack notification");

    // ── Part 6: B replies to A (the both-way proof) ─────────────────────
    // A's SSE stream, then B's deliver to A.
    let sse_a = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/wmp/events?session_id={session_a_id}"))
                .body(Body::empty())
                .expect("build"),
        )
        .await
        .expect("serve");
    let mut stream_a = sse_a.into_body().into_data_stream();
    let mut text_a = String::new();
    // Drain the replay (A's stream connects after the first deliver; the
    // outbox's replay window carries it).
    let (reply_status, _) = post_wmp(
        &app,
        serde_json::json!({
            "jsonrpc": "2.0",
            "method": "wmp.message.deliver",
            "params": {
                "wmp": { "version": "0.1", "session_id": session_b_id },
                "to": [session_a_id],
                "content_type": "text/plain",
                "body": { "text": "hello from B" }
            }
        })
        .to_string(),
    )
    .await;
    assert_eq!(reply_status, StatusCode::NO_CONTENT, "the reply deliver");
    let mut replied = None;
    for _ in 0..16 {
        let Some(message) = next_message(&mut stream_a, &mut text_a).await else {
            break;
        };
        if message.get("method").and_then(serde_json::Value::as_str) == Some("wmp.message.deliver")
        {
            replied = Some(message);
            break;
        }
    }
    let replied = replied.expect("A's stream carried the reply live");
    assert!(
        replied
            .pointer("/params/to/0")
            .and_then(serde_json::Value::as_str)
            == Some(session_a_id.as_str()),
        "the reply names A: {replied}"
    );
}
