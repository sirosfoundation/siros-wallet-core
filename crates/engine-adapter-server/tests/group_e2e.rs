//! Issue #77's group half, end to end: the `join` invitation → the group
//! session → in-group message passing. The acceptance test's engine
//! rehearsal (the MCP endpoint joins a wallet's group via the invitation,
//! then the group's messages reach it).
//!
//! 1. Wallet A creates its session (the group).
//! 2. A mints a `join` invitation naming it (`POST /wmp/invitation` with
//!    `purpose: "join"`).
//! 3. The MCP endpoint consumes the invitation (a session create carrying
//!    the `invitation_nonce`) — its session joins the group.
//! 4. A delivers a message `to` the group — the fan-out lands it in the
//!    member's mailbox (and its SSE stream).
//! 5. The member polls its own box: the group's message is there.
//!
//! And the refusals: a `join` naming no session, one naming an unknown
//! session, an unknown purpose — each `-32602` at the mint, never a silent
//! session invitation.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use engine_adapter_server::config::Config;
use engine_adapter_server::transport::router;
use futures_util::StreamExt;
use tower::ServiceExt;

/// `POST /wmp` (a JSON-RPC call or a notification), answering the status
/// and the parsed body.
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

/// `POST /wmp/invitation` with a JSON body, answering the status and the
/// parsed answer.
async fn post_invitation(
    app: &axum::Router,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let request = Request::builder()
        .method("POST")
        .uri("/wmp/invitation")
        .header("content-type", "application/json")
        .header("authorization", "Bearer e2e-inviter")
        .body(Body::from(body.to_string()))
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
}

/// A `wmp.session.create` answering the created session id (empty on a
/// refusal — the assertions name the shape).
async fn create_session(app: &axum::Router, id: &str) -> (StatusCode, String, serde_json::Value) {
    let (status, answer) = post_wmp(
        app,
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "wmp.session.create",
            "params": {
                "wmp": { "version": "0.1" },
                "security": { "mode": "tls" }
            }
        })
        .to_string(),
    )
    .await;
    let session_id = answer
        .pointer("/result/wmp/session_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_owned();
    (status, session_id, answer)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_join_invitation_group_and_in_group_delivery_end_to_end() {
    let server = Arc::new(engine_adapter_server::EngineServer::new(Config {
        listen_addr: "127.0.0.1:0".to_owned(),
        allow_plaintext: true,
        public_url: "https://wallet.example.com".to_owned(),
        ..Config::default()
    }));
    let app = router(server.clone());

    // ── The group: A's session ────────────────────────────────────────
    let (status, session_a_id, _) = create_session(&app, "req-a").await;
    assert_eq!(status, StatusCode::OK);
    assert!(!session_a_id.is_empty(), "A's session");

    // ── The join invitation naming it ─────────────────────────────────
    let (status, created) = post_invitation(
        &app,
        serde_json::json!({ "purpose": "join", "session_id": session_a_id }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the join invitation create: {created}"
    );
    assert_eq!(
        created["invitation"]["purpose"].as_str(),
        Some("join"),
        "the invitation carries the join purpose: {created}"
    );
    assert_eq!(
        created["invitation"]["session_id"].as_str(),
        Some(session_a_id.as_str()),
        "the invitation names the group session: {created}"
    );
    let nonce = created["invitation"]["nonce"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert!(!nonce.is_empty(), "the nonce");

    // ── The MCP endpoint consumes it — its session joins the group ────
    let (status, session_m) = {
        let (status, answer) = post_wmp(
            &app,
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": "req-m",
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
        assert_eq!(status, StatusCode::OK, "the join consume: {answer}");
        assert!(
            answer.get("error").is_none(),
            "the session bootstraps off the join invitation: {answer}"
        );
        let session_id = answer
            .pointer("/result/wmp/session_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned();
        assert!(!session_id.is_empty(), "the member session id: {answer}");
        (status, session_id)
    };
    let _ = status;

    // The member's SSE stream, before the group's message.
    let sse_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/wmp/events?session_id={session_m}"))
                .body(Body::empty())
                .expect("build"),
        )
        .await
        .expect("serve");
    assert_eq!(sse_response.status(), StatusCode::OK);
    let mut stream_m = sse_response.into_body().into_data_stream();
    let mut text_m = String::new();

    // ── A delivers TO THE GROUP — the member's box is a target ────────
    let (deliver_status, _) = post_wmp(
        &app,
        serde_json::json!({
            "jsonrpc": "2.0",
            "method": "wmp.message.deliver",
            "params": {
                "wmp": { "version": "0.1", "session_id": session_a_id },
                "to": [session_a_id],
                "content_type": "text/plain",
                "body": { "text": "hello, group" }
            }
        })
        .to_string(),
    )
    .await;
    assert_eq!(
        deliver_status,
        StatusCode::NO_CONTENT,
        "the group deliver notification"
    );

    // The member's stream carries the group's delivery live.
    let mut delivered = None;
    for _ in 0..16 {
        let frame = tokio::time::timeout(std::time::Duration::from_secs(10), stream_m.next())
            .await
            .expect("the stream stays live");
        let Some(Ok(bytes)) = frame else { break };
        text_m.push_str(&String::from_utf8_lossy(&bytes));
        while let Some(at) = text_m.find("data: ") {
            let after = at + 6;
            let Some(newline) = text_m[after..].find('\n') else {
                break;
            };
            let line = text_m[after..after + newline].to_owned();
            text_m.drain(..after + newline + 1);
            if line.starts_with('{') {
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) {
                    if value.get("method").and_then(serde_json::Value::as_str)
                        == Some("wmp.message.deliver")
                    {
                        delivered = Some(value);
                    }
                }
            }
        }
        if delivered.is_some() {
            break;
        }
    }
    let delivered = delivered.expect("the member's stream carried the group's delivery live");
    // The envelope the member receives is the ORIGINAL `to` (the group),
    // never the fan-out expansion.
    assert!(
        delivered
            .pointer("/params/to")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|to| to.len() == 1),
        "the delivery keeps its original addressee: {delivered}"
    );

    // ── The member polls its own box: the group's message is there ────
    let (status, polled) = post_wmp(
        &app,
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": "req-poll-m",
            "method": "wmp.message.poll",
            "params": {
                "wmp": { "version": "0.1", "session_id": session_m }
            }
        })
        .to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the member poll: {polled}");
    assert!(
        polled
            .pointer("/result/messages")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|messages| !messages.is_empty()),
        "the group's message reached the member's mailbox: {polled}"
    );

    // ── The member leaves (its close drops the membership) ───────────
    let (close_status, _) = post_wmp(
        &app,
        serde_json::json!({
            "jsonrpc": "2.0",
            "method": "wmp.session.close",
            "params": {
                "wmp": { "version": "0.1", "session_id": session_m }
            }
        })
        .to_string(),
    )
    .await;
    assert_eq!(close_status, StatusCode::NO_CONTENT, "the member close");

    // A deliver to the group AFTER the leave: the member's box gets
    // nothing new (the poll answers the same entries — the leave dropped
    // the membership, no new delivery lands).
    let (deliver_status, _) = post_wmp(
        &app,
        serde_json::json!({
            "jsonrpc": "2.0",
            "method": "wmp.message.deliver",
            "params": {
                "wmp": { "version": "0.1", "session_id": session_a_id },
                "to": [session_a_id],
                "content_type": "text/plain",
                "body": { "text": "after the leave" }
            }
        })
        .to_string(),
    )
    .await;
    assert_eq!(deliver_status, StatusCode::NO_CONTENT);
    let (_, polled_again) = post_wmp(
        &app,
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": "req-poll-m2",
            "method": "wmp.message.poll",
            "params": {
                "wmp": { "version": "0.1", "session_id": session_m },
                "since": ""
            }
        })
        .to_string(),
    )
    .await;
    let after_messages = polled_again
        .pointer("/result/messages")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    assert!(
        after_messages.len() == 1,
        "the left member's box carries only its pre-leave delivery ({} entries), never the post-leave one",
        after_messages.len()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_join_invitation_refusals() {
    let server = Arc::new(engine_adapter_server::EngineServer::new(Config {
        listen_addr: "127.0.0.1:0".to_owned(),
        allow_plaintext: true,
        public_url: "https://wallet.example.com".to_owned(),
        ..Config::default()
    }));
    let app = router(server.clone());

    // A join naming no session.
    let (status, answer) = post_invitation(&app, serde_json::json!({ "purpose": "join" })).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the unnamed group: {answer}"
    );
    assert!(
        answer["error"]["code"].as_i64().is_some(),
        "the refusal carries the code: {answer}"
    );

    // A join naming a session the store does not hold.
    let (status, answer) = post_invitation(
        &app,
        serde_json::json!({ "purpose": "join", "session_id": "session-that-never-was" }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the unknown group: {answer}"
    );

    // An unknown purpose.
    let (status, answer) =
        post_invitation(&app, serde_json::json!({ "purpose": "teleport" })).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the unknown purpose: {answer}"
    );

    // The plain create still works (the default purpose is session).
    let (status, answer) = post_invitation(&app, serde_json::json!({})).await;
    assert_eq!(status, StatusCode::OK, "the default invitation: {answer}");
    assert_eq!(
        answer["invitation"]["purpose"].as_str(),
        Some("session"),
        "the default purpose: {answer}"
    );
}
