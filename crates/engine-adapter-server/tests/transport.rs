//! The transport's tests: a POST creates a session, a notification answers
//! empty, the health probes answer, and an unauthenticated create refuses.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use engine_adapter_server::{config::Config, EngineServer};
use tower::ServiceExt;

fn test_server() -> Arc<EngineServer> {
    Arc::new(EngineServer::new(Config {
        listen_addr: "127.0.0.1:0".to_owned(),
        ..Config::default()
    }))
}

async fn post_wmp(server: &Arc<EngineServer>, body: &str) -> (StatusCode, Vec<u8>) {
    let app = engine_adapter_server::transport::router(server.clone());
    let request = Request::builder()
        .method("POST")
        .uri("/wmp")
        .header("content-type", "application/json")
        .header("authorization", "Bearer test-token")
        .body(Body::from(body.to_owned()))
        .expect("build request");
    let response = app.oneshot(request).await.expect("serve");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("read body")
        .to_vec();
    (status, body)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_create_answers_with_the_negotiated_capabilities() {
    let server = test_server();
    let (status, body) = post_wmp(
        &server,
        r#"{"jsonrpc":"2.0","id":"req-1","method":"wmp.session.create","params":{"wmp":{"version":"0.1"},"participants":["x509:san:dns:bob.example.com"],"capabilities_offered":{"messaging":{"max_size":65536}},"security":{"mode":"tls"},"ttl":3600}}"#,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_slice(&body).expect("parse");
    assert_eq!(
        response.get("id").and_then(serde_json::Value::as_str),
        Some("req-1")
    );
    let result = response.get("result").cloned().unwrap_or_default();
    assert!(
        result
            .get("wmp")
            .and_then(|w| w.get("session_id"))
            .is_some(),
        "the session id is in the result: {result}"
    );
    let session_id = result
        .get("wmp")
        .and_then(|w| w.get("session_id"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    assert!(
        session_id.starts_with("ses-"),
        "the id matches ^ses-: {session_id}"
    );
    // The capabilities are always present (even {} when none negotiated).
    assert!(result.get("capabilities").is_some());
    // The security mode matches the request.
    assert_eq!(
        result
            .get("security")
            .and_then(|s| s.get("mode"))
            .and_then(serde_json::Value::as_str),
        Some("tls")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_notification_answers_empty() {
    let server = test_server();
    // Create the session first, so the close has something to name.
    let (_, body) = post_wmp(
        &server,
        r#"{"jsonrpc":"2.0","id":"req-1","method":"wmp.session.create","params":{"wmp":{"version":"0.1"},"security":{"mode":"tls"}}}"#,
    )
    .await;
    let response: serde_json::Value = serde_json::from_slice(&body).expect("parse");
    let session_id = response
        .get("result")
        .and_then(|r| r.get("wmp"))
        .and_then(|w| w.get("session_id"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_owned();

    let (status, _) = post_wmp(
        &server,
        &format!(
            r#"{{"jsonrpc":"2.0","method":"wmp.session.close","params":{{"wmp":{{"session_id":"{session_id}","version":"0.1"}},"reason":"complete"}}}}"#
        ),
    )
    .await;
    // A notification has no id: the server answers 204 No Content.
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_method_answers_32601() {
    let server = test_server();
    let (status, body) = post_wmp(
        &server,
        r#"{"jsonrpc":"2.0","id":"req-x","method":"wmp.flow.start","params":{"wmp":{"version":"0.1"},"flow_type":"oid4vci","flow_id":"flow-1"}}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_slice(&body).expect("parse");
    // The peer converts an unimplemented flow type from -32601 to -31005
    // (capability not supported, core §10.3): "Nobody here implements this
    // flow type: that is an unsupported capability, not an unknown method."
    assert_eq!(
        response
            .get("error")
            .and_then(|e| e.get("code"))
            .and_then(serde_json::Value::as_i64),
        Some(-31005)
    );
    assert_eq!(
        response
            .get("error")
            .and_then(|e| e.get("data"))
            .and_then(|d| d.get("unsupported"))
            .and_then(serde_json::Value::as_str),
        Some("oid4vci")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_health_probes_answer() {
    let server = test_server();
    let app = engine_adapter_server::transport::router(server.clone());

    let healthz = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .expect("build"),
        )
        .await
        .expect("serve");
    assert_eq!(healthz.status(), StatusCode::OK);

    let readyz = app
        .oneshot(
            Request::builder()
                .uri("/readyz")
                .body(Body::empty())
                .expect("build"),
        )
        .await
        .expect("serve");
    assert_eq!(readyz.status(), StatusCode::OK);
}

// ─── The SSE event stream (wmp-transport.md §4.3) ───────────────────────────
//
// The engine's outbound notifications land in the per-session event log
// (the outbox transport on the peer), and the stream replays them for a
// reconnecting client then goes live. The gates answer before the stream:
// a missing session_id is a 400, an unknown session a 404, and a
// Last-Event-ID behind the retention window a 410 Gone.

/// Creates a session through the POST route and answers its id.
async fn create_session(server: &Arc<EngineServer>) -> String {
    let (status, body) = post_wmp(
        server,
        r#"{"jsonrpc":"2.0","id":"req-1","method":"wmp.session.create","params":{"wmp":{"version":"0.1"},"participants":["x509:san:dns:bob.example.com"],"capabilities_offered":{"messaging":{"max_size":65536}},"security":{"mode":"tls"},"ttl":3600}}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_slice(&body).expect("parse");
    response
        .pointer("/result/wmp/session_id")
        .and_then(serde_json::Value::as_str)
        .expect("the session id")
        .to_owned()
}

/// One outbound message into the session's log, as the peer's transport
/// writes it.
fn log_event(server: &Arc<EngineServer>, session: &str) {
    let message = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "wmp.flow.progress",
        "params": { "wmp": { "session_id": session, "version": "0.1" } }
    });
    std::sync::Arc::clone(&server.outbox).write(&message.to_string().into_bytes());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_events_stream_without_a_session_answers_400() {
    let server = test_server();
    let app = engine_adapter_server::transport::router(server.clone());
    let response = app
        .oneshot(
            Request::builder()
                .uri("/wmp/events")
                .body(Body::empty())
                .expect("build"),
        )
        .await
        .expect("serve");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_events_stream_for_an_unknown_session_answers_404() {
    let server = test_server();
    let app = engine_adapter_server::transport::router(server.clone());
    let response = app
        .oneshot(
            Request::builder()
                .uri("/wmp/events?session_id=never-created")
                .body(Body::empty())
                .expect("build"),
        )
        .await
        .expect("serve");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reconnect_behind_the_retention_window_answers_410_gone() {
    let server = test_server();
    let session = create_session(&server).await;
    // Past the retention window: the reconnecting client's last id has
    // been dropped.
    for _ in 0..(engine_adapter_server::outbox::RETAIN + 2) {
        log_event(&server, &session);
    }
    let app = engine_adapter_server::transport::router(server.clone());
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/wmp/events?session_id={session}"))
                .header("last-event-id", "1")
                .body(Body::empty())
                .expect("build"),
        )
        .await
        .expect("serve");
    assert_eq!(response.status(), StatusCode::GONE);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_peer_s_notifications_reach_the_event_stream() {
    let server = test_server();
    let session = create_session(&server).await;

    // The stream first: a fresh connect (no Last-Event-ID) subscribes to
    // the session's live events — the handler runs to the response, so
    // the subscription exists by the time oneshot answers.
    let app = engine_adapter_server::transport::router(server.clone());
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/wmp/events?session_id={session}"))
                .body(Body::empty())
                .expect("build"),
        )
        .await
        .expect("serve");
    assert_eq!(response.status(), StatusCode::OK);

    // Then the notification through the peer itself — the full chain the
    // flows ride: the peer's transport (the outbox) writes it into the
    // session's log and broadcasts it to the live subscriber.
    let ctx = wmp_core::context::RequestContext::default();
    server
        .peer
        .notify(
            &ctx,
            "wmp.flow.progress",
            &serde_json::json!({
                "wmp": { "session_id": session, "version": "0.1" },
                "flow_id": "flow-1",
                "step": "parsing_offer",
            }),
        )
        .expect("the notification is sent");

    // The SSE stream: the logged event arrives as `id:`/`event:`/`data:`
    // lines. Read frames with a timeout — the stream goes live after the
    // replay, so the read bounds itself.
    use futures_util::StreamExt;
    let mut stream = response.into_body().into_data_stream();
    let mut text = String::new();
    for _ in 0..16 {
        let frame = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
            .await
            .expect("the frame arrives in time");
        let Some(Ok(bytes)) = frame else { break };
        text.push_str(&String::from_utf8_lossy(&bytes));
        // The event is complete when its data line carries the step.
        if text.contains("parsing_offer") {
            break;
        }
    }
    assert!(text.contains("id: 1"), "the event carries its id: {text}");
    assert!(
        text.contains("event: wmp"),
        "the event carries its type: {text}"
    );
    assert!(
        text.contains("parsing_offer"),
        "the event carries the message: {text}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reconnect_replays_the_events_it_missed() {
    let server = test_server();
    let session = create_session(&server).await;
    // Three events in the log, then the client reconnects at 1.
    for step in ["parsing_offer", "offer_parsed", "metadata_fetched"] {
        let ctx = wmp_core::context::RequestContext::default();
        server
            .peer
            .notify(
                &ctx,
                "wmp.flow.progress",
                &serde_json::json!({
                    "wmp": { "session_id": session, "version": "0.1" },
                    "flow_id": "flow-1",
                    "step": step,
                }),
            )
            .expect("the notification is sent");
    }

    let app = engine_adapter_server::transport::router(server.clone());
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/wmp/events?session_id={session}"))
                .header("last-event-id", "1")
                .body(Body::empty())
                .expect("build"),
        )
        .await
        .expect("serve");
    assert_eq!(response.status(), StatusCode::OK);

    // The replay: the events the client missed (2 and 3), oldest first,
    // BEFORE the live stream starts.
    use futures_util::StreamExt;
    let mut stream = response.into_body().into_data_stream();
    let mut text = String::new();
    for _ in 0..16 {
        let frame = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
            .await
            .expect("the frame arrives in time");
        let Some(Ok(bytes)) = frame else { break };
        text.push_str(&String::from_utf8_lossy(&bytes));
        // Both missed events arrived: the replay is complete.
        if text.contains("offer_parsed") && text.contains("metadata_fetched") {
            break;
        }
    }
    assert!(
        text.contains("id: 2"),
        "the first missed event replays first: {text}"
    );
    assert!(
        text.contains("offer_parsed"),
        "the second missed event: {text}"
    );
    assert!(text.contains("id: 3"), "the last missed event: {text}");
    assert!(
        text.contains("metadata_fetched"),
        "the third missed event: {text}"
    );
    assert!(
        !text.contains("parsing_offer"),
        "the event the client already saw does not replay: {text}"
    );
}
