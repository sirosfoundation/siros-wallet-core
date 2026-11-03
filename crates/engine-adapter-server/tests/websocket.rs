//! The WebSocket transport's tests: a session create over the WebSocket
//! binding answers with the negotiated capabilities, a notification
//! produces no reply frame, and the HTTPS probes still answer alongside.

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

/// A full WebSocket round trip: start the server on a random port, connect
/// with a raw TCP stream doing the upgrade, send messages, read replies.
async fn ws_round_trip(server: Arc<EngineServer>, messages: Vec<&str>) -> Vec<Option<String>> {
    let app = engine_adapter_server::transport::router(server);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    // Do the WebSocket upgrade over a raw TCP stream, with the bearer
    // token the §3.4 HTTP-level authentication allows. Build the upgrade
    // request from the URL (which fills the WebSocket handshake headers),
    // then add the auth headers.
    let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let mut request = format!("ws://{addr}/wmp")
        .into_client_request()
        .expect("build upgrade request");
    request.headers_mut().insert(
        "authorization",
        "Bearer ws-test-token".parse().expect("auth header"),
    );
    request.headers_mut().insert(
        "sec-websocket-protocol",
        "wmp.v1".parse().expect("proto header"),
    );
    let (mut ws, _response) = tokio_tungstenite::client_async(request, stream)
        .await
        .expect("upgrade");

    let mut replies = Vec::new();
    for message in messages {
        use futures_util::SinkExt;
        ws.send(tokio_tungstenite::tungstenite::Message::Text(
            message.to_owned(),
        ))
        .await
        .expect("send");

        use futures_util::StreamExt;
        match tokio::time::timeout(std::time::Duration::from_secs(5), ws.next()).await {
            Ok(Some(Ok(tokio_tungstenite::tungstenite::Message::Text(reply)))) => {
                replies.push(Some(reply.to_string()));
            }
            _ => replies.push(None),
        }
    }

    replies
}

#[tokio::test]
async fn a_session_create_over_websocket_answers_with_capabilities() {
    let server = test_server();
    let replies = ws_round_trip(
        server,
        vec![r#"{"jsonrpc":"2.0","id":"ws-1","method":"wmp.session.create","params":{"wmp":{"version":"0.1"},"security":{"mode":"tls"}}}"#],
    )
    .await;

    assert_eq!(replies.len(), 1);
    let reply = replies[0].as_deref().expect("a reply frame");
    let response: serde_json::Value = serde_json::from_str(reply).expect("parse");
    assert_eq!(
        response.get("id").and_then(serde_json::Value::as_str),
        Some("ws-1")
    );
    let result = response.get("result").cloned().unwrap_or_default();
    assert!(
        result
            .get("wmp")
            .and_then(|w| w.get("session_id"))
            .is_some(),
        "session_id in the result: {result}"
    );
    assert!(result.get("capabilities").is_some());
    assert!(result.get("security").is_some());
}

#[tokio::test]
async fn a_notification_over_websocket_answers_no_frame() {
    let server = test_server();
    // Create a session first so the close has something to name, then send
    // a notification (no id) — which never produces a reply frame.
    let replies = ws_round_trip(
        server,
        vec![
            r#"{"jsonrpc":"2.0","id":"ws-1","method":"wmp.session.create","params":{"wmp":{"version":"0.1"},"security":{"mode":"tls"}}}"#,
            r#"{"jsonrpc":"2.0","method":"wmp.session.close","params":{"wmp":{"session_id":"ses-any","version":"0.1"},"reason":"complete"}}"#,
        ],
    )
    .await;

    // The create answered a frame.
    assert!(replies[0].is_some(), "the create answered a frame");
    // The close is a notification: no reply frame arrives within 5 s.
    assert!(
        replies[1].is_none(),
        "the notification produced no frame: got {:?}",
        replies[1]
    );
}

#[tokio::test]
async fn the_https_probes_still_answer_alongside_websocket() {
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
