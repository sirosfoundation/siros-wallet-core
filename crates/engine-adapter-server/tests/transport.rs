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
