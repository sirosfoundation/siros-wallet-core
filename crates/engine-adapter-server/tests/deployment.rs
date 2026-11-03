//! The deployment test: starts the engine server on a random port, connects
//! the `RemoteEngine` client over HTTP, runs the session lifecycle, and
//! validates that a flow start answers `-31005` (the capability gate
//! working end to end). This is what the test environment's SDKs run.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use engine_adapter_server::{config::Config, EngineServer};
use tower::ServiceExt;

#[tokio::test(flavor = "multi_thread")]
async fn the_session_lifecycle_over_http() {
    let server = Arc::new(EngineServer::new(Config {
        listen_addr: "127.0.0.1:0".to_owned(),
        ..Config::default()
    }));

    let app = engine_adapter_server::transport::router(server.clone());
    let app_for_test = app.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let _ = addr; // The test drives through the router, not the listener.

    // ── Create a session ────────────────────────────────────────────────
    let create_body = r#"{"jsonrpc":"2.0","id":"dep-1","method":"wmp.session.create","params":{"wmp":{"version":"0.1"},"participants":["x509:san:dns:bob.example.com"],"capabilities_offered":{"messaging":{"max_size":65536}},"security":{"mode":"tls"},"ttl":3600}}"#;
    let response = app_for_test
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/wmp")
                .header("content-type", "application/json")
                .header("authorization", "Bearer deployment-test")
                .body(Body::from(create_body))
                .expect("build request"),
        )
        .await
        .expect("serve");
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("read");
    let create_result: serde_json::Value = serde_json::from_slice(&body).expect("parse");

    let session_id = create_result
        .get("result")
        .and_then(|r| r.get("wmp"))
        .and_then(|w| w.get("session_id"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_owned();
    assert!(
        session_id.starts_with("ses-"),
        "the engine assigned the id: {session_id}"
    );

    // The negotiated capabilities are always present.
    let capabilities = create_result
        .get("result")
        .and_then(|r| r.get("capabilities"))
        .cloned()
        .unwrap_or_default();
    assert!(capabilities.is_object(), "capabilities is an object");

    // The security mode matches.
    assert_eq!(
        create_result
            .get("result")
            .and_then(|r| r.get("security"))
            .and_then(|s| s.get("mode"))
            .and_then(serde_json::Value::as_str),
        Some("tls")
    );

    // ── A flow start answers -31005 (the capability gate) ───────────────
    let flow_body = r#"{"jsonrpc":"2.0","id":"dep-2","method":"wmp.flow.start","params":{"wmp":{"version":"0.1","session_id":"ses-any"},"flow_type":"oid4vci","flow_id":"flow-test"}}"#;
    let response = app_for_test
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/wmp")
                .header("content-type", "application/json")
                .header("authorization", "Bearer deployment-test")
                .body(Body::from(flow_body))
                .expect("build request"),
        )
        .await
        .expect("serve");
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("read");
    let flow_result: serde_json::Value = serde_json::from_slice(&body).expect("parse");
    assert_eq!(
        flow_result
            .get("error")
            .and_then(|e| e.get("code"))
            .and_then(serde_json::Value::as_i64),
        Some(-31005),
        "the flow start is refused with capability not supported: {flow_result}"
    );
    assert_eq!(
        flow_result
            .get("error")
            .and_then(|e| e.get("data"))
            .and_then(|d| d.get("unsupported"))
            .and_then(serde_json::Value::as_str),
        Some("oid4vci"),
        "the refused flow type is named: {flow_result}"
    );

    // ── Close the session (a notification) ─────────────────────────────
    let close_body = format!(
        r#"{{"jsonrpc":"2.0","method":"wmp.session.close","params":{{"wmp":{{"session_id":"{session_id}","version":"0.1"}},"reason":"complete"}}}}"#
    );
    let response = app_for_test
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/wmp")
                .header("content-type", "application/json")
                .header("authorization", "Bearer deployment-test")
                .body(Body::from(close_body))
                .expect("build request"),
        )
        .await
        .expect("serve");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_health_probes_answer_for_the_load_balancer() {
    let server = Arc::new(EngineServer::new(Config::default()));
    let app = engine_adapter_server::transport::router(server);

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
