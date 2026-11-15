//! The transport's tests: a POST creates a session, a notification answers
//! empty, the health probes answer, and an unauthenticated create refuses.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use engine_adapter_server::{config::Config, EngineServer};
use engine_core::runtime::{FlowContext, FlowHandler};
use tower::ServiceExt;
use wmp_core::handler::HandlerError;
use wmp_core::methods::*;
use wmp_core::types::Metadata;

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

// ─── The wmp.resolve vctm lookup (WMP Core 5.8) ─────────────────────────────
//
// The engine fetches the uri through its own HttpClient port (the Go
// engine's direct-URL path) and projects the document to the six members
// a vctm resolution carries (Core 5.8.1). The lookup failure answers
// -32603 with reason metadata_fetch_error, never the raw body.

/// One HTTP request answered with a fixed JSON body: the vctm document
/// server for the resolve tests.
async fn serve_once(document: &'static str) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("address");
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut buffer = [0u8; 4096];
        let _ = socket.read(&mut buffer).await;
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
            document.len(),
            document
        );
        let _ = socket.write_all(response.as_bytes()).await;
    });
    format!("http://{addr}/vct/PID")
}

async fn post_resolve(server: &Arc<EngineServer>, uri: &str) -> (StatusCode, Vec<u8>) {
    post_wmp(
        server,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": "req-resolve",
            "method": "wmp.resolve",
            "params": {
                "wmp": { "version": "0.1" },
                "type": "vctm",
                "uri": uri,
            }
        })
        .to_string(),
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_vctm_resolution_projects_the_document_s_members() {
    // The local document server: the config's allow_plaintext gates the
    // http fetch (the port's transport rules).
    let uri = serve_once(
        r#"{"vct":"https://registry.example/vct/PID","name":"PID","description":"Identity","claims":{"given_name":{"display":"Given name"}},"schema":{"type":"object"},"extra":"dropped"}"#,
    )
    .await;
    let server = Arc::new(EngineServer::new(engine_adapter_server::config::Config {
        allow_plaintext: true,
        ..engine_adapter_server::config::Config::default()
    }));

    let (status, body) = post_resolve(&server, &uri).await;
    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_slice(&body).expect("parse");
    let result = response.get("result").cloned().unwrap_or_default();
    assert_eq!(
        result.get("type").and_then(serde_json::Value::as_str),
        Some("vctm")
    );
    let metadata = result.get("metadata").cloned().unwrap_or_default();
    let object = metadata.as_object().cloned().unwrap_or_default();
    // The carried members (Core 5.8.1): vct, name, description, claims —
    // and nothing else (the schema member here, the extra member
    // dropped).
    assert!(object.contains_key("vct"));
    assert!(object.contains_key("name"));
    assert!(object.contains_key("description"));
    assert!(object.contains_key("claims"));
    assert!(
        !object.contains_key("extra"),
        "the members a vctm resolution does not carry are dropped: {metadata}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_vctm_resolution_of_an_empty_uri_answers_32602() {
    let server = test_server();
    let (status, body) = post_resolve(&server, "").await;
    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_slice(&body).expect("parse");
    assert_eq!(
        response
            .pointer("/error/code")
            .and_then(serde_json::Value::as_i64),
        Some(-32602)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_vctm_resolution_that_cannot_fetch_answers_32603_with_the_reason() {
    // A port that refuses the fetch: plaintext refused (the config's
    // default), so the http document server is unreachable through the
    // port's rules.
    let uri = serve_once("{}").await;
    let server = test_server();
    let (status, body) = post_resolve(&server, &uri).await;
    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_slice(&body).expect("parse");
    assert_eq!(
        response
            .pointer("/error/code")
            .and_then(serde_json::Value::as_i64),
        Some(-32603),
        "a refused fetch is a resolution error: {response}"
    );
    assert_eq!(
        response
            .pointer("/error/data/reason")
            .and_then(serde_json::Value::as_str),
        Some("metadata_fetch_error"),
        "the safe reason only, never the transport detail: {response}"
    );
}

// ─── The host bridge: the engine's asks as child flows (F1) ──────────────────
//
// The engine's Host port asks ride child flows: a wmp.flow.start on the
// stream, the client's wmp.flow.complete the answer — routed back through
// the same registry the dispatch uses.

/// The next message on the event stream with `method` whose flow id contains
/// `flow_id`. `seen` holds what the stream delivered so far, so a frame that
/// carries several messages loses none between calls.
async fn streamed_message(
    stream: &mut axum::body::BodyDataStream,
    seen: &mut String,
    method: &str,
    flow_id: &str,
) -> serde_json::Value {
    use futures_util::StreamExt;
    for _ in 0..32 {
        let found = seen
            .lines()
            .filter_map(|line| line.strip_prefix("data: "))
            .filter_map(|json| serde_json::from_str::<serde_json::Value>(json).ok())
            .find(|message| {
                message.get("method").and_then(|m| m.as_str()) == Some(method)
                    && message
                        .pointer("/params/flow_id")
                        .and_then(|id| id.as_str())
                        .is_some_and(|id| id.contains(flow_id))
            });
        if let Some(message) = found {
            return message;
        }
        let frame = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
            .await
            .expect("the frame arrives in time");
        let Some(Ok(bytes)) = frame else { break };
        seen.push_str(&String::from_utf8_lossy(&bytes));
    }
    panic!("no {method} for {flow_id} streamed: {seen}");
}

/// An engine flow whose start asks the Host port for a signature and
/// completes with the answer.
struct SignAskFlow;

#[async_trait::async_trait]
impl FlowHandler for SignAskFlow {
    fn flow_types(&self) -> Vec<String> {
        vec!["sign-ask".to_owned()]
    }

    async fn start_flow(
        &self,
        ctx: &FlowContext,
        params: &FlowStartParams,
    ) -> Result<FlowStartResult, HandlerError> {
        let answer = ctx
            .host()
            .request_sign(engine_ports::SignParams {
                flow_id: params.flow_id.clone(),
                to_sign: vec![1, 2, 3],
                key_id: None,
                algorithm: "ES256".to_owned(),
            })
            .await
            .expect("the client answers the ask");
        ctx.complete(&answer).await?;
        Ok(FlowStartResult {
            wmp: Metadata::default(),
            flow_id: params.flow_id.clone(),
            flow_type: params.flow_type.clone(),
        })
    }

    async fn handle_action(
        &self,
        _ctx: &FlowContext,
        _params: &FlowActionParams,
    ) -> Result<FlowActionResult, HandlerError> {
        unreachable!("the client sends this flow no action")
    }

    async fn handle_progress(&self, _ctx: &FlowContext, _params: &FlowProgressParams) {}
    async fn handle_complete(&self, _ctx: &FlowContext, _params: &FlowCompleteParams) {}
    async fn handle_error(&self, _ctx: &FlowContext, _params: &FlowErrorParams) {}
    async fn handle_cancel(
        &self,
        _ctx: &FlowContext,
        _params: &FlowCancelParams,
    ) -> Result<bool, HandlerError> {
        Ok(false)
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_ask_rides_a_child_flow_and_its_completion_answers_it() {
    let server = test_server();
    server
        .runtime
        .register(Arc::new(SignAskFlow))
        .expect("the flow registers");
    let session = create_session(&server).await;

    // The SSE stream first — the real client's order: connected before
    // the flow asks anything.
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
    let mut stream = response.into_body().into_data_stream();
    let mut seen = String::new();

    // The flow start stays in flight until the flow's ask is answered.
    let start = tokio::spawn({
        let server = server.clone();
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "req-start",
            "method": "wmp.flow.start",
            "params": {
                "wmp": { "session_id": session, "version": "0.1" },
                "flow_type": "sign-ask",
                "flow_id": "flow-1",
            }
        })
        .to_string();
        async move { post_wmp(&server, &body).await }
    });

    let child_start =
        streamed_message(&mut stream, &mut seen, "wmp.flow.start", "flow-1::sign::").await;
    let child = child_start
        .pointer("/params/flow_id")
        .expect("the child start names its flow");

    // The client's completion: the answer the wallet signed, posted back
    // through the same POST /wmp route the dispatch serves.
    let (status, _body) = post_wmp(
        &server,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "method": "wmp.flow.complete",
            "params": {
                "wmp": { "session_id": session, "version": "0.1" },
                "flow_id": child,
                "result": { "signature": [4, 3, 2, 1] },
            }
        })
        .to_string(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "a notification answers empty"
    );

    // The ask resolves with the client's result: the flow completes on it.
    let (status, body) = tokio::time::timeout(std::time::Duration::from_secs(5), start)
        .await
        .expect("the flow start answers in time")
        .expect("the task joins");
    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_slice(&body).expect("parse");
    assert_eq!(
        response
            .pointer("/result/flow_id")
            .and_then(serde_json::Value::as_str),
        Some("flow-1"),
        "the flow started: {response}"
    );
    let complete = streamed_message(&mut stream, &mut seen, "wmp.flow.complete", "flow-1").await;
    assert_eq!(
        complete.pointer("/params/result/signature"),
        Some(&serde_json::json!([4, 3, 2, 1])),
        "the client's answer rode back: {complete}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_ask_that_times_out_cancels_the_child() {
    let server = test_server();
    let session = create_session(&server).await;

    // The SSE stream, to observe the cancel the timeout sends.
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
    let mut stream = response.into_body().into_data_stream();

    // The ask, with nobody answering it. The Host port's shortest bound is
    // 10 s, so this ask runs on a bridge over the server's peer with its own
    // bound.
    let bridge = engine_adapter_server::host_bridge::WmpHostBridge::new(server.peer.clone());
    let ask_session = session.clone();
    let ask = tokio::spawn(async move {
        let ctx = wmp_core::context::RequestContext::default();
        bridge
            .request(
                &ctx,
                "flow-1",
                &ask_session,
                "consent",
                &serde_json::json!({ "flow_id": "flow-1" }),
                std::time::Duration::from_millis(200),
            )
            .await
    });

    // The ask times out.
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), ask)
        .await
        .expect("the ask ends in time")
        .expect("the task joins");
    assert!(
        matches!(
            outcome,
            Err(engine_adapter_server::host_bridge::HostBridgeError::Timeout)
        ),
        "the unanswered ask times out: {outcome:?}"
    );

    // The client is told the ask is off.
    let mut seen = String::new();
    streamed_message(&mut stream, &mut seen, "wmp.flow.cancel", "::consent::").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_create_advertises_the_flows_capability() {
    // The engine's flows capability (core §10.3): the session create
    // carries it, so a client that did not offer it refuses at the
    // session, not at the first flow start. The wasm dispatcher
    // advertises the same shape.
    let server = test_server();
    let (status, body) = post_wmp(
        &server,
        r#"{"jsonrpc":"2.0","id":"req-1","method":"wmp.session.create","params":{"wmp":{"version":"0.1"},"participants":["x509:san:dns:bob.example.com"],"capabilities_offered":{"flows":{"max_concurrent":16},"messaging":{"max_size":65536}},"security":{"mode":"tls"},"ttl":3600}}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let response: serde_json::Value = serde_json::from_slice(&body).expect("parse");
    let flows = response
        .pointer("/result/capabilities/flows/max_concurrent")
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        flows.as_i64(),
        Some(16),
        "the engine advertises its flows bound: {response}"
    );
}

// ─── The auth gates at the flow start + the OpenID4x action translation ──────

/// Posts a flow start for `flow_type`, answering the JSON-RPC error
/// shape. `token`: `Some` sends the bearer, `None` sends no header at
/// all (the anonymous principal).
async fn post_flow_start(
    server: &Arc<EngineServer>,
    token: Option<&str>,
    flow_type: &str,
) -> (StatusCode, serde_json::Value) {
    let app = engine_adapter_server::transport::router(server.clone());
    let mut builder = Request::builder()
        .method("POST")
        .uri("/wmp")
        .header("content-type", "application/json");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let request = builder
        .body(Body::from(
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": "req-flow",
                "method": "wmp.flow.start",
                "params": {
                    "wmp": { "version": "0.1" },
                    "flow_id": "flow-gate-1",
                    "flow_type": flow_type,
                    "params": {},
                }
            })
            .to_string(),
        ))
        .expect("build request");
    let response = app.oneshot(request).await.expect("serve");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("read body");
    let value = serde_json::from_slice(&body).unwrap_or_default();
    (status, value)
}

#[tokio::test(flavor = "multi_thread")]
async fn an_anonymous_flow_start_refuses_with_31002() {
    let server = test_server();
    // No Authorization header at all: the anonymous principal (None,
    // not an empty bearer). The standalone engine requires a token for
    // engine flows (#319's anonymous refusal), so the flow start
    // refuses with -31002 before the capability gate fires.
    let (status, body) = post_flow_start(&server, None, "oid4vci").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body.pointer("/error/code")
            .and_then(serde_json::Value::as_i64),
        Some(-31002),
        "an unauthenticated flow start refuses: {body}"
    );
    assert!(
        body.pointer("/error/data/reason")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|r| r.contains("authenticated principal")),
        "the reason names the requirement: {body}"
    );
}
