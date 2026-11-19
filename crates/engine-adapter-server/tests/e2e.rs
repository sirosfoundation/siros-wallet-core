//! The end-to-end drop-in test (W9's third item): a wallet client drives a
//! complete issuance — and its notification — through the engine server's
//! real surfaces, with no test doubles inside the boundary:
//!
//! - the **HTTP+SSE WMP binding**: the client POSTs `wmp.flow.start` and the
//!   child answers, and reads the engine's messages (the child asks, the
//!   progress, the completion) off the SSE stream;
//! - the **host bridge (F1)**: the engine's wallet asks (the DPoP proof,
//!   the credential proof's signature) ride child flows to the client,
//!   whose completions answer them — while the parent POST is in flight,
//!   exactly as the SDK transport's polling thread drives it;
//! - the **PDP proxy**: the trust evaluation goes through
//!   `BackendProxyPdp` to the backend's `/v1/evaluate`;
//! - the **issuer fetches**: the engine resolves the metadata, exchanges
//!   the pre-authorized code, and requests the credential through
//!   `ServerHttpClient` (reqwest) against a scripted local issuer;
//! - the **notification flow (W7)**: the issuance's completion registered
//!   its context; the client's `credential_notification` flow claims it
//!   and the engine forwards the §10 event to the issuer with the
//!   issuance's own token.
//!
//! The scripted issuer and PDP are the world the engine talks to; the
//! assertions read what they saw. The drive's reference is the Go
//! deployment's client (go-wmp's WMP over HTTP+SSE) and the SDK's
//! transport shape.

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use engine_adapter_server::{config::Config, EngineServer};
use futures_util::StreamExt;
use tower::ServiceExt;

// ─── The scripted world: an issuer, an AS, a PDP ──────────────────────────

/// The requests the scripted world saw.
#[derive(Default)]
struct Seen {
    bodies: Mutex<Vec<(String, String)>>,
}

impl Seen {
    fn record(&self, path: &str, body: &str) {
        self.bodies
            .lock()
            .expect("lock")
            .push((path.to_owned(), body.to_owned()));
    }

    /// The first body recorded for `path`.
    fn body_of(&self, path: &str) -> Option<String> {
        self.bodies
            .lock()
            .expect("lock")
            .iter()
            .find(|(seen, _)| seen == path)
            .map(|(_, body)| body.clone())
    }

    /// How many requests reached `path`.
    fn count_of(&self, path: &str) -> usize {
        self.bodies
            .lock()
            .expect("lock")
            .iter()
            .filter(|(seen, _)| seen == path)
            .count()
    }
}

/// Binds a local port, then serves the documents the caller names against
/// it, recording what arrives — the scripted issuer/AS/notification
/// endpoint and the backend's PDP. Answers JSON to every path, `{}` to the
/// unlisted, so the §10 endpoint's 204 is answered as the accepted 200.
async fn serve(
    documents: impl FnOnce(&str) -> Vec<(String, &'static str)>,
    seen: Arc<Seen>,
) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let base = format!("http://{addr}");
    let routes = documents(&base);
    // The spawned server's copy: the function returns `base`, so the task
    // cannot own it.
    let origin = base.clone();
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let seen = seen.clone();
            let routes = routes.clone();
            let base = origin.clone();
            tokio::spawn(async move {
                // One request: the head, then the body by content-length.
                let mut buffer = Vec::new();
                let mut chunk = [0u8; 4096];
                let head_end = loop {
                    let n = socket.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buffer.extend_from_slice(&chunk[..n]);
                    if let Some(at) = find_head_end(&buffer) {
                        break at;
                    }
                };
                let head = String::from_utf8_lossy(&buffer[..head_end]).into_owned();
                let mut lines = head.lines();
                let request_line = lines.next().unwrap_or_default().to_owned();
                let mut content_length = 0usize;
                for line in lines {
                    if let Some(value) = line
                        .to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(str::trim)
                    {
                        content_length = value.parse().unwrap_or(0);
                    }
                }
                let mut body = buffer[head_end..].to_vec();
                while body.len() < content_length {
                    let n = socket.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    body.extend_from_slice(&chunk[..n]);
                }
                // The path, without the query.
                let path = request_line
                    .split(' ')
                    .nth(1)
                    .unwrap_or_default()
                    .split('?')
                    .next()
                    .unwrap_or_default()
                    .to_owned();
                seen.record(&path, &String::from_utf8_lossy(&body));
                let registered = routes
                    .iter()
                    .find(|(route, _)| *route == path)
                    .map(|(_, document)| document.replace("BASE", &base));
                let (status, document) = match registered {
                    Some(document) => ("200 OK", document),
                    // A miss must not masquerade as a document: the
                    // discovery falls through 404s, the flows refuse.
                    None => ("404 Not Found", "{}".to_owned()),
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
                    document.len(),
                    document
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    base
}

/// Where the request head ends, or None while it has not arrived.
fn find_head_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|at| at + 4)
}

// ─── The client's drive ─────────────────────────────────────────────────

/// POSTs one WMP message through the router; answers (status, body).
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

/// The next JSON message of the SSE stream, out of the buffered frames.
/// The `data:` lines carry the engine's JSON-RPC messages; the `id:` lines
/// (the replay markers) and the keep-alives ride along unnoted.
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
                // A non-JSON data line (or a broken one): dropped, the
                // stream read continues.
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

// ─── The test ────────────────────────────────────────────────────────────

/// The drop-in engine serves a whole issuance, over its real surfaces, to
/// a client that answers the wallet's asks as they stream — and forwards
/// the notification the issuance's completion registered.
#[tokio::test(flavor = "multi_thread")]
async fn the_engine_serves_an_issuance_and_its_notification_end_to_end() {
    // ── The scripted world ────────────────────────────────────────────
    let issuer_seen = Arc::new(Seen::default());
    let issuer = serve(
        |base| {
            let metadata = format!(
                r#"{{
                    "credential_issuer": "{base}",
                    "credential_endpoint": "{base}/credential",
                    "notification_endpoint": "{base}/notification",
                    "authorization_servers": ["{base}/as"],
                    "credential_configurations_supported": {{
                        "UniversityDegree": {{
                            "format": "dc+sd-jwt",
                            "vct": "https://vc.example/degree"
                        }}
                    }}
                }}"#
            );
            let leaked: &'static str = Box::leak(metadata.into_boxed_str());
            vec![
                ("/.well-known/openid-credential-issuer".to_owned(), leaked),
                (
                    "/.well-known/oauth-authorization-server/as".to_owned(),
                    r#"{"issuer": "BASE/as", "token_endpoint": "BASE/as/token"}"#,
                ),
                (
                    "/as/token".to_owned(),
                    r#"{"access_token": "at-issuance", "token_type": "Bearer", "expires_in": 3600}"#,
                ),
                (
                    "/credential".to_owned(),
                    r#"{"credential": "credential-jwt-1", "notification_id": "nid-1"}"#,
                ),
                // OID4VCI §10 answers 204 No Content; the scripted server
                // answers JSON everywhere, so the endpoint answers `{}` —
                // which the engine reads as the §10 success.
                ("/notification".to_owned(), "{}"),
            ]
        },
        issuer_seen.clone(),
    )
    .await;

    let pdp_seen = Arc::new(Seen::default());
    let pdp = serve(
        |_| {
            vec![(
                "/v1/evaluate".to_owned(),
                r#"{"decision": true, "context": {"reason": [{"message": "in the registry"}]}}"#,
            )]
        },
        pdp_seen.clone(),
    )
    .await;

    // ── The engine server, wired to the scripted world ─────────────────
    let server = Arc::new(EngineServer::new(Config {
        listen_addr: "127.0.0.1:0".to_owned(),
        allow_plaintext: true,
        pdp_url: pdp,
        ..Config::default()
    }));
    let app = engine_adapter_server::transport::router(server.clone());

    // ── The session, with the capabilities the flows gate on ───────────
    let (status, created) = post_wmp(
        &app,
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": "req-1",
            "method": "wmp.session.create",
            "params": {
                "wmp": { "version": "0.1" },
                "capabilities_offered": {
                    "flows": { "max_concurrent": 16 },
                    "credential_notification": {
                        "events": ["credential_accepted", "credential_failure"],
                        "context_ttl_seconds": 300
                    }
                },
                "security": { "mode": "tls" }
            }
        })
        .to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the session create: {created}");
    let session = created
        .pointer("/result/wmp/session_id")
        .and_then(serde_json::Value::as_str)
        .expect("the session id")
        .to_owned();
    let negotiated = created
        .pointer("/result/capabilities")
        .cloned()
        .unwrap_or_default();
    assert!(
        negotiated.get("flows").is_some() && negotiated.get("credential_notification").is_some(),
        "the capabilities negotiated: {negotiated}"
    );

    // ── The SSE stream, before the flow asks anything ───────────────────
    let sse_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/wmp/events?session_id={session}"))
                .body(Body::empty())
                .expect("build"),
        )
        .await
        .expect("serve");
    assert_eq!(sse_response.status(), StatusCode::OK);
    let mut stream = sse_response.into_body().into_data_stream();
    let mut sse_text = String::new();

    // ── The parent flow start, in flight while the client answers ──────
    let offer = serde_json::json!({
        "credential_issuer": issuer,
        "credential_configuration_ids": ["UniversityDegree"],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": "code-1"
            }
        },
        "redirect_uri": "https://wallet.example/cb",
        "client_id": "client-1"
    });
    let parent_app = app.clone();
    let parent = {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "req-2",
            "method": "wmp.flow.start",
            "params": {
                "wmp": { "version": "0.1", "session_id": session },
                "flow_id": "flow-e2e-1",
                "flow_type": "oid4vci",
                "params": offer
            }
        })
        .to_string();
        tokio::spawn(async move { post_wmp(&parent_app, body).await })
    };

    // The client's loop: answer the child asks, watch the messages, until
    // the parent's completion streams and the POST joins.
    let mut completion: Option<serde_json::Value> = None;
    let mut parent_answered = false;
    let mut parent = Some(parent);
    let elapsed = std::time::Instant::now();
    for _ in 0..256 {
        // The drive is over: the completion streamed and the parent POST
        // answered.
        if completion.is_some() && parent_answered {
            break;
        }
        // The parent POST's answer, once it lands.
        if !parent_answered && parent.as_ref().is_some_and(|task| task.is_finished()) {
            let (status, answer) = parent
                .take()
                .expect("the parent task is here")
                .await
                .expect("the parent task joins");
            assert_eq!(status, StatusCode::OK, "the flow start: {answer}");
            assert!(
                answer.get("error").is_none(),
                "the issuance flow succeeded: {answer}"
            );
            parent_answered = true;
        }
        let message = match tokio::time::timeout(
            std::time::Duration::from_secs(2),
            next_message(&mut stream, &mut sse_text),
        )
        .await
        {
            Ok(Some(message)) => message,
            // The stream closed: whatever the parent answered is all
            // there is.
            Ok(None) => break,
            // A quiet moment: the parent POST may have finished while
            // the read waited — loop and join it. A quiet stream with
            // the parent unfinished past the drive's bound is the hang
            // this diagnoses.
            Err(_) => {
                if elapsed.elapsed() > std::time::Duration::from_secs(30) {
                    panic!("the stream went quiet while the parent POST hung");
                }
                continue;
            }
        };
        let method = message
            .get("method")
            .and_then(|m| m.as_str())
            .unwrap_or_default();
        let flow_id = message
            .pointer("/params/flow_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned();
        match method {
            // The engine's wallet ask: a child flow. The client answers
            // per the ask type — the DPoP proof's empty answer keeps the
            // engine-held key (the legacy mode), the sign answer is the
            // wallet's own signature.
            "wmp.flow.start" => {
                let answer = if flow_id.contains("::dpop_proof::") {
                    // The empty proof: the engine-held key signs (the
                    // legacy mode).
                    serde_json::json!({ "proof": "" })
                } else if flow_id.contains("::sign::") {
                    // The wallet's own signature of the credential proof.
                    serde_json::json!({ "signature": [4, 3, 2, 1] })
                } else if flow_id.contains("::tx_code::") {
                    serde_json::json!("1234")
                } else if flow_id.contains("::attestation::") {
                    // No Wallet Instance Attestation: the flow proceeds
                    // without client attestation (the Go rule).
                    serde_json::json!({})
                } else if flow_id.contains("::signing_key::") {
                    // No named key: the proofs sign without a kid.
                    serde_json::json!({})
                } else {
                    panic!("an unexpected child ask streamed: {message}");
                };
                let (status, reply) = post_wmp(
                    &app,
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "method": "wmp.flow.complete",
                        "params": {
                            "wmp": { "session_id": session, "version": "0.1" },
                            "flow_id": flow_id,
                            "result": answer
                        }
                    })
                    .to_string(),
                )
                .await;
                assert!(
                    status == StatusCode::NO_CONTENT && reply.is_null(),
                    "the child answer posted: {status} {reply}"
                );
            }
            // The issuance's completion: the credential, and W7's
            // notification members.
            "wmp.flow.complete" if flow_id == "flow-e2e-1" => {
                completion = message.pointer("/params/result").cloned();
            }
            // The progress rides; nothing to do.
            _ => {}
        }
        if completion.is_some() && parent_answered {
            break;
        }
    }
    assert!(parent_answered, "the parent POST answered");
    let completion = completion.expect("the issuance's completion streamed");
    assert_eq!(completion["credential"], "credential-jwt-1");
    assert_eq!(completion["notification_id"], "nid-1");
    assert_eq!(
        completion["notification_endpoint"],
        format!("{issuer}/notification")
    );

    // ── The world the engine talked to ─────────────────────────────────
    // The trust evaluation reached the backend's PDP, in the AuthZEN Trust
    // Registry Profile's shape (the /v1/evaluate route binds it): the
    // subject as {type,id} — the issuer, a url — the resource as
    // {type,id,key} with the metadata's inline jwks, the action as
    // {name} (credential-issuer), the context beside them.
    let evaluation: serde_json::Value = serde_json::from_str(
        &pdp_seen
            .body_of("/v1/evaluate")
            .expect("the PDP was called"),
    )
    .unwrap_or_default();
    assert_eq!(
        evaluation["subject"],
        serde_json::json!({"type": "key", "id": issuer}),
        "the issuer was evaluated, as the key holder (the routed policy's subject type): {evaluation}"
    );
    assert_eq!(
        evaluation["resource"]["id"], issuer,
        "the resource is the subject: {evaluation}"
    );
    // The fixture's metadata carries no jwks: the engine's key material
    // is empty, and the resource's key mirrors it (the x5c default, a
    // null key) — the proxy decides on an empty answer, exactly what
    // the PDP contract leaves it.
    assert_eq!(
        evaluation["resource"]["type"], "x5c",
        "empty key material defaults to the chain form: {evaluation}"
    );
    assert!(
        evaluation["resource"]["key"].is_null(),
        "no key material rode the resource: {evaluation}"
    );
    assert_eq!(
        evaluation["action"],
        serde_json::json!({"name": "credential-issuer"}),
        "the issuance side names its action: {evaluation}"
    );

    // The pre-authorized exchange reached the issuer's AS.
    let token = issuer_seen
        .body_of("/as/token")
        .expect("the token endpoint was called");
    assert!(
        token.contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code"),
        "the pre-authorized grant: {token}"
    );

    // The credential request reached the issuer, with the wallet's proof.
    let credential_request: serde_json::Value = serde_json::from_str(
        &issuer_seen
            .body_of("/credential")
            .expect("the credential endpoint was called"),
    )
    .unwrap_or_default();
    assert_eq!(
        credential_request["credential_configuration_id"], "UniversityDegree",
        "the auto-selected configuration was requested: {credential_request}"
    );
    assert!(
        credential_request["proofs"].is_object(),
        "the credential proofs rode the request: {credential_request}"
    );

    // ── The notification flow, over the same session ───────────────────
    let (_status, answer) = post_wmp(
        &app,
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": "req-3",
            "method": "wmp.flow.start",
            "params": {
                "wmp": { "version": "0.1", "session_id": session },
                "flow_id": "flow-e2e-2",
                "flow_type": "credential_notification",
                "params": {
                    "issuance_flow_id": "flow-e2e-1",
                    "notification_id": "nid-1",
                    "event": "credential_accepted"
                }
            }
        })
        .to_string(),
    )
    .await;
    assert!(
        answer.get("error").is_none(),
        "the notification flow started: {answer}"
    );

    // The flow's completion streams (the start result is bare, like every
    // flow's): the forwarded status rides it.
    let mut forwarded = None;
    for _ in 0..8 {
        let Some(message) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            next_message(&mut stream, &mut sse_text),
        )
        .await
        .expect("the completion streams") else {
            break;
        };
        let is_the_notification_completion = message.get("method").and_then(|m| m.as_str())
            == Some("wmp.flow.complete")
            && message.pointer("/params/flow_id").and_then(|v| v.as_str()) == Some("flow-e2e-2");
        if is_the_notification_completion {
            forwarded = message.pointer("/params/result").cloned();
            break;
        }
    }
    let forwarded = forwarded.expect("the notification's completion streamed");
    assert_eq!(
        forwarded["status"], "forwarded",
        "the notification was forwarded: {forwarded}"
    );
    assert_eq!(forwarded["notification_id"], "nid-1");

    // The §10 notification reached the issuer, echoing the issuer's
    // notification_id.
    let notification: serde_json::Value = serde_json::from_str(
        &issuer_seen
            .body_of("/notification")
            .expect("the notification was forwarded"),
    )
    .unwrap_or_default();
    assert_eq!(notification["notification_id"], "nid-1");
    assert_eq!(notification["event"], "credential_accepted");

    // One issuance, ONE forward: the credential endpoint saw the one
    // request; the notification endpoint saw ONLY the
    // credential_notification flow's §10 send (issue #60: the issuance
    // path's own best-effort send double-delivered — the issuer answered
    // 409 illegal_transition to the second, and the wallet's flow reported
    // forward_failed after every phone-scan issuance; removed).
    assert_eq!(issuer_seen.count_of("/credential"), 1);
    assert_eq!(issuer_seen.count_of("/notification"), 1);
}

// ─── Issue #59: the client-held response keys, end to end ─────────────────
//
// The phone's path and nothing else: a wallet client that ANSWERS the
// engine's `response_encryption_key` ask (the pair it generates and
// holds) and its `decrypt_credential_response` ask (the JWE it opens
// with the held private half), against an issuer that REQUIRES
// encryption — so the engine's negotiation takes the client-held arm,
// the credential request offers the WALLET's public JWK, the issuer
// answers a JWE to it, and the engine relays that JWE back through the
// decrypt ask instead of opening it in-process.
//
// The CI suite never drove this arm before the phone did (the scripted
// issuer carried no `credential_response_encryption`, so the ask never
// fired): this is the repro harness for the v0.2.28 phone stall (issue
// #72) — a stall here fails this test with the exact quiet-stream
// symptom; a pass pins the whole path.

/// The dynamic scripted issuer for the client-held issuance: the
/// `/credential` route reads the wallet's offered JWK out of the request
/// and answers the response as a JWE encrypted to it (the static `serve`
/// helper cannot answer a request-dependent document).
async fn serve_encrypted_issuer(seen: Arc<Seen>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let base = format!("http://{addr}");

    let metadata = serde_json::json!({
        "credential_issuer": base,
        "credential_endpoint": format!("{base}/credential"),
        "notification_endpoint": format!("{base}/notification"),
        "authorization_servers": [format!("{base}/as")],
        "credential_configurations_supported": {
            "UniversityDegree": {"format": "dc+sd-jwt", "vct": "https://vc.example/degree"}
        },
        "credential_response_encryption": {
            "alg_values_supported": ["ECDH-ES"],
            "enc_values_supported": ["A256GCM"],
            "encryption_required": true,
        }
    });
    let as_metadata = serde_json::json!({
        "issuer": format!("{base}/as"),
        "token_endpoint": format!("{base}/as/token"),
    });
    let token = serde_json::json!({
        "access_token": "at-issuance",
        "token_type": "Bearer",
        "expires_in": 3600,
    });

    // One clone per route: each handler's `move` closure captures its own.
    let seen_metadata = seen.clone();
    let seen_as = seen.clone();
    let seen_token = seen.clone();
    let seen_credential = seen.clone();
    let seen_notification = seen.clone();
    let app = axum::Router::new()
        .route(
            "/.well-known/openid-credential-issuer",
            axum::routing::get(move || {
                let _ = &seen_metadata;
                let metadata = metadata.clone();
                async move { axum::Json(metadata) }
            }),
        )
        .route(
            "/.well-known/oauth-authorization-server/as",
            axum::routing::get(move || {
                let _ = &seen_as;
                let as_metadata = as_metadata.clone();
                async move { axum::Json(as_metadata) }
            }),
        )
        .route(
            "/as/token",
            axum::routing::post(move |body: String| {
                let seen_token = seen_token.clone();
                async move {
                    seen_token.record("/as/token", &body);
                    axum::Json(token)
                }
            }),
        )
        .route(
            "/credential",
            axum::routing::post(
                move |body: axum::body::Bytes| {
                    let seen_credential = seen_credential.clone();
                    async move {
                        use axum::response::IntoResponse;
                        let text = String::from_utf8_lossy(&body).into_owned();
                        seen_credential.record("/credential", &text);
                        // The wallet's offered public JWK, out of the request's
                        // `credential_response_encryption` (the client-held pair's
                        // public half — the private never left the wallet).
                        let value: serde_json::Value = match serde_json::from_str(&text) {
                            Ok(value) => value,
                            Err(_) => {
                                return (
                                    axum::http::StatusCode::BAD_REQUEST,
                                    axum::Json(serde_json::json!({"error": "invalid_request"})),
                                )
                                    .into_response()
                            }
                        };
                        let jwk: jose_rs::jwk::Jwk = match serde_json::from_value(
                            value
                                .pointer("/credential_response_encryption/jwk")
                                .cloned()
                                .unwrap_or(serde_json::Value::Null),
                        ) {
                            Ok(jwk) => jwk,
                            Err(_) => {
                                return (
                                    axum::http::StatusCode::BAD_REQUEST,
                                    axum::Json(
                                        serde_json::json!({"error": "invalid_encryption_request"}),
                                    ),
                                )
                                .into_response()
                            }
                        };
                        // The §7.3 answer: the response as a JWE to the offered key.
                        let mut recipient = jwk.clone();
                        recipient.alg = Some("ECDH-ES".to_owned());
                        let plaintext = br#"{"credential":"credential-jwt-encrypted-1","notification_id":"nid-enc-1","credential_metadata":[{"label":"ssc","value":"seed"}]}"#.to_vec();
                        let jwe = match jose_rs::jwe::compact::encrypt_with_jwk_header(
                            &recipient,
                            jose_rs::header::JoseHeader::for_jwe(
                                jose_rs::algorithm::JweAlgorithm::EcdhEs,
                                jose_rs::algorithm::JweEncryption::A256GCM,
                            ),
                            &plaintext,
                            jose_rs::algorithm::JweEncryption::A256GCM,
                        ) {
                            Ok(jwe) => jwe,
                            Err(_) => {
                                return (
                                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                                    axum::Json(serde_json::json!({"error": "encryption_failed"})),
                                )
                                .into_response()
                            }
                        };
                        (
                            [(axum::http::header::CONTENT_TYPE, "application/jwt")],
                            jwe,
                        )
                            .into_response()
                    }
                },
            ),
        )
        .route(
            "/notification",
            axum::routing::post(move |body: String| {
                let seen_notification = seen_notification.clone();
                async move {
                    seen_notification.record("/notification", &body);
                    axum::http::StatusCode::NO_CONTENT
                }
            }),
        );
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("the issuer serves");
    });
    base
}

/// Issue #59/#72: the drop-in engine serves a whole CLIENT-HELD issuance
/// — the key ask answered by the wallet's own pair, the JWE relayed back
/// through the decrypt ask — over its real surfaces, to a client that
/// answers the asks as they stream. The completion carries the opened
/// credential, the per-entry `credential_response_encrypted` flag, and
/// the response-level `credential_metadata` relay; the §10 notification
/// is the wallet's alone (#63: the engine sent nothing).
#[tokio::test(flavor = "multi_thread")]
async fn the_engine_serves_a_client_held_encrypted_issuance_end_to_end() {
    use std::sync::Mutex;

    // ── The scripted world ────────────────────────────────────────────
    let issuer_seen = Arc::new(Seen::default());
    let issuer = serve_encrypted_issuer(issuer_seen.clone()).await;

    let pdp_seen = Arc::new(Seen::default());
    let pdp = serve(
        |_| {
            vec![(
                "/v1/evaluate".to_owned(),
                r#"{"decision": true, "context": {"reason": [{"message": "in the registry"}]}}"#,
            )]
        },
        pdp_seen.clone(),
    )
    .await;

    // ── The engine server, wired to the scripted world ───────────────
    let server = Arc::new(EngineServer::new(Config {
        listen_addr: "127.0.0.1:0".to_owned(),
        allow_plaintext: true,
        pdp_url: pdp,
        ..Config::default()
    }));
    let app = engine_adapter_server::transport::router(server.clone());

    // ── The session ───────────────────────────────────────────────────
    let (status, created) = post_wmp(
        &app,
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": "req-1",
            "method": "wmp.session.create",
            "params": {
                "wmp": { "version": "0.1" },
                "capabilities_offered": {
                    "flows": { "max_concurrent": 16 },
                    "credential_notification": {
                        "events": ["credential_accepted", "credential_failure"],
                        "context_ttl_seconds": 300
                    }
                },
                "security": { "mode": "tls" }
            }
        })
        .to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the session create: {created}");
    let session = created
        .pointer("/result/wmp/session_id")
        .and_then(serde_json::Value::as_str)
        .expect("the session id")
        .to_owned();

    // ── The SSE stream, before the flow asks anything ─────────────────
    let sse_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/wmp/events?session_id={session}"))
                .body(Body::empty())
                .expect("build"),
        )
        .await
        .expect("serve");
    assert_eq!(sse_response.status(), StatusCode::OK);
    let mut stream = sse_response.into_body().into_data_stream();
    let mut sse_text = String::new();

    // ── The wallet client's held pair ────────────────────────────────
    // Generated on the key ask, held for the decrypt ask — the wallet's
    // own custody, exactly as the SDK's handlers do it.
    let held_private: Arc<Mutex<Option<jose_rs::jwk::Jwk>>> = Arc::new(Mutex::new(None));

    // ── The parent flow start, in flight while the client answers ────
    let offer = serde_json::json!({
        "credential_issuer": issuer,
        "credential_configuration_ids": ["UniversityDegree"],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": "code-enc-1"
            }
        },
        "redirect_uri": "https://wallet.example/cb",
        "client_id": "client-enc-1"
    });
    let parent_app = app.clone();
    let parent = {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "req-2",
            "method": "wmp.flow.start",
            "params": {
                "wmp": { "version": "0.1", "session_id": session },
                "flow_id": "flow-enc-1",
                "flow_type": "oid4vci",
                "params": offer
            }
        })
        .to_string();
        tokio::spawn(async move { post_wmp(&parent_app, body).await })
    };

    // ── The client's loop: answer the child asks until the completion ──
    let mut completion: Option<serde_json::Value> = None;
    let mut parent_answered = false;
    let mut parent = Some(parent);
    let elapsed = std::time::Instant::now();
    for _ in 0..512 {
        if completion.is_some() && parent_answered {
            break;
        }
        if !parent_answered && parent.as_ref().is_some_and(|task| task.is_finished()) {
            let (status, answer) = parent
                .take()
                .expect("the parent task is here")
                .await
                .expect("the parent task joins");
            assert_eq!(status, StatusCode::OK, "the flow start: {answer}");
            assert!(
                answer.get("error").is_none(),
                "the issuance flow succeeded: {answer}"
            );
            parent_answered = true;
        }
        let message = match tokio::time::timeout(
            std::time::Duration::from_secs(2),
            next_message(&mut stream, &mut sse_text),
        )
        .await
        {
            Ok(Some(message)) => message,
            Ok(None) => break,
            Err(_) => {
                if elapsed.elapsed() > std::time::Duration::from_secs(60) {
                    panic!("the stream went quiet while the parent POST hung: the client-held issuance stalled");
                }
                continue;
            }
        };
        let method = message
            .get("method")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let flow_id = message
            .pointer("/params/flow_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned();
        match method {
            "wmp.flow.start" => {
                let answer = if flow_id.contains("::response_encryption_key::") {
                    // Issue #59's key ask: the client generates the pair and
                    // answers the PUBLIC half; the private stays held for
                    // the decrypt ask.
                    let private =
                        jose_rs::jwk::generate::generate_ec("P-256").expect("the client pair");
                    let public: serde_json::Value = serde_json::from_str(
                        &private.to_public_jwk().to_json().expect("the public JWK"),
                    )
                    .expect("the public JWK value");
                    *held_private.lock().expect("lock") = Some(private);
                    serde_json::json!({ "public_jwk": public })
                } else if flow_id.contains("::decrypt_credential_response::") {
                    // Issue #59's decrypt ask: the engine relays the JWE the
                    // issuer answered to the WALLET's offered key; the client
                    // opens it with its held private half and answers the
                    // plaintext response JSON.
                    let jwe = message
                        .pointer("/params/params/jwe")
                        .and_then(serde_json::Value::as_str)
                        .expect("the relayed JWE");
                    let private = held_private
                        .lock()
                        .expect("lock")
                        .clone()
                        .expect("the held pair");
                    let mut private = private;
                    private.alg = Some("ECDH-ES".to_owned());
                    let plaintext = jose_rs::jwe::compact::decrypt_with_jwk(&private, jwe)
                        .expect("the client decrypt");
                    let response: serde_json::Value =
                        serde_json::from_slice(&plaintext).expect("the plaintext JSON");
                    serde_json::json!({ "response": response })
                } else if flow_id.contains("::dpop_proof::") {
                    serde_json::json!({ "proof": "" })
                } else if flow_id.contains("::sign::") {
                    serde_json::json!({ "signature": [4, 3, 2, 1] })
                } else if flow_id.contains("::tx_code::") {
                    serde_json::json!("1234")
                } else if flow_id.contains("::attestation::") || flow_id.contains("::signing_key::")
                {
                    serde_json::json!({})
                } else {
                    panic!("an unexpected child ask streamed: {message}");
                };
                let (answer_status, reply) = post_wmp(
                    &app,
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "method": "wmp.flow.complete",
                        "params": {
                            "wmp": { "session_id": session, "version": "0.1" },
                            "flow_id": flow_id,
                            "result": answer
                        }
                    })
                    .to_string(),
                )
                .await;
                assert!(
                    answer_status == StatusCode::NO_CONTENT && reply.is_null(),
                    "the child answer posted: {answer_status} {reply}"
                );
            }
            "wmp.flow.complete" if flow_id == "flow-enc-1" => {
                completion = message.pointer("/params/result").cloned();
            }
            _ => {}
        }
        if completion.is_some() && parent_answered {
            break;
        }
    }
    assert!(parent_answered, "the parent POST answered");
    let completion = completion.expect("the issuance's completion streamed");

    // ── The completion: the opened credential, the flags, the relay ────
    assert_eq!(
        completion["credential"], "credential-jwt-encrypted-1",
        "the wallet-opened credential: {completion}"
    );
    assert_eq!(
        completion["credentials"][0]["credential_response_encrypted"], true,
        "the per-entry encrypted flag (#59, the Go CredentialResult parity): {completion}"
    );
    assert_eq!(
        completion["credentials"][0]["credential"], "credential-jwt-encrypted-1",
        "the per-entry credential: {completion}"
    );
    assert_eq!(
        completion["credential_metadata"][0]["label"], "ssc",
        "the response-level credential_metadata relay (#59, the seed-delivery path): {completion}"
    );
    assert_eq!(
        completion["notification_id"], "nid-enc-1",
        "the §11.1 notification members: {completion}"
    );

    // ── The world the engine talked to ─────────────────────────────────
    let credential_request: serde_json::Value = serde_json::from_str(
        &issuer_seen
            .body_of("/credential")
            .expect("the credential endpoint was called"),
    )
    .unwrap_or_default();
    let offered = credential_request
        .pointer("/credential_response_encryption/jwk")
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        offered["kty"], "EC",
        "the credential request offered the WALLET's public JWK (the client-held pair): {credential_request}"
    );

    // #63 (the single sender): the engine did NOT notify on its own — the
    // §10 event is the wallet's flow alone, so nothing reached the
    // notification endpoint during the issuance.
    assert_eq!(
        issuer_seen.count_of("/notification"),
        0,
        "the engine sent no §10 event itself (the wallet's flow is the single sender)"
    );
}
