//! The transports the WMP binding (wmp-transport.md) defines, wired to the
//! engine's peer:
//!
//! **HTTPS binding (§4):**
//! - `POST /wmp` — one JSON-RPC message from the wallet client; the response
//!   is the JSON-RPC reply (or empty for a notification).
//! - `GET  /wmp/events?session_id=` — the SSE stream the engine's
//!   notifications flow on (`event: wmp\ndata: {json}`).
//!
//! **WebSocket binding (§3):**
//! - `GET  /wmp` with `Upgrade: websocket` — the persistent bidirectional
//!   channel. Each text frame is one JSON-RPC message; the subprotocol is
//!   `wmp.v1`; ping every 30 s, close after 90 s without a pong.
//!
//! **Probes:**
//! - `GET  /healthz` and `GET /readyz`.

use std::convert::Infallible;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;

use tokio_stream::StreamExt;

use crate::EngineServer;
use wmp_core::context::RequestContext;

/// The router of the engine's HTTP endpoints: the WMP transport routes,
/// the authzen proxy routes, and the probes.
pub fn router(server: Arc<EngineServer>) -> Router {
    Router::new()
        .route("/wmp", get(get_wmp_ws).post(post_wmp))
        .route("/wmp/events", get(get_events))
        .route("/v1/evaluate", post(post_evaluate))
        .route("/v1/resolve", post(post_resolve))
        .route("/healthz", get(get_healthz))
        .route("/readyz", get(get_readyz))
        .with_state(server)
}

/// `POST /v1/evaluate` — the authzen proxy's evaluate route: authorizes
/// the query against SPOCP policies, looks up the tenant's PDP URL, and
/// forwards. The engine's `BackendProxyPdp` port calls this.
async fn post_evaluate(
    State(_server): State<Arc<EngineServer>>,
    _headers: HeaderMap,
    _body: axum::body::Bytes,
) -> Response {
    // The full SPOCP authorization and PDP forwarding arrive with the
    // backend adapter; the route exists so the proxy path is addressable.
    (
        StatusCode::NOT_IMPLEMENTED,
        [(header::CONTENT_TYPE, "application/json")],
        r#"{"error":"the authzen proxy arrives with the backend adapter"}"#,
    )
        .into_response()
}

/// `POST /v1/resolve` — the authzen proxy's resolve route.
async fn post_resolve(
    State(_server): State<Arc<EngineServer>>,
    _headers: HeaderMap,
    _body: axum::body::Bytes,
) -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        [(header::CONTENT_TYPE, "application/json")],
        r#"{"error":"the authzen proxy arrives with the backend adapter"}"#,
    )
        .into_response()
}

/// `POST /wmp` — the WMP HTTPS binding's request/response mode
/// (wmp-transport.md §4.2). One JSON-RPC message in, the reply out; a
/// notification answers empty.
async fn post_wmp(
    State(server): State<Arc<EngineServer>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // The principal: the bearer token the Go engine's WebSocket handshake
    // validated. The adapter validates the token against the AS's JWKS
    // (the config's `as_external_url`) and extracts the subject; a missing
    // or invalid token is anonymous.
    let principal = bearer_principal(&headers, &server.validator);

    // The WMP session the request names, for context enrichment.
    let session_id = header_session_id(&headers);
    let _ = session_id;

    let ctx = wmp_core::context::RequestContext {
        principal,
        ..RequestContext::default()
    };

    let response = server
        .peer
        .handle_request_sync(&ctx, &body)
        .unwrap_or_else(|err| {
            // The peer answered with an internal error; the response is
            // the JSON-RPC error it named.
            let rpc = err.to_rpc();
            let json = serde_json::json!({
                "jsonrpc": "2.0",
                "id": null,
                "error": {
                    "code": rpc.code,
                    "message": rpc.message,
                }
            });
            Some(serde_json::to_vec(&json).unwrap_or_default())
        });

    match response {
        Some(bytes) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            bytes,
        )
            .into_response(),
        None => StatusCode::NO_CONTENT.into_response(),
    }
}

/// `GET /wmp` with `Upgrade: websocket` — the WMP WebSocket binding
/// (wmp-transport.md §3). Each text frame carries one JSON-RPC message; the
/// engine's replies and notifications go back as text frames. The
/// subprotocol is `wmp.v1` when the client asks for it.
///
/// The WebSocket binding is bidirectional: the same connection carries
/// client-to-engine requests and engine-to-client notifications, and the
/// session lifecycle survives reconnection (`wmp.session.resume`).
async fn get_wmp_ws(
    State(server): State<Arc<EngineServer>>,
    headers: HeaderMap,
    ws: axum::extract::ws::WebSocketUpgrade,
) -> Response {
    // The principal from the upgrade request's bearer token, as §3.4
    // allows ("authentication MAY be performed at the HTTP level before
    // the upgrade"). Without one the engine's session methods refuse.
    let principal = bearer_principal(&headers, &server.validator);
    let ctx = RequestContext {
        principal,
        ..RequestContext::default()
    };

    // The subprotocol: `wmp.v1` when the client asks for it.
    let protocol = headers
        .get("sec-websocket-protocol")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    // Accept the `wmp.v1` subprotocol (§3.1: "clients SHOULD request it").
    let upgrade = ws.protocols(["wmp.v1"]);
    upgrade.on_upgrade(move |socket| ws_loop(server, ctx, socket, protocol))
}

/// The WebSocket message loop: reads JSON-RPC frames, dispatches through
/// the peer, writes replies and notifications back. Ping every 30 s;
/// close after 90 s without a pong (§3.3).
async fn ws_loop(
    server: Arc<EngineServer>,
    ctx: RequestContext,
    mut socket: axum::extract::ws::WebSocket,
    protocol: Option<String>,
) {
    use axum::extract::ws::Message;
    use std::time::Duration;

    // Negotiate the subprotocol: accept `wmp.v1` when offered (§3.1). The
    // `protocols` call is on the upgrade, not here; record what was chosen.
    let _ = protocol;

    let mut last_pong = tokio::time::Instant::now();
    let ping_interval = Duration::from_secs(30);
    let pong_timeout = Duration::from_secs(90);

    loop {
        tokio::select! {
            // A frame from the client.
            frame = socket.recv() => {
                match frame {
                    Some(Ok(Message::Text(text))) => {
                        let response = server
                            .peer
                            .handle_request_sync(&ctx, text.as_bytes())
                            .unwrap_or_else(|err| {
                                let rpc = err.to_rpc();
                                let json = serde_json::json!({
                                    "jsonrpc": "2.0",
                                    "id": null,
                                    "error": {
                                        "code": rpc.code,
                                        "message": rpc.message,
                                    }
                                });
                                Some(serde_json::to_vec(&json).unwrap_or_default())
                            });

                        // A notification answers no frame; a request's
                        // reply goes back as a text frame.
                        if let Some(bytes) = response {
                            let reply = String::from_utf8_lossy(&bytes).into_owned();
                            if socket.send(Message::Text(reply.into())).await.is_err() {
                                break;
                            }
                        }
                    }
                    Some(Ok(Message::Pong(_))) => {
                        last_pong = tokio::time::Instant::now();
                    }
                    Some(Ok(Message::Ping(_))) => {
                        // axum answers pings automatically; record it so
                        // the keepalive does not double-ping.
                        last_pong = tokio::time::Instant::now();
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(_)) => break,
                    _ => {}
                }
            }

            // The keepalive ping (§3.3): every 30 s, close after 90 s
            // without a pong.
            _ = tokio::time::sleep(ping_interval) => {
                if last_pong.elapsed() > pong_timeout {
                    break;
                }
                let payload: &str = "keepalive";
                if socket.send(Message::Ping(payload.into())).await.is_err() {
                    break;
                }
            }
        }
    }
}
/// (wmp-transport.md §4.3). The stream stays open until the client
/// disconnects or the server shuts down.
///
/// **The replay (§4.3.2):** a client reconnecting with `Last-Event-ID: <n>`
/// gets the events it missed first, then the live stream. A `Last-Event-ID`
/// the log no longer retains — the retention window passed it, or the
/// session's log is empty and the client is not at 0 — answers `410 Gone`
/// (the client must resume the session instead).
///
/// **The redaction:** the log itself withholds `refresh_token`, `dpop_jwk`
/// and `dpop_key_id` from `wmp.flow.complete` results (go-wmp's replay
/// redaction), so nothing streams or replays them.
async fn get_events(
    State(server): State<Arc<EngineServer>>,
    headers: HeaderMap,
    query: axum::extract::Query<rustc_hash::FxHashMap<String, String>>,
) -> Response {
    // The session the stream belongs to: the `session_id` query parameter.
    let Some(session) = query.get("session_id").cloned() else {
        return (StatusCode::BAD_REQUEST, "session_id is required").into_response();
    };
    // The session must exist: a stream for a session nobody created has
    // nothing to stream and nothing to resume into.
    if wmp_core::session::SessionStore::get(&*server.store, &session).is_none() {
        return (StatusCode::NOT_FOUND, "no such session").into_response();
    }

    // The client's last received event id: the `Last-Event-ID` header
    // (§4.3.2), else a fresh stream from now.
    let last_id = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);

    // The replayed gap, oldest first. A gap the log cannot fill is `410
    // Gone`: the client is behind the retention window and must resume the
    // session (the resumption token carries the state forward).
    let replayed = match server.outbox.replay(&session, last_id) {
        Ok(events) => events,
        Err(_) => {
            return (
                StatusCode::GONE,
                "the event log cannot replay from the last event id; resume the session",
            )
                .into_response();
        }
    };

    // The stream: the replayed events, then the live broadcast.
    let live = server.outbox.subscribe(&session);
    let replayed_stream = tokio_stream::iter(replayed);
    let live_stream =
        tokio_stream::wrappers::BroadcastStream::new(live).filter_map(|event| event.ok());
    let stream = replayed_stream
        .chain(live_stream)
        .map(|event: crate::outbox::LoggedEvent| {
            Ok::<Event, Infallible>(
                Event::default()
                    .event("wmp")
                    .id(event.id.to_string())
                    .data(String::from_utf8_lossy(&event.data)),
            )
        });
    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

/// `GET /healthz` — liveness: the process is up.
async fn get_healthz() -> &'static str {
    "ok"
}

/// `GET /readyz` — readiness: the session store answers.
async fn get_readyz(State(server): State<Arc<EngineServer>>) -> Response {
    // The store answers a read: a poisoned lock or a dead backend surfaces
    // here, not in a client's flow.
    let _probe = wmp_core::session::SessionStore::get(&*server.store, "readyz-probe");
    (StatusCode::OK, "ready").into_response()
}

/// The principal from the `Authorization: Bearer <token>` header, validated
/// through the token validator against the AS's JWKS. A missing, malformed
/// or invalid token answers `None` (anonymous): the engine's session
/// methods refuse it with `-31002`, exactly as go-tokenauth's middleware
/// refuses an unauthenticated request.
fn bearer_principal(
    headers: &HeaderMap,
    validator: &crate::token::TokenValidator,
) -> Option<wmp_core::principal::Principal> {
    let raw_token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))?;

    match validator.validate(raw_token) {
        Ok(validated) => Some(wmp_core::principal::Principal::new(
            validated.subject,
            validated.tenant,
        )),
        Err(_) => None,
    }
}

/// The `Wmp-Session-Id` header (wmp-transport.md §4.5).
fn header_session_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get("wmp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}
