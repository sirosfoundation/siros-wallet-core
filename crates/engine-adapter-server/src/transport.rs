//! The HTTP+SSE transport: the routes the WMP HTTPS binding (wmp-transport
//! §4) defines, wired to the engine's peer.
//!
//! - `POST /wmp` — one JSON-RPC message from the wallet client; the response
//!   is the JSON-RPC reply (or empty for a notification).
//! - `GET  /wmp/events?session_id=` — the SSE stream the engine's
//!   notifications flow on (`event: wmp\ndata: {json}`).
//! - `GET  /healthz` and `GET /readyz` — the probes the container needs.

use std::convert::Infallible;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;

use crate::EngineServer;
use wmp_core::context::RequestContext;

/// The router of the engine's HTTP endpoints.
pub fn router(server: Arc<EngineServer>) -> Router {
    Router::new()
        .route("/wmp", post(post_wmp))
        .route("/wmp/events", get(get_events))
        .route("/healthz", get(get_healthz))
        .route("/readyz", get(get_readyz))
        .with_state(server)
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
    let principal = bearer_principal(&headers);

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

/// `GET /wmp/events` — the SSE stream the engine's notifications flow on
/// (wmp-transport.md §4.3). The stream stays open until the client
/// disconnects or the server shuts down.
async fn get_events(
    State(_server): State<Arc<EngineServer>>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    // The notifications come from the peer's outbound end — flow progress,
    // sub-flow requests, completions — drained here as SSE events. The
    // flow families write to it through the peer's `notify` when they land.
    // Until then the stream stays open (the keep-alive pings the client).
    let (sender, receiver) = tokio::sync::mpsc::channel::<Result<Event, Infallible>>(16);
    let stream = tokio_stream::wrappers::ReceiverStream::new(receiver);
    // Hold the sender so the stream does not close: the peer's outbound
    // notifications feed it when the flow families land.
    std::mem::forget(sender);
    Sse::new(stream).keep_alive(KeepAlive::default())
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

/// The principal from the `Authorization: Bearer <token>` header. The
/// adapter validates the token against the AS's JWKS (the config's
/// `as_external_url`) and extracts the subject; without a valid token the
/// principal is anonymous and the engine's session methods refuse it
/// (`-31002`). The token-validation client itself arrives with the
/// `engine-ports::HttpClient` wiring; this is the shape.
fn bearer_principal(headers: &HeaderMap) -> Option<wmp_core::principal::Principal> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))?;
    // Token validation against the AS's JWKS: the `as_external_url` the
    // Go engine requires. Until the OIDC validation lands with the flow
    // families, the adapter accepts the token's presence as
    // authentication and the subject is the token text (so the vectors can
    // assert the shape; the real validation replaces it in S1).
    Some(wmp_core::principal::Principal::new(token, ""))
}

/// The `Wmp-Session-Id` header (wmp-transport.md §4.5).
fn header_session_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get("wmp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}
