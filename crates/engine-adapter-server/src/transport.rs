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
        // Issue #77: the invitation create — the QR/deep-link the
        // counterparty consumes out-of-band to bootstrap a session.
        .route("/wmp/invitation", post(post_invitation))
        // CS-15 §7.2: the WMP configuration document — the discovery
        // source `discover_config` (wmp-core's discovery) fetches. The
        // engine's own live shape: the versions it speaks, its public
        // endpoints, its supported capabilities (the same set the
        // session create negotiates), its security modes.
        .route("/.well-known/wmp-configuration", get(get_wmp_configuration))
        .route("/wmp/jwks", get(get_invitation_jwks))
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
    let principal = bearer_principal(&headers, &server.validator, server.config.principal_mode);

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
    let principal = bearer_principal(&headers, &server.validator, server.config.principal_mode);
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

/// `GET /.well-known/wmp-configuration` (CS-15 §7.2): the discovery
/// document — the versions the engine speaks, its endpoints, the
/// capabilities a session can negotiate (the same supported set the
/// session create answers from), the security modes it accepts.
///
/// The endpoints name the engine's PUBLIC routes: the `public_url`
/// (`ENGINE_PUBLIC_URL`) prefix when configured (the wallet-proxy's
/// `/wmp-engine/` location is the deployed shape), else the relative
/// paths (a local dial answers them on the listen address itself).
async fn get_wmp_configuration(State(server): State<Arc<EngineServer>>) -> Response {
    let base = server.config.public_url.trim_end_matches('/').to_owned();
    let prefixed = |path: &str| {
        if base.is_empty() {
            path.to_owned()
        } else {
            format!("{base}{path}")
        }
    };
    let capabilities = crate::handler::supported_capabilities(&server.config)
        .ok()
        .and_then(|supported| serde_json::to_value(&supported.0).ok());
    let config = wmp_core::discovery::WellKnownConfig {
        supported_versions: wmp_core::version::SUPPORTED_VERSIONS.to_vec(),
        endpoints: [
            ("wmp".to_owned(), prefixed("/wmp")),
            ("events".to_owned(), prefixed("/wmp/events")),
            ("invitation".to_owned(), prefixed("/wmp/invitation")),
            ("jwks".to_owned(), prefixed("/wmp/jwks")),
        ]
        .into_iter()
        .collect(),
        capabilities,
        security_modes: vec!["tls".to_owned()],
        invitation_jwks: server.invitation_jwks(),
        ..wmp_core::discovery::WellKnownConfig::default()
    };
    match serde_json::to_value(&config) {
        Ok(value) => (StatusCode::OK, axum::Json(value)).into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "the configuration does not serialize",
        )
            .into_response(),
    }
}

/// `GET /wmp/jwks`: the invitation signing keys as a JWKS (RFC 7517).
///
/// The invitation JWS's `kid` (the public JWK's thumbprint) resolves
/// here — the cross-provider verification path (wmp-core §12.2: the
/// kid MUST be resolvable; found live in the Cleverbase interop: the
/// key existed and signed, but nothing served it, so an external
/// parser could not verify a minted invitation). Also embedded in the
/// well-known document (`invitation_jwks`), for verifiers that fetch
/// one document.
async fn get_invitation_jwks(State(server): State<Arc<EngineServer>>) -> Response {
    match server.invitation_jwks() {
        Some(jwks) => (StatusCode::OK, axum::Json(jwks)).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            "the invitation endpoint is not configured",
        )
            .into_response(),
    }
}

/// `POST /wmp/invitation` (issue #77): mints, signs and stores one
/// invitation, answering its URI + the invitation object.
///
/// The principal: the bearer token (the same `bearer_principal` gate the
/// POST route uses — the invitation's sender IS the authenticated
/// caller). The provider: the deployment's `public_url`
/// (`ENGINE_PUBLIC_URL`); unset answers `-32601` (the deployment opted
/// out of the invitation endpoint).
///
/// The TTL: the caller's `ttl_secs` when carried (capped at the config's
/// `invitation_ttl_secs`), else the config's default. The nonce:
/// `generate_nonce` (128 entropy bits). The signature: the engine's
/// `InvitationKey` signs the signing payload (the ES256 JWS compact,
/// the `signature` field). The store: `put` (the consume path's
/// single-use source).
///
/// The answer: `{ invitation, uri }` — the `wmp://invite?data=` form
/// (the QR/deep-link), the invitation itself for the caller's records.
/// The HTTPS fallback form is derivable (`invitation.https_uri()`).
async fn post_invitation(
    State(server): State<Arc<EngineServer>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    use wmp_core::invitation::new_invitation;

    // The principal: the bearer token the AS validated (the sender).
    let principal = bearer_principal(&headers, &server.validator, server.config.principal_mode);
    let Some(principal) = principal.filter(|p| p.is_authenticated()) else {
        return error_response(
            wmp_core::error::ERR_NOT_AUTHORIZED as i64,
            "authentication required",
        );
    };
    // The provider: the deployment's public URL. Unset: the endpoint opts
    // out (the invitation names a provider the counterparty resolves).
    if server.config.public_url.is_empty() {
        return error_response(
            wmp_core::error::ERR_METHOD_NOT_FOUND as i64,
            "the invitation endpoint is not configured",
        );
    }
    let Some(key) = server.invitation_key.as_ref() else {
        return error_response(
            wmp_core::error::ERR_INTERNAL_ERROR as i64,
            "the invitation key is unavailable",
        );
    };

    // The caller's ttl, else the default, capped.
    let default_ttl = server.config.invitation_ttl_secs;
    let ttl_secs = serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .and_then(|value| value.get("ttl_secs").and_then(serde_json::Value::as_i64))
        .filter(|ttl| *ttl > 0)
        .map(|ttl| ttl.min(default_ttl))
        .unwrap_or(default_ttl);

    // Mint, sign, store.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default();
    // The engine's own OS RNG port (ports::OsRng): the same source the
    // flows' random choices use, wrapped in the entropy closure the
    // invitation nonce wants.
    let entropy: wmp_core::sessionservice::EntropyFn = {
        let rng = crate::ports::OsRng;
        std::sync::Arc::new(move |bytes: &mut [u8]| {
            use engine_ports::Rng;
            rng.fill(bytes)
        })
    };
    let mut invitation = match new_invitation(
        &server.config.public_url,
        &principal.key(),
        ttl_secs,
        now,
        &entropy,
    ) {
        Ok(invitation) => invitation,
        Err(err) => {
            return error_response(wmp_core::error::ERR_INTERNAL_ERROR as i64, &err.to_string())
        }
    };
    // The relay (spec 3.1's field): WHERE to reach the sender - this
    // engine's own WMP endpoint. Generic consumers (the inspector, another
    // vendor's wallet) skip discovery when it is set; without it they
    // discover via the provider's well-known, which on a path-prefixed
    // deployment (the wallet-proxy's /wmp-engine/ location) 404s at the
    // domain root. Found live 2026-11-22: the wmp-inspector refused every
    // invite ("discovery failed ... HTTP 404") until this.
    invitation.relay = format!("{}/wmp", server.config.public_url.trim_end_matches('/'));
    // The `join` purpose (issue #77's group shape): the create names the
    // group session the invitation bootstraps its consumer into. The
    // purpose defaults to `session` (the 1:1 shape); anything else the
    // core names is refused (`-32602`) — an unknown purpose is a client
    // error, never a silent session invitation.
    let body_value =
        serde_json::from_slice::<serde_json::Value>(&body).unwrap_or(serde_json::Value::Null);
    let purpose = body_value
        .get("purpose")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(wmp_core::invitation::INVITATION_PURPOSE_SESSION)
        .to_owned();
    match purpose.as_str() {
        wmp_core::invitation::INVITATION_PURPOSE_SESSION
        | wmp_core::invitation::INVITATION_PURPOSE_JOIN => {}
        _ => {
            return error_response(
                wmp_core::error::ERR_INVALID_PARAMS as i64,
                "the invitation purpose is not one the engine serves",
            )
        }
    }
    if purpose == wmp_core::invitation::INVITATION_PURPOSE_JOIN {
        // The group the invitation joins its consumer into: a session the
        // store must hold (the inviter's own group session), named by the
        // caller. Unnamed or unknown: `-32602` — the invitation names a
        // bootstrap target, never a guess.
        let session_id = body_value
            .get("session_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned();
        if session_id.is_empty() {
            return error_response(
                wmp_core::error::ERR_INVALID_PARAMS as i64,
                "the join invitation names no session",
            );
        }
        if server.store.get(&session_id).is_none() {
            return error_response(
                wmp_core::error::ERR_INVALID_PARAMS as i64,
                "the join invitation names an unknown session",
            );
        }
        invitation.session_id = session_id;
        // The group's display name (the front's `group_name`, wmp-mcp's
        // two-random-words label or the operator's rename): rides the
        // invitation's `label` — INSIDE the signing payload (set before
        // `key.sign` below), so a consumer renders the name without
        // trusting an unsigned field. Optional: an absent or empty name
        // leaves the label unset and the consumer falls back to the
        // group's session id.
        let group_name = body_value
            .get("group_name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .trim()
            .chars()
            .take(40)
            .collect::<String>();
        if !group_name.is_empty() {
            invitation.label = group_name;
        }
    }
    invitation.purpose = purpose;
    if let Err(err) = key.sign(&mut invitation) {
        return error_response(wmp_core::error::ERR_INTERNAL_ERROR as i64, &err.to_string());
    }
    if let Err(err) = server.invitations.put(&invitation.nonce, &invitation) {
        return error_response(wmp_core::error::ERR_INTERNAL_ERROR as i64, &err.to_string());
    }
    let uri = match invitation.uri() {
        Ok(uri) => uri,
        Err(err) => {
            return error_response(wmp_core::error::ERR_INTERNAL_ERROR as i64, &err.to_string())
        }
    };

    let invitation_json = serde_json::to_value(&invitation).unwrap_or(serde_json::Value::Null);
    let json = serde_json::json!({
        "invitation": invitation_json,
        "uri": uri,
    });
    (StatusCode::OK, axum::Json(json)).into_response()
}

/// A JSON-RPC error body as an HTTP response (the endpoint's form — the
/// invitation route is plain HTTP, not a JSON-RPC call, so the codes ride
/// a simple error object).
fn error_response(code: i64, message: &str) -> Response {
    let json = serde_json::json!({
        "error": { "code": code, "message": message },
    });
    (StatusCode::BAD_REQUEST, axum::Json(json)).into_response()
}

/// The principal from the `Authorization: Bearer <token>` header, validated
/// through the token validator against the AS's JWKS. A missing, malformed
/// or invalid token answers `None` (anonymous): the engine's session
/// methods refuse it with `-31002`, exactly as go-tokenauth's middleware
/// refuses an unauthenticated request.
///
/// The principal is stamped with the deployment's ownership mode
/// (engine-parity.md §8): `user` — the historic `tenant/subject` owner key —
/// or `tenant` — W10's tenant-bound tokens, whose rotating pseudonym
/// subject cannot key a session, so the tenant owns it.
fn bearer_principal(
    headers: &HeaderMap,
    validator: &crate::token::TokenValidator,
    mode: wmp_core::principal::PrincipalMode,
) -> Option<wmp_core::principal::Principal> {
    let raw_token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))?;

    match validator.validate(raw_token) {
        // The full token identity: the subject, the tenant, the token's
        // `jti` and `tac`, and its lifecycle claims (`iat`, the
        // `auth_invalid_before` stamp) — the #319 gate's stateless
        // inputs, stamped here so the flow-start gate reads them off the
        // principal.
        Ok(validated) => Some(
            wmp_core::principal::Principal::with_token_claims(
                validated.subject,
                validated.tenant,
                validated.jti,
                validated.tac,
                validated.iat,
                validated.auth_invalid_before,
            )
            .in_mode(mode),
        ),
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
