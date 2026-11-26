//! The MCP tool surface's tests (issue #76): `tools/list`/`tools/call` as
//! profile-registered methods on the peer's registry, gated on the
//! session's negotiated `mcp` capability.
//!
//! The gate's three refusals, each `-31005`:
//!
//! - the engine answers no tools (`ENGINE_MCP_TOOLS=false` — the profile
//!   advertises no capability, so no session ever negotiates it)
//! - the session did not offer `mcp` at the create
//! - the call names no session (the peer resolved none)
//!
//! And the two answers: the list (every tool's name, description, schema)
//! and the call (`wallet.debug.status`/`config`), plus the `-32602` an
//! unknown tool answers.

use std::sync::Arc;

use serde_json::{json, Value};
use wmp_core::context::RequestContext;
use wmp_core::peer::{Peer, PeerBuilder};
use wmp_core::principal::Principal;
use wmp_core::session::MemorySessionStore;
use wmp_core::sessionservice::{SessionHandler, SessionService, SessionServiceConfig};
use wmp_core::types::Capabilities;

use engine_adapter_server::mcp_tools::{McpToolProfile, CAPABILITY_MCP};

/// A fixed clock (the session service's `now`).
fn fixed_clock() -> wmp_core::sessionservice::Clock {
    let now = std::sync::atomic::AtomicI64::new(1_000_000);
    Arc::new(move || now.load(std::sync::atomic::Ordering::SeqCst))
}

/// Deterministic "randomness" (the session id entropy): a counter.
fn counter_entropy() -> wmp_core::sessionservice::EntropyFn {
    let counter = std::sync::atomic::AtomicU64::new(0);
    Arc::new(move |bytes: &mut [u8]| {
        let n = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (n.wrapping_shr(i as u32 * 8) & 0xff) as u8;
        }
        true
    })
}

/// The engine-side peer shape: a session service advertising the engine's
/// supported set (flows + `mcp` when `mcp_tools`), the MCP profile registered
/// on the peer's registry — [crate::build_peer]'s wiring, in test form.
fn mcp_peer(mcp_tools: bool) -> Arc<Peer> {
    let store = Arc::new(MemorySessionStore::new());
    let mut supported = Capabilities(
        [(
            "flows".to_owned(),
            serde_json::from_str::<Box<serde_json::value::RawValue>>(r#"{"max_flows":16}"#)
                .expect("parse flows capability"),
        )]
        .into_iter()
        .collect(),
    );
    if mcp_tools {
        let params = serde_json::to_value(McpToolProfile::new(true).capability())
            .expect("the mcp capability serializes");
        let raw = serde_json::from_str::<Box<serde_json::value::RawValue>>(
            &serde_json::to_string(&params).expect("serializes"),
        )
        .expect("the mcp capability round-trips");
        supported.0.insert(CAPABILITY_MCP.to_owned(), raw);
    }
    let service = Arc::new(
        SessionService::new(SessionServiceConfig {
            store: Some(store.clone()),
            supported,
            entropy: Some(counter_entropy()),
            ..SessionServiceConfig::default()
        })
        .expect("the service config is valid"),
    );
    let handler = Arc::new(SessionHandler::new(service, fixed_clock()));
    PeerBuilder::new(handler)
        .session_store(store.clone())
        .profile(Arc::new(
            McpToolProfile::new(mcp_tools).with_clock(fixed_clock()),
        ))
        .expect("register the mcp profile")
        .build()
}

/// The request context a principal rides.
fn ctx() -> RequestContext {
    RequestContext {
        principal: Some(Principal::new("wallet", "")),
        ..RequestContext::default()
    }
}

/// `wmp.session.create` offering `mcp` (unless `offer_mcp` is false),
/// answering the negotiated session id. The negotiated capabilities ride
/// the result too (the assertions' source).
fn create_session(peer: &Arc<Peer>, offer_mcp: bool) -> (String, RequestContext) {
    let mut params = json!({
        "wmp": { "version": "0.1" },
        "capabilities_offered": { "flows": {} },
    });
    if offer_mcp {
        params["capabilities_offered"][CAPABILITY_MCP] = json!({});
    }
    let body = json!({
        "jsonrpc": "2.0",
        "id": "c1",
        "method": "wmp.session.create",
        "params": params,
    });
    let response = peer
        .handle_request_sync(&ctx(), &serde_json::to_vec(&body).expect("serializes"))
        .expect("create answers a response")
        .expect("create answers a result");
    let value: Value = serde_json::from_slice(&response).expect("a JSON response");
    let session_id = value["result"]["wmp"]["session_id"]
        .as_str()
        .expect("the session id")
        .to_owned();
    // The per-session context: the session the tools calls name.
    let mut session_ctx = ctx();
    session_ctx.session = Some(wmp_core::session::Session {
        id: session_id.clone(),
        capabilities: serde_json::from_value(value["result"]["capabilities"].clone())
            .expect("the negotiated capabilities parse"),
        ..Default::default()
    });
    (session_id, session_ctx)
}

/// One request against the peer, answering the parsed result or the
/// JSON-RPC error object.
fn request(
    peer: &Arc<Peer>,
    ctx: &RequestContext,
    method: &str,
    params: Value,
) -> Result<Value, Value> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": "r1",
        "method": method,
        "params": params,
    });
    let response = peer
        .handle_request_sync(ctx, &serde_json::to_vec(&body).expect("serializes"))
        .expect("the request answers a response")
        .expect("the request answers a payload");
    let value: Value = serde_json::from_slice(&response).expect("a JSON response");
    match value.get("error") {
        Some(_) => Err(value),
        None => Ok(value["result"].clone()),
    }
}

#[test]
fn a_session_offering_mcp_negotiates_the_capability_and_lists_tools() {
    let peer = mcp_peer(true);
    let (_, session_ctx) = create_session(&peer, true);
    // The negotiation carried the `mcp` params (the supported side's).
    let session = session_ctx.session.as_ref().expect("the session");
    assert!(
        session.capabilities.0.contains_key(CAPABILITY_MCP),
        "the session negotiated the mcp capability"
    );
    let list = request(&peer, &session_ctx, "tools/list", json!({})).expect("the list answers");
    let tools = list["tools"].as_array().expect("the list carries tools");
    assert!(tools
        .iter()
        .any(|tool| tool["name"] == "wallet.debug.status"));
    assert!(tools
        .iter()
        .any(|tool| tool["name"] == "wallet.debug.config"));
    // Every tool carries its description and schema.
    for tool in tools {
        assert!(!tool["description"].as_str().unwrap_or("").is_empty());
        assert!(tool["inputSchema"].is_object());
    }
}

#[test]
fn a_session_not_offering_mcp_refuses_every_tools_call() {
    let peer = mcp_peer(true);
    let (_, session_ctx) = create_session(&peer, false);
    let err = request(&peer, &session_ctx, "tools/list", json!({})).expect_err("the list refuses");
    assert_eq!(
        err["error"]["code"],
        wmp_core::error::ERR_CAPABILITY_NOT_SUPPORTED
    );
    let err = request(
        &peer,
        &session_ctx,
        "tools/call",
        json!({ "name": "wallet.debug.status" }),
    )
    .expect_err("the call refuses");
    assert_eq!(
        err["error"]["code"],
        wmp_core::error::ERR_CAPABILITY_NOT_SUPPORTED
    );
}

#[test]
fn a_call_naming_no_session_refuses() {
    let peer = mcp_peer(true);
    let _ = create_session(&peer, true);
    let err =
        request(&peer, &ctx(), "tools/list", json!({})).expect_err("the no-session call refuses");
    assert_eq!(
        err["error"]["code"],
        wmp_core::error::ERR_CAPABILITY_NOT_SUPPORTED
    );
}

/// Issue #104: a session the call NAMED but the store no longer holds
/// (the engine restarted and lost its in-memory table, or the id went
/// stale) answers the session's own `-31000` — the code the SDKs'
/// session recovery re-creates and retries on — not the capability's
/// `-31005`, which reads as "the server does not support this" and
/// bricked the wallet until a hard app restart (gdc 2026-11-24).
#[test]
fn a_call_naming_a_session_the_store_lost_answers_the_sessions_own_not_found() {
    let peer = mcp_peer(true);
    let _ = create_session(&peer, true);
    let err = request(
        &peer,
        &ctx(),
        "tools/list",
        json!({ "wmp": { "session_id": "ses-lost-in-the-restart" } }),
    )
    .expect_err("the lost-session call refuses");
    assert_eq!(
        err["error"]["code"],
        wmp_core::error::ERR_SESSION_NOT_FOUND,
        "the named-but-unresolved session is the session's semantics: {err}"
    );
    assert_eq!(
        err["error"]["data"]["session_id"], "ses-lost-in-the-restart",
        "the refusal names the lost session: {err}"
    );
    assert_eq!(
        err["error"]["data"]["capability"], CAPABILITY_MCP,
        "the refusal names the capability the recovery re-negotiates: {err}"
    );
}

/// Issue #104, the #48 mirror: a resolved but expired record answers
/// `-31001` Session expired — the recovery path re-creates the session —
/// instead of running the tool against a dead record.
#[test]
fn an_expired_sessions_tools_call_answers_session_expired() {
    let peer = mcp_peer(true);
    let _ = create_session(&peer, true);
    // A session the store resolved but whose TTL the clock has passed:
    // the fixed clock reads 1_000_000, the record expired at 999_000.
    let mut expired_ctx = ctx();
    expired_ctx.session = Some(wmp_core::session::Session {
        id: "ses-expired".to_owned(),
        expires_at: Some(999_000),
        capabilities: Capabilities::default(),
        ..Default::default()
    });
    let err = request(
        &peer,
        &expired_ctx,
        "tools/list",
        json!({ "wmp": { "session_id": "ses-expired" } }),
    )
    .expect_err("the expired-session call refuses");
    assert_eq!(
        err["error"]["code"],
        wmp_core::error::ERR_SESSION_EXPIRED,
        "the expired record answers the session's semantics: {err}"
    );
}

#[test]
fn an_engine_opting_out_refuses_even_the_offering_session() {
    let peer = mcp_peer(false);
    let (_, session_ctx) = create_session(&peer, true);
    let err = request(&peer, &session_ctx, "tools/list", json!({}))
        .expect_err("the opted-out engine refuses");
    assert_eq!(
        err["error"]["code"],
        wmp_core::error::ERR_CAPABILITY_NOT_SUPPORTED
    );
}

#[test]
fn a_call_answers_the_debug_tool_and_an_unknown_tool_refuses() {
    let peer = mcp_peer(true);
    let (_, session_ctx) = create_session(&peer, true);
    let call = request(
        &peer,
        &session_ctx,
        "tools/call",
        json!({ "name": "wallet.debug.status", "arguments": {} }),
    )
    .expect("the debug call answers");
    let content = call["content"].as_array().expect("the answer's content");
    assert_eq!(content[0]["type"], "text");
    assert!(!content[0]["text"].as_str().unwrap_or("").is_empty());

    let err = request(
        &peer,
        &session_ctx,
        "tools/call",
        json!({ "name": "wallet.not-a-tool" }),
    )
    .expect_err("the unknown tool refuses");
    assert_eq!(err["error"]["code"], wmp_core::error::ERR_INVALID_PARAMS);
}
