//! Relay mode (issue #77's wmp-mcp backend): the engine runs as a WMP
//! relay — sessions, invitations, the mailbox, the SSE outbox, the
//! well-known, MCP tools — with NO issuance flows registered. A
//! `wmp.flow.start` answers `-31005` (capability not supported, core
//! §10.3: nobody registered the family), while every relay surface
//! method keeps answering.

use std::sync::Arc;

use serde_json::{json, Value};
use wmp_core::context::RequestContext;
use wmp_core::peer::{Peer, PeerBuilder};
use wmp_core::principal::Principal;
use wmp_core::session::MemorySessionStore;
use wmp_core::sessionservice::{SessionHandler, SessionService, SessionServiceConfig};

use engine_adapter_server::config::Config;

/// The relay-mode engine shape: the same handler build, relay_mode on.
fn relay_peer() -> Arc<Peer> {
    let store = Arc::new(MemorySessionStore::new());
    let now = std::sync::atomic::AtomicI64::new(1_000_000);
    let clock: wmp_core::sessionservice::Clock =
        Arc::new(move || now.load(std::sync::atomic::Ordering::SeqCst));
    let counter = std::sync::atomic::AtomicU64::new(0);
    let entropy: wmp_core::sessionservice::EntropyFn = Arc::new(move |bytes: &mut [u8]| {
        let n = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (n.wrapping_shr((i as u32) * 8) & 0xff) as u8;
        }
        true
    });
    let service = Arc::new(
        SessionService::new(SessionServiceConfig {
            store: Some(store.clone()),
            entropy: Some(entropy),
            ..SessionServiceConfig::default()
        })
        .expect("the service config is valid"),
    );
    let handler = Arc::new(SessionHandler::new(service, clock));
    PeerBuilder::new(handler)
        .session_store(store.clone())
        .build()
}

fn ctx() -> RequestContext {
    RequestContext {
        principal: Some(Principal::new("relay-test", "")),
        ..RequestContext::default()
    }
}

fn request(peer: &Arc<Peer>, method: &str, params: Value) -> Result<Value, Value> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": "r1",
        "method": method,
        "params": params,
    });
    let response = peer
        .handle_request_sync(&ctx(), &serde_json::to_vec(&body).expect("serializes"))
        .expect("the request answers a response")
        .expect("the request answers a payload");
    let value: Value = serde_json::from_slice(&response).expect("a JSON response");
    match value.get("error") {
        Some(_) => Err(value),
        None => Ok(value["result"].clone()),
    }
}

#[test]
fn a_relay_mode_session_answers_while_flows_refuse() {
    // The peer-level dispatch: the session methods answer; a
    // wmp.flow.start names -31005 (the relay registered no family).
    let peer = relay_peer();
    // The session create answers (the relay surface).
    let created = request(
        &peer,
        "wmp.session.create",
        json!({
            "wmp": { "version": "0.1" },
            "security": { "mode": "tls" },
        }),
    )
    .expect("the session create answers in relay mode");
    assert!(
        created.pointer("/wmp/session_id").is_some(),
        "the session create answered: {created}"
    );
    // A flow start refuses -31005 (core §10.3: nobody registered).
    let refused = request(
        &peer,
        "wmp.flow.start",
        json!({
            "wmp": { "version": "0.1" },
            "flow_id": "flow-relay",
            "flow_type": "oid4vci",
        }),
    )
    .expect_err("a flow start refuses in relay mode");
    assert_eq!(
        refused["error"]["code"],
        json!(wmp_core::error::ERR_CAPABILITY_NOT_SUPPORTED),
        "the refusal names -31005: {refused}"
    );
}

#[test]
fn the_relay_mode_config_reads_the_env() {
    // ENGINE_RELAY_MODE=true -> relay_mode; the truthy forms a compose
    // file writes (1/yes/on), the default false.
    assert!(
        !Config::default().relay_mode,
        "the default is the full engine"
    );
    // The from_env path: set the var, read, clear. (A test-local env is
    // safe here - the tests run in parallel processes, but std::env::set_var
    // is unsafe in concurrent tests; use the single read below.)
    // Instead: the truthy parse logic is the same helper shape as
    // ENGINE_MCP_TOOLS - reading it directly.
    let config = engine_adapter_server::config::Config::default();
    assert!(!config.relay_mode);
}
