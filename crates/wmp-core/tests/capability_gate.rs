//! The capability gate at `wmp.flow.start` (core §10.3, #48): a flow type
//! whose capability was not negotiated is refused with `-31005` before the
//! profile sees it — and a start whose session no longer RESOLVES answers
//! the session's own semantics instead, so a client can self-heal.
//!
//! The gdc repro (2026-11-17): a routine engine restart emptied the
//! in-memory session store, and every connected wallet's next
//! `wmp.flow.start` — naming a session the store no longer held — was
//! answered `-31005 Capability not supported` within 110ms. Both SDKs'
//! `WmpSession` recovery re-creates the session and retries on exactly
//! the "Session not found" answer (`-31000`), the code every
//! session-bound method already answers; the capability code sent the
//! investigation into negotiation and bricked the wallets until a full
//! app restart.
//!
//! Driven through the peer exactly as the transport drives it, like
//! `tenant_mode.rs`: raw JSON-RPC over `handle_request_sync`, a session
//! service over an in-memory store, and a profile whose flows require a
//! capability.

use std::sync::Arc;

use serde_json::{json, Value};

use wmp_core::context::RequestContext;
use wmp_core::handler::HandlerError;
use wmp_core::methods::{FlowStartParams, FlowStartResult};
use wmp_core::peer::{Peer, PeerBuilder};
use wmp_core::principal::Principal;
use wmp_core::profile::Profile;
use wmp_core::session::{MemorySessionStore, SessionStore};
use wmp_core::sessionservice::{SessionHandler, SessionService, SessionServiceConfig};
use wmp_core::types::{Capabilities, Metadata};

/// A deterministic entropy source: every call yields a different counter
/// value, so session ids are distinct per request.
fn counter_entropy() -> wmp_core::sessionservice::EntropyFn {
    let counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
    Arc::new(move |bytes: &mut [u8]| {
        let n = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (n >> (i % 8)) as u8;
        }
        true
    })
}

/// A fixed clock: the service never reads the wall clock.
fn fixed_clock() -> wmp_core::sessionservice::Clock {
    Arc::new(|| 1_730_000_000)
}

/// A profile whose every flow requires the `flows` capability (the gate
/// engine-core's families sit behind, engine-parity.md §2), recording the
/// starts that reach it.
struct GatedProfile {
    starts: std::sync::atomic::AtomicUsize,
}

impl GatedProfile {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            starts: std::sync::atomic::AtomicUsize::new(0),
        })
    }
}

impl Profile for GatedProfile {
    fn name(&self) -> String {
        "gated".to_owned()
    }

    fn capabilities(&self) -> Vec<String> {
        Vec::new()
    }

    fn init(&self, _ctx: Arc<dyn wmp_core::profile::PeerContext>) -> Result<(), HandlerError> {
        Ok(())
    }

    fn flow_types(&self) -> Vec<String> {
        vec!["oid4vci".to_owned()]
    }

    fn required_capability(&self, _flow_type: &str) -> String {
        "flows".to_owned()
    }

    fn start_flow(
        &self,
        _ctx: &RequestContext,
        params: &FlowStartParams,
    ) -> Result<FlowStartResult, HandlerError> {
        let _ = self
            .starts
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(FlowStartResult {
            wmp: Metadata::default(),
            flow_id: params.flow_id.clone(),
            flow_type: params.flow_type.clone(),
        })
    }
}

/// A session service over an in-memory store, and the peer that dispatches
/// to it with the gated profile registered: the engine-server shape (a
/// restart is a fresh store with the same profile).
fn gated_peer() -> (Arc<Peer>, Arc<dyn SessionStore>, Arc<GatedProfile>) {
    let store = Arc::new(MemorySessionStore::new());
    let supported = Capabilities(
        [(
            "flows".to_owned(),
            serde_json::from_str::<Box<serde_json::value::RawValue>>(r#"{"max_flows":16}"#)
                .expect("parse capability"),
        )]
        .into_iter()
        .collect(),
    );
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
    let profile = GatedProfile::new();
    let peer = PeerBuilder::new(handler)
        .session_store(store.clone())
        .profile(profile.clone())
        .expect("register the gated profile")
        .build();
    (peer, store, profile)
}

/// `wmp.session.create`, offering the `flows` capability unless
/// `offer_flows` is false, answering the negotiated session id.
fn create_session(peer: &Arc<Peer>, ctx: &RequestContext, offer_flows: bool) -> String {
    let mut params = json!({
        "wmp": { "version": "0.1" },
    });
    if offer_flows {
        params["capabilities_offered"] = json!({ "flows": {} });
    }
    let body = json!({
        "jsonrpc": "2.0",
        "id": "c1",
        "method": "wmp.session.create",
        "params": params,
    });
    let response = peer
        .handle_request_sync(ctx, &serde_json::to_vec(&body).expect("serializes"))
        .expect("create answers a response")
        .expect("create answers a result");
    let value: Value = serde_json::from_slice(&response).expect("a JSON response");
    value["result"]["wmp"]["session_id"]
        .as_str()
        .expect("the session id")
        .to_owned()
}

/// `wmp.flow.start` for `oid4vci` under `ctx`, naming `session_id` in the
/// envelope unless it is empty (the peer's-own start). Answers the parsed
/// JSON-RPC error object, or the result value when the start succeeded.
fn start_flow(peer: &Arc<Peer>, ctx: &RequestContext, session_id: &str) -> Result<Value, Value> {
    let mut wmp = json!({ "version": "0.1" });
    if !session_id.is_empty() {
        wmp["session_id"] = json!(session_id);
    }
    let body = json!({
        "jsonrpc": "2.0",
        "id": "f1",
        "method": "wmp.flow.start",
        "params": {
            "wmp": wmp,
            "flow_id": "flow-gate",
            "flow_type": "oid4vci",
        }
    });
    let response = peer
        .handle_request_sync(ctx, &serde_json::to_vec(&body).expect("serializes"))
        .expect("the start answers a response")
        .expect("the start answers a payload");
    let value: Value = serde_json::from_slice(&response).expect("a JSON response");
    match value.get("error") {
        Some(_) => Err(value),
        None => Ok(value["result"].clone()),
    }
}

/// The request context a principal rides (the authorizer demands one
/// for session create, as tenant_mode.rs drives it).
fn ctx() -> RequestContext {
    RequestContext {
        principal: Some(Principal::new("wallet", "")),
        ..RequestContext::default()
    }
}

/// A start naming a session the store no longer holds — the engine-restart
/// shape (#48's repro: the in-memory store emptied, the wallet's session id
/// naming nothing) — answers `-31000` Session not found, with data naming
/// the session and the capability, and never reaches the profile: the
/// client's session recovery can re-create and retry, instead of reading a
/// capability refusal into it.
#[test]
fn a_start_on_a_session_the_store_no_longer_holds_answers_session_not_found() {
    // The wallet's session, created against the pre-restart store.
    let (before, _store, _profile) = gated_peer();
    let ctx = ctx();
    let session_id = create_session(&before, &ctx, true);

    // The restart: a fresh store, the same profile — the engine-server
    // shape after a machine restart.
    let (after, _store, profile) = gated_peer();
    let answer = start_flow(&after, &ctx, &session_id).expect_err("the start refuses");

    assert_eq!(
        answer["error"]["code"], -31000,
        "the session's own semantics, the same code every session-bound method answers"
    );
    assert_eq!(
        answer["error"]["message"], "Session not found",
        "the message both SDKs' WmpSession recovery keys on"
    );
    assert_eq!(
        answer["error"]["data"]["session_id"], session_id,
        "the data names the gone session"
    );
    assert_eq!(
        answer["error"]["data"]["capability"], "flows",
        "the data names the capability the flow needed"
    );
    assert_eq!(
        profile.starts.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the refusal happens before the profile sees it"
    );
}

/// A start naming a LIVE session that did not negotiate the capability —
/// the genuine refusal — keeps `-31005`: the fail-closed gate of core
/// §10.3, unchanged.
#[test]
fn a_start_on_a_live_session_without_the_capability_answers_31005() {
    let (peer, _store, profile) = gated_peer();
    let ctx = ctx();
    // Created WITHOUT offering `flows`: a live session, nothing negotiated.
    let session_id = create_session(&peer, &ctx, false);

    let answer = start_flow(&peer, &ctx, &session_id).expect_err("the start refuses");

    assert_eq!(
        answer["error"]["code"], -31005,
        "the genuine capability refusal, unchanged"
    );
    assert_eq!(answer["error"]["data"]["capability"], "flows");
    assert_eq!(
        profile.starts.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the refusal happens before the profile sees it"
    );
}

/// A start that names no session at all (the peer's own) keeps the
/// fail-closed `-31005`: nothing counts as negotiated there (core §10.3),
/// and the client lost no session it could re-create.
#[test]
fn a_start_that_names_no_session_fails_closed_with_31005() {
    let (peer, _store, profile) = gated_peer();
    let ctx = ctx();

    let answer = start_flow(&peer, &ctx, "").expect_err("the start refuses");

    assert_eq!(
        answer["error"]["code"], -31005,
        "the peer-own start fails closed, unchanged"
    );
    assert_eq!(profile.starts.load(std::sync::atomic::Ordering::SeqCst), 0);
}

/// A start on a live session that negotiated the capability passes the gate
/// and reaches the profile — the behaviour the three refusals above must
/// not disturb.
#[test]
fn a_start_on_a_negotiating_session_reaches_the_profile() {
    let (peer, _store, profile) = gated_peer();
    let ctx = ctx();
    let session_id = create_session(&peer, &ctx, true);

    let result = start_flow(&peer, &ctx, &session_id).expect("the start passes the gate");

    assert_eq!(result["flow_id"], "flow-gate");
    assert_eq!(
        profile.starts.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the profile ran exactly once"
    );
}
