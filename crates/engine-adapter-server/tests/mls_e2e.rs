//! The engine's MLS surface (the `mls` feature): the `wmp.mls.*` methods
//! answering through the peer's registry — the handler bridge over the
//! OpenMLS provider. The level-3 chain's engine leg.
//!
//! Requires the `mls` feature (the profile registers only under it); the
//! suite is `#![cfg(feature = "mls")`-gated so the default build skips it.

#![cfg(feature = "mls")]

use std::sync::Arc;

use serde_json::{json, Value};
use wmp_core::context::RequestContext;
use wmp_core::peer::{Peer, PeerBuilder};
use wmp_core::principal::Principal;
use wmp_core::session::MemorySessionStore;
use wmp_core::sessionservice::{SessionHandler, SessionService, SessionServiceConfig};

/// A fixed clock.
fn fixed_clock() -> wmp_core::sessionservice::Clock {
    let now = std::sync::atomic::AtomicI64::new(1_000_000);
    Arc::new(move || now.load(std::sync::atomic::Ordering::SeqCst))
}

/// Deterministic "randomness".
fn counter_entropy() -> wmp_core::sessionservice::EntropyFn {
    let counter = std::sync::atomic::AtomicU64::new(0);
    Arc::new(move |bytes: &mut [u8]| {
        let n = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (n.wrapping_shr((i as u32) * 8) & 0xff) as u8;
        }
        true
    })
}

/// The engine-shape peer (the handler + the MlsProfile registered), the
/// engine's own member identity.
fn mls_peer() -> Arc<Peer> {
    let store = Arc::new(MemorySessionStore::new());
    let service = Arc::new(
        SessionService::new(SessionServiceConfig {
            store: Some(store.clone()),
            entropy: Some(counter_entropy()),
            ..SessionServiceConfig::default()
        })
        .expect("the service config is valid"),
    );
    let handler = Arc::new(SessionHandler::new(service, fixed_clock()));
    let provider = wmp_mls::OpenMlsProvider::for_identity("engine").expect("the provider");
    let mls_handler = wmp_mls::EngineMlsHandler::new(provider);
    PeerBuilder::new(handler)
        .session_store(store.clone())
        .profile(wmp_core::mls::MlsProfile::new(Arc::new(mls_handler)))
        .expect("register the mls profile")
        .build()
}

fn ctx() -> RequestContext {
    RequestContext {
        principal: Some(Principal::new("wallet", "")),
        ..RequestContext::default()
    }
}

/// One request against the peer.
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
fn a_group_create_answers_the_callers_named_group() {
    let peer = mls_peer();
    // The caller names the group (the params' group_id); the create
    // answers it with the epoch 0.
    let created = request(
        &peer,
        "wmp.mls.group.create",
        json!({
            "wmp": { "version": "0.1" },
            "group_id": "grp-test-1",
            "cipher_suite": 1,
            "group_info": "",
            "welcomes": {},
        }),
    )
    .expect("the create answers");
    assert_eq!(created["group_id"], json!("grp-test-1"));
    assert_eq!(created["epoch"], json!(0));
    // The welcomes-naming create (participants) is the add flow's shape:
    // the create refuses it (-32602), never mints placeholder Welcomes.
    let refused = request(
        &peer,
        "wmp.mls.group.create",
        json!({
            "wmp": { "version": "0.1" },
            "group_id": "grp-test-2",
            "cipher_suite": 1,
            "group_info": "",
            "welcomes": { "wallet-b": "welcome" },
        }),
    )
    .expect_err("the participant-naming create refuses");
    assert_eq!(
        refused["error"]["code"],
        json!(wmp_core::error::ERR_INVALID_PARAMS)
    );
}

#[test]
fn a_join_announces_the_processed_welcome() {
    let peer = mls_peer();
    // A join without the processed Welcome refuses (-32602).
    let refused = request(
        &peer,
        "wmp.mls.group.join",
        json!({
            "wmp": { "version": "0.1" },
            "welcome_processed": false,
        }),
    )
    .expect_err("the unprocessed join refuses");
    assert_eq!(
        refused["error"]["code"],
        json!(wmp_core::error::ERR_INVALID_PARAMS)
    );
}

#[test]
fn an_add_and_a_removal_answer_the_callers_staging() {
    let peer = mls_peer();
    // A group exists (the create); the add carries the caller's staged
    // commit + welcome.
    let _ = request(
        &peer,
        "wmp.mls.group.create",
        json!({
            "wmp": { "version": "0.1" },
            "group_id": "grp-lifecycle",
            "cipher_suite": 1,
            "group_info": "",
            "welcomes": {},
        }),
    )
    .expect("the create answers");
    let added = request(
        &peer,
        "wmp.mls.group.add",
        json!({
            "wmp": { "version": "0.1" },
            "participant": "wallet-b",
            "commit": "commit",
            "welcome": "welcome",
        }),
    )
    .expect("the add answers");
    assert!(added.get("epoch").is_some(), "the add names its epoch");
    let removed = request(
        &peer,
        "wmp.mls.group.remove",
        json!({
            "wmp": { "version": "0.1" },
            "participant": "wallet-b",
            "commit": "commit",
        }),
    )
    .expect("the removal answers");
    assert!(removed.get("epoch").is_some(), "the removal names its epoch");
    // The update notification answers empty (no result).
    let updated = peer
        .handle_request_sync(
            &ctx(),
            &serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "method": "wmp.mls.group.update",
                "params": {
                    "wmp": { "version": "0.1" },
                    "commit": "commit",
                },
            }))
            .expect("serializes"),
        )
        .expect("the update answers a response");
    // A notification: no id, no result expected back (the registry may
    // answer an empty payload).
    let _ = updated;
}

#[test]
fn a_fetch_answers_the_page_shape() {
    let peer = mls_peer();
    let fetched = request(
        &peer,
        "wmp.message.fetch",
        json!({
            "wmp": { "version": "0.1" },
            "since_epoch": 0,
            "sessions": [],
        }),
    )
    .expect("the fetch answers");
    assert_eq!(fetched["messages"], json!([]));
    assert_eq!(fetched["has_more"], json!(false));
}