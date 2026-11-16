//! The tenant-bound principal mode (engine-parity.md §8, W10): the
//! session-ownership rules that follow from the tenant owning the session
//! — the rotating pseudonym `sub` cannot key it (G1).
//!
//! Driven through the `SessionService` exactly as the transport drives it:
//! `wmp.session.create` under one principal, `wmp.session.resume` under
//! another. The resumption token rotates on every resume, so each act
//! uses the token the previous one answered.

use std::sync::Arc;

use wmp_core::context::RequestContext;
use wmp_core::peer::{Peer, PeerBuilder};
use wmp_core::principal::{Principal, PrincipalMode};
use wmp_core::session::{MemorySessionStore, SessionStore};
use wmp_core::sessionservice::{SessionHandler, SessionService, SessionServiceConfig};

/// A deterministic entropy source: every call yields a different counter
/// value, so session ids and resumption tokens are distinct per request.
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

/// A session service over an in-memory store, with deterministic entropy,
/// and the peer that dispatches to it.
fn service_peer() -> (Arc<Peer>, Arc<dyn SessionStore>) {
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
    let peer = PeerBuilder::new(handler)
        .session_store(store.clone())
        .build();
    (peer, store)
}

/// A tenant-mode principal: the token's pseudonym `sub` in its `tenant`.
fn tenant_principal(pseudonym: &str, tenant: &str) -> Principal {
    Principal::new(pseudonym, tenant).in_mode(PrincipalMode::Tenant)
}

/// The request context a principal rides.
fn ctx(principal: Principal) -> RequestContext {
    RequestContext {
        principal: Some(principal),
        ..RequestContext::default()
    }
}

/// `wmp.session.create` under `ctx`, answering the negotiated session id
/// and the resumption token.
fn create_session(peer: &Arc<Peer>, ctx: &RequestContext) -> (String, String) {
    let response = peer
        .handle_request_sync(
            ctx,
            br#"{"jsonrpc":"2.0","id":"c1","method":"wmp.session.create","params":{"wmp":{"version":"0.1"}}}"#,
        )
        .expect("create answers a response")
        .expect("create answers a result");
    let value: serde_json::Value = serde_json::from_slice(&response).expect("a JSON response");
    let result = &value["result"];
    let session_id = result["wmp"]["session_id"]
        .as_str()
        .expect("the session id")
        .to_owned();
    let token = result["resumption_token"]
        .as_str()
        .expect("the resumption token")
        .to_owned();
    (session_id, token)
}

/// `wmp.session.resume` under `ctx` with the rotated `token`.
fn resume_session(
    peer: &Arc<Peer>,
    ctx: &RequestContext,
    session_id: &str,
    token: &str,
) -> serde_json::Value {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "r1",
        "method": "wmp.session.resume",
        "params": {
            "wmp": { "version": "0.1" },
            "session_id": session_id,
            "resumption_token": token,
        }
    });
    let response = peer
        .handle_request_sync(ctx, &serde_json::to_vec(&body).expect("serializes"))
        .expect("resume answers a response")
        .expect("resume answers a result");
    serde_json::from_slice(&response).expect("a JSON response")
}

#[test]
fn a_tenant_principal_resumes_the_session_a_different_pseudonym_created() {
    // G1 (engine-parity.md §8): the tenant-bound token's `sub` is a
    // rotating pseudonym — a fresh mint on every token refresh — so the
    // second token's principal differs from the one that created the
    // session, and the tenant's session must still resume. The
    // resumption token (single-use, rotated on every resume) is the
    // per-session security, not the subject.
    let (peer, _store) = service_peer();
    let creator = ctx(tenant_principal("pseudonym-one", "acme"));
    let (session_id, token) = create_session(&peer, &creator);

    // A different pseudonym of the SAME tenant resumes with the token
    // the create answered.
    let successor = ctx(tenant_principal("pseudonym-two", "acme"));
    let resumed = resume_session(&peer, &successor, &session_id, &token);
    assert!(
        resumed["result"]["wmp"]["session_id"].as_str() == Some(session_id.as_str()),
        "the successor pseudonym of the same tenant resumes: {resumed}"
    );
}

#[test]
fn a_cross_tenant_resume_still_refuses() {
    // The tenant owns: a principal of ANOTHER tenant reaches nothing of
    // the first tenant's, not with a stolen session id and token shape.
    let (peer, _store) = service_peer();
    let creator = ctx(tenant_principal("pseudonym-one", "acme"));
    let (session_id, token) = create_session(&peer, &creator);

    let other = ctx(tenant_principal("pseudonym-two", "globex"));
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "r2",
        "method": "wmp.session.resume",
        "params": {
            "wmp": { "version": "0.1" },
            "session_id": session_id,
            "resumption_token": token,
        }
    });
    let response = peer
        .handle_request_sync(&other, &serde_json::to_vec(&body).expect("serializes"))
        .expect("resume answers a response")
        .expect("resume answers a response body");
    let value: serde_json::Value = serde_json::from_slice(&response).expect("a JSON response");
    assert!(
        value["error"]["code"].as_i64().is_some_and(|code| code < 0),
        "the cross-tenant resume refuses with a WMP error: {value}"
    );
}

#[test]
fn a_tenant_mode_principal_without_a_tenant_creates_no_session() {
    // G3's token kind always claims a tenant. One that does not owns
    // nothing in the tenant mode: the create refuses, rather than
    // creating a session no principal can ever resume.
    let (peer, store) = service_peer();
    let unowned = ctx(tenant_principal("pseudonym", ""));
    let body = br#"{"jsonrpc":"2.0","id":"c2","method":"wmp.session.create","params":{"wmp":{"version":"0.1"}}}"#;
    let response = peer
        .handle_request_sync(&unowned, body)
        .expect("create answers a response")
        .expect("create answers a result");
    let value: serde_json::Value = serde_json::from_slice(&response).expect("a JSON response");
    assert!(
        value["error"]["code"].as_i64().is_some_and(|code| code < 0),
        "the tenantless principal creates nothing: {value}"
    );
    assert!(
        store
            .list(1_730_000_000)
            .map(|sessions| sessions.is_empty())
            .unwrap_or(false),
        "no orphaned session was stored"
    );
}

#[test]
fn user_mode_ownership_is_unchanged() {
    // The default mode keys the historic way: a different user of the
    // same tenant does NOT resume the first one's session.
    let (peer, _store) = service_peer();
    let creator = ctx(Principal::new("alice", "acme"));
    let (session_id, token) = create_session(&peer, &creator);

    let other = ctx(Principal::new("bob", "acme"));
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "r3",
        "method": "wmp.session.resume",
        "params": {
            "wmp": { "version": "0.1" },
            "session_id": session_id,
            "resumption_token": token,
        }
    });
    let response = peer
        .handle_request_sync(&other, &serde_json::to_vec(&body).expect("serializes"))
        .expect("resume answers a response")
        .expect("resume answers a response body");
    let value: serde_json::Value = serde_json::from_slice(&response).expect("a JSON response");
    assert!(
        value["error"]["code"].as_i64().is_some_and(|code| code < 0),
        "another user of the same tenant does not resume it: {value}"
    );
}
