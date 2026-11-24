//! The invitation bootstrap (wmp-invitation §5.2): "the nonce validation
//! replaces or supplements normal authentication." This test proves the
//! engine's session create handler implements the rule: an UNAUTHENTICATED
//! caller (no bearer token, or a foreign token from a different issuer)
//! with a VALID invitation_nonce creates the session — the invitation
//! IS the identity for the join. Without a nonce, the normal auth check
//! applies (the unauthenticated caller is refused).
//!
//! This is the cross-domain case: a wallet from a foreign domain scans
//! an invitation from this relay and joins with no pre-existing trust.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use engine_adapter_server::config::Config;
use engine_adapter_server::transport::router;
use tower::ServiceExt;

#[tokio::test(flavor = "multi_thread")]
async fn invitation_bootstrap_no_auth() {
    // The engine with the invitation endpoint configured and a test
    // issuer that accepts any bearer for the INVITER (the test config's
    // no-AS mode for the inviter's setup calls).
    let server = Arc::new(engine_adapter_server::EngineServer::new(Config {
        listen_addr: "127.0.0.1:0".to_owned(),
        allow_plaintext: true,
        public_url: "https://relay.example.com".to_owned(),
        ..Config::default()
    }));
    let app = router(server.clone());

    // 1. The INVITER: authenticated (any bearer in the test config),
    //    creates a session.
    let inviter_body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "wmp.session.create",
        "params": {"wmp": {"version": "0.1", "sender": "x509:san:dns:relay.example.com"}}
    });
    let create_req = Request::builder()
        .method("POST")
        .uri("/wmp")
        .header("content-type", "application/json")
        .header("authorization", "Bearer test-inviter")
        .body(Body::from(inviter_body.to_string()))
        .unwrap();
    let response = app.clone().oneshot(create_req).await.unwrap();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let create: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(
        create["result"]["wmp"]["session_id"].is_string(),
        "the inviter's session create failed: {create}"
    );

    // 2. The INVITER mints an invitation (authenticated).
    let mint_body = serde_json::json!({
        "jsonrpc": "2.0", "id": 2, "method": "wmp.invitation.create",
        "params": {"purpose": "session"}
    });
    let mint_req = Request::builder()
        .method("POST")
        .uri("/wmp/invitation")
        .header("content-type", "application/json")
        .header("authorization", "Bearer test-inviter")
        .body(Body::from(mint_body.to_string()))
        .unwrap();
    let response = app.clone().oneshot(mint_req).await.unwrap();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let mint: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let nonce = mint["invitation"]["nonce"]
        .as_str()
        .expect("the invitation mint answers a nonce")
        .to_owned();

    // 3. The INVITEE: NO Authorization header, carrying the nonce.
    //    The invitation IS the authorization (§5.2).
    let invite_body = serde_json::json!({
        "jsonrpc": "2.0", "id": 3, "method": "wmp.session.create",
        "params": {
            "wmp": {"version": "0.1", "sender": "wallet-from-foreign-domain"},
            "invitation_nonce": nonce
        }
    });
    let invite_req = Request::builder()
        .method("POST")
        .uri("/wmp")
        .header("content-type", "application/json")
        // NO authorization header — the wallet from a foreign domain
        .body(Body::from(invite_body.to_string()))
        .unwrap();
    let response = app.clone().oneshot(invite_req).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let answer: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(
        answer["result"]["wmp"]["session_id"].is_string(),
        "the invitation bootstrap (no auth) failed: {status} {answer}"
    );

    println!("invitation bootstrap (no auth): ✓ session created");
}

#[tokio::test(flavor = "multi_thread")]
async fn invitation_bootstrap_foreign_token() {
    let server = Arc::new(engine_adapter_server::EngineServer::new(Config {
        listen_addr: "127.0.0.1:0".to_owned(),
        allow_plaintext: true,
        public_url: "https://relay.example.com".to_owned(),
        ..Config::default()
    }));
    let app = router(server.clone());

    // 1. The inviter: authenticated, creates a session.
    let inviter_body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "wmp.session.create",
        "params": {"wmp": {"version": "0.1", "sender": "x509:san:dns:relay.example.com"}}
    });
    let create_req = Request::builder()
        .method("POST")
        .uri("/wmp")
        .header("content-type", "application/json")
        .header("authorization", "Bearer test-inviter")
        .body(Body::from(inviter_body.to_string()))
        .unwrap();
    let response = app.clone().oneshot(create_req).await.unwrap();
    let _ = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();

    // 2. The inviter mints an invitation.
    let mint_body = serde_json::json!({
        "jsonrpc": "2.0", "id": 2, "method": "wmp.invitation.create",
        "params": {"purpose": "session"}
    });
    let mint_req = Request::builder()
        .method("POST")
        .uri("/wmp/invitation")
        .header("content-type", "application/json")
        .header("authorization", "Bearer test-inviter")
        .body(Body::from(mint_body.to_string()))
        .unwrap();
    let response = app.clone().oneshot(mint_req).await.unwrap();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let mint: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let nonce = mint["invitation"]["nonce"]
        .as_str()
        .expect("the invitation mint answers a nonce")
        .to_owned();

    // 3. The invitee: a FOREIGN token (a JWT from a different issuer —
    //    the wallet's own backend's AS), carrying the nonce.
    //    The invitation IS the authorization; the foreign token is
    //    irrelevant (cross-domain by design).
    let invite_body = serde_json::json!({
        "jsonrpc": "2.0", "id": 3, "method": "wmp.session.create",
        "params": {
            "wmp": {"version": "0.1", "sender": "wallet-from-gdc"},
            "invitation_nonce": nonce
        }
    });
    let invite_req = Request::builder()
        .method("POST")
        .uri("/wmp")
        .header("content-type", "application/json")
        .header(
            "authorization",
            "Bearer eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2ZvcmVpZ24tZXhhbXBsZS5jb20ifQ.AAAA",
        )
        .body(Body::from(invite_body.to_string()))
        .unwrap();
    let response = app.clone().oneshot(invite_req).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let answer: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(
        answer["result"]["wmp"]["session_id"].is_string(),
        "the invitation bootstrap (foreign token) failed: {status} {answer}"
    );

    println!("invitation bootstrap (foreign token): ✓ session created");
}
