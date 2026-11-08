//! The tenant-bound principal mode (engine-parity.md §8, W10), driven
//! through the transport exactly as a wallet drives it: a bearer token
//! from the AS's JWKS, `ENGINE_PRINCIPAL_MODE`'s gate at each flow start.
//!
//! The gate's two halves (G2): the stateless `auth_invalid_before` claim
//! the AS stamped at issue, and the store-backed cut-off — keyed, in tenant
//! mode, by the **tenant** (the token's `sub` is a rotating pseudonym
//! with no store identity). The per-token revocation (G2's mitigation):
//! a `jti` pushed to the engine's blacklist refuses every later bearer
//! of that token.

use std::sync::Arc;

use axum::body::Body;
use axum::http::Request;
use engine_adapter_server::config::Config;
use engine_adapter_server::EngineServer;
use tower::ServiceExt;

/// Serves the JWKS document on a local port, every path answering it
/// (the same shape as the token-config tests').
async fn serve_jwks(jwks: &'static str) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                let n = socket.read(&mut buffer).await.unwrap_or(0);
                let _head = String::from_utf8_lossy(&buffer[..n]).into_owned();
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
                    jwks.len(),
                    jwks
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    format!("http://{addr}")
}

/// The AS's access token, with the claims the engine reads: the subject
/// (W10's rotating pseudonym in tenant mode), the tenant, the `jti`, the
/// `tac`, and the #319 lifecycle stamp (`iat` and the
/// `auth_invalid_before` it predates or does not).
fn access_token(
    jwk: &jose_rs::jwk::Jwk,
    issuer: &str,
    subject: &str,
    tenant: &str,
    jti: &str,
    tac: &str,
    iat: i64,
    auth_invalid_before: Option<i64>,
) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() + 3600)
        .unwrap_or_default();
    let mut extra = std::collections::HashMap::new();
    extra.insert(
        "tenant".to_owned(),
        serde_json::Value::String(tenant.to_owned()),
    );
    extra.insert("tac".to_owned(), serde_json::Value::String(tac.to_owned()));
    if let Some(before) = auth_invalid_before {
        extra.insert(
            "auth_invalid_before".to_owned(),
            serde_json::Value::Number(before.into()),
        );
    }
    let claims = jose_rs::jwt::Claims {
        iss: Some(issuer.to_owned()),
        sub: Some(subject.to_owned()),
        aud: Some(jose_rs::jwt::Audience::Single("wallet-engine".to_owned())),
        exp: Some(jose_rs::jwt::NumericDate::from(now)),
        iat: Some(jose_rs::jwt::NumericDate::from(
            std::time::Duration::from_secs(iat.unsigned_abs()),
        )),
        jti: Some(jti.to_owned()),
        extra,
        ..jose_rs::jwt::Claims::default()
    };
    let mut header = jose_rs::header::JoseHeader::new("ES256");
    header.typ = Some("at+jwt".to_owned());
    header.kid = Some("key-1".to_owned());
    let mut private = jwk.clone();
    private.alg = Some("ES256".to_owned());
    jose_rs::jwt::encode_with_jwk(&private, &header, &claims).expect("the token signs")
}

/// The JWKS document: the public half of the token's key, by its kid.
fn jwks_of(jwk: &jose_rs::jwk::Jwk) -> String {
    let public = jwk
        .to_public_jwk()
        .to_json()
        .expect("the public JWK serializes");
    let mut jwks = serde_json::json!({
        "keys": [serde_json::from_str::<serde_json::Value>(&public).expect("the public JWK parses")]
    });
    if let Some(object) = jwks["keys"][0].as_object_mut() {
        object.insert(
            "kid".to_owned(),
            serde_json::Value::String("key-1".to_owned()),
        );
        object.insert(
            "use".to_owned(),
            serde_json::Value::String("sig".to_owned()),
        );
    }
    jwks.to_string()
}

/// An engine whose AS is the local JWKS server, in `mode`.
async fn tenant_server(
    jwks: &'static str,
    mode: wmp_core::principal::PrincipalMode,
) -> (Arc<EngineServer>, String) {
    let base = serve_jwks(jwks).await;
    let config = Config {
        as_external_url: base.clone(),
        principal_mode: mode,
        ..Config::default()
    };
    (Arc::new(EngineServer::new(config)), base)
}

/// `wmp.flow.start` with the bearer token, answering the JSON-RPC reply.
async fn post_flow_start(
    server: &Arc<EngineServer>,
    token: &str,
    flow_type: &str,
) -> serde_json::Value {
    let app = engine_adapter_server::transport::router(server.clone());
    let request = Request::builder()
        .method("POST")
        .uri("/wmp")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": "req-flow",
                "method": "wmp.flow.start",
                "params": {
                    "wmp": { "version": "0.1" },
                    "flow_id": "flow-gate-1",
                    "flow_type": flow_type,
                    "params": {},
                }
            })
            .to_string(),
        ))
        .expect("build request");
    let response = app.oneshot(request).await.expect("serve");
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("read body");
    serde_json::from_slice(&body).unwrap_or_default()
}

/// The error code a WMP refusal answers, `None` for a result.
fn error_code(reply: &serde_json::Value) -> Option<i64> {
    reply
        .pointer("/error/code")
        .and_then(serde_json::Value::as_i64)
}

/// A fresh tenant token passes the flow-start gate: the reply is anything
/// but the `-31002` the authentication, staleness and TAC gates answer —
/// here the `-31005` of a flow type nobody registered, which proves the
/// request went past them all.
#[tokio::test(flavor = "multi_thread")]
async fn a_fresh_tenant_token_passes_the_flow_start_gate() {
    let private = jose_rs::jwk::generate::generate_ec("P-256").expect("key");
    let jwks: &'static str = Box::leak(jwks_of(&private).into_boxed_str());
    let (server, base) = tenant_server(jwks, wmp_core::principal::PrincipalMode::Tenant).await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default();
    let token = access_token(
        &private,
        &base,
        "pseudonym-alpha",
        "acme",
        "jti-1",
        "ri",
        now,
        None,
    );
    let reply = post_flow_start(&server, &token, "test.unregistered").await;
    assert_eq!(
        error_code(&reply),
        Some(-31005),
        "the fresh token passes the gates: {reply}"
    );
}

/// The stateless cut-off (G2): a token the AS stamped as predating its
/// tenant's cut-off starts no flow — in tenant mode the same as in user
/// mode, because the claim is about the token, not the subject.
#[tokio::test(flavor = "multi_thread")]
async fn a_stale_tenant_token_starts_no_flow() {
    let private = jose_rs::jwk::generate::generate_ec("P-256").expect("key");
    let jwks: &'static str = Box::leak(jwks_of(&private).into_boxed_str());
    let (server, base) = tenant_server(jwks, wmp_core::principal::PrincipalMode::Tenant).await;
    // Issued at 1000, the tenant's cut-off moved to 2000 after it.
    let token = access_token(
        &private,
        &base,
        "pseudonym-alpha",
        "acme",
        "jti-2",
        "ri",
        1000,
        Some(2000),
    );
    let reply = post_flow_start(&server, &token, "test.unregistered").await;
    assert_eq!(
        error_code(&reply),
        Some(-31002),
        "the cut-off token refuses the flow start: {reply}"
    );
    assert!(
        reply
            .pointer("/error/data/reason")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|reason| reason.contains("cut off")),
        "the reason names the cut-off: {reply}"
    );
}

/// The pseudonym rotation is invisible to the gate: the successor token,
/// whose `sub` is a fresh pseudonym, starts flows exactly as its
/// predecessor did — the gate never keyed the subject (G1/G3).
#[tokio::test(flavor = "multi_thread")]
async fn a_pseudonym_rotation_passes_the_flow_start_gate() {
    let private = jose_rs::jwk::generate::generate_ec("P-256").expect("key");
    let jwks: &'static str = Box::leak(jwks_of(&private).into_boxed_str());
    let (server, base) = tenant_server(jwks, wmp_core::principal::PrincipalMode::Tenant).await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default();
    let first = access_token(
        &private,
        &base,
        "pseudonym-alpha",
        "acme",
        "jti-3a",
        "ri",
        now,
        None,
    );
    let second = access_token(
        &private,
        &base,
        "pseudonym-beta",
        "acme",
        "jti-3b",
        "ri",
        now,
        None,
    );
    for token in [&first, &second] {
        let reply = post_flow_start(&server, token, "test.unregistered").await;
        assert_eq!(
            error_code(&reply),
            Some(-31005),
            "both pseudonyms pass the gate: {reply}"
        );
    }
}

/// A revoked `jti` refuses every later bearer (G2's per-token
/// revocation): the blacklist is consulted on each bearer validation,
/// so the token that passed a moment ago now answers as anonymous.
#[tokio::test(flavor = "multi_thread")]
async fn a_revoked_jti_starts_no_flow() {
    let private = jose_rs::jwk::generate::generate_ec("P-256").expect("key");
    let jwks: &'static str = Box::leak(jwks_of(&private).into_boxed_str());
    let (server, base) = tenant_server(jwks, wmp_core::principal::PrincipalMode::Tenant).await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default();
    let token = access_token(
        &private,
        &base,
        "pseudonym-alpha",
        "acme",
        "jti-revoked",
        "ri",
        now,
        None,
    );

    let before = post_flow_start(&server, &token, "test.unregistered").await;
    assert_eq!(
        error_code(&before),
        Some(-31005),
        "passes before the revocation"
    );

    server.revoke_jti("jti-revoked");
    let after = post_flow_start(&server, &token, "test.unregistered").await;
    assert_eq!(
        error_code(&after),
        Some(-31002),
        "the revoked token answers as anonymous: {after}"
    );
}

/// The user mode is unchanged: the same fresh-token shape passes, and the
/// owner key stays `tenant/subject` (the wmp-core tests' guarantee,
/// here through the transport's principal).
#[tokio::test(flavor = "multi_thread")]
async fn user_mode_gate_is_unchanged() {
    let private = jose_rs::jwk::generate::generate_ec("P-256").expect("key");
    let jwks: &'static str = Box::leak(jwks_of(&private).into_boxed_str());
    let (server, base) = tenant_server(jwks, wmp_core::principal::PrincipalMode::User).await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default();
    let token = access_token(
        &private,
        &base,
        "alice",
        "acme",
        "jti-user-1",
        "ri",
        now,
        None,
    );
    let reply = post_flow_start(&server, &token, "test.unregistered").await;
    assert_eq!(
        error_code(&reply),
        Some(-31005),
        "the user-mode gate passes the same fresh token: {reply}"
    );
    // The stale shape refuses exactly as it did before W10.
    let stale = access_token(
        &private,
        &base,
        "alice",
        "acme",
        "jti-user-2",
        "ri",
        1000,
        Some(2000),
    );
    let reply = post_flow_start(&server, &stale, "test.unregistered").await;
    assert_eq!(
        error_code(&reply),
        Some(-31002),
        "the stale user token still refuses: {reply}"
    );
}
