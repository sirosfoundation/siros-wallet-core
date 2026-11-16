//! The engine's bearer-token validation (`TokenValidator`), driven end to
//! end against the AS trust knobs the deployment configures
//! (`Config::from_env`'s `ENGINE_AS_*`): the derived JWKS URL and issuer
//! (the Go engine's shape) and their explicit overrides (the Go backend's
//! own AS publishes its JWKS under `/auth/.well-known/` and issues with
//! its configured `WALLET_AS_ISSUER`), and the accepted audiences (the
//! engine's own `wallet-engine`; an empty list accepting every audience,
//! the go-tokenauth behaviour the backend's AS relies on).

use engine_adapter_server::config::Config;
use engine_adapter_server::token::TokenValidator;

/// Serves the JWKS document on a local port, every path answering it.
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
                let head = String::from_utf8_lossy(&buffer[..n]).into_owned();
                let path = head.split(' ').nth(1).unwrap_or_default().to_owned();
                let document = jwks.replace("PATH", &path);
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
                    document.len(),
                    document
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    format!("http://{addr}")
}

/// An ES256-signed access token, as the AS issues them.
fn access_token(jwk: &jose_rs::jwk::Jwk, issuer: &str, audience: Option<&str>) -> String {
    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() + 3600)
        .unwrap_or_default();
    let claims = jose_rs::jwt::Claims {
        iss: Some(issuer.to_owned()),
        sub: Some("user-1".to_owned()),
        aud: audience.map(|audience| jose_rs::jwt::Audience::Single(audience.to_owned())),
        exp: Some(jose_rs::jwt::NumericDate::from(exp)),
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
    let mut jwks = serde_json::json!({ "keys": [serde_json::from_str::<serde_json::Value>(&public).expect("the public JWK parses")] });
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

/// The derived JWKS URL: `{as_external_url}/.well-known/jwks.json`, the
/// issuer the `as_external_url` — the Go engine's shape. The token the
/// AS issues validates.
#[tokio::test(flavor = "multi_thread")]
async fn the_derived_trust_validates_the_as_token() {
    let private = jose_rs::jwk::generate::generate_ec("P-256").expect("key");
    let jwks: &'static str = Box::leak(jwks_of(&private).into_boxed_str());
    let base = serve_jwks(jwks).await;

    let token = access_token(&private, &base, Some("wallet-engine"));
    let config = Config {
        as_external_url: base,
        ..Config::default()
    };
    let validator = TokenValidator::from_config(&config);
    let validated = validator.validate(&token).expect("the token validates");
    assert_eq!(validated.subject, "user-1");
}

/// The explicit overrides: the Go backend's own AS publishes its JWKS at
/// `{external}/auth/.well-known/jwks.json` while its `iss` is the
/// configured `WALLET_AS_ISSUER` (its external URL's public form, say) —
/// the engine reaches it with `as_jwks_url` and `as_issuer`, the
/// deployment's `ENGINE_AS_JWKS_URL` and `ENGINE_AS_ISSUER`.
#[tokio::test(flavor = "multi_thread")]
async fn the_overrides_reach_the_backend_own_as() {
    let private = jose_rs::jwk::generate::generate_ec("P-256").expect("key");
    let jwks: &'static str = Box::leak(jwks_of(&private).into_boxed_str());
    let base = serve_jwks(jwks).await;

    // The AS: its JWKS under /auth/.well-known/, its issuer the public
    // localhost form (as the dev stack configures it).
    let issuer = "http://localhost:8080";
    let token = access_token(&private, issuer, Some("wallet-backend"));
    let config = Config {
        // The external URL names the AS but derives neither shape here.
        as_external_url: format!("{base}/auth"),
        as_jwks_url: format!("{base}/auth/.well-known/jwks.json"),
        as_issuer: issuer.to_owned(),
        as_audiences: vec!["wallet-backend".to_owned()],
        ..Config::default()
    };
    let validator = TokenValidator::from_config(&config);
    let validated = validator.validate(&token).expect("the token validates");
    assert_eq!(validated.subject, "user-1");
}

/// The audience gate: a token the configured audiences do not name is
/// refused (the signature verifies; the audience does not).
#[tokio::test(flavor = "multi_thread")]
async fn an_unaccepted_audience_refuses() {
    let private = jose_rs::jwk::generate::generate_ec("P-256").expect("key");
    let jwks: &'static str = Box::leak(jwks_of(&private).into_boxed_str());
    let base = serve_jwks(jwks).await;

    let token = access_token(&private, &base, Some("wallet-backend"));
    let config = Config {
        as_external_url: base,
        ..Config::default()
    };
    let validator = TokenValidator::from_config(&config);
    assert!(
        validator.validate(&token).is_err(),
        "the wallet-engine audience does not name wallet-backend"
    );
}

/// The empty audience list accepts every audience — the go-tokenauth
/// behaviour the backend's AS relies on (`ENGINE_AS_AUDIENCES=`).
#[tokio::test(flavor = "multi_thread")]
async fn an_empty_audience_list_accepts_every_audience() {
    let private = jose_rs::jwk::generate::generate_ec("P-256").expect("key");
    let jwks: &'static str = Box::leak(jwks_of(&private).into_boxed_str());
    let base = serve_jwks(jwks).await;

    let token = access_token(&private, &base, Some("wallet-backend"));
    let config = Config {
        as_external_url: base,
        as_audiences: Vec::new(),
        ..Config::default()
    };
    let validator = TokenValidator::from_config(&config);
    validator
        .validate(&token)
        .expect("every audience is accepted");
}

/// No AS configured: the validator trusts the bearer (the dev engine's
/// shape — the same way the engine without a PDP treats trust).
#[tokio::test(flavor = "multi_thread")]
async fn no_as_configured_trusts_the_bearer() {
    let config = Config::default();
    let validator = TokenValidator::from_config(&config);
    let validated = validator
        .validate("any-bearer-at-all")
        .expect("the dev engine trusts the bearer");
    assert_eq!(validated.subject, "any-bearer-at-all");
}

/// The AS's OWN claim spelling: go-wallet-backend's AccessTokenClaims
/// serialises its tenant as `tenant_id` (the Go struct's json tag), not
/// `tenant`. Reading only `tenant` left the principal's tenant empty
/// against the real AS, and a tenant-mode principal with no tenant has an
/// empty ownership key — session create then refused every token "Not
/// authorized" (found on-device against the GDC released engine: the mint
/// succeeded, the validation passed, the session still died).
#[tokio::test(flavor = "multi_thread")]
async fn the_as_own_tenant_claim_name_is_read() {
    let private = jose_rs::jwk::generate::generate_ec("P-256").expect("key");
    let jwks: &'static str = Box::leak(jwks_of(&private).into_boxed_str());
    let base = serve_jwks(jwks).await;

    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() + 3600)
        .unwrap_or_default();
    // The AS's exact claim set: the registered claims plus `tenant_id` and
    // `tac` under their Go json tags.
    let claims = serde_json::json!({
        "iss": base,
        "sub": "p-hand-minted",
        "aud": ["wallet-engine"],
        "exp": exp,
        "iat": exp - 3600,
        "jti": "jti-1",
        "tenant_id": "default",
        "tac": "ri",
        "acr": "passkey",
    });
    let mut header = jose_rs::header::JoseHeader::new("ES256");
    header.typ = Some("at+jwt".to_owned());
    header.kid = Some("key-1".to_owned());
    let mut private_key = private.clone();
    private_key.alg = Some("ES256".to_owned());
    let claims: jose_rs::jwt::Claims =
        serde_json::from_value(claims).expect("the custom claims parse as Claims");
    let token =
        jose_rs::jwt::encode_with_jwk(&private_key, &header, &claims).expect("the token signs");

    let config = Config {
        as_external_url: base,
        ..Config::default()
    };
    let validator = TokenValidator::from_config(&config);
    let validated = validator.validate(&token).expect("the token validates");
    assert_eq!(
        validated.tenant, "default",
        "the AS's tenant_id claim is the principal's tenant"
    );
    assert_eq!(validated.tac, "ri");
    assert_eq!(validated.jti, "jti-1");
}

/// The generic `tenant` spelling still works — the fallback, for issuers
/// that spell it that way (the conformance suites' hand-minted tokens).
#[tokio::test(flavor = "multi_thread")]
async fn the_generic_tenant_claim_name_still_reads() {
    let private = jose_rs::jwk::generate::generate_ec("P-256").expect("key");
    let jwks: &'static str = Box::leak(jwks_of(&private).into_boxed_str());
    let base = serve_jwks(jwks).await;

    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() + 3600)
        .unwrap_or_default();
    let claims = serde_json::json!({
        "iss": base,
        "sub": "p-generic",
        "aud": "wallet-engine",
        "exp": exp,
        "tenant": "acme",
    });
    let mut header = jose_rs::header::JoseHeader::new("ES256");
    header.typ = Some("at+jwt".to_owned());
    header.kid = Some("key-1".to_owned());
    let mut private_key = private.clone();
    private_key.alg = Some("ES256".to_owned());
    let claims: jose_rs::jwt::Claims =
        serde_json::from_value(claims).expect("the custom claims parse as Claims");
    let token =
        jose_rs::jwt::encode_with_jwk(&private_key, &header, &claims).expect("the token signs");

    let config = Config {
        as_external_url: base,
        ..Config::default()
    };
    let validator = TokenValidator::from_config(&config);
    let validated = validator.validate(&token).expect("the token validates");
    assert_eq!(
        validated.tenant, "acme",
        "the generic spelling remains accepted"
    );
}
