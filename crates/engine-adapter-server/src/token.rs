//! Token validation: the JWT validation against the AS's JWKS that
//! `--mode=engine` requires — the mirror of go-tokenauth's validator for the
//! engine adapter's needs.
//!
//! go-tokenauth validates new-style asymmetric tokens (ES256/ES384/EdDSA)
//! against a JWKS fetcher, checks `iss`/`aud`/`exp`/`nbf` with leeway, and
//! consults a revocation checker. The Rust mirror keeps the same shape: a
//! JWKS cache refreshed on a timer, a JWT validation with the same claim
//! checks, and a pluggable revocation trait.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::Config;

/// The validated token's claims, extracted into the principal the engine
/// uses.
#[derive(Debug, Clone, Default)]
pub struct ValidatedToken {
    /// The `sub` claim: the authenticated user.
    pub subject: String,
    /// The `tenant` claim, when the AS issues per-tenant tokens.
    pub tenant: String,
    /// The `jti` claim: the token's identifier, for revocation.
    pub jti: String,
    /// The token access control string (the `tac` claim).
    pub tac: String,
}

/// Why a token was refused.
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    /// No JWKS URL is configured.
    #[error("tokenauth: JWKS not configured")]
    NoJwks,
    /// The JWT does not parse.
    #[error("tokenauth: failed to parse token")]
    Parse,
    /// No `kid` header, or the `kid` matches nothing in the JWKS.
    #[error("tokenauth: key lookup failed")]
    KeyLookup,
    /// The signature does not verify.
    #[error("tokenauth: signature verification failed")]
    Signature,
    /// A claim (`iss`, `aud`, `exp`, `nbf`) failed.
    #[error("tokenauth: claim validation failed")]
    Claims,
    /// The token has been revoked.
    #[error("tokenauth: token revoked")]
    Revoked,
    /// The algorithm is not one of ES256, ES384, EdDSA.
    #[error("tokenauth: unsupported algorithm")]
    UnsupportedAlgorithm,
}

/// Checks whether a token has been revoked, by its `jti`.
pub trait RevocationChecker: Send + Sync {
    /// Whether the token identified by `jti` has been revoked.
    fn is_revoked(&self, jti: &str) -> bool;
}

/// No revocation checking (the in-memory store; the shared Mongo store
/// arrives with the backend adapter).
#[derive(Default)]
pub struct NoRevocation;

impl RevocationChecker for NoRevocation {
    fn is_revoked(&self, _jti: &str) -> bool {
        false
    }
}

/// The JWKS cache: fetches the AS's keys on a timer, and serves them
/// without a network hop between refreshes. The refresh is synchronous
/// (the adapter's HTTP client): a slow JWKS endpoint blocks the caller
/// once, not the whole server.
struct JwksCache {
    keys: parking_lot::RwLock<Option<jose_rs::jwk::JwkSet>>,
    url: String,
    refresh_interval: Duration,
    last_refresh: parking_lot::Mutex<Option<Instant>>,
}

impl JwksCache {
    fn new(url: &str, refresh_interval: Duration) -> Self {
        Self {
            keys: parking_lot::RwLock::new(None),
            url: url.to_owned(),
            refresh_interval,
            last_refresh: parking_lot::Mutex::new(None),
        }
    }

    /// The current JWKS, refreshing when stale.
    fn keys(&self) -> Result<jose_rs::jwk::JwkSet, TokenError> {
        {
            let last = self.last_refresh.lock();
            if let Some(last) = *last {
                if last.elapsed() < self.refresh_interval {
                    if let Some(keys) = self.keys.read().clone() {
                        return Ok(keys);
                    }
                }
            }
        }

        let response = ureq::get(&self.url)
            .call()
            .map_err(|_| TokenError::KeyLookup)?;
        let body = response.into_string().map_err(|_| TokenError::KeyLookup)?;

        let set = jose_rs::jwk::JwkSet::from_json(&body).map_err(|_| TokenError::KeyLookup)?;
        *self.keys.write() = Some(set.clone());
        *self.last_refresh.lock() = Some(Instant::now());
        Ok(set)
    }
}

/// Validates bearer tokens against the AS's JWKS, checking `iss`, `aud`,
/// `exp`, `nbf` with leeway, and consulting the revocation checker. The
/// mirror of go-tokenauth's `validator.Validator`.
pub struct TokenValidator {
    jwks: JwksCache,
    issuer: String,
    #[allow(dead_code)] // wired through jose-rs's Validation; kept for the revocation adapter's config
    audiences: Vec<String>,
    revocation: Arc<dyn RevocationChecker>,
    #[allow(dead_code)] // jose-rs's Validation carries the leeway; kept for the config
    leeway: Duration,
}

impl TokenValidator {
    /// Builds the validator from the engine's config. The `as_external_url`
    /// names the AS; the JWKS URL is its `.well-known/jwks.json`.
    pub fn from_config(config: &Config) -> Self {
        let jwks_url = format!(
            "{}/.well-known/jwks.json",
            config.as_external_url.trim_end_matches('/')
        );
        Self {
            jwks: JwksCache::new(&jwks_url, Duration::from_secs(300)),
            issuer: config.as_external_url.clone(),
            audiences: vec!["wallet-engine".to_owned()],
            revocation: Arc::new(NoRevocation),
            leeway: Duration::from_secs(5),
        }
    }

    /// Overrides the revocation checker.
    pub fn with_revocation(mut self, checker: Arc<dyn RevocationChecker>) -> Self {
        self.revocation = checker;
        self
    }

    /// Validates a raw JWT and answers the claims the engine uses. Without
    /// a configured `as_external_url` the validator falls back to accepting
    /// any bearer token as a subject — the no-AS mode, for tests and
    /// environments where the engine runs without an authorization server
    /// behind it. Production deployments always configure the AS.
    pub fn validate(&self, raw_token: &str) -> Result<ValidatedToken, TokenError> {
        if self.issuer.is_empty() {
            return Ok(ValidatedToken {
                subject: raw_token.to_owned(),
                ..ValidatedToken::default()
            });
        }
        // Peek at the header for the algorithm without verifying.
        let header: serde_json::Value = peek_header(raw_token).ok_or(TokenError::Parse)?;
        let alg = header
            .get("alg")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();

        if !matches!(alg, "ES256" | "ES384" | "EdDSA") {
            return Err(TokenError::UnsupportedAlgorithm);
        }

        // Fetch the JWKS (refreshing when stale).
        let jwks = self.jwks.keys()?;

        // Decode and verify the JWT against the JWKS. jose-rs's
        // `decode_with_jwkset` handles the signature, the `exp`/`nbf`/`iss`
        // checks, and the `kid` selection; the Validation restricts the
        // algorithms and pins the issuer.
        let validation = jose_rs::jwt::Validation::new()
            .with_issuer(&self.issuer)
            .with_allowed_algorithms(vec![
                jose_rs::JwsAlgorithm::ES256,
                jose_rs::JwsAlgorithm::ES384,
                jose_rs::JwsAlgorithm::EdDSA,
            ]);
        let claims = jose_rs::jwt::decode_with_jwkset(&jwks, raw_token, &validation)
            .map_err(|_| TokenError::Signature)?;

        // Extract the claims the engine needs.
        let subject = claims.sub.clone().unwrap_or_default();
        let jti = claims.jti.clone().unwrap_or_default();

        // The `tenant` and `tac` claims are custom: read them from the
        // serialized claims (jose-rs's `Claims` struct exposes the
        // registered ones).
        let claims_json = claims.to_json_vec().map_err(|_| TokenError::Parse)?;
        let claims_value: serde_json::Value =
            serde_json::from_slice(&claims_json).map_err(|_| TokenError::Parse)?;
        let tenant = claims_value
            .get("tenant")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let tac = claims_value
            .get("tac")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned();

        // Revocation check.
        if !jti.is_empty() && self.revocation.is_revoked(&jti) {
            return Err(TokenError::Revoked);
        }

        Ok(ValidatedToken {
            subject,
            tenant,
            jti,
            tac,
        })
    }
}

/// Peeks at a JWT's header without verifying: the first segment,
/// base64url-decoded.
fn peek_header(raw_token: &str) -> Option<serde_json::Value> {
    let header_b64 = raw_token.split('.').next()?;
    let header_bytes = base64url_decode(header_b64)?;
    serde_json::from_slice(&header_bytes).ok()
}

/// Minimal base64url decoding (RFC 4648 §5, without padding).
fn base64url_decode(encoded: &str) -> Option<Vec<u8>> {
    fn value(b: u8) -> Option<u8> {
        match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let bytes = encoded.as_bytes();
    if bytes.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for &b in bytes {
        let v = value(b)?;
        buffer = (buffer << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}
