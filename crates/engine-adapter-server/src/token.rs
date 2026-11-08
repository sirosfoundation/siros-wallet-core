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
    /// The `iat` claim, unix seconds: when the token was issued. The
    /// #319 cut-off gate compares it — a token issued before the user's
    /// `auth_invalid_before` was moved forward is stale.
    pub iat: Option<i64>,
    /// The `auth_invalid_before` claim, unix seconds, when the AS stamps
    /// it: the user's token cut-off at issue time (the #319 lifecycle
    /// gate's stateless half — the store-backed check lives in the
    /// [`TokenGate`] the backend adapter implements).
    pub auth_invalid_before: Option<i64>,
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

/// The engine's per-token revocation list (engine-parity.md §8 G2): a
/// `jti` pushed here refuses every later bearer of that token — the
/// cheap per-token revocation the tenant-bound deployment pairs with
/// its short-TTL tokens, since a tenant-scoped token otherwise lives
/// out its TTL unrevokeable. Checked on every bearer validation.
///
/// In-memory: the standalone engine's deployment shape. The backend
/// adapter replaces it with its own store-backed checker.
#[derive(Default)]
pub struct JtiBlacklist {
    revoked: std::sync::Mutex<std::collections::HashSet<String>>,
}

impl JtiBlacklist {
    /// Revokes the token identified by `jti`.
    pub fn revoke(&self, jti: &str) {
        if let Ok(mut revoked) = self.revoked.lock() {
            revoked.insert(jti.to_owned());
        }
    }
}

impl RevocationChecker for JtiBlacklist {
    fn is_revoked(&self, jti: &str) -> bool {
        self.revoked
            .lock()
            .map(|revoked| revoked.contains(jti))
            .unwrap_or(false)
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
    // The accepted `aud` claims: empty accepts every audience (the
    // go-tokenauth behaviour the backend's AS relies on).
    audiences: Vec<String>,
    revocation: Arc<dyn RevocationChecker>,
    #[allow(dead_code)] // jose-rs's Validation carries the leeway; kept for the config
    leeway: Duration,
}

impl TokenValidator {
    /// Builds the validator from the engine's config. The `as_external_url`
    /// names the AS: the JWKS URL defaults to its
    /// `.well-known/jwks.json` and the issuer to itself — the Go engine's
    /// shape — with `as_jwks_url`/`as_issuer` overriding each (the Go
    /// backend's own AS publishes its JWKS under `/auth/.well-known/` and
    /// issues with its configured `WALLET_AS_ISSUER`). The audiences
    /// default to the engine's own `wallet-engine`; an empty list accepts
    /// every audience, the go-tokenauth behaviour the backend's AS relies on.
    pub fn from_config(config: &Config) -> Self {
        let jwks_url = if config.as_jwks_url.is_empty() {
            format!(
                "{}/.well-known/jwks.json",
                config.as_external_url.trim_end_matches('/')
            )
        } else {
            config.as_jwks_url.clone()
        };
        let issuer = if config.as_issuer.is_empty() {
            config.as_external_url.clone()
        } else {
            config.as_issuer.clone()
        };
        Self {
            jwks: JwksCache::new(&jwks_url, Duration::from_secs(300)),
            issuer,
            audiences: config.as_audiences.clone(),
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
        let mut validation = jose_rs::jwt::Validation::new()
            .with_issuer(&self.issuer)
            .with_allowed_algorithms(vec![
                jose_rs::JwsAlgorithm::ES256,
                jose_rs::JwsAlgorithm::ES384,
                jose_rs::JwsAlgorithm::EdDSA,
            ]);
        // The accepted audiences, when any are configured: jose-rs's
        // `audience` is one required value, so the first configured
        // audience pins it (the engine's own single-audience default);
        // an empty list skips the check entirely, exactly as
        // go-tokenauth treats an empty audiences list.
        if let Some(audience) = self.audiences.first() {
            validation = validation.with_audience(audience);
        }
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
        // The #319 lifecycle claims: `iat` (registered; jose-rs exposes
        // it) and the custom `auth_invalid_before` — the user's token
        // cut-off as the AS stamped it at issue.
        let iat = claims
            .iat
            .and_then(|t| i64::try_from(t.as_secs()).ok())
            .or_else(|| claims_value.get("iat").and_then(serde_json::Value::as_i64));
        let auth_invalid_before = claims_value
            .get("auth_invalid_before")
            .and_then(serde_json::Value::as_i64);

        // Revocation check.
        if !jti.is_empty() && self.revocation.is_revoked(&jti) {
            return Err(TokenError::Revoked);
        }

        Ok(ValidatedToken {
            subject,
            tenant,
            jti,
            tac,
            iat,
            auth_invalid_before,
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

// ─── The #319 lifecycle gate ──────────────────────────────────────────────────

/// The #319 token cut-off gate: whether the user's tokens were invalidated
/// after this one was issued. The Go backend consults
/// `User.AuthInvalidBefore` at the WebSocket handshake **and at each flow
/// start** (an instance revoked mid-token must not start new flows); the
/// Rust adapter replicates the flow-start half here (the handshake half is
/// the transport's `bearer_principal`, which refuses an invalid token
/// outright).
///
/// The two halves of the check:
///
/// - **Stateless** (always on): the token's own `auth_invalid_before`
///   claim — the user's cut-off as the AS stamped it — against its `iat`.
///   A token issued before the cut-off was moved forward is stale. This
///   sees everything the AS knew at issue; it cannot see a revocation
///   that happened after.
/// - **Store-backed** (the [`TokenGate`] trait): the backend's user store
///   answers the cut-off question live. The default
///   [`NoTokenGate`] answers nothing — the standalone engine has no
///   lifecycle backend; the backend adapter implements it.
pub trait TokenGate: Send + Sync {
    /// The user's current token cut-off, unix seconds: tokens issued
    /// before it are stale. `None` when the user has no cut-off (or the
    /// gate has no backend to ask).
    fn auth_invalid_before(&self, subject: &str, tenant: &str) -> Option<i64>;

    /// The tenant-wide cut-off (engine-parity.md §8 G2): in tenant mode
    /// the subject is a rotating pseudonym with no store identity, so
    /// the gate keys the **tenant** — every token of the tenant issued
    /// before the cut-off is stale. `None` when the gate has no
    /// tenant cut-off (the per-user gate's default: the backend
    /// adapter's user store has no tenant answer).
    fn tenant_auth_invalid_before(&self, _tenant: &str) -> Option<i64> {
        None
    }
}

/// No lifecycle backend: the standalone engine's default gate. Only the
/// stateless claim check applies.
#[derive(Default)]
pub struct NoTokenGate;

impl TokenGate for NoTokenGate {
    fn auth_invalid_before(&self, _subject: &str, _tenant: &str) -> Option<i64> {
        None
    }
}

/// Whether the validated token is stale: issued before the user's token
/// cut-off. The stateless claim check first (the token's own
/// `auth_invalid_before` against its `iat`), then the gate's answer (the
/// live cut-off, which overrides the claim — the store is newer than the
/// stamp).
#[must_use]
pub fn token_is_stale(token: &ValidatedToken, gate: &dyn TokenGate) -> bool {
    // The stateless claim check: the AS stamped the cut-off, the token
    // says it predates it.
    if let (Some(iat), Some(before)) = (token.iat, token.auth_invalid_before) {
        if iat < before {
            return true;
        }
    }
    // The store-backed check: the gate's answer is newer than the stamp.
    let live = gate.auth_invalid_before(&token.subject, &token.tenant);
    match (token.iat, live) {
        (Some(iat), Some(before)) => iat < before,
        _ => false,
    }
}

/// The principal-level stale check (the handler's flow-start gate): the
/// transport stamped the token's `iat` and its `auth_invalid_before` into
/// the principal, so the stateless half reads straight off it; the gate
/// adds the store-backed half (the live cut-off, which overrides the
/// stamp — the store is newer than the token).
///
/// A principal without token claims — the transport established it some
/// other way — is not stale: the transport decided it was good enough.
pub fn principal_token_is_stale(
    principal: &wmp_core::principal::Principal,
    gate: &dyn TokenGate,
) -> bool {
    // The stateless claim check: the AS stamped the cut-off, the token
    // says it predates it.
    if let (Some(iat), Some(before)) = (principal.iat, principal.auth_invalid_before) {
        if iat < before {
            return true;
        }
    }
    // The store-backed check: the gate's live answer. In tenant mode
    // (engine-parity.md §8 G2) the subject is a rotating pseudonym with
    // no store identity, so the gate keys the tenant.
    let live = match principal.mode {
        wmp_core::principal::PrincipalMode::User => {
            gate.auth_invalid_before(&principal.subject, &principal.tenant)
        }
        wmp_core::principal::PrincipalMode::Tenant => {
            gate.tenant_auth_invalid_before(&principal.tenant)
        }
    };
    match (principal.iat, live) {
        (Some(iat), Some(before)) => iat < before,
        _ => false,
    }
}

#[cfg(test)]
mod gate_tests {
    //! The #319 gate's own proof: the stateless claim check, the
    //! store-backed override, and the no-claims pass.

    use super::*;

    /// A gate that answers a fixed cut-off (the store-backed test double).
    struct FixedGate(Option<i64>);

    impl TokenGate for FixedGate {
        fn auth_invalid_before(&self, _subject: &str, _tenant: &str) -> Option<i64> {
            self.0
        }
    }

    #[test]
    fn a_token_predating_its_stamped_cut_off_is_stale() {
        // iat 100 < auth_invalid_before 200: the AS stamped a cut-off the
        // token predates.
        let token = ValidatedToken {
            subject: "alice".to_owned(),
            tenant: "acme".to_owned(),
            iat: Some(100),
            auth_invalid_before: Some(200),
            ..ValidatedToken::default()
        };
        assert!(token_is_stale(&token, &NoTokenGate));
    }

    #[test]
    fn a_token_after_its_cut_off_is_not_stale() {
        let token = ValidatedToken {
            subject: "alice".to_owned(),
            tenant: "acme".to_owned(),
            iat: Some(300),
            auth_invalid_before: Some(200),
            ..ValidatedToken::default()
        };
        assert!(!token_is_stale(&token, &NoTokenGate));
    }

    #[test]
    fn the_store_backed_gate_overrides_the_stamp() {
        // The token's stamp says fresh (iat 300 > stamp 200), but the live
        // store answers a newer cut-off the token predates.
        let token = ValidatedToken {
            subject: "alice".to_owned(),
            tenant: "acme".to_owned(),
            iat: Some(300),
            auth_invalid_before: Some(200),
            ..ValidatedToken::default()
        };
        let gate = FixedGate(Some(400));
        assert!(
            token_is_stale(&token, &gate),
            "the live cut-off overrides the stamp"
        );
        // And the reverse: the store says fresh, the stale stamp does not
        // win (the stateless check already passed iat >= stamp).
        let gate = FixedGate(Some(100));
        assert!(!token_is_stale(&token, &gate));
    }

    #[test]
    fn a_principal_without_token_claims_is_not_stale() {
        // The transport established the principal without lifecycle
        // claims: not stale — the transport decided it was good enough.
        let principal = wmp_core::principal::Principal::new("alice", "acme");
        assert!(!principal_token_is_stale(&principal, &NoTokenGate));
        // With claims, the same rules as the token.
        let stale = wmp_core::principal::Principal::with_token_claims(
            "alice",
            "acme",
            "jti-1",
            "ri",
            Some(100),
            Some(200),
        );
        assert!(principal_token_is_stale(&stale, &NoTokenGate));
        let gate = FixedGate(Some(400));
        let fresh_stamp = wmp_core::principal::Principal::with_token_claims(
            "alice",
            "acme",
            "jti-1",
            "ri",
            Some(300),
            Some(200),
        );
        assert!(principal_token_is_stale(&fresh_stamp, &gate));
    }
}
