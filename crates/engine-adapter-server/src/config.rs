//! The engine server's configuration — a struct passed to the constructor,
//! never read from the environment inside the core. Mirrors the Go
//! engine's `--mode=engine` configuration shape where the names overlap.

use serde::{Deserialize, Serialize};

/// The engine server's configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// The address the HTTP server listens on (`ENGINE_ADDR`, default
    /// `0.0.0.0:8780`).
    pub listen_addr: String,
    /// The maximum incoming WMP message size in bytes (default 1 MiB, the
    /// transport spec's minimum is 64 KiB).
    pub max_message_size: usize,
    /// The session TTL in seconds when a `wmp.session.create` carries no
    /// `ttl` (default 3600, the core's default).
    pub default_session_ttl_secs: i64,
    /// The AS's external URL, whose JWKS the standalone engine validates
    /// tokens against — the `as.external_url` the Go engine requires.
    /// Drives the derived JWKS URL and issuer (the defaults) when they
    /// are not named.
    pub as_external_url: String,
    /// The AS's JWKS URL, when it is not the derived
    /// `{as_external_url}/.well-known/jwks.json` — the Go backend's own AS
    /// publishes it at `{as_external_url}/auth/.well-known/jwks.json`.
    /// Empty means the derived form.
    pub as_jwks_url: String,
    /// The `iss` claim the tokens carry, when it is not the
    /// `as_external_url` (the Go AS's `iss` is its configured issuer,
    /// `WALLET_AS_ISSUER`, which can differ from its external URL).
    /// Empty means the `as_external_url`.
    pub as_issuer: String,
    /// The accepted `aud` claims. Empty accepts every audience (the
    /// go-tokenauth behaviour the backend's AS relies on); the default
    /// is `wallet-engine` (the engine's own audience).
    pub as_audiences: Vec<String>,
    /// The PDP URL the engine evaluates trust through. Empty means the
    /// backend's proxy (the legacy fallback); a URL means the engine calls
    /// the PDP directly.
    pub pdp_url: String,
    /// The bearer token the backend's proxy routes validate (the
    /// `/v1/evaluate` and `/v1/resolve` TAC gate: an AS-issued token
    /// with `tac` covering `r` and an audience the deployment accepts —
    /// `wallet-backend` or `wallet-registry` on the default rules).
    /// The deployment mints it: the dev stack's
    /// `scripts/mint_engine_pdp_token.py`, Fly's deploy from the AS
    /// signing key. Empty means no token: the proxy's routes 401 and
    /// the engine's trust evaluation fails closed.
    pub pdp_token: String,
    /// Whether plain `http` fetches are allowed (never in production; the
    /// Go engine's `http_client.allow_plaintext`).
    pub allow_plaintext: bool,
    /// The `metadata_type` policy: `prefer-signed` (default),
    /// `require-signed`, `prefer-unsigned`, `require-unsigned`, `any`.
    pub metadata_type: String,
    /// The maximum concurrent flows a session may run (the flows
    /// capability the session create advertises, core §10.3; default 16,
    /// the wasm dispatcher's bound).
    pub max_concurrent_flows: i64,
    /// How the deployment keys session ownership
    /// (`ENGINE_PRINCIPAL_MODE`, engine-parity.md §8): `user` — the
    /// historic shape, sessions owned by `tenant/subject` — or
    /// `tenant` — W10's tenant-bound remote principal, where the token's
    /// `sub` is a rotating pseudonym and the tenant owns the session.
    /// Default `user`.
    pub principal_mode: wmp_core::principal::PrincipalMode,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:8780".to_owned(),
            max_message_size: 1 << 20,
            default_session_ttl_secs: 3600,
            as_external_url: String::new(),
            as_jwks_url: String::new(),
            as_issuer: String::new(),
            as_audiences: vec!["wallet-engine".to_owned()],
            pdp_url: String::new(),
            pdp_token: String::new(),
            allow_plaintext: false,
            metadata_type: "prefer-signed".to_owned(),
            max_concurrent_flows: 16,
            principal_mode: wmp_core::principal::PrincipalMode::User,
        }
    }
}

impl Config {
    /// The configuration from the environment (`ENGINE_*`), over the
    /// defaults — the container's form: `ENGINE_ADDR`,
    /// `ENGINE_MAX_MESSAGE_SIZE`, `ENGINE_DEFAULT_SESSION_TTL_SECS`,
    /// `ENGINE_AS_EXTERNAL_URL`, `ENGINE_PDP_URL`,
    /// `ENGINE_ALLOW_PLAINTEXT`, `ENGINE_METADATA_TYPE`,
    /// `ENGINE_MAX_CONCURRENT_FLOWS`. An unset variable is the
    /// default; an empty `ENGINE_ADDR`-style string is the default
    /// too (the container's `ENV ENGINE_LISTEN_ADDR=` form), and an
    /// unparseable one is the default rather than a refusal — a
    /// misconfigured scaler's pod still starts and serves its
    /// probes, exactly as the Go engine's config treats its
    /// environment.
    ///
    /// A `ENGINE_CONFIG`-named JSON file remains the full-fidelity
    /// form (`main_entry` reads it); the variables are the container
    /// platform's deployment shape.
    #[must_use]
    pub fn from_env() -> Self {
        let mut config = Self::default();
        let text = |name: &str| {
            std::env::var(name)
                .ok()
                .filter(|value| !value.trim().is_empty())
        };
        if let Some(value) = text("ENGINE_LISTEN_ADDR").or_else(|| text("ENGINE_ADDR")) {
            config.listen_addr = value;
        }
        if let Some(value) = text("ENGINE_MAX_MESSAGE_SIZE") {
            if let Ok(parsed) = value.trim().parse() {
                config.max_message_size = parsed;
            }
        }
        if let Some(value) = text("ENGINE_DEFAULT_SESSION_TTL_SECS") {
            if let Ok(parsed) = value.trim().parse() {
                config.default_session_ttl_secs = parsed;
            }
        }
        if let Some(value) = text("ENGINE_AS_EXTERNAL_URL") {
            config.as_external_url = value;
        }
        if let Some(value) = text("ENGINE_AS_JWKS_URL") {
            config.as_jwks_url = value;
        }
        if let Some(value) = text("ENGINE_AS_ISSUER") {
            config.as_issuer = value;
        }
        // The audiences, comma-separated: `ENGINE_AS_AUDIENCES=wallet-engine,
        //wallet-backend`. The var is read set-but-empty too (unlike the
        // others): an empty list accepts every audience, the go-tokenauth
        // behaviour the backend's AS relies on, so `ENGINE_AS_AUDIENCES=`
        // is the operator's way to say exactly that.
        if let Ok(value) = std::env::var("ENGINE_AS_AUDIENCES") {
            config.as_audiences = value
                .split(',')
                .map(str::trim)
                .filter(|audience| !audience.is_empty())
                .map(str::to_owned)
                .collect();
        }
        if let Some(value) = text("ENGINE_PDP_URL") {
            config.pdp_url = value;
        }
        if let Some(value) = text("ENGINE_PDP_TOKEN") {
            config.pdp_token = value;
        }
        if let Some(value) = text("ENGINE_ALLOW_PLAINTEXT") {
            // The truthy forms a compose file or a chart writes.
            config.allow_plaintext = matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            );
        }
        if let Some(value) = text("ENGINE_METADATA_TYPE") {
            config.metadata_type = value;
        }
        if let Some(value) = text("ENGINE_MAX_CONCURRENT_FLOWS") {
            if let Ok(parsed) = value.trim().parse() {
                config.max_concurrent_flows = parsed;
            }
        }
        if let Some(value) = text("ENGINE_PRINCIPAL_MODE") {
            // `user` (the default, the historic shape) or `tenant` (W10's
            // tenant-bound remote principal, engine-parity.md §8). An
            // unrecognised value is the default, like the rest of the
            // container's variables: a misconfigured scaler's pod still
            // starts, on the safe historic mode.
            config.principal_mode = match value.trim().to_ascii_lowercase().as_str() {
                "tenant" => wmp_core::principal::PrincipalMode::Tenant,
                _ => wmp_core::principal::PrincipalMode::User,
            };
        }
        config
    }
}
