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
    pub as_external_url: String,
    /// The PDP URL the engine evaluates trust through. Empty means the
    /// backend's proxy (the legacy fallback); a URL means the engine calls
    /// the PDP directly.
    pub pdp_url: String,
    /// Whether plain `http` fetches are allowed (never in production; the
    /// Go engine's `http_client.allow_plaintext`).
    pub allow_plaintext: bool,
    /// The `metadata_type` policy: `prefer-signed` (default),
    /// `require-signed`, `prefer-unsigned`, `require-unsigned`, `any`.
    pub metadata_type: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:8780".to_owned(),
            max_message_size: 1 << 20,
            default_session_ttl_secs: 3600,
            as_external_url: String::new(),
            pdp_url: String::new(),
            allow_plaintext: false,
            metadata_type: "prefer-signed".to_owned(),
        }
    }
}
