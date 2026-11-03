//! The flow runtime and the OpenID4 flow family on top of it — the
//! engine's brain.
//!
//! The core is a library that depends only on the `engine-ports` traits
//! and `wmp-core`. It never opens a socket, reads a clock, samples
//! randomness, or touches a database: every environmental effect goes
//! through a port trait, supplied by the adapter (the server, the SDK, or
//! the WASM module).
//!
//! The flow seam: a flow family is a handler plus a spec, registered by
//! flow type through the [`FlowHandler`] trait. The runtime registers
//! handlers by flow type, gates them on negotiated capabilities, routes
//! sub-flow requests to the host through the flow context, and supplies
//! the ports. A family never reaches into the runtime's internals.
//! Adding a family (QERDS, agentic, MCP) takes its parameter and result
//! schemas, a handler module, and new ports only if the family needs
//! effects the existing ports do not cover — no change to this crate.

#![deny(missing_docs)]
#![deny(unsafe_code)]
// Nothing panics outside the tests. scripts/check_panic_sites.py refuses an
// allow of these lints there and finds the panics they cannot see.
#![cfg_attr(
    not(test),
    deny(
        clippy::panic,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::indexing_slicing,
        clippy::disallowed_methods
    )
)]

pub mod oid4vci;
pub mod runtime;

/// The engine's configuration, supplied by the adapter — a struct, never
/// read from the environment inside the core. Mirrors the Go engine's
/// `http_client.*` and trust settings where they apply.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EngineConfig {
    /// The `metadata_type` policy: `prefer-signed` (default),
    /// `require-signed`, `prefer-unsigned`, `require-unsigned`, `any`.
    pub metadata_type: String,
    /// Whether plain `http` fetches are allowed (never in production).
    pub allow_plaintext: bool,
    /// The session TTL in seconds when a `wmp.session.create` carries no
    /// `ttl`.
    pub default_session_ttl_secs: i64,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            metadata_type: "prefer-signed".to_owned(),
            allow_plaintext: false,
            default_session_ttl_secs: 3600,
        }
    }
}

/// The ports the engine core runs on: everything environmental, in one
/// struct, supplied by the adapter at construction. The core holds this
/// and reaches through it; it never constructs one itself.
pub struct Ports {
    /// The HTTP client the engine's fetches go through.
    pub http: std::sync::Arc<dyn engine_ports::HttpClient>,
    /// The clock the engine reads.
    pub clock: std::sync::Arc<dyn engine_ports::Clock>,
    /// The randomness the engine samples.
    pub rng: std::sync::Arc<dyn engine_ports::Rng>,
    /// The wallet host the engine asks for sign, consent and selection.
    pub host: std::sync::Arc<dyn engine_ports::Host>,
    /// The PDP the engine evaluates trust through.
    pub pdp: std::sync::Arc<dyn engine_ports::Pdp>,
    /// The optional persistence (default: in-memory).
    pub kv: std::sync::Arc<dyn engine_ports::KeyValue>,
    /// The telemetry the engine reports to (default: no-op).
    pub telemetry: std::sync::Arc<dyn engine_ports::Telemetry>,
}
