//! The port traits: the only way the engine core touches the world.
//!
//! Everything environmental is a port trait implemented by an adapter:
//! the server adapter (tokio, rustls, MongoDB), the SDK adapter (platform
//! HTTP, platform clock), or the WASM adapter (browser `fetch`,
//! wasm-bindgen). The core depends only on these traits — never on Tokio,
//! never on a socket, never on the wall clock.
//!
//! The traits are `async` (the P0.4 smoke proved async port traits work
//! over UniFFI for Kotlin and Swift). The `wasm32` target does not have
//! threads; the WASM adapter provides a sans-I/O execution model over the
//! same traits (see `docs/architecture-review.md`, finding 3).

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

use serde::{Deserialize, Serialize};

// ─── HttpRequest / HttpResponse ──────────────────────────────────────────

/// What an HTTP request is for. The engine core declares the purpose, and
/// the adapter enforces the network policy that purpose implies: the
/// address policy (no private, loopback, link-local or cloud-metadata
/// addresses), the size limit, the redirect policy.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum FetchPurpose {
    /// An issuer's metadata.
    IssuerMetadata,
    /// An authorization server's metadata.
    AsMetadata,
    /// A credential offer by reference.
    Offer,
    /// A nonce endpoint.
    Nonce,
    /// A token endpoint.
    Token,
    /// A credential endpoint.
    Credential,
    /// A deferred credential.
    Deferred,
    /// A notification endpoint.
    Notification,
    /// A request object (RFC 9101).
    RequestObject,
    /// Client metadata.
    ClientMetadata,
    /// A direct_post submission.
    DirectPost,
    /// A JWKS.
    Jwks,
    /// A logo (for display).
    Logo,
    /// The PDP.
    Pdp,
    /// An AS's JWKS (for token validation, not the engine's fetches).
    AsJwks,
}

/// The redirect policy the engine declares.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RedirectPolicy {
    /// No redirects: the first response is the answer (RFC 9101 §10.4.1
    /// request objects, and direct_post submissions, where a 307 resends
    /// the body to another URI).
    None,
    /// At most this many hops, http(s) only, no userinfo.
    Max(usize),
}

/// One HTTP request the engine makes. The adapter owns TLS, roots, proxies,
/// the address policy, and the execution; the core states WHY it is
/// fetching and what limits apply.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequest {
    /// The request's method.
    pub method: String,
    /// The request's URL.
    pub url: String,
    /// The request's headers.
    pub headers: Vec<(String, String)>,
    /// The request's body, when there is one.
    pub body: Vec<u8>,
    /// Why the engine is fetching — the purpose the adapter's network
    /// policy keys on.
    pub purpose: FetchPurpose,
    /// The response size limit the engine declares.
    pub max_response_bytes: usize,
    /// The redirect policy the engine declares.
    pub redirects: RedirectPolicy,
    /// Whether plain http is allowed for this request (from config; off in
    /// production).
    pub allow_plaintext: bool,
    /// The request's timeout.
    pub timeout_ms: u64,
}

/// The world's answer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponse {
    /// The response's status.
    pub status: u16,
    /// The response's headers.
    pub headers: Vec<(String, String)>,
    /// The response's body.
    pub body: Vec<u8>,
}

/// Why an HTTP request refused.
#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    /// The adapter refused the request: the address is private, loopback,
    /// link-local or a cloud metadata endpoint; or the URL's scheme is not
    /// allowed; or the size or redirect limit was exceeded.
    #[error("engine: request refused by the adapter's network policy")]
    Refused,
    /// The transport failed (connection refused, timeout, TLS error).
    #[error("engine: transport failed: {0}")]
    Transport(String),
}

// ─── HttpClient ──────────────────────────────────────────────────────────

/// Performs one HTTP request. The adapter owns TLS, roots, proxies,
/// redirects and the address policy; the core states why it is fetching and
/// what limits apply.
///
/// On the server: the adapter performs the request with rustls (in the TEE,
/// inside the trusted binary, so the untrusted host never sees plaintext).
/// In the SDK: the host performs the request with the platform stack, so
/// system roots, proxies and VPNs behave natively. In WASM: the browser's
/// `fetch`, through the backend's CORS proxy for the issuers and verifiers
/// the browser cannot reach directly.
#[async_trait::async_trait]
pub trait HttpClient: Send + Sync {
    /// Performs one request and answers the world's reply.
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, HttpError>;
}

// ─── Clock ───────────────────────────────────────────────────────────────

/// The clock the engine reads: the current time and the sleeps it waits
/// for. The core never calls `SystemTime::now` — the adapter supplies the
/// time (the OS clock on the server, the platform clock in the SDK, the
/// attested clock in a TEE, a fixed value in tests).
#[async_trait::async_trait]
pub trait Clock: Send + Sync {
    /// The current time, unix seconds.
    fn now_unix(&self) -> i64;

    /// Sleeps for the given duration.
    async fn sleep(&self, duration_ms: u64);
}

// ─── Rng ────────────────────────────────────────────────────────────────

/// The randomness the engine uses: ephemeral keys, nonces, request ids.
/// The core never samples ambient randomness — the adapter supplies it
/// (the OS's secure RNG in production, a counter in tests).
pub trait Rng: Send + Sync {
    /// Fills the buffer with random bytes, returning false when it cannot.
    fn fill(&self, buf: &mut [u8]) -> bool;
}

// ─── Host ───────────────────────────────────────────────────────────────

/// The wallet host, seen from the engine: the sub-flows the engine asks
/// the wallet's user for. In the SDK this is the native UI (Kotlin or
/// Swift through UniFFI); on the server it is the remote WMP peer (the
/// wallet client); in WASM it is the browser's consent dialog.
///
/// Every method is `async` because the answer is a person's: the engine
/// awaits the UI, not the other way round.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignParams {
    /// The flow the sign request belongs to.
    pub flow_id: String,
    /// The to-be-signed input (the JWT header + payload, the VP token, the
    /// DPoP proof — the raw bytes the host signs).
    pub to_sign: Vec<u8>,
    /// The key the host signs with, named by its identifier when the
    /// engine knows it.
    pub key_id: Option<String>,
    /// The signing algorithm the engine expects.
    pub algorithm: String,
}

/// The signature the host returned.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignResult {
    /// The signature bytes.
    pub signature: Vec<u8>,
}

/// A credential match the engine asks the host to select from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchEntry {
    /// The credential's identifier.
    pub credential_id: String,
    /// The credential's display name.
    pub display_name: String,
    /// The credential's type.
    pub credential_type: String,
}

/// The match answer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchResult {
    /// The selected credential's identifier.
    pub selected_id: String,
}

/// The consent the engine asks the host's user for.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentParams {
    /// The flow the consent request belongs to.
    pub flow_id: String,
    /// What the verifier is asking for, in displayable form.
    pub purpose: String,
    /// The claims the verifier requests.
    pub requested_claims: Vec<String>,
    /// The transaction data entries, when the request carries them.
    pub transaction_data: Vec<String>,
}

/// The consent answer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentResult {
    /// Whether the user consented.
    pub consented: bool,
}

/// Why a sub-flow refused.
#[derive(Debug, thiserror::Error)]
pub enum HostError {
    /// The host's user declined.
    #[error("engine: declined by the user")]
    Declined,
    /// The host cannot answer (no UI, no key, no credential).
    #[error("engine: host cannot answer: {0}")]
    Cannot(String),
}

/// The sub-flow requests the engine makes of the wallet's host.
#[async_trait::async_trait]
pub trait Host: Send + Sync {
    /// Asks the host to sign the given input with the named key.
    async fn request_sign(&self, params: SignParams) -> Result<SignResult, HostError>;

    /// Asks the host to select a credential from the given entries.
    async fn request_match(
        &self,
        flow_id: &str,
        entries: Vec<MatchEntry>,
    ) -> Result<MatchResult, HostError>;

    /// Asks the host's user for consent to the given presentation.
    async fn request_consent(&self, params: ConsentParams) -> Result<ConsentResult, HostError>;

    /// Asks the host's user for the transaction code.
    async fn request_tx_code(&self, flow_id: &str) -> Result<String, HostError>;

    /// Opens the authorization URL in the host's browser (the authorization
    /// code flow's user agent step).
    async fn open_authorization(&self, flow_id: &str, url: &str) -> Result<(), HostError>;

    /// Reports progress on a flow (a notification, not a request).
    fn progress(&self, flow_id: &str, step: &str, detail: Option<String>);
}

// ─── Pdp ────────────────────────────────────────────────────────────────

/// The trust evaluation the engine asks the PDP for. Two implementations:
/// `BackendProxy` (talks to the existing `/v1/evaluate` and `/v1/resolve`,
/// what the spike uses) and `AuthzenDirect` (talks to the tenant's PDP
/// directly — when go-trust gains go-tokenauth support).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationRequest {
    /// The subject whose trust is being evaluated (the issuer or verifier's
    /// identifier).
    pub subject: String,
    /// The key material from the signed metadata (x5c or jwk).
    pub key_material: Vec<u8>,
    /// The resource type being resolved (for `/v1/resolve`).
    pub resource_type: Option<String>,
}

/// The PDP's verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationResponse {
    /// Whether the subject is trusted.
    pub trusted: bool,
    /// The PDP's decision text, when there is one.
    pub decision: Option<String>,
}

/// The resolve request (the `/v1/resolve` shape).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveRequest {
    /// The URL subject to resolve.
    pub uri: String,
    /// The resource type: `credential_issuer` (default) or
    /// `oauth-authorization-server`.
    pub resource_type: String,
}

/// The resolve response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveResponse {
    /// The resolved metadata document.
    pub metadata: Vec<u8>,
    /// Trust information, when the PDP carries it.
    pub trust_info: Option<Vec<u8>>,
}

/// Why the PDP refused.
#[derive(Debug, thiserror::Error)]
pub enum PdpError {
    /// The PDP is unreachable; the engine fails closed.
    #[error("engine: PDP unreachable")]
    Unreachable,
    /// The PDP answered an error.
    #[error("engine: PDP error: {0}")]
    Error(String),
    /// The adapter does not implement this PDP operation.
    #[error("engine: PDP operation not implemented")]
    NotImplemented,
}

/// The trust port: evaluates issuer and verifier trust, and resolves
/// metadata by URL. The engine calls this through the `Pdp` port, never
/// the backend's proxy directly.
#[async_trait::async_trait]
pub trait Pdp: Send + Sync {
    /// Evaluates the trust of a subject (issuer or verifier) with the key
    /// material from its signed metadata.
    async fn evaluate(&self, request: EvaluationRequest) -> Result<EvaluationResponse, PdpError>;

    /// Resolves a URL to a metadata document (the `/v1/resolve` shape).
    async fn resolve(&self, request: ResolveRequest) -> Result<ResolveResponse, PdpError>;
}

// ─── TokenProvider ──────────────────────────────────────────────────────

/// Supplies the bearer token the engine's `BackendProxy` PDP implementation
/// presents to the backend's proxy.
#[async_trait::async_trait]
pub trait TokenProvider: Send + Sync {
    /// The bearer token, or None when the adapter has no session token.
    async fn bearer(&self) -> Result<String, PdpError>;
}

// ─── KeyValue ───────────────────────────────────────────────────────────

/// Optional persistence: metadata caches, DPoP nonces, attestation
/// challenges, flow state for resume. The default implementation is
/// in-memory; the server adapter's is the shared store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyValueEntry {
    /// The entry's value.
    pub value: Vec<u8>,
    /// The entry's TTL, in seconds; None means no expiry.
    pub ttl_secs: Option<u64>,
}

/// The optional persistence port.
#[async_trait::async_trait]
pub trait KeyValue: Send + Sync {
    /// Reads the entry with the given key.
    async fn get(&self, key: &str) -> Option<KeyValueEntry>;

    /// Writes the entry with the given key.
    async fn put(&self, key: &str, entry: KeyValueEntry);

    /// Removes the entry with the given key.
    async fn delete(&self, key: &str);
}

// ─── Telemetry ──────────────────────────────────────────────────────────

/// A redacted, allow-listed telemetry event. The core passes only the
/// fields the contract names; no tokens, nonces, openings, request bodies
/// or credential data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    /// The event's name (a stable, allow-listed identifier).
    pub name: String,
    /// The flow the event belongs to, when there is one.
    pub flow_id: Option<String>,
    /// The event's fields (redacted, allow-listed).
    pub fields: Vec<(String, String)>,
}

/// The telemetry port: logs and metrics. The core passes only redacted,
/// allow-listed fields.
pub trait Telemetry: Send + Sync {
    /// Records one event.
    fn event(&self, event: TelemetryEvent);
}
