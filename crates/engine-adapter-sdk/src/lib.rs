//! The UniFFI bindings of the WMP engine core for Kotlin and Swift.
//!
//! This is the **P0.4 smoke of the engine's port shapes**: the async-ports
//! design of the engine specification, exercised across the FFI that the
//! native SDKs will use. The traits here are the two the engine's whole
//! design rests on — an async [`HttpClient`] the host performs with its
//! platform stack, and an async [`Host`] the engine asks for sign, consent
//! and tx_code — plus one exported async function that drives a flow through
//! both, exactly as the engine core will.
//!
//! The verdict this crate records (see `docs/uniffi-smoke.md`): uniffi 0.28
//! supports foreign-implemented async trait methods for Kotlin (`suspend
//! fun`) and Swift (`async throws`) when the trait carries `#[async_trait]`
//! and the crate enables `uniffi/tokio`. The alternative designs — the
//! synchronous foreign callback with an async bridge in Rust (what
//! siros-wscd-manager ships) and the sans-I/O effect-list core (what the
//! wallet-core presentation crates are) — remain the recorded fallbacks.

#![deny(missing_docs)]
#![deny(unsafe_code)]
// Nothing panics outside the tests. scripts/check_panic_sites.py refuses an
// allow of these lints there and finds the panics they cannot see. The uniffi
// proc macros expand into foreign glue whose lints are not ours to control;
// the smoke's own code holds to the workspace rules.
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
#![allow(clippy::result_unit_err)]

uniffi::setup_scaffolding!();

/// What an HTTP request is for — the engine declares the purpose, and the
/// adapter enforces the network policy that purpose implies. The engine
/// core's `FetchPurpose`, crossing the FFI.
#[derive(uniffi::Enum, Clone, Debug, PartialEq)]
pub enum FetchPurpose {
    /// An issuer's metadata.
    IssuerMetadata,
    /// An authorization server's metadata.
    AsMetadata,
    /// A credential offer by reference.
    Offer,
    /// A nonce.
    Nonce,
    /// A token endpoint.
    Token,
    /// A credential endpoint.
    Credential,
    /// A deferred credential.
    Deferred,
    /// A notification endpoint.
    Notification,
    /// A request object.
    RequestObject,
    /// Client metadata.
    ClientMetadata,
    /// A direct_post submission.
    DirectPost,
    /// A JWKS.
    Jwks,
    /// A logo.
    Logo,
    /// The PDP.
    Pdp,
}

/// One HTTP request the engine makes.
#[derive(uniffi::Record, Clone, Debug)]
pub struct HttpRequest {
    /// The request's method.
    pub method: String,
    /// The request's URL.
    pub url: String,
    /// The bytes of the body, when there is one.
    pub body: Vec<u8>,
    /// Why the engine is fetching, and the policy that follows.
    pub purpose: FetchPurpose,
    /// The response size limit the engine declared.
    pub max_response_bytes: u64,
}

/// The world's answer.
#[derive(uniffi::Record, Clone, Debug)]
pub struct HttpResponse {
    /// The response's status.
    pub status: u16,
    /// The bytes of the body.
    pub body: Vec<u8>,
}

/// Why a fetch or a sub-flow refused.
#[derive(uniffi::Error, Clone, Debug)]
pub enum SdkError {
    /// The network refused.
    Network,
    /// The host declined the sub-flow.
    Declined,
    /// The engine's answer was wrong for the request.
    BadResponse,
}

impl std::fmt::Display for SdkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::Network => "network",
            Self::Declined => "declined",
            Self::BadResponse => "bad response",
        };
        write!(f, "engine-adapter-sdk: {text}")
    }
}

/// The engine's HTTP port: the host performs each request with its platform
/// stack, so system roots, proxies and VPNs behave natively. This is the
/// async-ports design — the host implements this trait from Kotlin or
/// Swift.
#[uniffi::export(callback_interface)]
#[async_trait::async_trait]
pub trait HttpClient: Send + Sync {
    /// Performs one request and answers the world's reply.
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, SdkError>;
}

/// The wallet host, seen from the engine: the sign, consent and selection
/// sub-flows. Async, because the answer is a person's.
#[uniffi::export(callback_interface)]
#[async_trait::async_trait]
pub trait Host: Send + Sync {
    /// Asks the wallet's user for the transaction code.
    async fn request_tx_code(&self, flow_id: String) -> Result<String, SdkError>;
}

/// Drives one flow through both ports, end to end: fetches through the
/// host's HTTP stack, asks the host for the tx_code, and returns what the
/// flow produced. This is the engine core's calling shape — the exported
/// async function the SDKs call to run a flow.
#[uniffi::export(async_runtime = "tokio")]
pub async fn run_pre_authorized_flow(
    http: Box<dyn HttpClient>,
    host: Box<dyn Host>,
    issuer_url: String,
) -> Result<String, SdkError> {
    let metadata = http
        .send(HttpRequest {
            method: "GET".to_owned(),
            url: format!("{issuer_url}/.well-known/openid-credential-issuer"),
            body: Vec::new(),
            purpose: FetchPurpose::IssuerMetadata,
            max_response_bytes: 1_048_576,
        })
        .await?;
    if metadata.status != 200 {
        return Err(SdkError::BadResponse);
    }
    let tx_code = host.request_tx_code("flow-1".to_owned()).await?;
    if tx_code.is_empty() {
        return Err(SdkError::Declined);
    }
    let token = http
        .send(HttpRequest {
            method: "POST".to_owned(),
            url: format!("{issuer_url}/token"),
            body: format!("tx_code={tx_code}").into_bytes(),
            purpose: FetchPurpose::Token,
            max_response_bytes: 262_144,
        })
        .await?;
    if token.status != 200 {
        return Err(SdkError::BadResponse);
    }
    Ok(String::from_utf8_lossy(&token.body).to_string())
}

/// A smoke that needs no host: the exported async function awaits an
/// internally-provided future, proving the async runtime wiring from the
/// foreign side's point of view.
#[uniffi::export(async_runtime = "tokio")]
pub async fn ping() -> String {
    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    "pong".to_owned()
}
