//! The UniFFI bindings of the WMP engine core for Kotlin and Swift.
//!
//! This is the **SDK adapter**: it takes the `engine-ports` trait
//! definitions (the engine core's only interface with the world) and adds
//! the UniFFI derives that let Kotlin and Swift implement them as async
//! callback interfaces. The P0.4 smoke proved the shape: async port traits
//! over UniFFI work on the JVM (`suspend fun`) and in Swift
//! (`async throws`).
//!
//! The port types are defined in `engine-ports`; the UniFFI-compatible
//! wrappers are defined here, with conversions between them. The engine
//! core sees only `engine-ports`; the SDK sees only the UniFFI types; the
//! adapter maps between them.

#![deny(missing_docs)]
#![deny(unsafe_code)]
// The uniffi proc macros expand into code that is not ours to lint; the
// adapter's own code holds to the workspace rules.
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

pub mod client;
pub mod engine;

// ─── UniFFI-compatible types (mirror the engine-ports types) ─────────────

/// What an HTTP request is for. Mirrors `engine_ports::FetchPurpose`.
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
    /// An AS's JWKS.
    AsJwks,
}

impl From<FetchPurpose> for engine_ports::FetchPurpose {
    fn from(p: FetchPurpose) -> Self {
        match p {
            FetchPurpose::IssuerMetadata => Self::IssuerMetadata,
            FetchPurpose::AsMetadata => Self::AsMetadata,
            FetchPurpose::Offer => Self::Offer,
            FetchPurpose::Nonce => Self::Nonce,
            FetchPurpose::Token => Self::Token,
            FetchPurpose::Credential => Self::Credential,
            FetchPurpose::Deferred => Self::Deferred,
            FetchPurpose::Notification => Self::Notification,
            FetchPurpose::RequestObject => Self::RequestObject,
            FetchPurpose::ClientMetadata => Self::ClientMetadata,
            FetchPurpose::DirectPost => Self::DirectPost,
            FetchPurpose::Jwks => Self::Jwks,
            FetchPurpose::Logo => Self::Logo,
            FetchPurpose::Pdp => Self::Pdp,
            FetchPurpose::AsJwks => Self::AsJwks,
        }
    }
}

/// The redirect policy. Mirrors `engine_ports::RedirectPolicy`.
#[derive(uniffi::Enum, Clone, Debug, PartialEq)]
pub enum RedirectPolicy {
    /// No redirects.
    None,
    /// At most this many hops.
    Max(u32),
}

/// One HTTP request. Mirrors `engine_ports::HttpRequest`.
#[derive(uniffi::Record, Clone, Debug)]
pub struct HttpRequest {
    /// The request's method.
    pub method: String,
    /// The request's URL.
    pub url: String,
    /// The request's headers.
    pub headers: Vec<HeaderPair>,
    /// The request's body.
    pub body: Vec<u8>,
    /// Why the engine is fetching.
    pub purpose: FetchPurpose,
    /// The response size limit.
    pub max_response_bytes: u64,
    /// The redirect policy.
    pub redirects: RedirectPolicy,
    /// Whether plain http is allowed.
    pub allow_plaintext: bool,
    /// The timeout, in milliseconds.
    pub timeout_ms: u64,
}

/// One header pair (UniFFI cannot pass tuples directly).
#[derive(uniffi::Record, Clone, Debug)]
pub struct HeaderPair {
    /// The header's name.
    pub name: String,
    /// The header's value.
    pub value: String,
}

impl From<&HttpRequest> for engine_ports::HttpRequest {
    fn from(r: &HttpRequest) -> Self {
        Self {
            method: r.method.clone(),
            url: r.url.clone(),
            headers: r
                .headers
                .iter()
                .map(|h| (h.name.clone(), h.value.clone()))
                .collect(),
            body: r.body.clone(),
            purpose: r.purpose.clone().into(),
            max_response_bytes: r.max_response_bytes as usize,
            redirects: match r.redirects {
                RedirectPolicy::None => engine_ports::RedirectPolicy::None,
                RedirectPolicy::Max(hops) => engine_ports::RedirectPolicy::Max(hops as usize),
            },
            allow_plaintext: r.allow_plaintext,
            timeout_ms: r.timeout_ms,
        }
    }
}

/// The world's answer. Mirrors `engine_ports::HttpResponse`.
#[derive(uniffi::Record, Clone, Debug)]
pub struct HttpResponse {
    /// The response's status.
    pub status: u16,
    /// The response's body.
    pub body: Vec<u8>,
}

impl From<engine_ports::HttpResponse> for HttpResponse {
    fn from(r: engine_ports::HttpResponse) -> Self {
        Self {
            status: r.status,
            body: r.body,
        }
    }
}

/// The sign request. Mirrors `engine_ports::SignParams`.
#[derive(uniffi::Record, Clone, Debug)]
pub struct SignParams {
    /// The flow the request belongs to.
    pub flow_id: String,
    /// The to-be-signed input.
    pub to_sign: Vec<u8>,
    /// The key the host signs with.
    pub key_id: Option<String>,
    /// The signing algorithm.
    pub algorithm: String,
}

impl From<SignParams> for engine_ports::SignParams {
    fn from(p: SignParams) -> Self {
        Self {
            flow_id: p.flow_id,
            to_sign: p.to_sign,
            key_id: p.key_id,
            algorithm: p.algorithm,
        }
    }
}

/// The signature. Mirrors `engine_ports::SignResult`.
#[derive(uniffi::Record, Clone, Debug)]
pub struct SignResult {
    /// The signature bytes.
    pub signature: Vec<u8>,
}

impl From<engine_ports::SignResult> for SignResult {
    fn from(r: engine_ports::SignResult) -> Self {
        Self {
            signature: r.signature,
        }
    }
}

/// A match entry. Mirrors `engine_ports::MatchEntry`.
#[derive(uniffi::Record, Clone, Debug)]
pub struct MatchEntry {
    /// The credential's identifier.
    pub credential_id: String,
    /// The credential's display name.
    pub display_name: String,
    /// The credential's type.
    pub credential_type: String,
}

impl From<MatchEntry> for engine_ports::MatchEntry {
    fn from(e: MatchEntry) -> Self {
        Self {
            credential_id: e.credential_id,
            display_name: e.display_name,
            credential_type: e.credential_type,
        }
    }
}

/// The match answer. Mirrors `engine_ports::MatchResult`.
#[derive(uniffi::Record, Clone, Debug)]
pub struct MatchResult {
    /// The selected credential's identifier.
    pub selected_id: String,
}

impl From<engine_ports::MatchResult> for MatchResult {
    fn from(r: engine_ports::MatchResult) -> Self {
        Self {
            selected_id: r.selected_id,
        }
    }
}

/// The consent request. Mirrors `engine_ports::ConsentParams`.
#[derive(uniffi::Record, Clone, Debug)]
pub struct ConsentParams {
    /// The flow.
    pub flow_id: String,
    /// What the verifier asks for.
    pub purpose: String,
    /// The claims the verifier requests.
    pub requested_claims: Vec<String>,
    /// The transaction data entries.
    pub transaction_data: Vec<String>,
}

impl From<ConsentParams> for engine_ports::ConsentParams {
    fn from(p: ConsentParams) -> Self {
        Self {
            flow_id: p.flow_id,
            purpose: p.purpose,
            requested_claims: p.requested_claims,
            transaction_data: p.transaction_data,
        }
    }
}

/// The consent answer. Mirrors `engine_ports::ConsentResult`.
#[derive(uniffi::Record, Clone, Debug)]
pub struct ConsentResult {
    /// Whether the user consented.
    pub consented: bool,
}

impl From<engine_ports::ConsentResult> for ConsentResult {
    fn from(r: engine_ports::ConsentResult) -> Self {
        Self {
            consented: r.consented,
        }
    }
}

// ─── The SDK's error type ────────────────────────────────────────────────

/// The error the SDK's foreign implementations answer with.
#[derive(uniffi::Error, Clone, Debug)]
pub enum SdkError {
    /// The network refused.
    NetworkRefused,
    /// The transport failed.
    Transport(String),
    /// The host declined.
    Declined,
    /// The host cannot answer.
    Cannot(String),
    /// An internal error.
    Internal,
}

impl std::fmt::Display for SdkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::NetworkRefused => "network refused",
            Self::Transport(detail) => return write!(f, "transport: {detail}"),
            Self::Declined => "declined",
            Self::Cannot(detail) => return write!(f, "cannot: {detail}"),
            Self::Internal => "internal",
        };
        write!(f, "engine-adapter-sdk: {text}")
    }
}

impl From<engine_ports::HttpError> for SdkError {
    fn from(err: engine_ports::HttpError) -> Self {
        match err {
            engine_ports::HttpError::Refused => Self::NetworkRefused,
            engine_ports::HttpError::Transport(detail) => Self::Transport(detail),
        }
    }
}

impl From<engine_ports::HostError> for SdkError {
    fn from(err: engine_ports::HostError) -> Self {
        match err {
            engine_ports::HostError::Declined => Self::Declined,
            engine_ports::HostError::Cannot(detail) => Self::Cannot(detail),
        }
    }
}

// ─── The port traits, with UniFFI derives ────────────────────────────────

/// The engine's HTTP port: the host performs each request with its
/// platform stack. The Kotlin/Swift implementation of this trait is the
/// adapter's `engine_ports::HttpClient`.
#[uniffi::export(callback_interface)]
#[async_trait::async_trait]
pub trait HttpClient: Send + Sync {
    /// Performs one request and answers the world's reply.
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, SdkError>;
}

/// The wallet host: the sub-flows the engine asks the wallet's user for.
/// The Kotlin/Swift implementation is the adapter's
/// `engine_ports::Host`.
#[uniffi::export(callback_interface)]
#[async_trait::async_trait]
pub trait Host: Send + Sync {
    /// Asks the host to sign the given input.
    async fn request_sign(&self, params: SignParams) -> Result<SignResult, SdkError>;

    /// Asks the host to select a credential.
    async fn request_match(
        &self,
        flow_id: String,
        entries: Vec<MatchEntry>,
    ) -> Result<MatchResult, SdkError>;

    /// Asks the host's user for consent.
    async fn request_consent(&self, params: ConsentParams) -> Result<ConsentResult, SdkError>;

    /// Asks the host's user for the transaction code.
    async fn request_tx_code(&self, flow_id: String) -> Result<String, SdkError>;

    /// Opens the authorization URL in the host's browser.
    async fn open_authorization(&self, flow_id: String, url: String) -> Result<(), SdkError>;

    /// Reports progress on a flow.
    fn progress(&self, flow_id: String, step: String, detail: Option<String>);
}

// ─── The smoke test target ───────────────────────────────────────────────

/// Drives one flow through both ports, end to end. This is the P0.4
/// smoke's target — the engine core's calling shape.
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
            headers: Vec::new(),
            body: Vec::new(),
            purpose: FetchPurpose::IssuerMetadata,
            max_response_bytes: 1_048_576,
            redirects: RedirectPolicy::None,
            allow_plaintext: false,
            timeout_ms: 10_000,
        })
        .await?;
    if metadata.status != 200 {
        return Err(SdkError::Transport(format!(
            "metadata answered {}",
            metadata.status
        )));
    }
    let tx_code = host.request_tx_code("flow-1".to_owned()).await?;
    if tx_code.is_empty() {
        return Err(SdkError::Declined);
    }
    let token = http
        .send(HttpRequest {
            method: "POST".to_owned(),
            url: format!("{issuer_url}/token"),
            headers: vec![HeaderPair {
                name: "content-type".to_owned(),
                value: "application/x-www-form-urlencoded".to_owned(),
            }],
            body: format!("tx_code={tx_code}").into_bytes(),
            purpose: FetchPurpose::Token,
            max_response_bytes: 262_144,
            redirects: RedirectPolicy::None,
            allow_plaintext: false,
            timeout_ms: 10_000,
        })
        .await?;
    if token.status != 200 {
        return Err(SdkError::Transport(format!(
            "token answered {}",
            token.status
        )));
    }
    Ok(String::from_utf8_lossy(&token.body).to_string())
}

/// A smoke that needs no host.
#[uniffi::export(async_runtime = "tokio")]
pub async fn ping() -> String {
    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    "pong".to_owned()
}
