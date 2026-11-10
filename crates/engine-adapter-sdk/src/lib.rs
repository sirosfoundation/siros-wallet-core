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
pub mod ports;

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

/// The client_id scheme of the verifier. Mirrors
/// `engine_ports::ClientIdScheme`.
#[derive(uniffi::Enum, Clone, Debug)]
pub enum ClientIdScheme {
    /// An x.509 certificate's SAN DNS entry (`x509_san_dns:`).
    X509SanDns,
    /// An x.509 certificate's SAN URI entry (`x509_san_uri:`).
    X509SanUri,
    /// The base64url SHA-256 over the verifier's certificate
    /// (`x509_hash:`, OpenID4VP 1.0 §5.2.3) — the chain rides the
    /// request object's `x5c`.
    X509Hash,
    /// A DID-based request (`did:`).
    DecentralizedIdentifier,
    /// A verifier attestation (`verifier_attestation:`).
    VerifierAttestation,
    /// The redirect URI itself (unsigned requests only).
    RedirectUri,
    /// An unrecognized prefix.
    Unknown,
}

impl From<engine_ports::ClientIdScheme> for ClientIdScheme {
    fn from(s: engine_ports::ClientIdScheme) -> Self {
        match s {
            engine_ports::ClientIdScheme::X509SanDns => Self::X509SanDns,
            engine_ports::ClientIdScheme::X509SanUri => Self::X509SanUri,
            engine_ports::ClientIdScheme::X509Hash => Self::X509Hash,
            engine_ports::ClientIdScheme::DecentralizedIdentifier => Self::DecentralizedIdentifier,
            engine_ports::ClientIdScheme::VerifierAttestation => Self::VerifierAttestation,
            engine_ports::ClientIdScheme::RedirectUri => Self::RedirectUri,
            engine_ports::ClientIdScheme::Unknown(_) => Self::Unknown,
        }
    }
}

/// The verifier info the consent UI shows. Mirrors
/// `engine_ports::VerifierInfo`.
#[derive(uniffi::Record, Clone, Debug)]
pub struct VerifierInfo {
    /// The display name (the metadata's client_name, else the client_id).
    pub name: String,
    /// The client_id, with its scheme prefix.
    pub client_id: String,
    /// The inferred client_id scheme.
    pub client_id_scheme: ClientIdScheme,
    /// The domain extracted from the client_id, when there is one.
    pub domain: String,
    /// The logo URI, when the metadata published one.
    pub logo_uri: String,
    /// Whether the PDP trusts the verifier.
    pub trusted: bool,
    /// The trust framework that made the decision, when there is one.
    pub framework: String,
    /// Why the decision was made (the PDP's reason).
    pub reason: String,
}

impl From<engine_ports::VerifierInfo> for VerifierInfo {
    fn from(v: engine_ports::VerifierInfo) -> Self {
        Self {
            name: v.name,
            client_id: v.client_id,
            client_id_scheme: v.client_id_scheme.into(),
            domain: v.domain,
            logo_uri: v.logo_uri,
            trusted: v.trusted,
            framework: v.framework,
            reason: v.reason,
        }
    }
}

/// One credential the host selected to present. Mirrors
/// `engine_ports::VpSelection`.
#[derive(uniffi::Record, Clone, Debug)]
pub struct VpSelection {
    /// The DCQL query's credential id this selection answers.
    pub credential_query_id: String,
    /// The wallet credential to present.
    pub credential_id: String,
    /// The claim names the presentation discloses.
    pub disclosed_claims: Vec<String>,
}

impl From<VpSelection> for engine_ports::VpSelection {
    fn from(s: VpSelection) -> Self {
        Self {
            credential_query_id: s.credential_query_id,
            credential_id: s.credential_id,
            disclosed_claims: s.disclosed_claims,
        }
    }
}

impl From<engine_ports::VpSelection> for VpSelection {
    fn from(s: engine_ports::VpSelection) -> Self {
        Self {
            credential_query_id: s.credential_query_id,
            credential_id: s.credential_id,
            disclosed_claims: s.disclosed_claims,
        }
    }
}

/// The presentation match request. Mirrors `engine_ports::MatchParams`.
#[derive(uniffi::Record, Clone, Debug)]
pub struct MatchParams {
    /// The flow.
    pub flow_id: String,
    /// The DCQL query as raw JSON text, when the request carried one.
    pub dcql_query: Option<String>,
    /// The scope, when the request used scope instead of a query.
    pub scope: String,
    /// The verifier as the consent UI shows it.
    pub verifier: VerifierInfo,
    /// The transaction data entries, raw, for the UI's summary.
    pub transaction_data: Vec<String>,
}

impl From<engine_ports::MatchParams> for MatchParams {
    fn from(m: engine_ports::MatchParams) -> Self {
        Self {
            flow_id: m.flow_id,
            dcql_query: m.dcql_query.and_then(|q| serde_json::to_string(&q).ok()),
            scope: m.scope,
            verifier: m.verifier.into(),
            transaction_data: m.transaction_data,
        }
    }
}

/// The match answer. Mirrors `engine_ports::MatchResult`.
#[derive(uniffi::Record, Clone, Debug)]
pub struct MatchResult {
    /// The selected credentials; empty means nothing matched.
    pub selections: Vec<VpSelection>,
    /// The transport's opaque selection handle (WMP OpenID4x 3.2.3.1),
    /// when it issued one; the engine passes it through unchanged.
    pub handle: Option<String>,
}

impl From<engine_ports::MatchResult> for MatchResult {
    fn from(r: engine_ports::MatchResult) -> Self {
        Self {
            selections: r.selections.into_iter().map(Into::into).collect(),
            handle: r.handle,
        }
    }
}

/// The presentation construction request. Mirrors
/// `engine_ports::VpParams`.
#[derive(uniffi::Record, Clone, Debug)]
pub struct VpParams {
    /// The flow.
    pub flow_id: String,
    /// The audience (the client_id, or the redirect_uri fallback).
    pub audience: String,
    /// The request's nonce.
    pub nonce: String,
    /// The selected credentials to present.
    pub selections: Vec<VpSelection>,
    /// The response endpoint (the mdoc session transcript input).
    pub response_uri: String,
    /// The verifier encryption key's JWK thumbprint, for
    /// direct_post.jwt's OpenID4VPHandover — empty otherwise.
    pub verifier_jwk_thumbprint: String,
    /// The verifier's session id (the ZK/PPID verifier_context) —
    /// empty for non-ZK presentations.
    pub verifier_session_id: String,
    /// The transaction data entries, raw — the KB-JWT hashes.
    pub transaction_data: Vec<String>,
    /// The transport's selection handle, as the match answer carried
    /// it (WMP OpenID4x 3.2.3.1): passed through unchanged.
    pub selection_handle: Option<String>,
}

impl From<engine_ports::VpParams> for VpParams {
    fn from(p: engine_ports::VpParams) -> Self {
        Self {
            flow_id: p.flow_id,
            audience: p.audience,
            nonce: p.nonce,
            selections: p.selections.into_iter().map(Into::into).collect(),
            response_uri: p.response_uri,
            verifier_jwk_thumbprint: p.verifier_jwk_thumbprint,
            verifier_session_id: p.verifier_session_id,
            transaction_data: p.transaction_data,
            selection_handle: p.selection_handle,
        }
    }
}

/// The presentation answer. Mirrors `engine_ports::VpResult`.
#[derive(uniffi::Record, Clone, Debug)]
pub struct VpResult {
    /// The VP token: newline-separated per selection, or a pre-formed
    /// JSON object.
    pub vp_token: String,
    /// The sign refusal, when the host answered with a refusal instead
    /// of a token (the Go `sign_response.error_code`, #472): the
    /// engine answers the verifier `access_denied` at once.
    pub refusal: Option<SignRefusal>,
}

/// A sign-stage refusal with its allowlisted code (the Go
/// `SignError.Code` — only the code crosses, never the wallet's
/// free-form reason).
#[derive(uniffi::Record, Clone, Debug)]
pub struct SignRefusal {
    /// The refusal's code: `SIGN_REFUSED` (the user declined at the
    /// sign step) or `UNSUPPORTED_TRANSACTION_DATA` (the client
    /// refuses a transaction type only it can judge).
    pub code: String,
}

impl From<VpResult> for engine_ports::VpResult {
    fn from(r: VpResult) -> Self {
        Self {
            vp_token: r.vp_token,
            refusal: r
                .refusal
                .map(|refusal| engine_ports::SignRefusal { code: refusal.code }),
        }
    }
}

impl From<engine_ports::VpResult> for VpResult {
    fn from(r: engine_ports::VpResult) -> Self {
        Self {
            vp_token: r.vp_token,
            refusal: r.refusal.map(|refusal| SignRefusal { code: refusal.code }),
        }
    }
}

/// The client-held DPoP proof request. Mirrors
/// `engine_ports::DpopProofParams`.
#[derive(uniffi::Record, Clone, Debug)]
pub struct DpopProofParams {
    /// The flow.
    pub flow_id: String,
    /// The device key to sign with, named when the flow knows it.
    pub key_id: Option<String>,
    /// The HTTP method the proof is bound to.
    pub htm: String,
    /// The HTTP URI the proof is bound to.
    pub htu: String,
    /// The access token, when a resource request is being proofed.
    pub access_token: String,
    /// The server-provided DPoP nonce, when one was demanded.
    pub nonce: String,
}

impl From<engine_ports::DpopProofParams> for DpopProofParams {
    fn from(p: engine_ports::DpopProofParams) -> Self {
        Self {
            flow_id: p.flow_id,
            key_id: p.key_id,
            htm: p.htm,
            htu: p.htu,
            access_token: p.access_token,
            nonce: p.nonce,
        }
    }
}

/// The DPoP proof answer. Mirrors `engine_ports::DpopProofResult`.
#[derive(uniffi::Record, Clone, Debug)]
pub struct DpopProofResult {
    /// The proof JWT (`dpop+jwt`).
    pub proof: String,
}

impl From<DpopProofResult> for engine_ports::DpopProofResult {
    fn from(r: DpopProofResult) -> Self {
        Self { proof: r.proof }
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

    /// Asks the host to match the wallet's credentials against the DCQL
    /// query and select what to present. An empty answer means nothing
    /// matched: the flow ends there.
    async fn request_match(&self, params: MatchParams) -> Result<MatchResult, SdkError>;

    /// Asks the host to construct and sign the VP token for the
    /// selected credentials — the wallet's presentation formats and
    /// key custody live in the host.
    async fn request_vp(&self, params: VpParams) -> Result<VpResult, SdkError>;

    /// Asks the host for a client-held DPoP proof; the engine falls
    /// back to its own key when the host cannot answer.
    async fn request_dpop_proof(
        &self,
        params: DpopProofParams,
    ) -> Result<DpopProofResult, SdkError>;

    /// Asks the host's user for consent.
    async fn request_consent(&self, params: ConsentParams) -> Result<ConsentResult, SdkError>;

    /// Asks the host's user for the transaction code.
    async fn request_tx_code(&self, flow_id: String) -> Result<String, SdkError>;

    /// Opens the authorization URL in the host's browser.
    async fn open_authorization(&self, flow_id: String, url: String) -> Result<(), SdkError>;

    /// Asks the host for the public JWK of a named signing key, so the
    /// engine can identify the key in the proof headers it builds. Keys
    /// always live in the app; the engine only ever sees the public
    /// JWK. A refusal keeps the flows working without key identification.
    async fn request_signing_key(
        &self,
        params: SigningKeyParams,
    ) -> Result<SigningKeyResult, SdkError>;

    /// Asks the host for a client attestation (a Wallet Instance
    /// Attestation and its proof of possession), when the AS demands
    /// one. A refusal continues without client attestation.
    async fn request_attestation(
        &self,
        params: AttestationParams,
    ) -> Result<AttestationResult, SdkError>;

    /// Asks the host's user to pick one of the offered credential
    /// configurations, when the offer names more than one. A refusal
    /// fails the flow closed (exactly one configuration is
    /// auto-selected and never asked).
    async fn request_credential_selection(
        &self,
        params: CredentialSelectionParams,
    ) -> Result<CredentialSelectionResult, SdkError>;

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

// ─── The key, attestation and selection asks ─────────────────────────────

/// The signing-key request. Mirrors `engine_ports::SigningKeyParams`.
#[derive(uniffi::Record, Clone, Debug)]
pub struct SigningKeyParams {
    /// The flow the ask belongs to.
    pub flow_id: String,
    /// The key the engine will sign with, named when the flow knows it.
    pub key_id: Option<String>,
    /// Whether the host must answer with a FRESH key (the OID4VCI batch
    /// rule: each credential in a batch binds to its own key —
    /// SDJWT-10.1). Default false.
    pub fresh: bool,
}

impl From<SigningKeyParams> for engine_ports::SigningKeyParams {
    fn from(p: SigningKeyParams) -> Self {
        Self {
            flow_id: p.flow_id,
            key_id: p.key_id,
            fresh: p.fresh,
        }
    }
}

/// The public JWK answer. Mirrors `engine_ports::SigningKeyResult`.
#[derive(uniffi::Record, Clone, Debug)]
pub struct SigningKeyResult {
    /// The public JWK as JSON text, public members only.
    pub jwk: String,
}

impl From<SigningKeyResult> for engine_ports::SigningKeyResult {
    fn from(r: SigningKeyResult) -> Self {
        Self {
            jwk: serde_json::from_str(&r.jwk).unwrap_or_default(),
        }
    }
}

/// The client-attestation request. Mirrors
/// `engine_ports::AttestationParams`.
#[derive(uniffi::Record, Clone, Debug)]
pub struct AttestationParams {
    /// The flow the ask belongs to.
    pub flow_id: String,
    /// The PoP audience: the authorization server.
    pub audience: String,
    /// The client_id the WIA names as `sub`.
    pub client_id: String,
    /// The server-provided challenge, when the AS demanded one.
    pub challenge: String,
}

impl From<AttestationParams> for engine_ports::AttestationParams {
    fn from(p: AttestationParams) -> Self {
        Self {
            flow_id: p.flow_id,
            audience: p.audience,
            client_id: p.client_id,
            challenge: p.challenge,
        }
    }
}

/// The client-attestation answer. Mirrors
/// `engine_ports::AttestationResult`.
#[derive(uniffi::Record, Clone, Debug, Default)]
pub struct AttestationResult {
    /// The Wallet Instance Attestation JWT, when the host provided one.
    pub wia: String,
    /// The PoP JWT binding the WIA to the audience, when provided.
    pub pop: String,
}

impl From<AttestationResult> for engine_ports::AttestationResult {
    fn from(r: AttestationResult) -> Self {
        Self {
            wia: r.wia,
            pop: r.pop,
        }
    }
}

/// One credential configuration the host may select. Mirrors
/// `engine_ports::AvailableCredential`.
#[derive(uniffi::Record, Clone, Debug)]
pub struct AvailableCredential {
    /// The configuration's id.
    pub id: String,
    /// The first display entry, as JSON text, for the selection UI.
    pub display: Option<String>,
    /// The configuration's credential format identifier.
    pub format: String,
    /// The `vct`, when the configuration carries one.
    pub vct: String,
}

impl From<engine_ports::AvailableCredential> for AvailableCredential {
    fn from(a: engine_ports::AvailableCredential) -> Self {
        Self {
            id: a.id,
            display: a.display.and_then(|d| serde_json::to_string(&d).ok()),
            format: a.format,
            vct: a.vct,
        }
    }
}

impl From<AvailableCredential> for engine_ports::AvailableCredential {
    fn from(a: AvailableCredential) -> Self {
        Self {
            id: a.id,
            display: a.display.and_then(|text| serde_json::from_str(&text).ok()),
            format: a.format,
            vct: a.vct,
        }
    }
}

/// The credential configuration selection ask. Mirrors
/// `engine_ports::CredentialSelectionParams`.
#[derive(uniffi::Record, Clone, Debug)]
pub struct CredentialSelectionParams {
    /// The flow the selection belongs to.
    pub flow_id: String,
    /// The configurations on offer, in the offer's order.
    pub available: Vec<AvailableCredential>,
}

impl From<CredentialSelectionParams> for engine_ports::CredentialSelectionParams {
    fn from(p: CredentialSelectionParams) -> Self {
        Self {
            flow_id: p.flow_id,
            available: p.available.into_iter().map(Into::into).collect(),
        }
    }
}

/// The selection answer. Mirrors
/// `engine_ports::CredentialSelectionResult`.
#[derive(uniffi::Record, Clone, Debug)]
pub struct CredentialSelectionResult {
    /// The chosen configuration's id.
    pub credential_configuration_id: String,
}

impl From<CredentialSelectionResult> for engine_ports::CredentialSelectionResult {
    fn from(r: CredentialSelectionResult) -> Self {
        Self {
            credential_configuration_id: r.credential_configuration_id,
        }
    }
}

// ─── The trust port (the PDP) ────────────────────────────────────────────

/// The trust evaluation request. Mirrors
/// `engine_ports::EvaluationRequest`.
#[derive(uniffi::Record, Clone, Debug)]
pub struct EvaluationRequest {
    /// The subject whose trust is being evaluated.
    pub subject: String,
    /// The key material, as the engine extracted it.
    pub key_material: Vec<u8>,
    /// The resource type being resolved, when there is one.
    pub resource_type: Option<String>,
    /// The evaluation's context, as JSON text (the client_id scheme,
    /// the response/redirect URIs, the trust chain, the attestation).
    pub context: String,
}

impl From<engine_ports::EvaluationRequest> for EvaluationRequest {
    fn from(r: engine_ports::EvaluationRequest) -> Self {
        Self {
            subject: r.subject,
            key_material: r.key_material,
            resource_type: r.resource_type,
            context: r.context.to_string(),
        }
    }
}

/// The trust evaluation's verdict. Mirrors
/// `engine_ports::EvaluationResponse`.
#[derive(uniffi::Record, Clone, Debug)]
pub struct EvaluationResponse {
    /// Whether the subject is trusted.
    pub trusted: bool,
    /// The decision text, when there is one.
    pub decision: Option<String>,
}

impl From<EvaluationResponse> for engine_ports::EvaluationResponse {
    fn from(r: EvaluationResponse) -> Self {
        Self {
            trusted: r.trusted,
            decision: r.decision,
        }
    }
}

/// The metadata resolution request. Mirrors
/// `engine_ports::ResolveRequest`.
#[derive(uniffi::Record, Clone, Debug)]
pub struct ResolveRequest {
    /// The URL subject to resolve.
    pub uri: String,
    /// The resource type (`credential_issuer`,
    /// `oauth-authorization-server`, `did_document`).
    pub resource_type: String,
}

impl From<ResolveRequest> for engine_ports::ResolveRequest {
    fn from(r: ResolveRequest) -> Self {
        Self {
            uri: r.uri,
            resource_type: r.resource_type,
        }
    }
}

/// The metadata resolution's answer. Mirrors
/// `engine_ports::ResolveResponse`.
#[derive(uniffi::Record, Clone, Debug)]
pub struct ResolveResponse {
    /// The resolved document, raw.
    pub metadata: Vec<u8>,
    /// Trust information, when the PDP carries it.
    pub trust_info: Option<Vec<u8>>,
}

impl From<ResolveResponse> for engine_ports::ResolveResponse {
    fn from(r: ResolveResponse) -> Self {
        Self {
            metadata: r.metadata,
            trust_info: r.trust_info,
        }
    }
}

/// One offered credential the entitlement evaluator matches against
/// the registration. Mirrors `engine_ports::EntitlementOffer`.
#[derive(uniffi::Record, Clone, Debug)]
pub struct EntitlementOffer {
    /// The OpenID4VCI credential format identifier.
    pub format: String,
    /// The `vct` or `doctype`.
    pub credential_type: String,
}

impl From<EntitlementOffer> for engine_ports::EntitlementOffer {
    fn from(o: EntitlementOffer) -> Self {
        Self {
            format: o.format,
            credential_type: o.credential_type,
        }
    }
}

impl From<engine_ports::EntitlementOffer> for EntitlementOffer {
    fn from(o: engine_ports::EntitlementOffer) -> Self {
        Self {
            format: o.format,
            credential_type: o.credential_type,
        }
    }
}

/// The issuer entitlement evaluation's request. Mirrors
/// `engine_ports::EntitlementRequest`.
#[derive(uniffi::Record, Clone, Debug)]
pub struct EntitlementRequest {
    /// The issuer's identifier.
    pub issuer: String,
    /// The raw issuer metadata document.
    pub metadata: Vec<u8>,
    /// The metadata's signing key material.
    pub key_material: Vec<u8>,
    /// The configurations the flow is about to request.
    pub offers: Vec<EntitlementOffer>,
}

impl From<EntitlementRequest> for engine_ports::EntitlementRequest {
    fn from(r: EntitlementRequest) -> Self {
        Self {
            issuer: r.issuer,
            metadata: r.metadata,
            key_material: r.key_material,
            offers: r.offers.into_iter().map(Into::into).collect(),
        }
    }
}

/// The entitlement mode. Mirrors `engine_ports::EntitlementMode`.
#[derive(uniffi::Enum, Clone, Debug, PartialEq)]
pub enum EntitlementMode {
    /// Records findings and still allows issuance.
    Warn,
    /// Turns the findings into a refusal.
    Fail,
    /// Skips the evaluation.
    Off,
}

impl From<EntitlementMode> for engine_ports::EntitlementMode {
    fn from(m: EntitlementMode) -> Self {
        match m {
            EntitlementMode::Warn => Self::Warn,
            EntitlementMode::Fail => Self::Fail,
            EntitlementMode::Off => Self::Off,
        }
    }
}

impl From<engine_ports::EntitlementMode> for EntitlementMode {
    fn from(m: engine_ports::EntitlementMode) -> Self {
        match m {
            engine_ports::EntitlementMode::Warn => Self::Warn,
            engine_ports::EntitlementMode::Fail => Self::Fail,
            engine_ports::EntitlementMode::Off => Self::Off,
        }
    }
}

/// One entitlement finding. Mirrors `engine_ports::EntitlementFinding`.
#[derive(uniffi::Record, Clone, Debug)]
pub struct EntitlementFinding {
    /// The finding's code.
    pub code: EntitlementCode,
    /// The code's message.
    pub message: String,
    /// The offered type, when the finding is about one.
    pub credential_type: Option<String>,
}

impl From<EntitlementFinding> for engine_ports::EntitlementFinding {
    fn from(f: EntitlementFinding) -> Self {
        Self {
            code: f.code.into(),
            message: f.message,
            credential_type: f.credential_type,
        }
    }
}

impl From<engine_ports::EntitlementFinding> for EntitlementFinding {
    fn from(f: engine_ports::EntitlementFinding) -> Self {
        Self {
            code: f.code.into(),
            message: f.message,
            credential_type: f.credential_type,
        }
    }
}

/// The entitlement finding's code. Mirrors
/// `engine_ports::EntitlementCode`.
#[derive(uniffi::Enum, Clone, Debug, PartialEq)]
pub enum EntitlementCode {
    /// The issuer metadata was signed by no certificate chain.
    NoAccessCertificate,
    /// The chain's leaf does not meet the WRPAC profile.
    NotWrpac,
    /// The issuer metadata carries no registration certificate.
    NoRegistrationCertificate,
    /// The registration certificate is not readable.
    RegistrationMalformed,
    /// The registration certificate is not current.
    RegistrationExpired,
    /// The registration certificate's validity is not conformant.
    RegistrationOverlong,
    /// The registration certificate describes another provider.
    BindingMismatch,
    /// The registered entitlements name no provider role.
    NotProvider,
    /// The provider is not registered for an offered credential.
    TypeNotRegistered,
    /// The registration certificate's signature was not verified.
    RegistrationUnverified,
    /// The signer is no trusted Registrar.
    RegistrarNotTrusted,
    /// Nothing established the signing chain's trust.
    AccessCertificateNotTrusted,
}

impl From<EntitlementCode> for engine_ports::EntitlementCode {
    fn from(c: EntitlementCode) -> Self {
        match c {
            EntitlementCode::NoAccessCertificate => Self::NoAccessCertificate,
            EntitlementCode::NotWrpac => Self::NotWrpac,
            EntitlementCode::NoRegistrationCertificate => Self::NoRegistrationCertificate,
            EntitlementCode::RegistrationMalformed => Self::RegistrationMalformed,
            EntitlementCode::RegistrationExpired => Self::RegistrationExpired,
            EntitlementCode::RegistrationOverlong => Self::RegistrationOverlong,
            EntitlementCode::BindingMismatch => Self::BindingMismatch,
            EntitlementCode::NotProvider => Self::NotProvider,
            EntitlementCode::TypeNotRegistered => Self::TypeNotRegistered,
            EntitlementCode::RegistrationUnverified => Self::RegistrationUnverified,
            EntitlementCode::RegistrarNotTrusted => Self::RegistrarNotTrusted,
            EntitlementCode::AccessCertificateNotTrusted => Self::AccessCertificateNotTrusted,
        }
    }
}

impl From<engine_ports::EntitlementCode> for EntitlementCode {
    fn from(c: engine_ports::EntitlementCode) -> Self {
        match c {
            engine_ports::EntitlementCode::NoAccessCertificate => Self::NoAccessCertificate,
            engine_ports::EntitlementCode::NotWrpac => Self::NotWrpac,
            engine_ports::EntitlementCode::NoRegistrationCertificate => {
                Self::NoRegistrationCertificate
            }
            engine_ports::EntitlementCode::RegistrationMalformed => Self::RegistrationMalformed,
            engine_ports::EntitlementCode::RegistrationExpired => Self::RegistrationExpired,
            engine_ports::EntitlementCode::RegistrationOverlong => Self::RegistrationOverlong,
            engine_ports::EntitlementCode::BindingMismatch => Self::BindingMismatch,
            engine_ports::EntitlementCode::NotProvider => Self::NotProvider,
            engine_ports::EntitlementCode::TypeNotRegistered => Self::TypeNotRegistered,
            engine_ports::EntitlementCode::RegistrationUnverified => Self::RegistrationUnverified,
            engine_ports::EntitlementCode::RegistrarNotTrusted => Self::RegistrarNotTrusted,
            engine_ports::EntitlementCode::AccessCertificateNotTrusted => {
                Self::AccessCertificateNotTrusted
            }
        }
    }
}

/// The entitlement evaluation's decision. Mirrors
/// `engine_ports::EntitlementDecision`.
#[derive(uniffi::Record, Clone, Debug)]
pub struct EntitlementDecision {
    /// Whether issuance may proceed.
    pub allowed: bool,
    /// Which mode produced the decision.
    pub mode: EntitlementMode,
    /// Whether anything was evaluated.
    pub evaluated: bool,
    /// The findings.
    pub findings: Vec<EntitlementFinding>,
    /// True when more findings arose than the answer carries.
    pub findings_truncated: bool,
}

impl From<EntitlementDecision> for engine_ports::EntitlementDecision {
    fn from(d: EntitlementDecision) -> Self {
        Self {
            allowed: d.allowed,
            mode: d.mode.into(),
            evaluated: d.evaluated,
            findings: d.findings.into_iter().map(Into::into).collect(),
            findings_truncated: d.findings_truncated,
        }
    }
}

impl From<engine_ports::EntitlementDecision> for EntitlementDecision {
    fn from(d: engine_ports::EntitlementDecision) -> Self {
        Self {
            allowed: d.allowed,
            mode: d.mode.into(),
            evaluated: d.evaluated,
            findings: d.findings.into_iter().map(Into::into).collect(),
            findings_truncated: d.findings_truncated,
        }
    }
}

/// The engine's trust port: the policy decision point the engine
/// evaluates issuer, verifier and entitlement trust through. The
/// Kotlin/Swift implementation is the adapter's `engine_ports::Pdp` —
/// the app's trust stack (the backend's `/v1/evaluate` over the app's
/// HTTP, or a local evaluator).
#[uniffi::export(callback_interface)]
#[async_trait::async_trait]
pub trait Pdp: Send + Sync {
    /// Evaluates the trust of a subject with the key material the
    /// engine extracted.
    async fn evaluate(&self, request: EvaluationRequest) -> Result<EvaluationResponse, SdkError>;

    /// Resolves a URL to a metadata document (the `/v1/resolve`
    /// shape), including the DID documents of `did:`-schemed verifiers.
    async fn resolve(&self, request: ResolveRequest) -> Result<ResolveResponse, SdkError>;

    /// Evaluates the issuer's entitlement (ARF 6.6.2.3).
    async fn evaluate_entitlement(
        &self,
        request: EntitlementRequest,
    ) -> Result<EntitlementDecision, SdkError>;
}
