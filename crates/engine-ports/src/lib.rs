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

/// The signing-key ask: the public JWK of the key the engine is about
/// to ask the host to sign with, so the engine can identify the key in
/// the proof headers it builds (the OID4VCI JWT proof's `jwk` and its
/// RFC 7638 thumbprint `kid` — the SDK's
/// `jose.calculateJwkThumbprint(jwk, "sha256")` convention).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningKeyParams {
    /// The flow the ask belongs to.
    pub flow_id: String,
    /// The key the engine will sign with, named when the flow knows
    /// it — a renewal's reissuance kid; the device key when unnamed.
    #[serde(default)]
    pub key_id: Option<String>,
}

/// The public JWK answer. Keys always live in the app; the engine
/// only ever sees the public JWK.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SigningKeyResult {
    /// The public JWK, public members only, as the app holds it.
    #[serde(default)]
    pub jwk: serde_json::Value,
}

/// The client_id scheme, inferred from the `client_id` prefix — a
/// wire contract (it crosses the Host boundary in the verifier info).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientIdScheme {
    /// `x509_san_dns:` — an x.509 certificate's SAN DNS entry.
    X509SanDns,
    /// `x509_san_uri:` — an x.509 certificate's SAN URI entry.
    X509SanUri,
    /// `x509_hash:` — the base64url SHA-256 over the verifier's
    /// DER-encoded certificate (OpenID4VP 1.0 §5.2.3): the chain rides
    /// the request object's `x5c`, and the leaf's hash must equal the
    /// client_id's value.
    X509Hash,
    /// `did:` — a DID-based request (verified first, per the spec).
    DecentralizedIdentifier,
    /// `verifier_attestation:` — a verifier attestation.
    VerifierAttestation,
    /// `redirect_uri:` — the redirect URI itself (unsigned requests only).
    RedirectUri,
    /// An unrecognized prefix.
    Unknown(String),
}

impl ClientIdScheme {
    /// Infers the scheme from the `client_id` string's prefix.
    pub fn infer(client_id: &str) -> Self {
        if client_id.starts_with("x509_san_dns:") {
            Self::X509SanDns
        } else if client_id.starts_with("x509_san_uri:") {
            Self::X509SanUri
        } else if client_id.starts_with("x509_hash:") {
            Self::X509Hash
        } else if client_id.starts_with("did:") {
            Self::DecentralizedIdentifier
        } else if client_id.starts_with("decentralized_identifier:") {
            // OpenID4VP 1.0's name for the scheme the drafts called
            // "did": the same scheme (the Go engine's
            // ClientIDSchemeDecentralizedIdentifier alias).
            Self::DecentralizedIdentifier
        } else if client_id.starts_with("verifier_attestation:") {
            Self::VerifierAttestation
        } else if client_id.starts_with("http://") || client_id.starts_with("https://") {
            Self::RedirectUri
        } else {
            Self::Unknown(client_id.to_owned())
        }
    }

    /// The prefix this scheme implies; the client_id must start with it.
    pub fn prefix(&self) -> &str {
        match self {
            Self::X509SanDns => "x509_san_dns:",
            Self::X509SanUri => "x509_san_uri:",
            Self::X509Hash => "x509_hash:",
            Self::DecentralizedIdentifier => "did:",
            Self::VerifierAttestation => "verifier_attestation:",
            Self::RedirectUri => "",
            Self::Unknown(_) => "",
        }
    }

    /// The scheme's claim name — the `client_id_scheme` the request
    /// names and the trust evaluation's context carries (the Go
    /// engine's `ClientIDScheme*` constants).
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::X509SanDns => "x509_san_dns",
            Self::X509SanUri => "x509_san_uri",
            Self::X509Hash => "x509_hash",
            Self::DecentralizedIdentifier => "decentralized_identifier",
            Self::VerifierAttestation => "verifier_attestation",
            Self::RedirectUri => "redirect_uri",
            Self::Unknown(_) => "unknown",
        }
    }
}

/// The verifier info the host's consent UI shows (OpenID4VP §5.2's
/// client metadata, plus the trust decision the PDP made) — a wire
/// contract.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerifierInfo {
    /// The display name (the client metadata's client_name, else the
    /// client_id).
    pub name: String,
    /// The client_id, with its scheme prefix.
    pub client_id: String,
    /// The inferred client_id scheme.
    pub client_id_scheme: ClientIdScheme,
    /// The domain extracted from the client_id, when there is one.
    pub domain: String,
    /// The logo URI, when the metadata published one.
    #[serde(default)]
    pub logo_uri: String,
    /// Whether the PDP trusts the verifier.
    pub trusted: bool,
    /// The trust framework that made the decision, when there is one.
    #[serde(default)]
    pub framework: String,
    /// Why the decision was made (the PDP's reason).
    #[serde(default)]
    pub reason: String,
}

/// One credential the host selected to present, as the match answer
/// reports it (the Go engine's `ConsentSelection`): which DCQL query it
/// answers, which credential satisfies it, and the claims the user
/// agreed to disclose.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VpSelection {
    /// The DCQL query's credential id this selection answers
    /// (OpenID4VP §8.1: the vp_token object is keyed by it).
    #[serde(default)]
    pub credential_query_id: String,
    /// The wallet credential to present.
    pub credential_id: String,
    /// The claim names the presentation discloses.
    #[serde(default)]
    pub disclosed_claims: Vec<String>,
}

/// The presentation match: the engine asks the host to match the
/// wallet's credentials against the DCQL query (or the scope) and
/// select what to present. The local matching is the host's — it has
/// the wallet state and the credential formats; the engine never
/// enumerates the wallet's credentials.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchParams {
    /// The flow the match belongs to.
    pub flow_id: String,
    /// The DCQL query, raw, when the request carried one.
    #[serde(default)]
    pub dcql_query: Option<serde_json::Value>,
    /// The scope, when the request used scope instead of a query.
    #[serde(default)]
    pub scope: String,
    /// The verifier as the consent UI shows it.
    pub verifier: VerifierInfo,
    /// The transaction data entries, raw (the base64url strings), for
    /// the UI's transaction summary.
    #[serde(default)]
    pub transaction_data: Vec<String>,
}

/// The match answer: the selected credentials, one per DCQL query
/// answered. An empty answer means nothing matched — the flow ends
/// there, exactly as the Go engine's `credentials_matched` with an
/// empty set.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MatchResult {
    /// The selected credentials.
    #[serde(default)]
    pub selections: Vec<VpSelection>,
    /// The transport's opaque selection handle, when it issued one
    /// (WMP OpenID4x 3.2.3.1: the `select_credentials` ask's
    /// correlation handle). The engine does not interpret it: it rides
    /// unchanged into the presentation ask
    /// ([`VpParams::selection_handle`](crate::VpParams::selection_handle)),
    /// so the transport's answer correlates with its ask. Absent when
    /// the transport has no handle (the plain host asks).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
}

/// The presentation the engine asks the host to construct and sign:
/// the VP token for the selected credentials. The wallet's
/// presentation formats (mdoc, SD-JWT, ZK) and its key custody live in
/// the host; the engine never sees a private key (the Go engine's
/// `SignActionSignPresentation`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpParams {
    /// The flow the presentation belongs to.
    pub flow_id: String,
    /// The audience: the client_id (the redirect_uri fallback when the
    /// request carried none).
    pub audience: String,
    /// The request's nonce.
    pub nonce: String,
    /// The selected credentials to present.
    pub selections: Vec<VpSelection>,
    /// The response endpoint — the mdoc session transcript input.
    pub response_uri: String,
    /// The base64url SHA-256 JWK thumbprint of the verifier's
    /// encryption key, for direct_post.jwt's OpenID4VPHandover
    /// transcript. Empty for the other response modes.
    #[serde(default)]
    pub verifier_jwk_thumbprint: String,
    /// The verifier-assigned session id (the `sessionId` query
    /// parameter) — the ZK/PPID pseudonym's verifier_context binds to
    /// it. Empty for non-ZK presentations.
    #[serde(default)]
    pub verifier_session_id: String,
    /// The transaction data entries, raw — the host hashes each into
    /// the KB-JWT (TS12).
    #[serde(default)]
    pub transaction_data: Vec<String>,
    /// The transport's selection handle, as the match answer carried
    /// it (WMP OpenID4x 3.2.3.1): passed through unchanged, never
    /// interpreted. Absent when the transport has no handle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selection_handle: Option<String>,
}

/// The presentation answer.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VpResult {
    /// The VP token: one token per selection, newline-separated — the
    /// engine restructures the multi-selection answer into the DCQL
    /// object — or a pre-formed JSON object, which passes through.
    #[serde(default)]
    pub vp_token: String,
    /// The sign refusal, when the host answered the ask with a refusal
    /// instead of a token: the Go engine's `sign_response.error_code`
    /// (the #472 contract). `Err(HostError::Declined)` stays the
    /// short form for "the user declined"; this carries the allowlisted
    /// code when the host knows more (`SIGN_REFUSED`, an unsupported
    /// transaction type). The engine answers the verifier
    /// `access_denied` at once — never a partial vp_token — and the
    /// client gets the decline error with the verifier's redirect, if
    /// any (OpenID4x 3.2.6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<SignRefusal>,
}

/// A sign-stage refusal, with its allowlisted code (the Go engine's
/// `SignError.Code` — only the code crosses the ask, never the wallet's
/// free-form reason: the verifier must not learn why the wallet refused).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignRefusal {
    /// The refusal's code: `SIGN_REFUSED` (the user declined at the sign
    /// step) or `UNSUPPORTED_TRANSACTION_DATA` (the client refuses a
    /// transaction type only it can judge — the verifier is told
    /// `invalid_transaction_data` rather than left waiting).
    pub code: String,
}

impl SignRefusal {
    /// The user's sign refusal (the Go `ErrCodeSignRefused`).
    #[must_use]
    pub fn sign_refused() -> Self {
        Self {
            code: "SIGN_REFUSED".to_owned(),
        }
    }

    /// The unsupported-transaction-data refusal (the Go
    /// `ErrCodeUnsupportedTransactionData`): the client refuses a
    /// transaction type only it can judge.
    #[must_use]
    pub fn unsupported_transaction_data() -> Self {
        Self {
            code: "UNSUPPORTED_TRANSACTION_DATA".to_owned(),
        }
    }
}

/// The client-held DPoP proof the engine asks the host for (RFC 9449
/// §4.2, the Go engine's `SignActionSignClientAuth` — the target
/// design, go-wallet-backend#317: the device's key signs whole proofs
/// on demand). The engine falls back to its own ephemeral key when
/// the host cannot answer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpopProofParams {
    /// The flow the proof belongs to.
    pub flow_id: String,
    /// The device key to sign with, named when the flow knows it — a
    /// renewal must reuse the key its refresh_token was bound to at
    /// issuance (RFC 9449 / ARF 3.0 §6.6.6.2.2).
    #[serde(default)]
    pub key_id: Option<String>,
    /// The HTTP method the proof is bound to.
    pub htm: String,
    /// The HTTP URI the proof is bound to.
    pub htu: String,
    /// The access-token hash input, when a resource request is being
    /// proofed (the `ath`).
    #[serde(default)]
    pub access_token: String,
    /// The server-provided DPoP nonce, when one was demanded.
    #[serde(default)]
    pub nonce: String,
}

/// The DPoP proof answer.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DpopProofResult {
    /// The proof JWT (`dpop+jwt`), signed by the device-held key with
    /// its public JWK in the header.
    #[serde(default)]
    pub proof: String,
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

/// The client attestation the engine asks the host for: a Wallet Instance
/// Attestation and the matching proof of possession
/// (draft-ietf-oauth-attestation-based-client-auth §3.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationParams {
    /// The flow the request belongs to.
    pub flow_id: String,
    /// The PoP audience: the authorization server the request is sent to.
    pub audience: String,
    /// The client_id the WIA names as `sub` and the PoP as `iss`.
    pub client_id: String,
    /// The server-provided challenge for the PoP, when the AS demanded
    /// one (`use_attestation_challenge`).
    #[serde(default)]
    pub challenge: String,
}

/// The attestation answer: the WIA and the client-signed PoP.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AttestationResult {
    /// The Wallet Instance Attestation JWT (`oauth-client-attestation+jwt`).
    #[serde(default)]
    pub wia: String,
    /// The PoP JWT binding the WIA to the audience
    /// (`oauth-client-attestation-pop+jwt`), signed with the instance
    /// key the WIA's `cnf` names.
    #[serde(default)]
    pub pop: String,
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

    /// Asks the host for the public JWK of the named signing key, so
    /// the engine can identify the key in the proof headers it builds
    /// (the OID4VCI JWT proof's `jwk` and its RFC 7638 thumbprint
    /// `kid`). Keys always live in the app; the engine only ever sees
    /// the public JWK. The default refusal keeps older hosts working —
    /// those flows send the proof header without key identification.
    async fn request_signing_key(
        &self,
        _params: SigningKeyParams,
    ) -> Result<SigningKeyResult, HostError> {
        Err(HostError::Cannot(
            "the host does not expose its signing keys".to_owned(),
        ))
    }

    /// Asks the host to match the wallet's credentials against the
    /// DCQL query (or the scope) and select what to present. The local
    /// matching is the host's — it has the wallet state and the
    /// credential formats; the engine never enumerates the wallet's
    /// credentials (the Go engine's `credentials_matched` contract).
    ///
    /// An empty answer means nothing matched: the flow ends there
    /// without an error, exactly as the Go engine treats an empty
    /// match set.
    async fn request_match(&self, params: MatchParams) -> Result<MatchResult, HostError>;

    /// Asks the host's user for consent to the given presentation.
    async fn request_consent(&self, params: ConsentParams) -> Result<ConsentResult, HostError>;

    /// Asks the host's user for the transaction code.
    async fn request_tx_code(&self, flow_id: &str) -> Result<String, HostError>;

    /// Opens the authorization URL in the host's browser (the authorization
    /// code flow's user agent step).
    async fn open_authorization(&self, flow_id: &str, url: &str) -> Result<(), HostError>;

    /// Asks the host to construct and sign the VP token for the
    /// selected credentials — the wallet's presentation formats (mdoc,
    /// SD-JWT, ZK) and its key custody live in the host; the engine
    /// never sees a private key (the Go engine's
    /// `SignActionSignPresentation`).
    ///
    /// The answer's `vp_token` is one token per selection,
    /// newline-separated (the engine restructures the multi-selection
    /// answer into the DCQL object, OpenID4VP §8.1), or a pre-formed
    /// JSON object, which passes through unchanged.
    ///
    /// The default implementation refuses, so older hosts and adapters
    /// keep working; a flow whose host cannot present ends with the
    /// user's decline rather than a fabricated token.
    async fn request_vp(&self, _params: VpParams) -> Result<VpResult, HostError> {
        Err(HostError::Cannot(
            "presentation signing not supported by this host".to_owned(),
        ))
    }

    /// Asks the host for a client-held DPoP proof (RFC 9449 §4.2, the
    /// Go engine's `SignActionSignClientAuth` — the target design,
    /// go-wallet-backend#317: the device's key signs whole proofs on
    /// demand). The engine falls back to its own ephemeral key when
    /// the host cannot answer — the legacy mode — so the default
    /// refusal keeps every flow working.
    async fn request_dpop_proof(
        &self,
        _params: DpopProofParams,
    ) -> Result<DpopProofResult, HostError> {
        Err(HostError::Cannot(
            "client-held DPoP not supported by this host".to_owned(),
        ))
    }

    /// Asks the host for a client attestation: the Wallet Instance
    /// Attestation and the matching PoP, for the PAR/token request's
    /// `OAuth-Client-Attestation` headers.
    ///
    /// **The WIA comes from the existing wallet provider** (go-wallet-
    /// backend's `/wallet-provider/wia/challenge` + `/wia/generate`):
    /// the host's implementation fetches the challenge, signs the WIA-PoP
    /// with the device's instance key, obtains the WIA from the wallet
    /// provider, and signs the per-flow PoP for the audience. The
    /// instance key never reaches the engine — the core builds no JWT
    /// here, it only forwards what the host signed.
    ///
    /// A host that cannot answer refuses, and the flow proceeds without
    /// client attestation (an issuer that requires it rejects on its
    /// own) — the Go engine's exact rule. The default implementation
    /// refuses, so older hosts and adapters keep working.
    async fn request_attestation(
        &self,
        _params: AttestationParams,
    ) -> Result<AttestationResult, HostError> {
        Err(HostError::Cannot(
            "client attestation not supported by this host".to_owned(),
        ))
    }

    /// Asks the host's user to pick one of the offered credential
    /// configurations, when the offer names more than one (the Go
    /// `awaiting_selection` + `select_credential` action path): the
    /// user decides what the wallet issues.
    ///
    /// The default implementation refuses — an older host keeps every
    /// single-configuration flow working (exactly one configuration is
    /// auto-selected and never asked).
    async fn request_credential_selection(
        &self,
        _params: CredentialSelectionParams,
    ) -> Result<CredentialSelectionResult, HostError> {
        Err(HostError::Cannot(
            "credential selection not supported by this host".to_owned(),
        ))
    }

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
    /// The subject's role for the evaluator: `credential-issuer` on
    /// the issuance side (the subject is the credential's issuer),
    /// `credential-verifier` on the presentation side (the subject is
    /// the presentation's verifier). The backend's proxy maps it to
    /// the AuthZEN action name (one of its default rules' allowed
    /// set); a plain PDP ignores it.
    pub resource_type: Option<String>,
    /// The evaluation's context (the Go engine's
    /// `buildVerifierEvalContext`, carried by
    /// `EvaluateVerifierWithContext`): what the PDP decides on beside
    /// the key material — the `client_id_scheme`, the `response_uri`
    /// and `redirect_uri`, the `trust_chain` from the request object's
    /// JAR header (OID4VP §5.9.3.6), and the verifier attestation's
    /// `attestation_issuer`/`attestation_subject`/`attestation_jwt`
    /// (§5.9.3.4, whose whole JWT the PDP verifies). An empty object
    /// when there is nothing to carry (the issuer evaluation).
    #[serde(default)]
    pub context: serde_json::Value,
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

    /// Evaluates the issuer's entitlement (ARF 6.6.2.3): is the provider
    /// registered to issue what it offers. A question distinct from
    /// trust, with its own wire shapes.
    ///
    /// The default implementation is [`PdpError::NotImplemented`], which
    /// the caller treats as "not evaluated" — the findings never arise,
    /// the flow proceeds — so a minimal PDP keeps every flow working and
    /// the backend's implementation answers the check.
    async fn evaluate_entitlement(
        &self,
        _request: EntitlementRequest,
    ) -> Result<EntitlementDecision, PdpError> {
        Err(PdpError::NotImplemented)
    }
}

// ─── The presentation consent policy ────────────────────────────────────
//
// How the engine treats a match answer that does not fit the DCQL query
// it was sent (#525, the Go `presentation.dcql_consent_check`): the
// modes off, warn and enforce. The mode is deployment policy — the
// adapter parses its configured value and sets it on
// [`crate::Ports`](engine_core::Ports).

/// How a match answer that does not fit the DCQL query it was sent is
/// treated: `warn` (the default) records the violation and proceeds,
/// `enforce` refuses the presentation before anything is signed, `off`
/// compares nothing.
///
/// The default is warn — a consent check that cannot run must never
/// read as "checked and fine", and an unrecognised configured value
/// becomes warn, never off, so a typo cannot silently disable the
/// check (the Go `DCQLConsentCheckMode.Effective()`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsentCheckMode {
    /// Records the violation (telemetry) and proceeds.
    #[default]
    Warn,
    /// Refuses the presentation before anything is signed: the
    /// verifier is answered `access_denied`, as a decline is.
    Enforce,
    /// Compares nothing.
    Off,
}

impl ConsentCheckMode {
    /// Parses a configured mode name, defaulting to warn — an empty or
    /// unrecognised value is warn, never off, so a typo cannot
    /// silently disable the check.
    #[must_use]
    pub fn parse(configured: &str) -> Self {
        match configured {
            "off" => Self::Off,
            "enforce" => Self::Enforce,
            _ => Self::Warn,
        }
    }

    /// The mode's configured name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Warn => "warn",
            Self::Enforce => "enforce",
            Self::Off => "off",
        }
    }
}

// ─── The credential configuration selection ─────────────────────────────

/// One credential configuration the wallet may select, as the
/// `awaiting_selection` progress carries it: the configuration's id
/// and the display members the selection UI shows (the Go
/// `AvailableCredential`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvailableCredential {
    /// The credential configuration's id.
    pub id: String,
    /// The configuration's first `display` entry, raw, for the
    /// selection UI to render (the core passes it through; it is
    /// issuer-controlled display content).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<serde_json::Value>,
    /// The configuration's credential format identifier.
    #[serde(default)]
    pub format: String,
    /// The `vct` (SD-JWT VC), when the configuration carries one.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub vct: String,
}

/// The credential configuration selection the engine asks the host for,
/// when the offer names more than one configuration: the user picks
/// what to issue (the Go `awaiting_selection` + `select_credential`
/// action path).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSelectionParams {
    /// The flow the selection belongs to.
    pub flow_id: String,
    /// The configurations on offer, in the offer's order.
    pub available: Vec<AvailableCredential>,
}

/// The selection answer: the chosen configuration's id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSelectionResult {
    /// The chosen configuration's id.
    pub credential_configuration_id: String,
}

// ─── TokenProvider ──────────────────────────────────────────────────────

// ─── The issuer entitlement (ARF 6.6.2.3) ─────────────────────────────────
//
// The wallet-side registration check: is the provider entitled to issue
// what it offers. A question distinct from trust (a trusted issuer can
// still be unregistered), so it rides its own PDP operation with its own
// wire shapes.

/// What a failed entitlement check does (the mode, ARF 6.6.2.3): `warn`
/// records findings and allows issuance (the default — the ARF obligation
/// applies 24 months after the amending Regulation), `fail` refuses, `off`
/// skips evaluation. The mode lives with the evaluator: the PDP
/// implementation applies its own configured mode to the answer it returns.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntitlementMode {
    /// Records failures and still allows issuance (the default).
    #[default]
    Warn,
    /// Turns the same failures into a refusal to request issuance.
    Fail,
    /// Skips evaluation entirely.
    Off,
}

impl EntitlementMode {
    /// Parses a configured mode name, defaulting to warn — an
    /// unrecognised value becomes warn rather than off, so a typo cannot
    /// silently disable the check.
    #[must_use]
    pub fn parse(configured: &str) -> Self {
        match configured {
            "off" => Self::Off,
            "fail" => Self::Fail,
            _ => Self::Warn,
        }
    }

    /// The mode's wire name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Warn => "warn",
            Self::Fail => "fail",
            Self::Off => "off",
        }
    }
}

/// Why an entitlement evaluation failed (the finding's code — a caller acts
/// on the code, never on a sentence).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntitlementCode {
    /// The issuer metadata was signed by no certificate chain.
    NoAccessCertificate,
    /// The chain's leaf does not meet the WRPAC profile.
    NotWrpac,
    /// The issuer metadata carries no registration certificate.
    NoRegistrationCertificate,
    /// The registration certificate is not a readable `rc-wrp+jwt`.
    RegistrationMalformed,
    /// The registration certificate is not current.
    RegistrationExpired,
    /// The registration certificate's validity is not conformant
    /// (GEN-5.2.4-08's cap).
    RegistrationOverlong,
    /// The registration certificate describes another provider.
    BindingMismatch,
    /// The registered entitlements name no provider role.
    NotProvider,
    /// The provider is not registered for an offered credential.
    TypeNotRegistered,
    /// The registration certificate's signature was not verified (or
    /// nobody checked): its claims are not used.
    RegistrationUnverified,
    /// The signature is valid but the signer is no trusted Registrar.
    RegistrarNotTrusted,
    /// Nothing established that the chain that signed the metadata is
    /// trusted.
    AccessCertificateNotTrusted,
}

impl EntitlementCode {
    /// The code's wire name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoAccessCertificate => "no_access_certificate",
            Self::NotWrpac => "access_certificate_not_wrpac",
            Self::NoRegistrationCertificate => "no_registration_certificate",
            Self::RegistrationMalformed => "registration_certificate_malformed",
            Self::RegistrationExpired => "registration_certificate_expired",
            Self::RegistrationOverlong => "registration_certificate_validity_too_long",
            Self::BindingMismatch => "registration_certificate_not_bound",
            Self::NotProvider => "not_an_attestation_provider",
            Self::TypeNotRegistered => "attestation_type_not_registered",
            Self::RegistrationUnverified => "registration_certificate_unverified",
            Self::RegistrarNotTrusted => "registrar_not_trusted",
            Self::AccessCertificateNotTrusted => "access_certificate_not_trusted",
        }
    }
}

/// One thing that did not check out. The message is the code's own —
/// never issuer text; `credential_type` is the offered type when the
/// finding is about one (issuer-controlled: bounded).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntitlementFinding {
    /// The finding's code.
    pub code: EntitlementCode,
    /// The code's message.
    pub message: String,
    /// The offered type, bounded, when the finding is about one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_type: Option<String>,
}

/// The bounded entitlement decision (the #526 relay shape): the verdict
/// and the findings, never the registration certificate's own content
/// (`entitlements`, `subject` — issuer-controlled and display-only).
///
/// The bounds are part of the type (AGENTS.md's "Types"): a
/// [`BoundedEntitlementDecision`] cannot carry more than 16 findings, a
/// message beyond 256 bytes, or a credential type beyond 128 bytes —
/// whatever the evaluator returned.
pub const MAX_ENTITLEMENT_FINDINGS: usize = 16;
/// The bound on a finding message, in bytes.
pub const MAX_FINDING_MESSAGE_BYTES: usize = 256;
/// The bound on a finding's credential type, in bytes.
pub const MAX_FINDING_TYPE_BYTES: usize = 128;

/// The entitlement evaluation's input: the evidence the evaluator (the
/// PDP implementation) needs — the issuer's identifier, the raw issuer
/// metadata document (the evaluator reads the `issuer_info` registration
/// certificate from it, ETSI TS 119 472-3: the core does not model that
/// member), the signing key material, and the configurations the wallet
/// is about to request.
///
/// The shape mirrors the Go evaluator's input (`pkg/issuertrust`'s
/// `Evaluate`: `Metadata` the raw document, `SignerX5C` the resolver's
/// signing chain) — with the chain in the form [`Pdp::evaluate`]
/// already receives, so one evaluator handles both questions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntitlementRequest {
    /// The issuer's identifier (the metadata's `credential_issuer`).
    pub issuer: String,
    /// The raw issuer metadata document, as resolved (the signed form:
    /// the verified payload), carrying the members the core does not
    /// model (`issuer_info` among them).
    pub metadata: Vec<u8>,
    /// The metadata's signing key material, as [`Pdp::evaluate`] received
    /// it: the signed metadata JWT, or the inline `jwks`. The WRPAC — the
    /// access certificate the entitlement check reads — is the chain that
    /// signed this document.
    pub key_material: Vec<u8>,
    /// The configurations the flow is about to request (the offer's
    /// configuration ids): the evaluator matches these against the
    /// registration's entitlements.
    pub offers: Vec<EntitlementOffer>,
}

/// One offered credential the evaluator matches against the
/// registration: the format identifier and the type (`vct` for
/// SD-JWT, `doctype` for mdoc).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntitlementOffer {
    /// The OpenID4VCI credential format identifier, e.g. `dc+sd-jwt`.
    pub format: String,
    /// The `vct` or `doctype`. May be empty, in which case the evaluator
    /// matches the format alone.
    pub credential_type: String,
}

/// The entitlement evaluator's decision, as the flow and the wire carry
/// it — already bounded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoundedEntitlementDecision {
    /// Whether issuance may proceed. In warn mode it stays true even with
    /// findings, so a wallet can still surface them.
    pub allowed: bool,
    /// Which mode produced the decision, so "passed" reads apart from
    /// "would have failed but we are in warn mode".
    pub mode: EntitlementMode,
    /// False when there was nothing to evaluate against — no registration
    /// certificate, or mode off. Deliberately distinct from `allowed`:
    /// "not checked" must never read as "checked and fine".
    pub evaluated: bool,
    /// The findings, at most [`MAX_ENTITLEMENT_FINDINGS`].
    pub findings: Vec<EntitlementFinding>,
    /// True when more findings arose than the bound carries.
    pub findings_truncated: bool,
}

/// The unbounded decision the evaluator returns, before the relay bounds
/// it: the registration certificate's own content (`entitlements`,
/// `subject`) rides here — display-only, stripped by
/// [`EntitlementDecision::bounded`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntitlementDecision {
    /// The verdict and the mode, as [`BoundedEntitlementDecision`].
    pub allowed: bool,
    /// The mode that produced the decision.
    pub mode: EntitlementMode,
    /// Whether anything was evaluated.
    pub evaluated: bool,
    /// The findings (unbounded in the evaluator's own answer).
    #[serde(default)]
    pub findings: Vec<EntitlementFinding>,
    /// True when the findings were truncated upstream.
    #[serde(default)]
    pub findings_truncated: bool,
}

/// The no-evaluation decision: `Evaluated=false`, `Allowed=true`, mode
/// off — nothing was checked, nothing refused. The answer a minimal PDP
/// gives (its operation is not implemented), so the flow proceeds the
/// way the ARF's grace period intends.
#[must_use]
pub fn entitlement_not_evaluated() -> EntitlementDecision {
    EntitlementDecision {
        allowed: true,
        mode: EntitlementMode::Off,
        evaluated: false,
        findings: Vec::new(),
        findings_truncated: false,
    }
}

impl EntitlementDecision {
    /// The bounded relay form (#526): the verdict and the findings, the
    /// issuer-controlled display content (`entitlements`, `subject`)
    /// stripped, the findings capped at [`MAX_ENTITLEMENT_FINDINGS`] with
    /// `findings_truncated` set, the messages and types cut on rune
    /// boundaries. Nothing of the registration certificate's own content
    /// is relayed.
    #[must_use]
    pub fn bounded(&self) -> BoundedEntitlementDecision {
        let mut findings = Vec::new();
        let mut truncated = self.findings_truncated;
        for finding in &self.findings {
            if findings.len() >= MAX_ENTITLEMENT_FINDINGS {
                truncated = true;
                break;
            }
            findings.push(EntitlementFinding {
                code: finding.code,
                message: bound_text(&finding.message, MAX_FINDING_MESSAGE_BYTES),
                credential_type: finding
                    .credential_type
                    .as_deref()
                    .map(|text| bound_text(text, MAX_FINDING_TYPE_BYTES)),
            });
        }
        BoundedEntitlementDecision {
            allowed: self.allowed,
            mode: self.mode,
            evaluated: self.evaluated,
            findings,
            findings_truncated: truncated,
        }
    }
}

/// Cuts `text` to at most `max` bytes on a char boundary, dropping
/// control and non-printable characters.
#[must_use]
fn bound_text(text: &str, max: usize) -> String {
    let mut out = String::with_capacity(text.len().min(max));
    for ch in text.chars() {
        if !ch.is_control() && !ch.is_whitespace() || ch == ' ' {
            if out.len() + ch.len_utf8() > max {
                break;
            }
            out.push(ch);
        }
    }
    out
}

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
