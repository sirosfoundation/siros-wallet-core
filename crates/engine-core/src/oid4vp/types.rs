//! The OpenID4VP types: the authorization request, the client metadata, the
//! transaction data, and the response modes.

use serde::{Deserialize, Serialize};

// ─── Authorization Request (OpenID4VP §5) ─────────────────────────────────

/// The client_id scheme, inferred from the `client_id` prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientIdScheme {
    /// `x509_san_dns:` — an x.509 certificate's SAN DNS entry.
    X509SanDns,
    /// `x509_san_uri:` — an x.509 certificate's SAN URI entry.
    X509SanUri,
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
        } else if client_id.starts_x509_san_uri() {
            Self::X509SanUri
        } else if client_id.starts_with("did:") {
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
            Self::DecentralizedIdentifier => "did:",
            Self::VerifierAttestation => "verifier_attestation:",
            Self::RedirectUri => "",
            Self::Unknown(_) => "",
        }
    }
}

trait StrExt {
    fn starts_x509_san_uri(&self) -> bool;
}
impl StrExt for str {
    fn starts_x509_san_uri(&self) -> bool {
        self.starts_with("x509_san_uri:")
    }
}

/// The response mode, from the request's `response_mode`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponseMode {
    /// `direct_post` — a plain form POST to the response URI.
    DirectPost,
    /// `direct_post.jwt` — a JWE-encrypted JWT POST.
    DirectPostJwt,
    /// `fragment` — a redirect with the response in the fragment.
    Fragment,
    /// `query` — a redirect with the response in the query.
    Query,
}

impl ResponseMode {
    /// Parses from the request's `response_mode`; the default is `direct_post`.
    pub fn parse(mode: &str) -> Self {
        match mode {
            "direct_post.jwt" => Self::DirectPostJwt,
            "fragment" => Self::Fragment,
            "query" => Self::Query,
            _ => Self::DirectPost,
        }
    }

    /// The wire name.
    pub fn as_str(&self) -> &str {
        match self {
            Self::DirectPost => "direct_post",
            Self::DirectPostJwt => "direct_post.jwt",
            Self::Fragment => "fragment",
            Self::Query => "query",
        }
    }
}

/// The parsed authorization request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    /// The client_id, with the scheme prefix.
    pub client_id: String,
    /// The inferred client_id scheme.
    pub client_id_scheme: ClientIdScheme,
    /// The request URI, when the request is by reference.
    #[serde(default)]
    pub request_uri: String,
    /// The response URI (where the VP response goes).
    #[serde(default)]
    pub response_uri: String,
    /// The redirect URI (the fallback when response_uri is absent).
    #[serde(default)]
    pub redirect_uri: String,
    /// The response mode.
    pub response_mode: ResponseMode,
    /// The nonce (anti-replay).
    #[serde(default)]
    pub nonce: String,
    /// The state (returned to the verifier).
    #[serde(default)]
    pub state: String,
    /// The DCQL query, as raw JSON.
    #[serde(default)]
    pub dcql_query: Option<serde_json::Value>,
    /// The transaction_data entries (base64url-encoded JSON strings).
    #[serde(default)]
    pub transaction_data_raw: Vec<String>,
    /// The client_metadata, as raw JSON.
    #[serde(default)]
    pub client_metadata: Option<serde_json::Value>,
    /// The client_metadata_uri, when the metadata is by reference.
    #[serde(default)]
    pub client_metadata_uri: String,
    /// The verifier's JWK, for direct_post.jwt encryption.
    #[serde(default)]
    pub verifier_jwk: Option<serde_json::Value>,
    /// The scope, when the request uses scope instead of dcql_query.
    #[serde(default)]
    pub scope: String,
}

/// Why an authorization request was refused.
#[derive(Debug, thiserror::Error)]
pub enum RequestError {
    /// The request is not a JSON object or a recognized URI.
    #[error("oid4vp: request is not a recognized form")]
    NotRecognized,
    /// The `client_id` scheme prefix doesn't match the `client_id`.
    #[error("oid4vp: client_id_scheme {scheme:?} does not match the client_id prefix")]
    SchemeMismatch {
        /// The scheme the request claimed.
        scheme: String,
    },
    /// The outer and inner `client_id` are not equal.
    #[error("oid4vp: client_id mismatch")]
    ClientIdMismatch,
    /// The `nonce` is missing.
    #[error("oid4vp: nonce is required but absent")]
    NonceRequired,
    /// The response mode doesn't belong to the channel.
    #[error("oid4vp: response_mode {mode:?} not valid for this channel")]
    InvalidResponseMode {
        /// The mode the request named.
        mode: String,
    },
    /// The transaction_data is malformed or unsupported.
    #[error("oid4vp: {0}")]
    TransactionData(String),
    /// The request object fetch failed.
    #[error("oid4vp: request object fetch failed: {0}")]
    Fetch(String),
}

// ─── Transaction Data (OpenID4VP §5.1) ────────────────────────────────────

/// One parsed transaction data entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionData {
    /// The type (e.g. `owf_payment_initiation`).
    #[serde(rename = "type")]
    pub transaction_type: String,
    /// The credential_ids this entry applies to.
    #[serde(default)]
    pub credential_ids: Vec<String>,
    /// The payload, as raw JSON.
    #[serde(default)]
    pub payload: Option<serde_json::Value>,
}

/// Why transaction data was refused.
#[derive(Debug, thiserror::Error)]
pub enum TransactionDataError {
    /// JSON null is a type error, not an absent value.
    #[error("oid4vp: transaction_data must be an array, not null")]
    Null,
    /// Not an array of base64url strings.
    #[error("oid4vp: transaction_data[{index}] is not valid base64url")]
    InvalidEncoding {
        /// The entry's index.
        index: usize,
    },
    /// The decoded JSON is not an object with a type.
    #[error("oid4vp: transaction_data[{index}] is not a JSON object with a type")]
    InvalidJson {
        /// The entry's index.
        index: usize,
    },
    /// The type is not in the allow-list.
    #[error("oid4vp: transaction_data[{index}] has unsupported type {ty:?}")]
    UnsupportedType {
        /// The entry's index.
        index: usize,
        /// The unsupported type.
        ty: String,
    },
}

/// The allow-listed transaction data types (the Go engine has one; the spec
/// allows type authors to define their own, but the engine checks against
/// what it knows).
pub const KNOWN_TRANSACTION_DATA_TYPES: &[&str] = &["owf_payment_initiation"];

// ─── Response submission ──────────────────────────────────────────────────

/// Why the response submission refused.
#[derive(Debug, thiserror::Error)]
pub enum ResponseError {
    /// No response URI or redirect URI in the request.
    #[error("oid4vp: no response endpoint in request")]
    NoEndpoint,
    /// The response mode is unsupported.
    #[error("oid4vp: unsupported response_mode: {0}")]
    UnsupportedMode(String),
    /// The transport failed.
    #[error("oid4vp: response submission failed: {0}")]
    Fetch(String),
    /// The JARM (direct_post.jwt) response could not be built or
    /// encrypted. Per P0.6, this refusal is NOT sent to the verifier —
    /// the verifier times out; the flow error goes to the host.
    #[error("oid4vp: {0}")]
    Jarm(#[from] super::jarm::JarmError),
}
