//! The OpenID4VCI types: the credential offer, the issuer metadata, and
//! the AS metadata — the documents the S1 resolvers parse and validate.

use serde::{Deserialize, Serialize};

// ─── Credential Offer (OpenID4VCI §4.1) ────────────────────────────────────

/// A parsed credential offer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialOffer {
    /// The issuer's identifier — the URL the wallet resolves metadata from.
    pub credential_issuer: String,
    /// The configuration ids the issuer offers.
    pub credential_configuration_ids: Vec<String>,
    /// The grants the issuer supports (pre-authorized_code, authorization_code, etc).
    #[serde(default)]
    pub grants: serde_json::Value,
}

/// Why an offer was refused.
#[derive(Debug, thiserror::Error)]
pub enum OfferError {
    /// The offer is not a JSON object.
    #[error("oid4vci: offer is not a JSON object")]
    NotAnObject,
    /// The `credential_issuer` is missing or empty.
    #[error("oid4vci: offer has no credential_issuer")]
    NoIssuer,
    /// The `credential_configuration_ids` is missing or empty.
    #[error("oid4vci: offer has no credential_configuration_ids")]
    NoConfigurationIds,
    /// The offer-by-reference fetch failed (size limit, transport, non-200).
    #[error("oid4vci: offer fetch failed: {0}")]
    Fetch(String),
    /// The `openid-credential-offer:` URI is malformed.
    #[error("oid4vci: malformed offer URI: {0}")]
    MalformedUri(String),
}

// ─── Issuer Metadata (OpenID4VCI §11.2) ───────────────────────────────────

/// The `metadata_type` policy: how the engine negotiates signed vs unsigned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MetadataType {
    /// Try signed first; fall back to unsigned on HTTP 406 (default).
    PreferSigned,
    /// Only signed; a 406 or verification failure is terminal.
    RequireSigned,
    /// Try unsigned first; fall back to signed on HTTP 406.
    PreferUnsigned,
    /// Only unsigned; a 406 is terminal.
    RequireUnsigned,
    /// Either form; no preference.
    Any,
}

impl MetadataType {
    /// Parses the config string. Unknown values answer `PreferSigned`.
    pub fn from_config(config: &str) -> Self {
        match config {
            "require-signed" => Self::RequireSigned,
            "prefer-unsigned" => Self::PreferUnsigned,
            "require-unsigned" => Self::RequireUnsigned,
            "any" => Self::Any,
            _ => Self::PreferSigned,
        }
    }

    /// The `Accept` header for the first attempt.
    pub fn accept_header(&self) -> &str {
        match self {
            Self::PreferSigned | Self::RequireSigned => {
                "application/openid-credential-issuer+jwt, application/json"
            }
            Self::PreferUnsigned | Self::RequireUnsigned => {
                "application/json, application/openid-credential-issuer+jwt"
            }
            Self::Any => "application/json, application/openid-credential-issuer+jwt, */*",
        }
    }

    /// Whether to fall back to the other form on HTTP 406.
    pub fn falls_back_on_406(&self) -> bool {
        matches!(self, Self::PreferSigned | Self::PreferUnsigned | Self::Any)
    }
}

/// The parsed issuer metadata document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuerMetadata {
    /// The issuer's identifier. Must equal the identifier as received.
    pub credential_issuer: String,
    /// The authorization servers the issuer uses.
    #[serde(default)]
    pub authorization_servers: Vec<String>,
    /// The credential configurations, keyed by id.
    #[serde(default)]
    pub credential_configurations: serde_json::Value,
    /// The nonce endpoint (OpenID4VCI §7), when the issuer advertises one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce_endpoint: Option<String>,
    /// The signed metadata JWT, when the document was served as a JWT.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_metadata: Option<String>,
    /// Whether the document was served in the signed form.
    #[serde(default, skip_serializing)]
    pub is_signed: bool,
}

/// Why the issuer metadata resolution refused.
#[derive(Debug, thiserror::Error)]
pub enum IssuerMetadataError {
    /// The document is not a JSON object.
    #[error("oid4vci: metadata is not a JSON object")]
    NotAnObject,
    /// The `credential_issuer` does not equal the identifier as received.
    #[error("oid4vci: credential_issuer mismatch: expected {expected:?}, got {actual:?}")]
    IdentityMismatch {
        /// What the wallet expected.
        expected: String,
        /// What the document said.
        actual: String,
    },
    /// A signed document failed verification (terminal; never a fallback).
    #[error("oid4vci: signed metadata verification failed")]
    SignedVerificationFailed,
    /// The transport failed.
    #[error("oid4vci: metadata fetch failed: {0}")]
    Fetch(String),
    /// Both the literal and the fallback URL answered non-404 errors.
    #[error("oid4vci: metadata answered {0}")]
    Status(u16),
}

// ─── AS Metadata (RFC 8414 / OIDC Discovery) ──────────────────────────────

/// The parsed AS metadata document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsMetadata {
    /// The AS's identifier. Must equal the issuer URL as received.
    pub issuer: String,
    /// The token endpoint.
    #[serde(default)]
    pub token_endpoint: String,
    /// The authorization endpoint.
    #[serde(default)]
    pub authorization_endpoint: String,
    /// The pushed authorization request endpoint.
    #[serde(default, alias = "pushed_authorization_request_endpoint")]
    pub par_endpoint: String,
    /// Whether the AS requires PAR (RFC 9126
    /// `require_pushed_authorization_requests`): no non-PAR /authorize
    /// path exists, so a PAR failure has no fallback.
    #[serde(default)]
    pub require_par: bool,
    /// The client-attestation challenge endpoint
    /// (`challenge_endpoint`, draft-ietf-oauth-attestation-based-client-
    /// auth): where a fresh PoP challenge comes from after a
    /// `use_attestation_challenge` rejection.
    #[serde(default)]
    pub challenge_endpoint: String,
    /// The supported code challenge methods. `None` when the document did
    /// not declare the member at all — the OID4VCI default assumes S256
    /// support; an explicit (even empty) list is the declaration.
    #[serde(default)]
    pub code_challenge_methods: Option<Vec<String>>,
    /// The supported grant types.
    #[serde(default)]
    pub grant_types: Vec<String>,
}

impl AsMetadata {
    /// Whether the AS supports PKCE S256: assumed when the document did
    /// not declare `code_challenge_methods_supported` (the OID4VCI
    /// default); an explicit list must name S256.
    pub fn supports_pkce_s256(&self) -> bool {
        match &self.code_challenge_methods {
            None => true,
            Some(methods) => methods.iter().any(|m| m == "S256"),
        }
    }
}

/// Why the AS metadata resolution refused.
#[derive(Debug, thiserror::Error)]
pub enum AsMetadataError {
    /// No candidate URL answered 200.
    #[error("oid4vci: no AS metadata found for {0}")]
    NotFound(String),
    /// The `issuer` does not equal the identifier.
    #[error("oid4vci: AS issuer mismatch: expected {expected:?}, got {actual:?}")]
    IdentityMismatch {
        /// What the wallet expected.
        expected: String,
        /// What the document said.
        actual: String,
    },
    /// The served document has no token endpoint.
    #[error("oid4vci: AS metadata has no token_endpoint")]
    NoTokenEndpoint,
    /// The transport failed.
    #[error("oid4vci: AS metadata fetch failed: {0}")]
    Fetch(String),
    /// A non-404 status from a candidate (terminal, no fallback).
    #[error("oid4vci: AS metadata answered {0}")]
    Status(u16),
}
