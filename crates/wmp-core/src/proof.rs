//! The per-request proof for HTTPS sessions (wmp-core §4.4.8): the DPoP
//! model (RFC 9449) — a compact JWS whose payload binds the request to the
//! session. The proof travels as `Authorization: DPoP <proof-jws>` when the
//! HTTPS transport cannot carry the client's credential at the TLS level.

use serde::{Deserialize, Serialize};

/// The proof's payload fields (RFC 9449 §4.1 + the WMP session binding).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofPayload {
    /// The HTTP request method (`htm`).
    pub htm: String,
    /// The HTTP request URI, no query or fragment (`htu`).
    pub htu: String,
    /// The proof's issuance time, unix seconds (`iat`).
    pub iat: i64,
    /// A unique proof identifier for replay detection (`jti`).
    pub jti: String,
    /// The WMP session id the proof binds to (`sid`). Omitted for
    /// authentication on `session.create` messages, mandatory otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
}

impl ProofPayload {
    /// Builds a proof payload for one request.
    pub fn for_request(method: &str, uri: &str, sid: &str, iat: i64, jti: &str) -> Self {
        Self {
            htm: method.to_owned(),
            htu: uri.to_owned(),
            iat,
            jti: jti.to_owned(),
            sid: Some(sid.to_owned()),
        }
    }

    /// Builds the `session.create` proof payload: no session id exists yet,
    /// so `sid` is omitted (PR #46). Mandatory on every other request.
    pub fn for_session_create(method: &str, uri: &str, iat: i64, jti: &str) -> Self {
        Self {
            htm: method.to_owned(),
            htu: uri.to_owned(),
            iat,
            jti: jti.to_owned(),
            sid: None,
        }
    }

    /// JCS-canonicalized JSON bytes (the JWS payload, per §5.4).
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProofError> {
        serde_json::to_vec(self).map_err(|_| ProofError::MalformedJws)
    }

    /// Whether the proof's session binding is valid for this request.
    /// `session.create` carries no session id (PR #46), so `sid` is optional
    /// there; every other request MUST carry it and it MUST match the
    /// session the request names.
    pub fn session_binding_matches(
        &self,
        session_id: Option<&str>,
        is_session_create: bool,
    ) -> bool {
        if is_session_create {
            return true;
        }
        match (&self.sid, session_id) {
            (Some(expected), Some(actual)) => expected == actual,
            _ => false,
        }
    }
}

/// The proof header's key material: the certificate chain (`x5c`) or a
/// DID Document key id (`kid`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofHeader {
    /// The JOSE algorithm.
    pub alg: String,
    /// The proof type marker (`wmp-proof+jwt`).
    pub typ: String,
    /// The certificate chain, base64-encoded DER, leaf first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub x5c: Vec<String>,
    /// The DID Document key id (for DID-authenticated sessions).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub kid: String,
}

/// The proof: a compact JWS (header.payload.signature).
#[derive(Debug, Clone)]
pub struct Proof {
    /// The JWS header (algorithm, key material).
    pub header: ProofHeader,
    /// The request-binding payload.
    pub payload: ProofPayload,
}

/// Why a proof failed verification.
#[derive(Debug, PartialEq)]
pub enum ProofError {
    /// The proof is not a valid JWS.
    MalformedJws,
    /// The algorithm is not supported.
    UnsupportedAlgorithm,
    /// The signature is invalid.
    InvalidSignature,
    /// The session id does not match.
    SessionMismatch,
    /// The HTTP method or URI does not match.
    RequestMismatch,
    /// The timestamp is outside the skew tolerance.
    TimestampInvalid,
    /// The proof was already seen (replay).
    Replay,
    /// The certificate chain is untrusted.
    UntrustedChain,
    /// The identity does not match.
    IdentityMismatch,
}

/// The parsed Authorization header's scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthScheme {
    /// `Authorization: Bearer <token>`.
    Bearer,
    /// `Authorization: DPoP <proof-jws>`.
    Dpop,
    /// An unrecognized or absent scheme.
    Unknown,
}

impl AuthScheme {
    /// Parses the Authorization header's scheme prefix.
    pub fn parse(value: &str) -> Self {
        let lower = value.to_ascii_lowercase();
        if lower.starts_with("dpop ") {
            Self::Dpop
        } else if lower.starts_with("bearer ") {
            Self::Bearer
        } else {
            Self::Unknown
        }
    }
}

/// The parsed Authorization header: the scheme and the raw credential.
pub struct ParsedAuth<'a> {
    /// The parsed scheme.
    pub scheme: AuthScheme,
    /// The raw credential value.
    pub credential: &'a str,
}

impl<'a> ParsedAuth<'a> {
    /// Parses an Authorization header value.
    pub fn parse(value: &'a str) -> Option<Self> {
        let scheme = AuthScheme::parse(value);
        if matches!(scheme, AuthScheme::Unknown) {
            return None;
        }
        let credential = value
            .split_once(' ')
            .map(|(_, rest)| rest)
            .unwrap_or_default();
        Some(Self { scheme, credential })
    }
}
