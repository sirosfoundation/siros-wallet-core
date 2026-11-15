//! Client attestation (draft-ietf-oauth-attestation-based-client-auth):
//! the OAuth-Client-Attestation headers for the PAR and token requests,
//! and the `use_attestation_challenge` retry.
//!
//! **The WIA comes from the existing wallet provider** (go-wallet-
//! backend's `/wallet-provider/wia/challenge` + `/wia/generate`): the
//! engine asks the Host for the (WIA, PoP) pair — the Go engine's exact
//! contract (`SignActionRequestAttestation`) — because the instance key
//! that signs the PoPs lives on the device and never reaches the
//! engine. The core builds no JWT here; it forwards what the host
//! signed, resolves the server challenge when the AS demands one, and
//! re-asks with it.
//!
//! The P0.6-verified behaviours:
//! - Any host refusal leaves the flow without attestation and it
//!   proceeds (private_key_jwt or client_id remain); an issuer that
//!   requires attestation rejects on its own. Attestation is best-effort
//!   exactly like the Go engine's `requestClientAttestation`.
//! - The headers: `OAuth-Client-Attestation` (the WIA) and
//!   `OAuth-Client-Attestation-PoP` (the PoP), never one without the
//!   other.
//! - `use_attestation_challenge` (a 400/401 with that error code): the
//!   fresh challenge comes from the
//!   `OAuth-Client-Attestation-Challenge` response header first, else
//!   the AS's `challenge_endpoint` (POST; the same header on the
//!   answer, else the `attestation_challenge` body member). The host
//!   re-answers with a PoP bound to it, and the request retries once.
//! - PAR carries attestation but no DPoP proof (DPoP binds tokens, and
//!   PAR issues none).

use engine_ports::{
    AttestationParams, AttestationResult, FetchPurpose, HttpClient, HttpRequest, RedirectPolicy,
};

use super::types::AsMetadata;

/// The maximum size of a challenge endpoint response.
const MAX_CHALLENGE_BYTES: usize = 64 << 10;

/// The attestation pair the host supplied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientAttestation {
    /// The WIA JWT (`oauth-client-attestation+jwt`).
    pub wia: String,
    /// The PoP JWT (`oauth-client-attestation-pop+jwt`).
    pub pop: String,
}

/// Why the attestation challenge resolution refused.
#[derive(Debug, thiserror::Error)]
pub enum AttestationError {
    /// The challenge endpoint answered an error.
    #[error("oid4vci: attestation challenge endpoint failed: {0}")]
    Endpoint(String),
    /// The transport failed.
    #[error("oid4vci: attestation challenge fetch failed: {0}")]
    Fetch(String),
}

/// Asks the host for the client attestation — best-effort, exactly the
/// Go rule: any refusal (a host without attestation support, a wallet
/// provider that is down, a missing instance key) proceeds without
/// attestation rather than failing the flow.
///
/// `challenge` is the server-provided challenge when the AS demanded
/// one; the host binds the fresh PoP to it.
pub async fn request_client_attestation(
    host: &dyn engine_ports::Host,
    flow_id: &str,
    audience: &str,
    client_id: &str,
    challenge: &str,
) -> Option<ClientAttestation> {
    let result = host
        .request_attestation(AttestationParams {
            flow_id: flow_id.to_owned(),
            audience: audience.to_owned(),
            client_id: client_id.to_owned(),
            challenge: challenge.to_owned(),
        })
        .await
        .ok()?;
    attestation_from(result)
}

/// The attestation pair from the host's answer — `None` when the host
/// supplied only one half or neither (never send the headers half-
/// equipped).
fn attestation_from(result: AttestationResult) -> Option<ClientAttestation> {
    if result.wia.is_empty() || result.pop.is_empty() {
        return None;
    }
    Some(ClientAttestation {
        wia: result.wia,
        pop: result.pop,
    })
}

/// The headers the attested request carries, when attestation is
/// available.
pub fn attestation_headers(attestation: Option<&ClientAttestation>) -> Vec<(String, String)> {
    match attestation {
        Some(attestation) => vec![
            (
                "OAuth-Client-Attestation".to_owned(),
                attestation.wia.clone(),
            ),
            (
                "OAuth-Client-Attestation-PoP".to_owned(),
                attestation.pop.clone(),
            ),
        ],
        None => Vec::new(),
    }
}

/// Whether an error response is the AS demanding a server-provided
/// challenge in the Client Attestation PoP: a 400/401 whose body's
/// `error` is `use_attestation_challenge`.
pub fn is_attestation_challenge_error(status: u16, body: &[u8]) -> bool {
    if status != 400 && status != 401 {
        return false;
    }
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("error")
                .and_then(|v| v.as_str())
                .map(|error| error == "use_attestation_challenge")
        })
        .unwrap_or(false)
}

/// The challenge from a response's `OAuth-Client-Attestation-Challenge`
/// header, when it carries one.
pub fn challenge_from_headers(headers: &[(String, String)]) -> Option<String> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("OAuth-Client-Attestation-Challenge"))
        .map(|(_, value)| value.clone())
        .filter(|value| !value.is_empty())
}

/// Fetches a fresh challenge from the AS's `challenge_endpoint`.
///
/// The draft's convention: the challenge arrives in the
/// `OAuth-Client-Attestation-Challenge` response header; the
/// `{"attestation_challenge": ...}` body is the compatibility fallback
/// (the SDK's client-side path uses the body form, so both are
/// accepted).
pub async fn fetch_attestation_challenge(
    http: &dyn HttpClient,
    challenge_endpoint: &str,
) -> Result<String, AttestationError> {
    let response = http
        .send(HttpRequest {
            method: "POST".to_owned(),
            url: challenge_endpoint.to_owned(),
            headers: vec![
                ("accept".to_owned(), "application/json".to_owned()),
                ("content-type".to_owned(), "application/json".to_owned()),
            ],
            body: b"{}".to_vec(),
            purpose: FetchPurpose::Token,
            max_response_bytes: MAX_CHALLENGE_BYTES,
            redirects: RedirectPolicy::None,
            allow_plaintext: false,
            timeout_ms: 10_000,
        })
        .await
        .map_err(|err| AttestationError::Fetch(err.to_string()))?;

    if response.status != 200 {
        return Err(AttestationError::Endpoint(format!(
            "challenge endpoint answered {}",
            response.status
        )));
    }

    // The header first, else the body member.
    if let Some(challenge) = challenge_from_headers(&response.headers) {
        return Ok(challenge);
    }
    serde_json::from_slice::<serde_json::Value>(&response.body)
        .ok()
        .and_then(|value| {
            value
                .get("attestation_challenge")
                .and_then(|v| v.as_str())
                .map(str::to_owned)
        })
        .filter(|challenge| !challenge.is_empty())
        .ok_or_else(|| {
            AttestationError::Endpoint("challenge endpoint returned no challenge".to_owned())
        })
}

/// Resolves the fresh challenge after a `use_attestation_challenge`
/// rejection: the response header first, else the AS's
/// `challenge_endpoint`. `None` when no challenge could be obtained
/// (the retry is then impossible and the original error stands).
pub async fn resolve_challenge(
    http: &dyn HttpClient,
    as_metadata: &AsMetadata,
    response_headers: &[(String, String)],
) -> Option<String> {
    if let Some(challenge) = challenge_from_headers(response_headers) {
        return Some(challenge);
    }
    if as_metadata.challenge_endpoint.is_empty() {
        return None;
    }
    fetch_attestation_challenge(http, &as_metadata.challenge_endpoint)
        .await
        .ok()
}
