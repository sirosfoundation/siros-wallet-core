//! The token exchange: the pre-authorized-code grant, the tx_code sub-flow,
//! and the OAuth 2.0 token endpoint POST — S2's first step.

use engine_ports::{FetchPurpose, Host, HttpClient, HttpError, HttpRequest, RedirectPolicy};
use serde::{Deserialize, Serialize};

use super::types::AsMetadata;

/// The maximum size of a token endpoint response: 1 MiB.
const MAX_TOKEN_BYTES: usize = 1 << 20;

/// The parsed token response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    /// The access token.
    pub access_token: String,
    /// The token type (always "Bearer" for OID4VCI).
    #[serde(default)]
    pub token_type: String,
    /// The expires-in, in seconds.
    #[serde(default)]
    pub expires_in: Option<i64>,
    /// The refresh token, when the issuer issued one.
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// The c_nonce, when the issuer sent one (the legacy nonce).
    #[serde(default)]
    pub c_nonce: Option<String>,
    /// The nonce, when the issuer sent one (the current form).
    #[serde(default)]
    pub nonce: Option<String>,
    /// The `authorization_details` the AS granted, when it sent any (raw
    /// JSON, as received). The granted `credential_identifiers` inside are
    /// the Credential Request's `credential_identifier` substitution source.
    #[serde(default)]
    pub authorization_details: Option<serde_json::Value>,
    /// The server-provided DPoP nonce (RFC 9449 §8), captured from the
    /// token response's `DPoP-Nonce` header — never a wire member. The
    /// resource requests' DPoP proofs carry it, so the binding holds
    /// across the token and credential endpoints.
    #[serde(default, skip_serializing)]
    pub dpop_nonce: Option<String>,
}

/// Why the token exchange refused.
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    /// No token endpoint was resolvable (the AS metadata had none and the
    /// guess was not attempted).
    #[error("oid4vci: no token endpoint")]
    NoTokenEndpoint,
    /// The host declined to provide the tx_code.
    #[error("oid4vci: tx_code declined")]
    TxCodeDeclined,
    /// The token endpoint answered a non-200.
    #[error("oid4vci: token endpoint answered {0}: {1}")]
    Status(u16, String),
    /// The AS demanded a server-provided challenge in the Client
    /// Attestation PoP (`use_attestation_challenge`): the response
    /// headers, for the challenge resolution. The retry loop consumes
    /// this.
    #[error("oid4vci: token endpoint demanded an attestation challenge")]
    ChallengeNeeded {
        /// The rejection response's headers.
        response_headers: Vec<(String, String)>,
    },
    /// The transport failed.
    #[error("oid4vci: token exchange failed: {0}")]
    Fetch(String),
    /// The response body is not a token response.
    #[error("oid4vci: token response is not JSON")]
    NotJson,
}

/// The flow context the token exchange needs: the client identity, the
/// DPoP binding, and the entropy and time the proofs carry.
#[derive(Clone)]
pub struct TokenExchangeContext<'a> {
    /// The flow the exchange belongs to (the attestation ask).
    pub flow_id: &'a str,
    /// The device DPoP key to sign with, when the flow names one — a
    /// renewal reuses the key its refresh_token was bound to at
    /// issuance (RFC 9449 / ARF 3.0 §6.6.6.2.2).
    pub dpop_key_id: Option<&'a str>,
    /// The wallet's registered client key's kid — the private_key_jwt
    /// assertion's `kid`. The app knows the kid it registered; the
    /// engine asks the host to sign with it.
    pub client_key_kid: Option<&'a str>,
    /// The wallet's client_id (the form member; the attestation PoP's
    /// `iss`).
    pub client_id: &'a str,
    /// The flow's DPoP key, when there is one (the engine-held legacy
    /// mode).
    pub dpop: Option<&'a super::dpop::DpopKey>,
    /// The Rng port (the DPoP proof's `jti`).
    pub rng: &'a dyn engine_ports::Rng,
    /// The Clock port's now (the DPoP proof's `iat`).
    pub now_unix: i64,
}

/// Exchanges a pre-authorized code for an access token, asking the host
/// for the tx_code when the grant requires it.
///
/// The grant params: `grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code`,
/// `pre-authorized_code=<code>`, and the optional `tx_code` from the host.
/// The request goes through the `HttpClient` port with the declared
/// `FetchPurpose::Token` and the 1 MiB size limit.
///
/// The client-auth loop (the Go engine's `doTokenExchange`): each attempt
/// carries the host-supplied OAuth-Client-Attestation headers and a fresh
/// DPoP proof over the token endpoint. A DPoP nonce error (RFC 9449 §8)
/// captures the fresh nonce and retries; a `use_attestation_challenge`
/// rejection resolves the challenge and re-asks the host; three attempts
/// in all — the tx_code is asked once, before the loop.
pub async fn exchange_pre_authorized_code(
    http: &dyn HttpClient,
    host: &dyn Host,
    as_metadata: &AsMetadata,
    pre_authorized_code: &str,
    tx_code_required: bool,
    exchange: &TokenExchangeContext<'_>,
) -> Result<TokenResponse, TokenError> {
    // Ask the host for the tx_code when the grant requires it — once,
    // not per attempt.
    let tx_code = if tx_code_required {
        host.request_tx_code("oid4vci-token")
            .await
            .map_err(|_| TokenError::TxCodeDeclined)?
    } else {
        String::new()
    };

    if as_metadata.token_endpoint.is_empty() {
        return Err(TokenError::NoTokenEndpoint);
    }

    // Build the form body: the grant, the code, the tx_code, and the
    // client_id (some AS require it in the form even with attestation
    // in the headers).
    let mut form = format!(
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code&pre-authorized_code={}",
        url_encode(pre_authorized_code),
    );
    if !tx_code.is_empty() {
        form.push_str(&format!("&tx_code={}", url_encode(&tx_code)));
    }
    if !exchange.client_id.is_empty() {
        form.push_str(&format!("&client_id={}", url_encode(exchange.client_id)));
    }

    token_exchange_loop(http, host, as_metadata, form, exchange).await
}

/// Exchanges a refresh token (the renewal grant): the same client-auth
/// loop as every grant — the attestation headers, a fresh DPoP proof
/// per attempt, the nonce and challenge retries.
///
/// **The DPoP key is the one the refresh_token was bound to at
/// issuance** (RFC 9449 / ARF 3.0 §6.6.6.2.2): the caller's exchange
/// context names the client-held key or carries the relayed
/// engine-held key; a fresh key here would be rejected by the issuer.
pub async fn exchange_refresh_token(
    http: &dyn HttpClient,
    host: &dyn Host,
    as_metadata: &AsMetadata,
    refresh_token: &str,
    exchange: &TokenExchangeContext<'_>,
) -> Result<TokenResponse, TokenError> {
    if as_metadata.token_endpoint.is_empty() {
        return Err(TokenError::NoTokenEndpoint);
    }
    let mut form = format!(
        "grant_type=refresh_token&refresh_token={}",
        url_encode(refresh_token),
    );
    if !exchange.client_id.is_empty() {
        form.push_str(&format!("&client_id={}", url_encode(exchange.client_id)));
    }
    token_exchange_loop(http, host, as_metadata, form, exchange).await
}

/// The shared token-endpoint loop: the client-auth state (the
/// attestation the host supplied, the server's DPoP nonce once it
/// demands one), three attempts, the tx_code already in the form.
async fn token_exchange_loop(
    http: &dyn HttpClient,
    host: &dyn Host,
    as_metadata: &AsMetadata,
    form: String,
    exchange: &TokenExchangeContext<'_>,
) -> Result<TokenResponse, TokenError> {
    // Resolve the token endpoint.
    let token_endpoint = as_metadata.token_endpoint.clone();
    if token_endpoint.is_empty() {
        return Err(TokenError::NoTokenEndpoint);
    }
    let mut attestation = super::attestation::request_client_attestation(
        host,
        exchange.flow_id,
        &as_metadata.issuer,
        exchange.client_id,
        "",
    )
    .await;
    let mut dpop_nonce: Option<String> = None;

    // private_key_jwt (RFC 7523): the AS metadata names it, the client
    // assertion is a JWT the engine builds and the host signs — iss
    // and sub the client_id, aud the AS issuer, a short life, the jti
    // from the Rng port. One assertion PER REQUEST (RFC 7523 §3: the
    // jti is single-use, so every attempt — including the DPoP nonce
    // retry — builds a fresh one); the key is the host's, named by the
    // registered kid or the conventional `client-auth` key id.
    let client_assertion_required = as_metadata
        .token_endpoint_auth_methods
        .iter()
        .any(|m| m == "private_key_jwt");

    for attempt in 0..3 {
        // The per-attempt form: the grant and the fresh assertion.
        let mut form = form.clone();
        if client_assertion_required {
            if let Some(assertion) =
                build_client_assertion(host, exchange, &as_metadata.issuer).await
            {
                form.push_str(
                    "&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer",
                );
                form.push_str(&format!("&client_assertion={}", url_encode(&assertion)));
            }
        }

        // The headers: the attestation pair, and a fresh DPoP proof
        // per attempt (a new `jti`, the current nonce).
        let mut headers: Vec<(String, String)> = vec![
            (
                "content-type".to_owned(),
                "application/x-www-form-urlencoded".to_owned(),
            ),
            ("accept".to_owned(), "application/json".to_owned()),
        ];
        headers.extend(super::attestation::attestation_headers(
            attestation.as_ref(),
        ));
        if let Some(proof) = super::dpop::proof_for(
            host,
            exchange.dpop,
            super::dpop::ProofRequest {
                flow_id: exchange.flow_id,
                key_id: exchange.dpop_key_id,
                htm: "POST",
                htu: &token_endpoint,
                access_token: None,
                nonce: dpop_nonce.as_deref(),
                rng: exchange.rng,
                now_unix: exchange.now_unix,
            },
        )
        .await
        {
            headers.push(("DPoP".to_owned(), proof));
        }

        let response = http
            .send(HttpRequest {
                method: "POST".to_owned(),
                url: token_endpoint.clone(),
                headers,
                body: form.clone().into_bytes(),
                purpose: FetchPurpose::Token,
                max_response_bytes: MAX_TOKEN_BYTES,
                redirects: RedirectPolicy::None,
                allow_plaintext: false,
                timeout_ms: 15_000,
            })
            .await
            .map_err(|err| match err {
                HttpError::Refused => TokenError::Fetch("refused by the adapter".to_owned()),
                HttpError::Transport(detail) => TokenError::Fetch(detail),
            })?;

        if response.status == 200 {
            // Decode the token response, carrying the captured DPoP nonce
            // (RFC 9449 §8) for the resource requests' proofs.
            let mut token: TokenResponse =
                serde_json::from_slice(&response.body).map_err(|_| TokenError::NotJson)?;
            token.dpop_nonce = dpop_nonce.clone();
            return Ok(token);
        }

        // The DPoP nonce demand (RFC 9449 §8): capture the fresh nonce
        // and retry with a new proof.
        if super::dpop::is_dpop_nonce_error(&response) && attempt < 2 {
            dpop_nonce = super::dpop::dpop_nonce_from_response(&response);
            continue;
        }

        // The attestation challenge demand: resolve the fresh
        // challenge and re-ask the host for a PoP bound to it.
        if super::attestation::is_attestation_challenge_error(response.status, &response.body)
            && attempt < 2
        {
            if let Some(challenge) =
                super::attestation::resolve_challenge(http, as_metadata, &response.headers).await
            {
                attestation = super::attestation::request_client_attestation(
                    host,
                    exchange.flow_id,
                    &as_metadata.issuer,
                    exchange.client_id,
                    &challenge,
                )
                .await;
                continue;
            }
        }

        // The safe error code only: no raw body in the error.
        let error_code = response
            .body
            .split(|&b| b == b'"')
            .nth(3)
            .map(|s| String::from_utf8_lossy(s).to_string())
            .unwrap_or_default();
        return Err(TokenError::Status(
            response.status,
            if error_code.is_empty() {
                "unknown".to_owned()
            } else {
                error_code
            },
        ));
    }

    Err(TokenError::Fetch(
        "token exchange attempts exhausted".to_owned(),
    ))
}

/// Minimal URL form-encoding for the grant params.
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char);
            }
            b' ' => out.push_str("%20"),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The conventional key id the client assertion asks the host to sign
/// with: the wallet's registered client key. The host that holds it
/// answers; a host without it refuses and the token request goes
/// without the assertion (an AS that requires it rejects on its own).
pub const CLIENT_AUTH_KEY_ID: &str = "client-auth";

/// Builds the RFC 7523 client assertion: the JWT the engine assembles
/// and the host signs. The TBS is the base64url header + payload; the
/// host returns the raw JOSE signature bytes.
///
/// The kid is the key id the host was asked for — the AS matches the
/// assertion's key against the client's registered JWKS.
pub(super) async fn build_client_assertion(
    host: &dyn Host,
    exchange: &TokenExchangeContext<'_>,
    audience: &str,
) -> Option<String> {
    let now = exchange.now_unix;
    let mut entropy = [0u8; 12];
    if !exchange.rng.fill(&mut entropy) {
        return None;
    }
    let mut jti = String::with_capacity(24);
    for b in entropy {
        jti.push_str(&format!("{b:02x}"));
    }
    let header = serde_json::json!({
        "alg": "ES256",
        "typ": "JWT",
        "kid": exchange.client_key_kid.unwrap_or(CLIENT_AUTH_KEY_ID),
    });
    let payload = serde_json::json!({
        "iss": exchange.client_id,
        "sub": exchange.client_id,
        "aud": audience,
        "iat": now,
        "exp": now + 300,
        "jti": jti,
    });
    let tbs = format!("{}.{}", base64url_json(&header), base64url_json(&payload),);
    let kid = exchange
        .client_key_kid
        .unwrap_or(CLIENT_AUTH_KEY_ID)
        .to_owned();
    let Ok(sign) = host
        .request_sign(engine_ports::SignParams {
            flow_id: exchange.flow_id.to_owned(),
            to_sign: tbs.as_bytes().to_vec(),
            key_id: Some(kid),
            algorithm: "ES256".to_owned(),
        })
        .await
    else {
        return None;
    };
    // The signature as base64url — the JOSE wire form (the shared
    // helper; a hand-rolled tail-chunk loop once emitted three chars
    // for a one-byte tail, and the 64-byte ES256 signature arrived as
    // a bogus 65-byte value the suite rightly refused).
    Some(format!("{tbs}.{}", base64url(&sign.signature)))
}

/// Minimal base64url encoding of a JSON value — the JOSE wire form.
fn base64url_json(value: &serde_json::Value) -> String {
    base64url(value.to_string().as_bytes())
}

/// Minimal base64url encoding of bytes.
fn base64url(bytes: &[u8]) -> String {
    fn six_to_char(v: u8) -> char {
        // The base64url character for a 6-bit value: A-Z, a-z, 0-9, -, _.
        if v < 26 {
            (b'A' + v) as char
        } else if v < 52 {
            (b'a' + (v - 26)) as char
        } else if v < 62 {
            (b'0' + (v - 52)) as char
        } else if v == 62 {
            '-'
        } else {
            '_'
        }
    }
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk.first().copied().unwrap_or_default();
        let b1 = chunk.get(1).copied().unwrap_or_default();
        let b2 = chunk.get(2).copied().unwrap_or_default();
        let n = ((u32::from(b0)) << 16) | ((u32::from(b1)) << 8) | u32::from(b2);
        out.push(six_to_char(((n >> 18) & 0x3f) as u8));
        out.push(six_to_char(((n >> 12) & 0x3f) as u8));
        if chunk.len() > 1 {
            out.push(six_to_char(((n >> 6) & 0x3f) as u8));
        }
        if chunk.len() > 2 {
            out.push(six_to_char((n & 0x3f) as u8));
        }
    }
    out
}
