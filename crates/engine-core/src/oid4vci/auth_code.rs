//! The authorization-code grant: PKCE (RFC 7636), the PAR client
//! (RFC 9126), the authorization URL, and the code-for-token exchange —
//! the pieces S1/S2 deferred and auth_params.rs prepared.
//!
//! The P0.6-verified behaviours:
//! - **PKCE**: a 32-byte verifier from the Rng port (the core's own
//!   random choice — not the crypto library's), base64url-encoded (43
//!   chars, within RFC 7636 §4.1's 43–128), S256 challenge. Enabled
//!   when the AS supports it: `code_challenge_methods_supported` absent
//!   means assume S256 (the OID4VCI default); an explicit list must name
//!   it.
//! - **The state**: 16 random bytes, base64url — the CSRF check the
//!   redirect answer must match.
//! - **PAR**: the parameters POST to the pushed_authorization_request
//!   endpoint; a 200/201 answers a `request_uri`; the authorization URL
//!   then carries only `client_id` and `request_uri`. A PAR failure has
//!   no fallback when the AS requires PAR (RFC 9126 §5: there is no
//!   non-PAR /authorize path at all); when PAR is merely advertised, the
//!   failure falls back to the plain authorization URL with all
//!   parameters.
//! - **The authorization URL** preserves the endpoint's fixed query
//!   parameters (set, not replace).
//! - **The exchange**: grant_type=authorization_code, the code, the
//!   redirect_uri, the code_verifier, and the RFC 8707 `resource` the
//!   auth_params decision already made — the same decision the
//!   authorization request used, so the two always agree.

use engine_ports::{FetchPurpose, HttpClient, HttpError, HttpRequest, RedirectPolicy, Rng};

use super::token::TokenError;
use super::token::TokenResponse;
use super::types::AsMetadata;

/// The maximum size of a PAR or token response body.
const MAX_RESPONSE_BYTES: usize = 1 << 20;

/// The PKCE pair (RFC 7636).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkcePair {
    /// The code_verifier — 43 unreserved characters, sent to the token
    /// endpoint and never in the authorization URL.
    pub code_verifier: String,
    /// The code_challenge — BASE64URL(SHA256(verifier)).
    pub code_challenge: String,
}

impl PkcePair {
    /// Generates a fresh pair from the Rng port: 32 bytes → the 43-char
    /// verifier, and its S256 challenge.
    pub fn generate(rng: &dyn Rng) -> Option<Self> {
        let mut entropy = [0u8; 32];
        if !rng.fill(&mut entropy) {
            return None;
        }
        let code_verifier = base64url(&entropy);
        let code_challenge = s256_challenge(&code_verifier);
        Some(Self {
            code_verifier,
            code_challenge,
        })
    }
}

/// The S256 code challenge: BASE64URL(SHA256(verifier)) (RFC 7636 §4.2).
pub fn s256_challenge(verifier: &str) -> String {
    let digest = kryptering::digest::digest(kryptering::HashAlgorithm::Sha256, verifier.as_bytes())
        .unwrap_or_default();
    base64url(&digest)
}

/// Generates the OAuth state: 16 random bytes, base64url.
pub fn generate_state(rng: &dyn Rng) -> Option<String> {
    let mut entropy = [0u8; 16];
    if !rng.fill(&mut entropy) {
        return None;
    }
    Some(base64url(&entropy))
}

/// Why the PAR request refused.
#[derive(Debug, thiserror::Error)]
pub enum ParError {
    /// The transport failed.
    #[error("oid4vci: PAR request failed: {0}")]
    Fetch(String),
    /// The AS answered an error status, with its error code when the
    /// body carried one.
    #[error("oid4vci: PAR endpoint answered {status}: {error}")]
    Status {
        /// The HTTP status.
        status: u16,
        /// The AS's error code and description, when the body had them.
        error: String,
    },
    /// The AS demanded a server-provided challenge in the Client
    /// Attestation PoP (`use_attestation_challenge`): the response
    /// headers, for the challenge resolution. The retry loop consumes
    /// this; a caller seeing it has exhausted its retry.
    #[error("oid4vci: PAR demanded an attestation challenge")]
    ChallengeNeeded {
        /// The rejection response's headers.
        response_headers: Vec<(String, String)>,
    },
    /// The response carried no request_uri.
    #[error("oid4vci: PAR response missing request_uri")]
    NoRequestUri,
    /// The response was not JSON.
    #[error("oid4vci: PAR response is not JSON")]
    NotJson,
}

/// The PAR response (RFC 9126 §2.1).
#[derive(Debug, serde::Deserialize)]
struct ParResponse {
    #[serde(default)]
    request_uri: String,
    #[serde(default)]
    error: String,
    #[serde(default)]
    error_description: String,
}

/// Pushes the authorization request to the AS's PAR endpoint and
/// returns the `request_uri` the authorization URL carries.
///
/// The parameters are the assembled auth_params set (plus the PKCE
/// challenge pair when PKCE is enabled).
pub async fn push_authorization_request(
    http: &dyn HttpClient,
    par_endpoint: &str,
    params: &[(String, String)],
) -> Result<String, ParError> {
    push_with_headers(http, par_endpoint, params, &[]).await
}

/// The one PAR POST, with the client-attestation headers when the host
/// supplied a pair. The AS's `use_attestation_challenge` demand comes
/// back as [`ParError::ChallengeNeeded`] for the retry loop.
async fn push_with_headers(
    http: &dyn HttpClient,
    par_endpoint: &str,
    params: &[(String, String)],
    attestation_headers: &[(String, String)],
) -> Result<String, ParError> {
    let form = encode_form(params);
    let mut headers = vec![
        (
            "content-type".to_owned(),
            "application/x-www-form-urlencoded".to_owned(),
        ),
        ("accept".to_owned(), "application/json".to_owned()),
    ];
    headers.extend(attestation_headers.iter().cloned());
    let response = http
        .send(HttpRequest {
            method: "POST".to_owned(),
            url: par_endpoint.to_owned(),
            headers,
            body: form.into_bytes(),
            purpose: FetchPurpose::Token,
            max_response_bytes: MAX_RESPONSE_BYTES,
            redirects: RedirectPolicy::None,
            allow_plaintext: false,
            timeout_ms: 15_000,
        })
        .await
        .map_err(|err| match err {
            HttpError::Refused => ParError::Fetch("refused by the adapter".to_owned()),
            HttpError::Transport(detail) => ParError::Fetch(detail),
        })?;

    if (200..300).contains(&response.status) {
        let parsed: ParResponse =
            serde_json::from_slice(&response.body).map_err(|_| ParError::NotJson)?;
        if !parsed.error.is_empty() {
            return Err(ParError::Status {
                status: response.status,
                error: format!("{} {}", parsed.error, parsed.error_description),
            });
        }
        if parsed.request_uri.is_empty() {
            return Err(ParError::NoRequestUri);
        }
        return Ok(parsed.request_uri);
    }

    // The AS demanding a server-provided attestation challenge: the
    // headers go to the retry loop's challenge resolution.
    if super::attestation::is_attestation_challenge_error(response.status, &response.body) {
        return Err(ParError::ChallengeNeeded {
            response_headers: response.headers,
        });
    }

    // The error body: the AS's error code and description, when present.
    let parsed: ParResponse = serde_json::from_slice(&response.body).unwrap_or(ParResponse {
        request_uri: String::new(),
        error: String::new(),
        error_description: String::new(),
    });
    let error = if parsed.error.is_empty() {
        String::new()
    } else {
        format!("{} {}", parsed.error, parsed.error_description)
    };
    Err(ParError::Status {
        status: response.status,
        error,
    })
}

/// Pushes with the client-attestation challenge retry (once) — the
/// P0.6-verified PAR loop: the host supplies the (WIA, PoP) pair (the
/// WIA from the existing wallet provider, the PoP signed with the
/// device's instance key), and a `use_attestation_challenge` rejection
/// resolves the fresh challenge (the response header, else the AS's
/// `challenge_endpoint`) and re-asks the host for a PoP bound to it.
///
/// A host that refuses attestation at any point proceeds without it
/// (best-effort, the Go rule); an AS that requires it rejects on its
/// own.
pub async fn push_authorization_request_with_attestation(
    http: &dyn HttpClient,
    host: &dyn engine_ports::Host,
    as_metadata: &AsMetadata,
    flow_id: &str,
    client_id: &str,
    params: &[(String, String)],
) -> Result<String, ParError> {
    let mut attestation = super::attestation::request_client_attestation(
        host,
        flow_id,
        &as_metadata.issuer,
        client_id,
        "",
    )
    .await;

    for attempt in 0..2 {
        let headers = super::attestation::attestation_headers(attestation.as_ref());
        match push_with_headers(http, &as_metadata.par_endpoint, params, &headers).await {
            Ok(uri) => return Ok(uri),
            Err(ParError::ChallengeNeeded { response_headers }) if attempt == 0 => {
                // Resolve the fresh challenge; without one the original
                // demand stands.
                let Some(challenge) =
                    super::attestation::resolve_challenge(http, as_metadata, &response_headers)
                        .await
                else {
                    return Err(ParError::Fetch(
                        "no attestation challenge could be obtained".to_owned(),
                    ));
                };
                attestation = super::attestation::request_client_attestation(
                    host,
                    flow_id,
                    &as_metadata.issuer,
                    client_id,
                    &challenge,
                )
                .await;
            }
            Err(other) => return Err(other),
        }
    }

    Err(ParError::Fetch("PAR retry exhausted".to_owned()))
}

/// The authorization URL to hand the host.
///
/// - **With a PAR `request_uri`**: only `client_id` and `request_uri` —
///   the pushed parameters live server-side.
/// - **Without**: every parameter in the URL.
///
/// The endpoint's fixed query parameters are preserved (set, not
/// replaced) — an AS that pins a tenant or version in its endpoint URL
/// keeps it.
pub fn build_authorization_url(
    authorization_endpoint: &str,
    client_id: &str,
    params: &[(String, String)],
    request_uri: Option<&str>,
) -> String {
    let mut pairs: Vec<(String, String)> = Vec::new();
    if let Some(uri) = request_uri {
        pairs.push(("client_id".to_owned(), client_id.to_owned()));
        pairs.push(("request_uri".to_owned(), uri.to_owned()));
    } else {
        pairs.push(("client_id".to_owned(), client_id.to_owned()));
        pairs.extend(params.iter().cloned());
    }
    append_query(authorization_endpoint, &pairs)
}

/// Exchanges the authorization code for tokens (RFC 6749 §4.1.3) with
/// the PKCE verifier and the RFC 8707 resource indicator.
pub async fn exchange_authorization_code(
    http: &dyn HttpClient,
    as_metadata: &AsMetadata,
    code: &str,
    redirect_uri: &str,
    code_verifier: &str,
    resource: Option<&str>,
) -> Result<TokenResponse, TokenError> {
    exchange_code_with_headers(
        http,
        as_metadata,
        code,
        redirect_uri,
        code_verifier,
        resource,
        &[],
        // No host on this path: no assertion can be built (an AS that
        // requires private_key_jwt rejects the request on its own).
        None,
    )
    .await
}

/// The one code-for-token POST, with the client-attestation headers when
/// the host supplied a pair, and the RFC 7523 assertion when the AS
/// demands the method.
//
// The argument count is the shape: the POST carries the code, its
/// redirect and verifier, the resource, the attestation pair and the
// assertion — each a distinct wire member, so they ride loose.
#[allow(clippy::too_many_arguments)]
async fn exchange_code_with_headers(
    http: &dyn HttpClient,
    as_metadata: &AsMetadata,
    code: &str,
    redirect_uri: &str,
    code_verifier: &str,
    resource: Option<&str>,
    attestation_headers: &[(String, String)],
    client_assertion: Option<&str>,
) -> Result<TokenResponse, TokenError> {
    if as_metadata.token_endpoint.is_empty() {
        return Err(TokenError::NoTokenEndpoint);
    }

    let mut form = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}",
        url_encode(code),
        url_encode(redirect_uri),
    );
    if !code_verifier.is_empty() {
        form.push_str(&format!("&code_verifier={}", url_encode(code_verifier)));
    }
    // RFC 8707: the same cross-origin decision the authorization request
    // made, so the two always agree.
    if let Some(resource) = resource.filter(|r| !r.is_empty()) {
        form.push_str(&format!("&resource={}", url_encode(resource)));
    }

    // The RFC 7523 client assertion (private_key_jwt): the engine built
    // it above; the type and the value ride the form (RFC 7523 §2.2).
    // `None` without a host — an AS that requires the method rejects
    // the request on its own.
    if let Some(assertion) = client_assertion {
        form.push_str(
            "&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer",
        );
        form.push_str(&format!("&client_assertion={}", url_encode(assertion)));
    }

    let mut headers = vec![
        (
            "content-type".to_owned(),
            "application/x-www-form-urlencoded".to_owned(),
        ),
        ("accept".to_owned(), "application/json".to_owned()),
    ];
    headers.extend(attestation_headers.iter().cloned());

    let response = http
        .send(HttpRequest {
            method: "POST".to_owned(),
            url: as_metadata.token_endpoint.clone(),
            headers,
            body: form.into_bytes(),
            purpose: FetchPurpose::Token,
            max_response_bytes: MAX_RESPONSE_BYTES,
            redirects: RedirectPolicy::None,
            allow_plaintext: false,
            timeout_ms: 15_000,
        })
        .await
        .map_err(|err| match err {
            HttpError::Refused => TokenError::Fetch("refused by the adapter".to_owned()),
            HttpError::Transport(detail) => TokenError::Fetch(detail),
        })?;

    if response.status != 200 {
        // The DPoP nonce demand (RFC 9449 §8): the fresh nonce goes to
        // the retry loop's next proof. Resolved before the challenge
        // check so a response carrying both serves both.
        if super::dpop::is_dpop_nonce_error(&response) {
            return Err(TokenError::ChallengeNeeded {
                response_headers: response.headers,
            });
        }
        // The AS demanding a server-provided attestation challenge: the
        // headers go to the retry loop's challenge resolution.
        if super::attestation::is_attestation_challenge_error(response.status, &response.body) {
            return Err(TokenError::ChallengeNeeded {
                response_headers: response.headers,
            });
        }
        // The safe error code only: no raw body in the error.
        let error_code = extract_error_code(&response.body);
        return Err(TokenError::Status(response.status, error_code));
    }

    serde_json::from_slice(&response.body).map_err(|_| TokenError::NotJson)
}

/// The inputs to the attested code-for-token exchange.
pub struct CodeExchangeSpec<'a> {
    /// The flow the exchange belongs to.
    pub flow_id: &'a str,
    /// The device DPoP key to sign with, when the flow names one — a
    /// renewal reuses the key its refresh_token was bound to at
    /// issuance (RFC 9449 / ARF 3.0 §6.6.6.2.2).
    pub dpop_key_id: Option<&'a str>,
    /// The wallet's registered client key's kid — the RFC 7523
    /// private_key_jwt assertion's kid. The flow start received it in
    /// the offer params; the resume reads it back from the stash, so
    /// the code-for-token exchange names the same key the
    /// pre-authorized exchange does (RFC 7523 §2: the assertion's
    /// `kid` identifies the registered key).
    pub client_key_kid: Option<&'a str>,
    /// The wallet's client_id (the PoP `iss`).
    pub client_id: &'a str,
    /// The authorization code the redirect answered.
    pub code: &'a str,
    /// The redirect_uri the authorization request named.
    pub redirect_uri: &'a str,
    /// The PKCE code_verifier from the stash.
    pub code_verifier: &'a str,
    /// The RFC 8707 resource indicator, when cross-origin.
    pub resource: Option<&'a str>,
    /// The flow's DPoP key (the engine-held legacy mode), when there is
    /// one.
    pub dpop: Option<&'a super::dpop::DpopKey>,
    /// The Rng port (the DPoP proof's `jti`).
    pub rng: &'a dyn engine_ports::Rng,
    /// The Clock port's now (the DPoP proof's `iat`).
    pub now_unix: i64,
}

/// Exchanges the code with the client-attestation challenge retry
/// (once) — the same loop as the PAR path: the host supplies the (WIA,
/// PoP) pair, a `use_attestation_challenge` rejection resolves the
/// fresh challenge and re-asks, and the exchange retries once.
pub async fn exchange_authorization_code_with_attestation(
    http: &dyn HttpClient,
    host: &dyn engine_ports::Host,
    as_metadata: &AsMetadata,
    spec: &CodeExchangeSpec<'_>,
) -> Result<TokenResponse, TokenError> {
    // The client-auth state: the attestation the host supplied, and the
    // server's DPoP nonce once it demands one.
    let mut attestation = super::attestation::request_client_attestation(
        host,
        spec.flow_id,
        &as_metadata.issuer,
        spec.client_id,
        "",
    )
    .await;
    let mut dpop_nonce: Option<String> = None;

    // private_key_jwt (RFC 7523): the AS metadata names the method, so
    // the code-for-token POST carries the client assertion — the same
    // JWT the pre-authorized exchange sends (token.rs), built by the
    // engine and signed by the host with the registered kid. One
    // assertion PER REQUEST (RFC 7523 §3: the jti is single-use), so
    // every attempt — including the DPoP nonce retry — builds a fresh
    // one.
    let client_assertion_required = as_metadata
        .token_endpoint_auth_methods
        .iter()
        .any(|m| m == "private_key_jwt");

    for attempt in 0..3 {
        // The per-attempt assertion, when the AS demands the method.
        let client_assertion = if client_assertion_required {
            super::token::build_client_assertion(
                host,
                &super::token::TokenExchangeContext {
                    flow_id: spec.flow_id,
                    dpop_key_id: spec.dpop_key_id,
                    client_key_kid: spec.client_key_kid,
                    client_id: spec.client_id,
                    dpop: spec.dpop,
                    rng: spec.rng,
                    now_unix: spec.now_unix,
                },
                &as_metadata.issuer,
            )
            .await
        } else {
            None
        };

        // The headers: the attestation pair, and a fresh DPoP proof
        // per attempt (the client-held proof the host signs, else the
        // engine-held key; a new `jti`, the current nonce).
        let mut headers = super::attestation::attestation_headers(attestation.as_ref());
        if let Some(proof) = super::dpop::proof_for(
            host,
            spec.dpop,
            super::dpop::ProofRequest {
                flow_id: spec.flow_id,
                key_id: spec.dpop_key_id,
                htm: "POST",
                htu: &as_metadata.token_endpoint,
                access_token: None,
                nonce: dpop_nonce.as_deref(),
                rng: spec.rng,
                now_unix: spec.now_unix,
            },
        )
        .await
        {
            headers.push(("DPoP".to_owned(), proof));
        }
        match exchange_code_with_headers(
            http,
            as_metadata,
            spec.code,
            spec.redirect_uri,
            spec.code_verifier,
            spec.resource,
            &headers,
            client_assertion.as_deref(),
        )
        .await
        {
            Ok(token) => return Ok(token),
            Err(TokenError::ChallengeNeeded { response_headers }) if attempt < 2 => {
                // A DPoP nonce demand (RFC 9449 §8): capture the fresh
                // nonce; the next attempt's proof carries it. No
                // attestation re-ask — the pair is still good.
                if let Some(nonce) = super::dpop::dpop_nonce_from_headers(&response_headers) {
                    dpop_nonce = Some(nonce);
                    continue;
                }
                // An attestation challenge demand: resolve the fresh
                // challenge and re-ask the host for a PoP bound to it.
                let Some(challenge) =
                    super::attestation::resolve_challenge(http, as_metadata, &response_headers)
                        .await
                else {
                    return Err(TokenError::Fetch(
                        "no attestation challenge could be obtained".to_owned(),
                    ));
                };
                attestation = super::attestation::request_client_attestation(
                    host,
                    spec.flow_id,
                    &as_metadata.issuer,
                    spec.client_id,
                    &challenge,
                )
                .await;
            }
            Err(other) => return Err(other),
        }
    }

    Err(TokenError::Fetch(
        "token exchange retry exhausted".to_owned(),
    ))
}

/// Extracts the OAuth error code from a token/par error body — the safe
/// member only, never the raw body.
fn extract_error_code(body: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("error")
                .and_then(|v| v.as_str())
                .map(str::to_owned)
        })
        .unwrap_or_default()
}

/// Encodes (name, value) pairs as a form body.
fn encode_form(params: &[(String, String)]) -> String {
    let mut out = String::new();
    for (name, value) in params {
        if !out.is_empty() {
            out.push('&');
        }
        out.push_str(&url_encode(name));
        out.push('=');
        out.push_str(&url_encode(value));
    }
    out
}

/// Appends (name, value) pairs to a URL's query, preserving the fixed
/// parameters already there.
fn append_query(url: &str, pairs: &[(String, String)]) -> String {
    let (base, existing) = match url.split_once('?') {
        Some((base, query)) => (base, query.to_owned()),
        None => (url, String::new()),
    };

    // The fixed parameters first; the appended pairs set (override) by
    // name and add the rest.
    let mut merged: Vec<(String, String)> = Vec::new();
    if !existing.is_empty() {
        for pair in existing.split('&') {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            merged.push((url_decode(name), url_decode(value)));
        }
    }
    for (name, value) in pairs {
        match merged.iter_mut().find(|(n, _)| n == name) {
            Some(existing) => existing.1 = value.clone(),
            None => merged.push((name.clone(), value.clone())),
        }
    }

    let mut out = base.to_owned();
    if !merged.is_empty() {
        out.push('?');
        let mut first = true;
        for (name, value) in &merged {
            if !first {
                out.push('&');
            }
            first = false;
            out.push_str(&url_encode(name));
            out.push('=');
            out.push_str(&url_encode(value));
        }
    }
    out
}

/// Minimal URL form-encoding (the unreserved set plus %XX).
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Minimal percent-decoding for preserved query values.
fn url_decode(s: &str) -> String {
    let mut out = Vec::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '%' {
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            continue;
        }
        let mut hex = String::with_capacity(2);
        for _ in 0..2 {
            if let Some(h) = chars.next() {
                hex.push(h);
            }
        }
        match u8::from_str_radix(&hex, 16) {
            Ok(byte) if hex.len() == 2 => out.push(byte),
            _ => {
                out.push(b'%');
                out.extend(hex.as_bytes());
            }
        }
    }
    String::from_utf8(out).unwrap_or_default()
}

/// Minimal base64url encoding (unpadded).
fn base64url(bytes: &[u8]) -> String {
    fn six_to_char(v: u8) -> char {
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
        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | b2 as u32;
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

#[cfg(test)]
mod tests {
    use super::*;
    use engine_ports::HttpResponse;

    struct FakeRng;
    impl Rng for FakeRng {
        fn fill(&self, buf: &mut [u8]) -> bool {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = (i as u8).wrapping_add(7);
            }
            true
        }
    }

    struct FailingRng;
    impl Rng for FailingRng {
        fn fill(&self, _buf: &mut [u8]) -> bool {
            false
        }
    }

    struct FakeHttp {
        status: u16,
        body: Vec<u8>,
        requests: std::sync::Mutex<Vec<HttpRequest>>,
    }

    #[async_trait::async_trait]
    impl HttpClient for FakeHttp {
        async fn send(&self, request: HttpRequest) -> Result<HttpResponse, HttpError> {
            self.requests.lock().map(|mut r| r.push(request)).ok();
            Ok(HttpResponse {
                status: self.status,
                headers: Vec::new(),
                body: self.body.clone(),
            })
        }
    }

    fn test_as() -> AsMetadata {
        AsMetadata {
            issuer: "https://as.example".to_owned(),
            token_endpoint: "https://as.example/token".to_owned(),
            authorization_endpoint: "https://as.example/authorize".to_owned(),
            par_endpoint: "https://as.example/par".to_owned(),
            token_endpoint_auth_methods: Vec::new(),
            require_par: false,
            challenge_endpoint: String::new(),
            code_challenge_methods: None,
            grant_types: vec!["authorization_code".to_owned()],
        }
    }

    // ─── client attestation ──────────────────────────────────────────

    struct TestRng;
    impl engine_ports::Rng for TestRng {
        fn fill(&self, buf: &mut [u8]) -> bool {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = i as u8;
            }
            true
        }
    }

    /// A host that supplies the (WIA, PoP) pair and records the
    /// challenges it was asked to bind.
    struct AttestingHost {
        challenges: std::sync::Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl engine_ports::Host for AttestingHost {
        async fn request_sign(
            &self,
            _p: engine_ports::SignParams,
        ) -> Result<engine_ports::SignResult, engine_ports::HostError> {
            Err(engine_ports::HostError::Cannot("no sign".to_owned()))
        }
        async fn request_match(
            &self,
            _params: engine_ports::MatchParams,
        ) -> Result<engine_ports::MatchResult, engine_ports::HostError> {
            Err(engine_ports::HostError::Cannot("no match".to_owned()))
        }
        async fn request_consent(
            &self,
            _p: engine_ports::ConsentParams,
        ) -> Result<engine_ports::ConsentResult, engine_ports::HostError> {
            Err(engine_ports::HostError::Cannot("no consent".to_owned()))
        }
        async fn request_tx_code(&self, _f: &str) -> Result<String, engine_ports::HostError> {
            Err(engine_ports::HostError::Cannot("no tx code".to_owned()))
        }
        async fn open_authorization(
            &self,
            _f: &str,
            _u: &str,
        ) -> Result<(), engine_ports::HostError> {
            Ok(())
        }
        fn progress(&self, _f: &str, _s: &str, _d: Option<String>) {}

        async fn request_attestation(
            &self,
            params: engine_ports::AttestationParams,
        ) -> Result<engine_ports::AttestationResult, engine_ports::HostError> {
            self.challenges
                .lock()
                .map(|mut c| c.push(params.challenge.clone()))
                .ok();
            Ok(engine_ports::AttestationResult {
                wia: "wia-jwt".to_owned(),
                pop: format!("pop-for-{}", params.challenge),
            })
        }
    }

    /// An HTTP fake with a scripted answer sequence per URL.
    struct SequencedHttp {
        answers: std::sync::Mutex<Vec<(String, HttpResponse)>>,
        seen: std::sync::Mutex<Vec<HttpRequest>>,
    }

    impl SequencedHttp {
        fn new(answers: Vec<(String, HttpResponse)>) -> Self {
            Self {
                answers: std::sync::Mutex::new(answers),
                seen: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn take_answer(&self, url: &str) -> Option<HttpResponse> {
            let mut answers = self.answers.lock().ok()?;
            let index = answers.iter().position(|(u, _)| u == url)?;
            Some(answers.remove(index).1)
        }
    }

    #[async_trait::async_trait]
    impl HttpClient for SequencedHttp {
        async fn send(&self, request: HttpRequest) -> Result<HttpResponse, HttpError> {
            self.seen.lock().map(|mut s| s.push(request.clone())).ok();
            match self.take_answer(&request.url) {
                Some(response) => Ok(response),
                None => Ok(HttpResponse {
                    status: 404,
                    headers: Vec::new(),
                    body: Vec::new(),
                }),
            }
        }
    }

    #[tokio::test]
    async fn the_par_push_carries_the_attestation_headers() {
        let http = SequencedHttp::new(vec![(
            "https://as.example/par".to_owned(),
            HttpResponse {
                status: 201,
                headers: Vec::new(),
                body: br#"{"request_uri":"urn:par:1"}"#.to_vec(),
            },
        )]);
        let host = AttestingHost {
            challenges: std::sync::Mutex::new(Vec::new()),
        };
        let uri = push_authorization_request_with_attestation(
            &http,
            &host,
            &test_as(),
            "flow-1",
            "client-1",
            &[("response_type".to_owned(), "code".to_owned())],
        )
        .await
        .expect("push");
        assert_eq!(uri, "urn:par:1");

        // The attestation pair arrived as the two headers.
        let seen = http.seen.lock().expect("lock");
        assert_eq!(seen.len(), 1);
        let attestation = seen[0]
            .headers
            .iter()
            .find(|(name, _)| name == "OAuth-Client-Attestation")
            .map(|(_, value)| value.clone());
        let pop = seen[0]
            .headers
            .iter()
            .find(|(name, _)| name == "OAuth-Client-Attestation-PoP")
            .map(|(_, value)| value.clone());
        assert_eq!(attestation.as_deref(), Some("wia-jwt"));
        assert_eq!(pop.as_deref(), Some("pop-for-"));

        // The host was asked once, unchallenged.
        let challenges = host.challenges.lock().expect("lock");
        assert_eq!(challenges.len(), 1);
    }

    #[tokio::test]
    async fn a_par_attestation_challenge_retries_once_with_the_fresh_challenge() {
        let http = SequencedHttp::new(vec![
            (
                "https://as.example/par".to_owned(),
                HttpResponse {
                    status: 400,
                    headers: vec![(
                        "OAuth-Client-Attestation-Challenge".to_owned(),
                        "challenge-1".to_owned(),
                    )],
                    body: br#"{"error":"use_attestation_challenge"}"#.to_vec(),
                },
            ),
            (
                "https://as.example/par".to_owned(),
                HttpResponse {
                    status: 201,
                    headers: Vec::new(),
                    body: br#"{"request_uri":"urn:par:2"}"#.to_vec(),
                },
            ),
        ]);
        let host = AttestingHost {
            challenges: std::sync::Mutex::new(Vec::new()),
        };
        let uri = push_authorization_request_with_attestation(
            &http,
            &host,
            &test_as(),
            "flow-1",
            "client-1",
            &[],
        )
        .await
        .expect("push after the challenge");
        assert_eq!(uri, "urn:par:2");

        // The host was asked twice: unchallenged, then with the fresh
        // challenge from the response header.
        let challenges = host.challenges.lock().expect("lock");
        assert_eq!(*challenges, vec![String::new(), "challenge-1".to_owned()]);

        // The retry's PoP was bound to the challenge.
        let seen = http.seen.lock().expect("lock");
        let pop = seen[1]
            .headers
            .iter()
            .find(|(name, _)| name == "OAuth-Client-Attestation-PoP")
            .map(|(_, value)| value.clone());
        assert_eq!(pop.as_deref(), Some("pop-for-challenge-1"));
    }

    #[tokio::test]
    async fn the_par_challenge_retry_happens_once() {
        let challenge = HttpResponse {
            status: 400,
            headers: vec![(
                "OAuth-Client-Attestation-Challenge".to_owned(),
                "challenge-1".to_owned(),
            )],
            body: br#"{"error":"use_attestation_challenge"}"#.to_vec(),
        };
        let http = SequencedHttp::new(vec![
            ("https://as.example/par".to_owned(), challenge.clone()),
            ("https://as.example/par".to_owned(), challenge),
        ]);
        let host = AttestingHost {
            challenges: std::sync::Mutex::new(Vec::new()),
        };
        assert!(push_authorization_request_with_attestation(
            &http,
            &host,
            &test_as(),
            "flow-1",
            "client-1",
            &[],
        )
        .await
        .is_err());
        // Two pushes, two host asks — not more.
        let challenges = host.challenges.lock().expect("lock");
        assert_eq!(challenges.len(), 2);
    }

    #[tokio::test]
    async fn the_code_exchange_carries_the_attestation_and_retries_the_challenge() {
        let http = SequencedHttp::new(vec![
            (
                "https://as.example/token".to_owned(),
                HttpResponse {
                    status: 401,
                    headers: vec![(
                        "OAuth-Client-Attestation-Challenge".to_owned(),
                        "challenge-1".to_owned(),
                    )],
                    body: br#"{"error":"use_attestation_challenge"}"#.to_vec(),
                },
            ),
            (
                "https://as.example/token".to_owned(),
                HttpResponse {
                    status: 200,
                    headers: Vec::new(),
                    body: br#"{"access_token":"at-1","token_type":"Bearer"}"#.to_vec(),
                },
            ),
        ]);
        let host = AttestingHost {
            challenges: std::sync::Mutex::new(Vec::new()),
        };
        let token = exchange_authorization_code_with_attestation(
            &http,
            &host,
            &test_as(),
            &CodeExchangeSpec {
                flow_id: "flow-1",
                dpop_key_id: None,
                client_key_kid: None,
                client_id: "client-1",
                code: "code-1",
                redirect_uri: "https://wallet.example/cb",
                code_verifier: "verifier-1",
                resource: None,
                dpop: None,
                rng: &TestRng,
                now_unix: 1_000,
            },
        )
        .await
        .expect("exchange");
        assert_eq!(token.access_token, "at-1");

        let challenges = host.challenges.lock().expect("lock");
        assert_eq!(*challenges, vec![String::new(), "challenge-1".to_owned()]);
    }

    // ─── PKCE ─────────────────────────────────────────────────────────

    #[test]
    fn the_verifier_is_43_unreserved_characters() {
        let pkce = PkcePair::generate(&FakeRng).expect("generate");
        assert_eq!(pkce.code_verifier.len(), 43);
        assert!(pkce
            .code_verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
    }

    #[test]
    fn the_challenge_is_the_s256_of_the_verifier() {
        let pkce = PkcePair::generate(&FakeRng).expect("generate");
        assert_eq!(pkce.code_challenge, s256_challenge(&pkce.code_verifier));
        // RFC 7636's own test vector (appendix B): the deterministic
        // verifier and its challenge.
        assert_eq!(
            s256_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn an_rng_that_cannot_fill_refuses() {
        assert!(PkcePair::generate(&FailingRng).is_none());
        assert!(generate_state(&FailingRng).is_none());
    }

    #[test]
    fn pkce_support_follows_the_declaration() {
        // Absent: assume S256 (the OID4VCI default).
        assert!(test_as().supports_pkce_s256());
        // An explicit list naming S256.
        let mut as_meta = test_as();
        as_meta.code_challenge_methods = Some(vec!["S256".to_owned(), "plain".to_owned()]);
        assert!(as_meta.supports_pkce_s256());
        // An explicit list without S256: no PKCE.
        as_meta.code_challenge_methods = Some(vec!["plain".to_owned()]);
        assert!(!as_meta.supports_pkce_s256());
        // An explicitly empty list: no PKCE.
        as_meta.code_challenge_methods = Some(Vec::new());
        assert!(!as_meta.supports_pkce_s256());
    }

    // ─── PAR ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn par_posts_the_parameters_and_takes_the_request_uri() {
        let http = FakeHttp {
            status: 201,
            body: br#"{"request_uri":"urn:ietf:params:oauth:request_uri:abc","expires_in":90}"#
                .to_vec(),
            requests: std::sync::Mutex::new(Vec::new()),
        };
        let params = vec![
            ("response_type".to_owned(), "code".to_owned()),
            ("scope".to_owned(), "openid".to_owned()),
        ];
        let uri = push_authorization_request(&http, "https://as.example/par", &params)
            .await
            .expect("push");
        assert_eq!(uri, "urn:ietf:params:oauth:request_uri:abc");

        let requests = http.requests.lock().expect("lock");
        let body = String::from_utf8_lossy(&requests[0].body).into_owned();
        assert!(body.contains("response_type=code"));
        assert!(body.contains("scope=openid"));
        assert_eq!(requests[0].url, "https://as.example/par");
    }

    #[tokio::test]
    async fn a_par_error_carries_the_as_error_code() {
        let http = FakeHttp {
            status: 400,
            body: br#"{"error":"invalid_client","error_description":"unknown client"}"#.to_vec(),
            requests: std::sync::Mutex::new(Vec::new()),
        };
        let err = push_authorization_request(&http, "https://as.example/par", &[])
            .await
            .expect_err("refuses");
        assert!(matches!(err, ParError::Status { status: 400, .. }));
    }

    #[tokio::test]
    async fn a_par_response_without_a_request_uri_refuses() {
        let http = FakeHttp {
            status: 200,
            body: br#"{}"#.to_vec(),
            requests: std::sync::Mutex::new(Vec::new()),
        };
        assert!(matches!(
            push_authorization_request(&http, "https://as.example/par", &[]).await,
            Err(ParError::NoRequestUri)
        ));
    }

    // ─── the authorization URL ────────────────────────────────────────

    #[test]
    fn the_par_url_carries_only_client_id_and_request_uri() {
        let url = build_authorization_url(
            "https://as.example/authorize?tenant=x",
            "client-1",
            &[("scope".to_owned(), "openid".to_owned())],
            Some("urn:ietf:params:oauth:request_uri:abc"),
        );
        // The fixed tenant parameter is preserved; nothing else leaks.
        assert_eq!(
            url,
            "https://as.example/authorize?tenant=x&client_id=client-1&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Aabc"
        );
    }

    #[test]
    fn the_plain_url_carries_all_parameters_and_preserves_the_fixed_ones() {
        let url = build_authorization_url(
            "https://as.example/authorize?tenant=x",
            "client-1",
            &[
                ("response_type".to_owned(), "code".to_owned()),
                ("scope".to_owned(), "openid".to_owned()),
            ],
            None,
        );
        assert!(url.contains("tenant=x"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("scope=openid"));
        assert!(url.contains("client_id=client-1"));
    }

    #[test]
    fn an_appended_parameter_overrides_a_fixed_one() {
        let url = build_authorization_url(
            "https://as.example/authorize?client_id=fixed",
            "client-1",
            &[],
            None,
        );
        // client_id is set, not duplicated.
        assert!(url.contains("client_id=client-1"));
        assert!(!url.contains("client_id=fixed"));
    }

    // ─── the exchange ─────────────────────────────────────────────────

    #[tokio::test]
    async fn the_code_exchanges_with_the_verifier_and_resource() {
        let http = FakeHttp {
            status: 200,
            body: br#"{"access_token":"at-1","token_type":"Bearer","expires_in":3600}"#.to_vec(),
            requests: std::sync::Mutex::new(Vec::new()),
        };
        let token = exchange_authorization_code(
            &http,
            &test_as(),
            "code-1",
            "https://wallet.example/cb",
            "verifier-1",
            Some("https://issuer.example"),
        )
        .await
        .expect("exchange");
        assert_eq!(token.access_token, "at-1");

        let requests = http.requests.lock().expect("lock");
        let body = String::from_utf8_lossy(&requests[0].body).into_owned();
        assert!(body.contains("grant_type=authorization_code"));
        assert!(body.contains("code=code-1"));
        assert!(body.contains("code_verifier=verifier-1"));
        assert!(body.contains("resource=https%3A%2F%2Fissuer.example"));
        assert_eq!(requests[0].url, "https://as.example/token");
    }

    #[tokio::test]
    async fn a_failed_exchange_reports_the_safe_error_code() {
        let http = FakeHttp {
            status: 400,
            body: br#"{"error":"invalid_grant"}"#.to_vec(),
            requests: std::sync::Mutex::new(Vec::new()),
        };
        let err = exchange_authorization_code(
            &http,
            &test_as(),
            "code-1",
            "https://wallet.example/cb",
            "verifier-1",
            None,
        )
        .await
        .expect_err("refuses");
        assert!(matches!(
            err,
            TokenError::Status(400, ref error_code) if error_code == "invalid_grant"
        ));
    }
}
