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

/// The PAR push's client-auth context: the same identity the code
/// exchange authenticates with. The AS that names `private_key_jwt`
/// (RFC 7523, from `token_endpoint_auth_methods_supported`)
/// authenticates the client at the pushed request too, so the push
/// carries the same client assertion the token exchange will.
pub struct ParPushSpec<'a> {
    /// The flow the push belongs to (the attestation and sign asks).
    pub flow_id: &'a str,
    /// The wallet's client_id (the assertion's `iss` and `sub`).
    pub client_id: &'a str,
    /// The wallet's registered client key's kid — the assertion's
    /// `kid`, when the flow start carried one (the app knows the kid
    /// it registered).
    pub client_key_kid: Option<&'a str>,
    /// The Rng port (the assertion's `jti`).
    pub rng: &'a dyn engine_ports::Rng,
    /// The Clock port's now (the assertion's `iat` and `exp`).
    pub now_unix: i64,
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
    spec: &ParPushSpec<'_>,
    params: &[(String, String)],
) -> Result<String, ParError> {
    let mut attestation = super::attestation::request_client_attestation(
        host,
        spec.flow_id,
        &as_metadata.issuer,
        spec.client_id,
        "",
    )
    .await;

    // private_key_jwt (RFC 7523) at the pushed request: the AS's client
    // authentication policy applies to the PAR endpoint as to the token
    // endpoint — the same assertion builder, the registered kid, a
    // fresh single-use `jti` per attempt (RFC 7523 §3).
    let client_assertion_required = as_metadata
        .token_endpoint_auth_methods
        .iter()
        .any(|m| m == "private_key_jwt");

    for attempt in 0..2 {
        let headers = super::attestation::attestation_headers(attestation.as_ref());
        // The pushed parameters, with the client assertion riding as
        // form members when the AS demands the method (RFC 9126 §2.1:
        // the pushed set carries the client authentication beside the
        // authorization parameters).
        let mut push_params: Vec<(String, String)> = params.to_vec();
        if client_assertion_required {
            if let Some(assertion) = super::token::build_client_assertion(
                host,
                &super::token::TokenExchangeContext {
                    flow_id: spec.flow_id,
                    dpop_key_id: None,
                    client_key_kid: spec.client_key_kid,
                    client_id: spec.client_id,
                    dpop: None,
                    rng: spec.rng,
                    now_unix: spec.now_unix,
                },
                &as_metadata.issuer,
            )
            .await
            {
                push_params.push((
                    "client_assertion_type".to_owned(),
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".to_owned(),
                ));
                push_params.push(("client_assertion".to_owned(), assertion));
            }
        }
        match push_with_headers(http, &as_metadata.par_endpoint, &push_params, &headers).await {
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
