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
/// challenge pair when PKCE is enabled). Client attestation (WIA + PoP)
/// is not yet wired; the PAR retry-once for an attestation challenge
/// arrives with it.
pub async fn push_authorization_request(
    http: &dyn HttpClient,
    par_endpoint: &str,
    params: &[(String, String)],
) -> Result<String, ParError> {
    let form = encode_form(params);
    let response = http
        .send(HttpRequest {
            method: "POST".to_owned(),
            url: par_endpoint.to_owned(),
            headers: vec![
                (
                    "content-type".to_owned(),
                    "application/x-www-form-urlencoded".to_owned(),
                ),
                ("accept".to_owned(), "application/json".to_owned()),
            ],
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

    let response = http
        .send(HttpRequest {
            method: "POST".to_owned(),
            url: as_metadata.token_endpoint.clone(),
            headers: vec![
                (
                    "content-type".to_owned(),
                    "application/x-www-form-urlencoded".to_owned(),
                ),
                ("accept".to_owned(), "application/json".to_owned()),
            ],
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
        // The safe error code only: no raw body in the error.
        let error_code = extract_error_code(&response.body);
        return Err(TokenError::Status(response.status, error_code));
    }

    serde_json::from_slice(&response.body).map_err(|_| TokenError::NotJson)
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
            require_par: false,
            code_challenge_methods: None,
            grant_types: vec!["authorization_code".to_owned()],
        }
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
