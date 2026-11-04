//! AS metadata discovery: the RFC 8414 §3.1 candidates, the OIDC discovery
//! form, the 404-only fallback, the exact `issuer` check, and the endpoint
//! guessing rule — the S1 resolver's third step.

use engine_ports::{FetchPurpose, HttpClient, HttpError, HttpRequest, RedirectPolicy};

use super::types::{AsMetadata, AsMetadataError};

/// The maximum size of an AS metadata document: 1 MiB.
const MAX_AS_METADATA_BYTES: usize = 1 << 20;

/// Discovers the AS metadata for the given authorization server URL.
///
/// The P0.6-verified behaviour:
/// - Candidates in order: RFC 8414 §3.1 insertion
///   (`/.well-known/oauth-authorization-server` between host and path),
///   then OIDC discovery (`/.well-known/openid-configuration` appended).
///   One terminating slash removed in each.
/// - 404-only fallback between candidates; other statuses are terminal.
/// - The document's `issuer` must equal the AS identifier exactly.
/// - A served document without a token endpoint is an error, not a guess.
/// - Endpoint guessing (`<issuer>/token`, `<AS>/authorize`) only when every
///   candidate answered 404.
pub async fn discover_as_metadata(
    http: &dyn HttpClient,
    as_url: &str,
    allow_plaintext: bool,
) -> Result<AsMetadata, AsMetadataError> {
    // Build the candidates in order.
    let candidates = build_candidates(as_url);

    // Try each candidate. 404 falls through; other statuses are terminal.
    for url in &candidates {
        let response = http
            .send(HttpRequest {
                method: "GET".to_owned(),
                url: url.clone(),
                headers: vec![("accept".to_owned(), "application/json".to_owned())],
                body: Vec::new(),
                purpose: FetchPurpose::AsMetadata,
                max_response_bytes: MAX_AS_METADATA_BYTES,
                redirects: RedirectPolicy::Max(5),
                allow_plaintext,
                timeout_ms: 10_000,
            })
            .await
            .map_err(|err| match err {
                HttpError::Refused => {
                    AsMetadataError::Fetch("refused by the adapter's policy".to_owned())
                }
                HttpError::Transport(detail) => AsMetadataError::Fetch(detail),
            })?;

        match response.status {
            200 => {
                // Parse the document.
                let metadata: AsMetadata = serde_json::from_slice(&response.body)
                    .map_err(|_| AsMetadataError::Fetch("not a JSON object".to_owned()))?;

                // Exact identity: `issuer` must equal the AS identifier.
                if metadata.issuer != as_url {
                    return Err(AsMetadataError::IdentityMismatch {
                        expected: as_url.to_owned(),
                        actual: metadata.issuer,
                    });
                }

                // A served document without a token endpoint is an error,
                // not a guess. Defence in depth: never guess when a
                // matching document was served.
                if metadata.token_endpoint.is_empty() {
                    return Err(AsMetadataError::NoTokenEndpoint);
                }

                return Ok(metadata);
            }
            404 => continue,
            status => return Err(AsMetadataError::Status(status)),
        }
    }

    // Every candidate 404'd: fall back to endpoint guessing.
    // The guessed form uses the trimmed issuer URL.
    let trimmed = as_url.trim_end_matches('/');
    let metadata = AsMetadata {
        issuer: as_url.to_owned(),
        token_endpoint: format!("{trimmed}/token"),
        authorization_endpoint: format!("{trimmed}/authorize"),
        par_endpoint: String::new(),
        require_par: false,
        token_endpoint_auth_methods: Vec::new(),
        challenge_endpoint: String::new(),
        code_challenge_methods: Some(vec!["S256".to_owned()]),
        grant_types: vec![
            "authorization_code".to_owned(),
            "pre-authorized_code".to_owned(),
        ],
    };
    Ok(metadata)
}

/// Builds the candidate URLs in order:
/// 1. RFC 8414 §3.1 insertion (with the trailing slash kept)
/// 2. RFC 8414 §3.1 insertion (with one terminating slash removed)
/// 3. OIDC discovery (with the trailing slash kept)
/// 4. OIDC discovery (with one terminating slash removed)
///
/// The 404-only fallback tries each in order; a candidate that differs only
/// by the slash is only tried when the first form 404'd.
fn build_candidates(as_url: &str) -> Vec<String> {
    let (scheme, rest) = as_url.split_once("://").unwrap_or(("https", as_url));
    let (host, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, ""),
    };

    let mut candidates = Vec::new();

    // RFC 8414 §3.1: insert between host and path. An issuer
    // identifier with a terminating slash keeps its path components —
    // the well-known path is the identifier's path with the
    // terminating slash REMOVED (the suite's RFC 8414-3.1 check
    // demands exactly that), so the trimmed form is tried first.
    let rfc8414 = format!("{scheme}://{host}/.well-known/oauth-authorization-server{path}");
    if let Some(trimmed) = rfc8414.strip_suffix('/') {
        if trimmed != rfc8414 {
            candidates.push(trimmed.to_owned());
        }
    }
    candidates.push(rfc8414.clone());

    // OIDC discovery: append to the full URL.
    let oidc = format!("{as_url}/.well-known/openid-configuration");
    candidates.push(oidc.clone());
    if let Some(trimmed) = oidc.strip_suffix('/') {
        if trimmed != oidc {
            candidates.push(trimmed.to_owned());
        }
    }

    // Deduplicate (the trailing-slash forms may coincide).
    candidates.dedup();
    candidates
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeHttp {
        body: Vec<u8>,
        status: u16,
        calls: std::sync::Mutex<Vec<String>>,
    }

    impl FakeHttp {
        fn ok(body: serde_json::Value) -> Self {
            Self {
                body: body.to_string().into_bytes(),
                status: 200,
                calls: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn not_found() -> Self {
            Self {
                body: Vec::new(),
                status: 404,
                calls: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl HttpClient for FakeHttp {
        async fn send(
            &self,
            request: HttpRequest,
        ) -> Result<engine_ports::HttpResponse, HttpError> {
            self.calls
                .lock()
                .map(|mut c| c.push(request.url.clone()))
                .ok();
            assert_eq!(request.purpose, FetchPurpose::AsMetadata);
            assert_eq!(request.max_response_bytes, MAX_AS_METADATA_BYTES);
            Ok(engine_ports::HttpResponse {
                status: self.status,
                headers: Vec::new(),
                body: self.body.clone(),
            })
        }
    }

    fn as_metadata_json(issuer: &str) -> serde_json::Value {
        serde_json::json!({
            "issuer": issuer,
            "token_endpoint": format!("{issuer}/token"),
            "authorization_endpoint": format!("{issuer}/authorize"),
        })
    }

    #[tokio::test]
    async fn resolves_the_rfc8414_form() {
        let http = FakeHttp::ok(as_metadata_json("https://as.example"));
        let metadata = discover_as_metadata(&http, "https://as.example", false)
            .await
            .expect("resolve");
        assert_eq!(metadata.issuer, "https://as.example");
        assert_eq!(metadata.token_endpoint, "https://as.example/token");
    }

    #[tokio::test]
    async fn refuses_an_issuer_mismatch() {
        let http = FakeHttp::ok(as_metadata_json("https://other.example"));
        let err = discover_as_metadata(&http, "https://as.example", false)
            .await
            .expect_err("mismatch refuses");
        assert!(matches!(
            err,
            AsMetadataError::IdentityMismatch { expected, actual }
                if expected == "https://as.example" && actual == "https://other.example"
        ));
    }

    #[tokio::test]
    async fn refuses_a_served_document_without_a_token_endpoint() {
        let http = FakeHttp::ok(serde_json::json!({
            "issuer": "https://as.example",
            // No token_endpoint.
        }));
        assert!(matches!(
            discover_as_metadata(&http, "https://as.example", false).await,
            Err(AsMetadataError::NoTokenEndpoint)
        ));
    }

    #[tokio::test]
    async fn guesses_endpoints_only_when_every_candidate_404s() {
        let http = FakeHttp::not_found();
        let metadata = discover_as_metadata(&http, "https://as.example", false)
            .await
            .expect("guessed");
        assert_eq!(metadata.token_endpoint, "https://as.example/token");
        assert_eq!(
            metadata.authorization_endpoint,
            "https://as.example/authorize"
        );
    }

    #[tokio::test]
    async fn a_5xx_is_terminal_not_a_fallback() {
        struct ServerError;
        #[async_trait::async_trait]
        impl HttpClient for ServerError {
            async fn send(&self, _r: HttpRequest) -> Result<engine_ports::HttpResponse, HttpError> {
                Ok(engine_ports::HttpResponse {
                    status: 500,
                    headers: Vec::new(),
                    body: Vec::new(),
                })
            }
        }
        assert!(matches!(
            discover_as_metadata(&ServerError, "https://as.example", false).await,
            Err(AsMetadataError::Status(500))
        ));
    }

    #[test]
    fn builds_candidates_in_order() {
        let candidates = build_candidates("https://as.example/path/");
        // The RFC 8414 path-insertion form comes first, with the
        // terminating slash removed (the RFC 8414-3.1 expectation);
        // the slash-kept form is the fallback. The OIDC discovery
        // form is appended after.
        assert_eq!(
            candidates[0],
            "https://as.example/.well-known/oauth-authorization-server/path"
        );
        assert!(candidates
            .iter()
            .any(|c| c == "https://as.example/.well-known/oauth-authorization-server/path/"));
        assert!(candidates
            .iter()
            .any(|c| c.contains("openid-configuration")));
    }
}
