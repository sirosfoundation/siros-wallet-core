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
