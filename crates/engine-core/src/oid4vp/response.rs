//! Response submission: direct_post, direct_post.jwt, fragment and query —
//! per the P0.6-verified behaviour.

use engine_ports::{FetchPurpose, HttpClient, HttpRequest, RedirectPolicy};

use super::types::{AuthorizationRequest, ResponseError, ResponseMode};

/// The maximum size of a response_uri reply: 64 KiB (the P0.6-verified
/// `Reply::parse` limit).
pub(crate) const MAX_REPLY_BYTES: usize = 64 << 10;

/// Submits the VP response to the verifier's endpoint, per the request's
/// response mode.
///
/// The P0.6-verified behaviour:
/// - `direct_post`: a plain `application/x-www-form-urlencoded` POST with
///   `vp_token` and `state` to the response URI.
/// - `direct_post.jwt`: a JWE-encrypted JWT POST; the verifier is NOT
///   contacted for most errors (transaction data, encryption contract) —
///   the verifier times out.
/// - `fragment`: a redirect with the response in the fragment.
/// - `query`: a redirect with the response in the query string.
pub async fn submit_response(
    http: &dyn HttpClient,
    auth_req: &AuthorizationRequest,
    vp_token: &str,
    now_unix: i64,
) -> Result<String, ResponseError> {
    // Determine the response endpoint.
    let endpoint = if !auth_req.response_uri.is_empty() {
        auth_req.response_uri.clone()
    } else if !auth_req.redirect_uri.is_empty() {
        auth_req.redirect_uri.clone()
    } else {
        return Err(ResponseError::NoEndpoint);
    };

    // The endpoint sanitization: the request names where the wallet
    // POSTs the presentation, and only http/https URLs are posted to —
    // anything else (another scheme, a malformed URL) is refused before
    // the transport. The Go engine's sanitizeEndpointURL.
    let scheme = endpoint
        .split_once(':')
        .map(|(scheme, _)| scheme)
        .unwrap_or_default()
        .to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(ResponseError::InvalidEndpoint(endpoint.clone()));
    }

    match auth_req.response_mode {
        ResponseMode::DirectPost => submit_direct_post(http, &endpoint, auth_req, vp_token).await,
        ResponseMode::DirectPostJwt => {
            // The encrypted submission (JARM): the claims JWE-encrypted
            // to the verifier's usable key, POSTed as response=<jwe>.
            // The Clock port supplies `now_unix` — the core never reads
            // a clock itself. Unusable jwks entries are skipped at the
            // key selection (RFC 7517 §5); an encryption contract no
            // key can meet is not sent (the verifier times out).
            super::jarm::submit_jarm_response(http, auth_req, vp_token, None, now_unix).await
        }
        ResponseMode::Fragment => Ok(build_fragment_redirect(&endpoint, auth_req, vp_token)),
        ResponseMode::Query => Ok(build_query_redirect(&endpoint, auth_req, vp_token)),
        // The Digital Credentials API channel never submits over HTTP:
        // the flow hands the response to the host (OpenID4VP 1.0
        // §8.4). Reaching this arm is an internal routing fault.
        ResponseMode::DcApi | ResponseMode::DcApiJwt => Err(ResponseError::NoEndpoint),
    }
}

/// Submits the decline / error response (#441: the mode's shape):
///
/// - **`direct_post.jwt`**: the error as a JARM response — the error
///   claims (`iss`, `aud`, `exp`, `error`, `error_description`,
///   `state`) encrypted with the same key selection the success path
///   uses, POSTed as `response=<jwe>`. A plain form would be rejected
///   by the mode's verifier, so its session would never end.
/// - **`query` / `fragment`**: the error redirect — the error
///   parameters in the URL's query or fragment.
/// - **`direct_post`** (and the default): the plain form POST — the
///   mode's own shape.
pub async fn submit_error_response(
    http: &dyn HttpClient,
    auth_req: &AuthorizationRequest,
    error_code: &str,
    error_description: &str,
    now_unix: i64,
) -> Result<String, ResponseError> {
    let endpoint = if !auth_req.response_uri.is_empty() {
        auth_req.response_uri.clone()
    } else if !auth_req.redirect_uri.is_empty() {
        auth_req.redirect_uri.clone()
    } else {
        return Err(ResponseError::NoEndpoint);
    };

    // The response mode dispatch: the error answer rides the mode's
    // shape, exactly as the success answer does.
    match auth_req.response_mode {
        ResponseMode::DirectPostJwt => {
            super::jarm::submit_jarm_error_response(
                http,
                auth_req,
                error_code,
                error_description,
                now_unix,
            )
            .await
        }
        ResponseMode::Query => Ok(build_error_redirect(
            &endpoint,
            auth_req,
            error_code,
            error_description,
            '?',
        )),
        ResponseMode::Fragment => Ok(build_error_redirect(
            &endpoint,
            auth_req,
            error_code,
            error_description,
            '#',
        )),
        ResponseMode::DirectPost => {
            submit_plain_error(http, &endpoint, auth_req, error_code, error_description).await
        }
        // The Digital Credentials API channel never submits over HTTP
        // (OpenID4VP 1.0 §8.4) — the decline reaches the verifier
        // through the browser API, the host's business.
        ResponseMode::DcApi | ResponseMode::DcApiJwt => Err(ResponseError::NoEndpoint),
    }
}

/// The plain-form error POST: `error`, `error_description`, `state` —
/// the direct_post mode's error shape.
async fn submit_plain_error(
    http: &dyn HttpClient,
    endpoint: &str,
    auth_req: &AuthorizationRequest,
    error_code: &str,
    error_description: &str,
) -> Result<String, ResponseError> {
    let mut form = format!("error={}", url_encode(error_code));
    if !error_description.is_empty() {
        form.push_str(&format!(
            "&error_description={}",
            url_encode(error_description)
        ));
    }
    if !auth_req.state.is_empty() {
        form.push_str(&format!("&state={}", url_encode(&auth_req.state)));
    }

    let response = http
        .send(HttpRequest {
            method: "POST".to_owned(),
            url: endpoint.to_owned(),
            headers: vec![(
                "content-type".to_owned(),
                "application/x-www-form-urlencoded".to_owned(),
            )],
            body: form.into_bytes(),
            purpose: FetchPurpose::DirectPost,
            max_response_bytes: MAX_REPLY_BYTES,
            redirects: RedirectPolicy::None,
            allow_plaintext: false,
            timeout_ms: 10_000,
        })
        .await
        .map_err(|err| ResponseError::Fetch(err.to_string()))?;

    Ok(String::from_utf8_lossy(&response.body).into_owned())
}

/// The error redirect for the `query`/`fragment` modes: the error
/// parameters in the URL's query (`?`) or fragment (`#`) — the Go
/// engine's `buildErrorRedirect`.
fn build_error_redirect(
    endpoint: &str,
    auth_req: &AuthorizationRequest,
    error_code: &str,
    error_description: &str,
    separator: char,
) -> String {
    let mut params = format!("error={}", url_encode(error_code));
    if !error_description.is_empty() {
        params.push_str(&format!(
            "&error_description={}",
            url_encode(error_description)
        ));
    }
    if !auth_req.state.is_empty() {
        params.push_str(&format!("&state={}", url_encode(&auth_req.state)));
    }
    format!("{endpoint}{separator}{params}")
}

/// The `direct_post` submission: a plain form POST with `vp_token` and
/// `state`.
async fn submit_direct_post(
    http: &dyn HttpClient,
    endpoint: &str,
    auth_req: &AuthorizationRequest,
    vp_token: &str,
) -> Result<String, ResponseError> {
    let mut form = format!("vp_token={}", url_encode(vp_token));
    if !auth_req.state.is_empty() {
        form.push_str(&format!("&state={}", url_encode(&auth_req.state)));
    }

    let response = http
        .send(HttpRequest {
            method: "POST".to_owned(),
            url: endpoint.to_owned(),
            headers: vec![(
                "content-type".to_owned(),
                "application/x-www-form-urlencoded".to_owned(),
            )],
            body: form.into_bytes(),
            purpose: FetchPurpose::DirectPost,
            max_response_bytes: MAX_REPLY_BYTES,
            redirects: RedirectPolicy::None,
            allow_plaintext: false,
            timeout_ms: 10_000,
        })
        .await
        .map_err(|err| ResponseError::Fetch(err.to_string()))?;

    if response.status != 200 {
        return Err(ResponseError::Fetch(format!(
            "response_uri answered {}",
            response.status
        )));
    }

    Ok(String::from_utf8_lossy(&response.body).into_owned())
}

/// The `fragment` redirect: the response in the URL fragment.
fn build_fragment_redirect(
    endpoint: &str,
    auth_req: &AuthorizationRequest,
    vp_token: &str,
) -> String {
    let mut redirect = format!("{}#vp_token={}", endpoint, url_encode(vp_token));
    if !auth_req.state.is_empty() {
        redirect.push_str(&format!("&state={}", url_encode(&auth_req.state)));
    }
    redirect
}

/// The `query` redirect: the response in the query string.
fn build_query_redirect(endpoint: &str, auth_req: &AuthorizationRequest, vp_token: &str) -> String {
    let separator = if endpoint.contains('?') { "&" } else { "?" };
    let mut redirect = format!("{}{}vp_token={}", endpoint, separator, url_encode(vp_token));
    if !auth_req.state.is_empty() {
        redirect.push_str(&format!("&state={}", url_encode(&auth_req.state)));
    }
    redirect
}

/// Minimal URL form-encoding.
pub(super) fn url_encode(s: &str) -> String {
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
