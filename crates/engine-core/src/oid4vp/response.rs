//! Response submission: direct_post, direct_post.jwt, fragment and query —
//! per the P0.6-verified behaviour.

use engine_ports::{FetchPurpose, HttpClient, HttpRequest, RedirectPolicy};

use super::types::{AuthorizationRequest, ResponseError, ResponseMode};

/// The maximum size of a response_uri reply: 64 KiB (the P0.6-verified
/// `Reply::parse` limit).
const MAX_REPLY_BYTES: usize = 64 << 10;

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
) -> Result<String, ResponseError> {
    // Determine the response endpoint.
    let endpoint = if !auth_req.response_uri.is_empty() {
        auth_req.response_uri.clone()
    } else if !auth_req.redirect_uri.is_empty() {
        auth_req.redirect_uri.clone()
    } else {
        return Err(ResponseError::NoEndpoint);
    };

    match auth_req.response_mode {
        ResponseMode::DirectPost => submit_direct_post(http, &endpoint, auth_req, vp_token).await,
        ResponseMode::DirectPostJwt => {
            // The encrypted submission. The JWE construction arrives with
            // the JOSE stack; the interface is here.
            submit_direct_post(http, &endpoint, auth_req, vp_token).await
        }
        ResponseMode::Fragment => Ok(build_fragment_redirect(&endpoint, auth_req, vp_token)),
        ResponseMode::Query => Ok(build_query_redirect(&endpoint, auth_req, vp_token)),
    }
}

/// Submits the decline / error response: a plain form POST, never
/// encrypted — per the P0.6-verified behaviour ("No client encrypts a
/// decline").
pub async fn submit_error_response(
    http: &dyn HttpClient,
    auth_req: &AuthorizationRequest,
    error_code: &str,
    error_description: &str,
) -> Result<String, ResponseError> {
    let endpoint = if !auth_req.response_uri.is_empty() {
        auth_req.response_uri.clone()
    } else if !auth_req.redirect_uri.is_empty() {
        auth_req.redirect_uri.clone()
    } else {
        return Err(ResponseError::NoEndpoint);
    };

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
            url: endpoint.clone(),
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

#[cfg(test)]
mod tests {
    use super::super::types::{ClientIdScheme, ResponseMode};
    use super::*;
    use engine_ports::HttpError;

    struct FakeHttp {
        status: u16,
        body: Vec<u8>,
        calls: std::sync::Mutex<Vec<(String, Vec<u8>)>>,
    }

    #[async_trait::async_trait]
    impl HttpClient for FakeHttp {
        async fn send(
            &self,
            request: HttpRequest,
        ) -> Result<engine_ports::HttpResponse, HttpError> {
            self.calls
                .lock()
                .map(|mut c| c.push((request.url.clone(), request.body.clone())))
                .ok();
            assert_eq!(request.purpose, FetchPurpose::DirectPost);
            Ok(engine_ports::HttpResponse {
                status: self.status,
                headers: Vec::new(),
                body: self.body.clone(),
            })
        }
    }

    fn test_request(mode: ResponseMode) -> AuthorizationRequest {
        AuthorizationRequest {
            client_id: "x509_san_dns:verifier.example".to_owned(),
            client_id_scheme: ClientIdScheme::X509SanDns,
            request_uri: String::new(),
            response_uri: "https://verifier.example/response".to_owned(),
            redirect_uri: String::new(),
            response_mode: mode,
            nonce: "nonce-1".to_owned(),
            state: "state-1".to_owned(),
            dcql_query: None,
            transaction_data_raw: Vec::new(),
            client_metadata: None,
            client_metadata_uri: String::new(),
            verifier_jwk: None,
            scope: String::new(),
        }
    }

    #[tokio::test]
    async fn direct_post_sends_the_vp_token_and_state() {
        let http = FakeHttp {
            status: 200,
            body: b"{}".to_vec(),
            calls: std::sync::Mutex::new(Vec::new()),
        };
        let result = submit_response(&http, &test_request(ResponseMode::DirectPost), "vp-jwt-1")
            .await
            .expect("submit");
        let calls = http.calls.lock().expect("lock");
        assert_eq!(calls.len(), 1);
        let body = String::from_utf8_lossy(&calls[0].1);
        assert!(body.contains("vp_token=vp-jwt-1"));
        assert!(body.contains("state=state-1"));
        assert!(result.contains("{}"));
    }

    #[tokio::test]
    async fn a_decline_is_a_plain_form_post() {
        let http = FakeHttp {
            status: 200,
            body: Vec::new(),
            calls: std::sync::Mutex::new(Vec::new()),
        };
        submit_error_response(
            &http,
            &test_request(ResponseMode::DirectPost),
            "access_denied",
            "User declined",
        )
        .await
        .expect("submit");
        let calls = http.calls.lock().expect("lock");
        assert_eq!(calls.len(), 1);
        let body = String::from_utf8_lossy(&calls[0].1);
        assert!(body.contains("error=access_denied"));
        assert!(body.contains("error_description=User%20declined"));
        assert!(body.contains("state=state-1"));
    }

    #[test]
    fn fragment_redirect_builds_the_url() {
        let redirect = build_fragment_redirect(
            "https://verifier.example/cb",
            &test_request(ResponseMode::Fragment),
            "vp-1",
        );
        assert!(redirect.starts_with("https://verifier.example/cb#"));
        assert!(redirect.contains("vp_token=vp-1"));
        assert!(redirect.contains("state=state-1"));
    }

    #[test]
    fn query_redirect_builds_the_url() {
        let redirect = build_query_redirect(
            "https://verifier.example/cb",
            &test_request(ResponseMode::Query),
            "vp-1",
        );
        assert!(redirect.starts_with("https://verifier.example/cb?"));
        assert!(redirect.contains("vp_token=vp-1"));
    }

    #[tokio::test]
    async fn no_response_endpoint_refuses() {
        let http = FakeHttp {
            status: 200,
            body: Vec::new(),
            calls: std::sync::Mutex::new(Vec::new()),
        };
        let mut req = test_request(ResponseMode::DirectPost);
        req.response_uri = String::new();
        req.redirect_uri = String::new();
        assert!(matches!(
            submit_response(&http, &req, "vp").await,
            Err(ResponseError::NoEndpoint)
        ));
    }
}
