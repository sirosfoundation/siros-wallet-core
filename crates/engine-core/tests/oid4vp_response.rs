//! The response submission per response mode (OpenID4VP 1.0 §8): the
//! success answer and the error answer.

use engine_core::oid4vp::response::{submit_error_response, submit_response};
use engine_core::oid4vp::types::{
    AuthorizationRequest, ClientIdScheme, ResponseError, ResponseMode,
};
use engine_ports::{FetchPurpose, HttpClient, HttpError, HttpRequest};
struct FakeHttp {
    status: u16,
    body: Vec<u8>,
    calls: std::sync::Mutex<Vec<(String, Vec<u8>)>>,
}

#[async_trait::async_trait]
impl HttpClient for FakeHttp {
    async fn send(&self, request: HttpRequest) -> Result<engine_ports::HttpResponse, HttpError> {
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
        // The trust evaluation's inputs: the tests carry no
        // signed request object.
        request_jwt: None,
        x5c: None,
        attestation_jwt: None,
    }
}

#[tokio::test]
async fn direct_post_sends_the_vp_token_and_state() {
    let http = FakeHttp {
        status: 200,
        body: b"{}".to_vec(),
        calls: std::sync::Mutex::new(Vec::new()),
    };
    let result = submit_response(
        &http,
        &test_request(ResponseMode::DirectPost),
        "vp-jwt-1",
        0,
    )
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
        1_000,
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

/// A request whose only endpoint is the given redirect_uri.
fn redirect_request(mode: ResponseMode) -> AuthorizationRequest {
    let mut request = test_request(mode);
    request.response_uri = String::new();
    request.redirect_uri = "https://verifier.example/cb".to_owned();
    request
}

#[tokio::test]
async fn fragment_redirect_builds_the_url() {
    let http = FakeHttp {
        status: 200,
        body: Vec::new(),
        calls: std::sync::Mutex::new(Vec::new()),
    };
    let redirect = submit_response(&http, &redirect_request(ResponseMode::Fragment), "vp-1", 0)
        .await
        .expect("the redirect builds");
    assert!(redirect.starts_with("https://verifier.example/cb#"));
    assert!(redirect.contains("vp_token=vp-1"));
    assert!(redirect.contains("state=state-1"));
}

#[tokio::test]
async fn query_redirect_builds_the_url() {
    let http = FakeHttp {
        status: 200,
        body: Vec::new(),
        calls: std::sync::Mutex::new(Vec::new()),
    };
    let redirect = submit_response(&http, &redirect_request(ResponseMode::Query), "vp-1", 0)
        .await
        .expect("the redirect builds");
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
        submit_response(&http, &req, "vp", 0).await,
        Err(ResponseError::NoEndpoint)
    ));
}

// ─── #441: the mode-dispatched error responses ───────────────────────────

#[tokio::test]
async fn a_direct_post_jwt_error_rides_the_response_parameter_as_jarm() {
    // The mode's only acceptable error shape: the error claims,
    // JARM-encrypted to the verifier's key, in response=<jwe>.
    // A plain form would be rejected, so the verifier's session
    // would never end.
    let http = FakeHttp {
        status: 200,
        body: Vec::new(),
        calls: std::sync::Mutex::new(Vec::new()),
    };
    let mut request = test_request(ResponseMode::DirectPostJwt);
    // The verifier's encryption key, in the metadata the JARM path
    // selects from.
    request.client_metadata = Some(serde_json::json!({
        "jwks": {"keys": [serde_json::json!({
            "kty": "EC", "crv": "P-256",
            "x": "ktT77AqMntawPyU772lBg8nd7cwENrYyOL_KWbYN8Jc",
            "y": "67lPXEq5gJdimDYD0AacxLfRfIm2-fSNd3HBqyXXvBI",
            "use": "enc", "alg": "ECDH-ES",
        })]},
        "authorization_encrypted_response_alg": "ECDH-ES",
        "authorization_encrypted_response_enc": "A128GCM",
    }));
    submit_error_response(
        &http,
        &request,
        "access_denied",
        "The wallet did not fulfil the request",
        1_000,
    )
    .await
    .expect("the JARM error submits");
    let calls = http.calls.lock().expect("lock");
    assert_eq!(calls.len(), 1);
    let body = String::from_utf8_lossy(&calls[0].1);
    assert!(
        body.starts_with("response="),
        "the error rides the response parameter: {body}"
    );
    assert!(
        !body.contains("error=access_denied"),
        "the error parameters ride INSIDE the JWE, not as plain form: {body}"
    );
}

#[tokio::test]
async fn a_query_error_is_a_redirect_with_the_query_parameters() {
    let http = FakeHttp {
        status: 200,
        body: Vec::new(),
        calls: std::sync::Mutex::new(Vec::new()),
    };
    let redirect = submit_error_response(
        &http,
        &test_request(ResponseMode::Query),
        "access_denied",
        "The wallet did not fulfil the request",
        1_000,
    )
    .await
    .expect("the redirect builds");
    assert!(redirect.starts_with("https://verifier.example/response?"));
    assert!(redirect.contains("error=access_denied"));
    assert!(redirect.contains("state=state-1"));
    // No POST: the redirect carries the answer.
    let calls = http.calls.lock().expect("lock");
    assert!(calls.is_empty(), "the query mode redirects: {calls:?}");
}

#[tokio::test]
async fn a_fragment_error_is_a_redirect_with_the_fragment_parameters() {
    let http = FakeHttp {
        status: 200,
        body: Vec::new(),
        calls: std::sync::Mutex::new(Vec::new()),
    };
    let redirect = submit_error_response(
        &http,
        &test_request(ResponseMode::Fragment),
        "access_denied",
        "The wallet did not fulfil the request",
        1_000,
    )
    .await
    .expect("the redirect builds");
    assert!(redirect.contains('#'), "the fragment separator: {redirect}");
    assert!(redirect.contains("error=access_denied"));
    let calls = http.calls.lock().expect("lock");
    assert!(calls.is_empty());
}
