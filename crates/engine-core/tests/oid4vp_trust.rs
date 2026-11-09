//! The verifier trust (OpenID4VP 1.0 §5): the domain, the PDP evaluation,
//! the client metadata, the §5 validations, and the typed refusal data.

use engine_core::oid4vp::trust::{
    build_verifier_info, evaluate_verifier_trust, extract_domain, fetch_client_metadata,
    resolve_client_metadata, untrusted_verifier_data, validate_client_id_match,
    validate_response_uri_origin, TrustError,
};
use engine_core::oid4vp::types::{AuthorizationRequest, ClientIdScheme, ResponseMode};
use engine_ports::{EvaluationRequest, FetchPurpose, HttpClient, HttpRequest, Pdp, PdpError};
use serde_json::json;

/// The metadata fetch limit of docs/engine-spec.md §Ports.
const METADATA_LIMIT: usize = 1024 * 1024;

struct FakePdp {
    trusted: bool,
    reason: Option<String>,
    unreachable: bool,
    subjects: std::sync::Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl Pdp for FakePdp {
    async fn evaluate(
        &self,
        request: EvaluationRequest,
    ) -> Result<engine_ports::EvaluationResponse, PdpError> {
        if self.unreachable {
            return Err(PdpError::Unreachable);
        }
        self.subjects
            .lock()
            .map(|mut s| s.push(request.subject.clone()))
            .ok();
        Ok(engine_ports::EvaluationResponse {
            trusted: self.trusted,
            decision: self.reason.clone(),
        })
    }

    async fn resolve(
        &self,
        _request: engine_ports::ResolveRequest,
    ) -> Result<engine_ports::ResolveResponse, PdpError> {
        Err(PdpError::NotImplemented)
    }
}

struct FakeHttp {
    status: u16,
    body: Vec<u8>,
}

#[async_trait::async_trait]
impl HttpClient for FakeHttp {
    async fn send(
        &self,
        request: HttpRequest,
    ) -> Result<engine_ports::HttpResponse, engine_ports::HttpError> {
        assert_eq!(request.purpose, FetchPurpose::ClientMetadata);
        assert_eq!(request.max_response_bytes, METADATA_LIMIT);
        Ok(engine_ports::HttpResponse {
            status: self.status,
            headers: Vec::new(),
            body: self.body.clone(),
        })
    }
}

fn test_request(client_id: &str) -> AuthorizationRequest {
    let scheme = ClientIdScheme::infer(client_id);
    AuthorizationRequest {
        client_id: client_id.to_owned(),
        client_id_scheme: scheme,
        request_uri: String::new(),
        response_uri: "https://verifier.example/response".to_owned(),
        redirect_uri: String::new(),
        response_mode: ResponseMode::DirectPost,
        nonce: "nonce-1".to_owned(),
        state: String::new(),
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
        expected_origins: Vec::new(),
    }
}

#[test]
fn the_domain_is_extracted_per_scheme() {
    assert_eq!(
        extract_domain("x509_san_dns:verifier.example"),
        "verifier.example"
    );
    assert_eq!(
        extract_domain("https://verifier.example/cb"),
        "verifier.example"
    );
    assert_eq!(
        extract_domain("did:web:verifier.example"),
        "did:web:verifier.example"
    );
}

#[tokio::test]
async fn a_trusted_verifier_passes_the_pdp() {
    let pdp = FakePdp {
        trusted: true,
        reason: Some("in the registry".to_owned()),
        unreachable: false,
        subjects: std::sync::Mutex::new(Vec::new()),
    };
    let auth_req = test_request("x509_san_dns:verifier.example");
    let mut verifier = build_verifier_info(&auth_req, None);
    evaluate_verifier_trust(&pdp, &auth_req, None, &mut verifier)
        .await
        .expect("trusted");
    assert!(verifier.trusted);
    assert_eq!(verifier.name, "x509_san_dns:verifier.example");
    assert_eq!(verifier.domain, "verifier.example");
    // The PDP saw the full client_id, prefix and all.
    let subjects = pdp.subjects.lock().expect("lock");
    assert_eq!(subjects[0], "x509_san_dns:verifier.example");
}

#[tokio::test]
async fn an_untrusted_verifier_refuses_with_the_reason() {
    let pdp = FakePdp {
        trusted: false,
        reason: Some("not in registry".to_owned()),
        unreachable: false,
        subjects: std::sync::Mutex::new(Vec::new()),
    };
    let auth_req = test_request("x509_san_dns:verifier.example");
    let mut verifier = build_verifier_info(&auth_req, None);
    let err = evaluate_verifier_trust(&pdp, &auth_req, None, &mut verifier)
        .await
        .expect_err("untrusted");
    assert!(matches!(err, TrustError::Untrusted { .. }));
}

#[tokio::test]
async fn a_pdp_error_fails_closed() {
    let pdp = FakePdp {
        trusted: true,
        reason: None,
        unreachable: true,
        subjects: std::sync::Mutex::new(Vec::new()),
    };
    let auth_req = test_request("x509_san_dns:verifier.example");
    let mut verifier = build_verifier_info(&auth_req, None);
    assert!(matches!(
        evaluate_verifier_trust(&pdp, &auth_req, None, &mut verifier).await,
        Err(TrustError::PdpUnreachable)
    ));
}

#[tokio::test]
async fn the_client_metadata_is_fetched_bounded_and_raw_preserved() {
    let http = FakeHttp {
        status: 200,
        body: json!({
            "client_name": "Verifier AB",
            "logo_uri": "https://verifier.example/logo.png",
            "jwks": { "keys": [] },
            "extra": "preserved"
        })
        .to_string()
        .into_bytes(),
    };
    let metadata = fetch_client_metadata(&http, "https://verifier.example/metadata")
        .await
        .expect("fetch");
    assert_eq!(metadata.client_name, "Verifier AB");
    assert_eq!(metadata.logo_uri, "https://verifier.example/logo.png");
    // The raw document is preserved, unknown members and all.
    assert_eq!(metadata.raw["extra"], "preserved");
}

#[tokio::test]
async fn a_failed_metadata_fetch_continues_without_metadata() {
    let http = FakeHttp {
        status: 500,
        body: Vec::new(),
    };
    let mut auth_req = test_request("x509_san_dns:verifier.example");
    auth_req.client_metadata_uri = "https://verifier.example/metadata".to_owned();
    assert!(resolve_client_metadata(&http, &auth_req).await.is_none());
    // The verifier info falls back to the client_id as the name.
    let verifier = build_verifier_info(&auth_req, None);
    assert_eq!(verifier.name, "x509_san_dns:verifier.example");
}

#[test]
fn the_client_id_match_is_checked_against_the_request_uri() {
    let auth_req = test_request("x509_san_dns:verifier.example");
    let matching = "https://verifier.example/request?client_id=x509_san_dns%3Averifier.example";
    assert!(validate_client_id_match(&auth_req, matching).is_ok());
    let mismatching = "https://verifier.example/request?client_id=x509_san_dns%3Asomeone-else";
    assert!(validate_client_id_match(&auth_req, mismatching).is_err());
    // No client_id in the URL: nothing to check.
    assert!(validate_client_id_match(&auth_req, "https://verifier.example/request").is_ok());
}

#[test]
fn the_response_uri_origin_is_checked_for_x509_san_dns_only() {
    let auth_req = test_request("x509_san_dns:verifier.example");
    let same = "https://verifier.example/request.jwt";
    assert!(validate_response_uri_origin(&auth_req, same).is_ok());
    let other = "https://requests.example/request.jwt";
    assert!(validate_response_uri_origin(&auth_req, other).is_err());

    // The other schemes are out of the check's scope (§5).
    let did_req = test_request("did:web:verifier.example");
    assert!(validate_response_uri_origin(&did_req, "https://other.example/r.jwt").is_ok());
}

#[test]
fn the_custom_schemes_resolve_to_their_request_uri() {
    let auth_req = test_request("x509_san_dns:verifier.example");
    let via_scheme = "openid4vp://?request_uri=https%3A%2F%2Fverifier.example%2Frequest.jwt";
    assert!(validate_response_uri_origin(&auth_req, via_scheme).is_ok());
    let via_scheme_other = "haip://?request_uri=https%3A%2F%2Fother.example%2Frequest.jwt";
    assert!(validate_response_uri_origin(&auth_req, via_scheme_other).is_err());
}

#[test]
fn a_non_url_request_uri_skips_the_origin_check() {
    let auth_req = test_request("x509_san_dns:verifier.example");
    // A raw query string: not a proper URL, no origin to compare.
    assert!(validate_response_uri_origin(&auth_req, "client_id=x&nonce=y").is_ok());
}

#[test]
fn the_untrusted_verifier_data_carries_the_class_reason_and_detail() {
    let data = untrusted_verifier_data("x509_san_dns:verifier.example", "not in registry");
    assert_eq!(
        data.get("reason").and_then(serde_json::Value::as_str),
        Some("untrusted_verifier")
    );
    assert_eq!(
        data.get("verifier").and_then(serde_json::Value::as_str),
        Some("x509_san_dns:verifier.example")
    );
    assert_eq!(
        data.get("detail").and_then(serde_json::Value::as_str),
        Some("not in registry")
    );
    assert_eq!(
        data.get("retryable").and_then(serde_json::Value::as_bool),
        Some(false),
        "an untrusted verdict is never retryable: the wallet never re-asks"
    );
}
