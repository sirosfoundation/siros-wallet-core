//! The request parsing (OpenID4VP 1.0 §5): by value, by reference, the
//! client_id schemes, and the signed request object.

use engine_core::oid4vp::request::parse_request;
use engine_core::oid4vp::types::{ClientIdScheme, RequestError, ResponseMode};
use engine_ports::{FetchPurpose, HttpClient, HttpError, HttpRequest};
struct FakeHttp {
    body: Vec<u8>,
    status: u16,
}

#[async_trait::async_trait]
impl HttpClient for FakeHttp {
    async fn send(&self, request: HttpRequest) -> Result<engine_ports::HttpResponse, HttpError> {
        assert_eq!(request.purpose, FetchPurpose::RequestObject);
        assert_eq!(request.max_response_bytes, 256 << 10);
        Ok(engine_ports::HttpResponse {
            status: self.status,
            headers: Vec::new(),
            body: self.body.clone(),
        })
    }
}

/// The plain-params parse fixture: the redirect_uri scheme — the
/// x509_san_dns scheme now requires the signed request form (§5),
/// which a plain JSON object cannot carry.
fn request_json() -> serde_json::Value {
    serde_json::json!({
        "client_id": "https://verifier.example",
        "nonce": "nonce-1",
        "response_uri": "https://verifier.example/response",
        "response_mode": "direct_post",
        "state": "state-1",
        "dcql_query": {"credentials": []}
    })
}

#[tokio::test]
async fn parses_a_request_by_value() {
    let http = FakeHttp {
        body: Vec::new(),
        status: 200,
    };
    let request = parse_request(&http, &request_json()).await.expect("parse");
    assert_eq!(request.client_id, "https://verifier.example");
    assert_eq!(request.client_id_scheme, ClientIdScheme::RedirectUri);
    assert_eq!(request.nonce, "nonce-1");
    assert_eq!(request.response_mode, ResponseMode::DirectPost);
    assert!(request.dcql_query.is_some());
}

#[tokio::test]
async fn refuses_a_missing_nonce() {
    let http = FakeHttp {
        body: Vec::new(),
        status: 200,
    };
    let bad = serde_json::json!({
        "client_id": "https://verifier.example",
        "response_uri": "https://verifier.example/response"
    });
    assert!(matches!(
        parse_request(&http, &bad).await,
        Err(RequestError::NonceRequired)
    ));
}

#[tokio::test]
async fn refuses_a_scheme_mismatch() {
    let http = FakeHttp {
        body: Vec::new(),
        status: 200,
    };
    let bad = serde_json::json!({
        "client_id": "x509_san_dns:verifier.example",
        "client_id_scheme": "decentralized_identifier",
        "nonce": "n",
        "response_uri": "https://v.example/r"
    });
    assert!(matches!(
        parse_request(&http, &bad).await,
        Err(RequestError::SchemeMismatch { .. })
    ));
}

#[tokio::test]
async fn parses_a_request_by_reference() {
    let body = serde_json::to_string(&request_json()).expect("serialize");
    let http = FakeHttp {
        body: body.into_bytes(),
        status: 200,
    };
    let params = serde_json::json!({
        "request_uri": "https://verifier.example/request.jwt"
    });
    let request = parse_request(&http, &params).await.expect("parse");
    assert_eq!(request.client_id, "https://verifier.example");
}

#[tokio::test]
async fn the_did_scheme_is_inferred_from_the_prefix() {
    let http = FakeHttp {
        body: Vec::new(),
        status: 200,
    };
    let req = serde_json::json!({
        "client_id": "did:web:verifier.example",
        "nonce": "n",
        "response_uri": "https://v.example/r"
    });
    let request = parse_request(&http, &req).await.expect("parse");
    assert_eq!(
        request.client_id_scheme,
        ClientIdScheme::DecentralizedIdentifier
    );
}

#[tokio::test]
async fn the_default_response_mode_is_direct_post() {
    let http = FakeHttp {
        body: Vec::new(),
        status: 200,
    };
    let req = serde_json::json!({
        "client_id": "https://verifier.example",
        "nonce": "n",
        "response_uri": "https://v.example/r"
    });
    let request = parse_request(&http, &req).await.expect("parse");
    assert_eq!(request.response_mode, ResponseMode::DirectPost);
}

#[tokio::test]
async fn an_unknown_client_id_scheme_refuses() {
    let http = FakeHttp {
        body: Vec::new(),
        status: 200,
    };
    let req = serde_json::json!({
        "client_id": "x509_san_bogus:verifier.example",
        "nonce": "n",
        "response_uri": "https://v.example/r"
    });
    assert!(matches!(
        parse_request(&http, &req).await,
        Err(RequestError::UnknownClientIdScheme)
    ));
}

#[tokio::test]
async fn direct_post_without_a_response_uri_refuses() {
    let http = FakeHttp {
        body: Vec::new(),
        status: 200,
    };
    let req = serde_json::json!({
        "client_id": "x509_san_dns:verifier.example",
        "nonce": "n",
        "response_mode": "direct_post",
        "redirect_uri": "https://v.example/cb"
    });
    assert!(matches!(
        parse_request(&http, &req).await,
        Err(RequestError::DirectPostWithoutResponseUri { .. })
    ));
}

/// A compact-serialization JWT with the given header, for the
/// request-object checks: the signature is irrelevant bytes.
fn request_object_jwt(header: &serde_json::Value) -> String {
    let header_text = jose_rs::base64url::encode(header.to_string().as_bytes());
    let payload_text = jose_rs::base64url::encode(request_json().to_string().as_bytes());
    format!("{header_text}.{payload_text}.c2ln")
}

#[tokio::test]
async fn a_signed_request_object_without_the_oauth_typ_refuses() {
    let http = FakeHttp {
        body: Vec::new(),
        status: 200,
    };
    let params = serde_json::json!({
        "request": request_object_jwt(&serde_json::json!({
            "alg": "ES256",
            "typ": "jwt"
        }))
    });
    assert!(matches!(
        parse_request(&http, &params).await,
        Err(RequestError::RequestObjectTyp)
    ));
}

#[tokio::test]
async fn a_signed_request_object_with_a_missing_typ_refuses() {
    let http = FakeHttp {
        body: Vec::new(),
        status: 200,
    };
    let params = serde_json::json!({
        "request": request_object_jwt(&serde_json::json!({
            "alg": "ES256"
        }))
    });
    assert!(matches!(
        parse_request(&http, &params).await,
        Err(RequestError::RequestObjectTyp)
    ));
}

// ─── The x509_hash client_id scheme (OpenID4VP 1.0 §5.2.3) ─────────────
//
// The verifier's private JWK and certificate, from the conformance
// suite's own wallet test configuration (siros-conformance,
// configs/conformance/vp-wallet-config.json) — the key the suite's
// request objects are signed with, and the certificate its x5c
// chains carry.
fn verifier_jwk() -> serde_json::Value {
    serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "HPtEYEEQNGcOGGtQXnm8VbbryWYOF7dlmTKcDwIxk60",
        "y": "Knv02968XSiEmNSoGPaHX3LXl-boQztsK0DB46VhE68",
        "d": "Z8iB5ltQ0Yf8Wyyafbmypw49VKegZLn2BBjzFzhMHGU",
        "kid": "vp-verifier-key-1",
        "use": "sig",
        "alg": "ES256",
        "x5c": [
            "MIIBvjCCAWOgAwIBAgIUfw4in2xbbaO4BRVzCMJ9jcx+MYUwCgYIKoZIzj0EAwIwIjEgMB4GA1UEAwwXY29uZm9ybWFuY2UuZXhhbXBsZS5jb20wHhcNMjYwNTE1MDc1MzQ1WhcNMjcwNTE1MDc1MzQ1WjAiMSAwHgYDVQQDDBdjb25mb3JtYW5jZS5leGFtcGxlLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBz7RGBBEDRnDhhrUF55vFW268lmDhe3ZZkynA8CMZOtKnv02968XSiEmNSoGPaHX3LXl+boQztsK0DB46VhE6+jdzB1MB0GA1UdDgQWBBR/zA7h3+ikKBoa3jyMiSX7sFdkyzAfBgNVHSMEGDAWgBR/zA7h3+ikKBoa3jyMiSX7sFdkyzAPBgNVHRMBAf8EBTADAQH/MCIGA1UdEQQbMBmCF2NvbmZvcm1hbmNlLmV4YW1wbGUuY29tMAoGCCqGSM49BAMCA0kAMEYCIQC4lhxwiQy3+GPtzdQW9IlDSrQoEnncom6YsKZ3izHuIgIhAKZIjNYWTG0xIpFrS4DVkvo1qiV9kNf1Qvp8StOW6pEr"
        ]
    })
}

/// The base64url SHA-256 over the verifier's certificate — the
/// client_id value the scheme carries.
fn verifier_hash() -> String {
    let jwk = verifier_jwk();
    let cert = jwk["x5c"][0].as_str().unwrap_or_default();
    // The x5c entry is padded base64 (RFC 7515 §4.1.6): the URL-safe
    // alphabet decodes it once mapped.
    let url_safe: String = cert
        .trim_end_matches('=')
        .chars()
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            c => c,
        })
        .collect();
    let der = jose_rs::base64url::decode(&url_safe).expect("the certificate decodes");
    let digest =
        kryptering::digest::digest(kryptering::HashAlgorithm::Sha256, &der).expect("sha256");
    wmp_core::token::base64url_unpadded(&digest)
}

/// A signed request object for the `x509_hash` scheme: the JWS header
/// carries the verifier's `x5c` chain, the payload the given
/// `client_id`, signed with the verifier's key.
fn x509_hash_request_object(client_id: &str) -> String {
    let jwk: jose_rs::jwk::Jwk =
        serde_json::from_value(verifier_jwk()).expect("the verifier JWK parses");
    let mut header = jose_rs::header::JoseHeader::new("ES256");
    header.typ = Some("oauth-authz-req+jwt".to_owned());
    header.kid = Some("vp-verifier-key-1".to_owned());
    header.x5c = Some(vec![verifier_jwk()["x5c"][0]
        .as_str()
        .unwrap_or_default()
        .to_owned()]);
    let payload = serde_json::json!({
        "client_id": client_id,
        "nonce": "nonce-1",
        "response_uri": "https://verifier.example/response",
        "response_mode": "direct_post"
    });
    let payload_bytes = payload.to_string().into_bytes();
    // The x5c chain is a key-reference member (RFC 7515 §4.1.6): the
    // deliberate reference the opt-in is for — the scheme's chain
    // rides the header.
    let mut options = jose_rs::jws::compact::SignOptions::default();
    options.allow_key_reference_headers = true;
    jose_rs::jws::compact::sign_with_jwk_options(&jwk, &payload_bytes, &header, &options)
        .expect("the request object signs")
}

#[tokio::test]
async fn an_x509_hash_request_with_a_matching_hash_parses() {
    let http = FakeHttp {
        body: Vec::new(),
        status: 200,
    };
    let client_id = format!("x509_hash:{}", verifier_hash());
    let params = serde_json::json!({
        "request": x509_hash_request_object(&client_id)
    });
    let request = parse_request(&http, &params).await.expect("parse");
    assert_eq!(request.client_id, client_id);
    assert_eq!(request.client_id_scheme, ClientIdScheme::X509Hash);
}

#[tokio::test]
async fn an_x509_hash_request_with_a_mismatched_hash_refuses() {
    let http = FakeHttp {
        body: Vec::new(),
        status: 200,
    };
    // The hash of something else: a valid base64url shape, not the
    // certificate's.
    let client_id = format!("x509_hash:{}", "A".repeat(43));
    let params = serde_json::json!({
        "request": x509_hash_request_object(&client_id)
    });
    assert!(matches!(
        parse_request(&http, &params).await,
        Err(RequestError::ClientIdHashMismatch)
    ));
}

#[tokio::test]
async fn an_x509_hash_request_without_a_chain_refuses() {
    let http = FakeHttp {
        body: Vec::new(),
        status: 200,
    };
    // Plain JSON: no request object, no x5c — the scheme cannot name
    // the certificate.
    let params = serde_json::json!({
        "client_id": format!("x509_hash:{}", verifier_hash()),
        "nonce": "nonce-1",
        "response_uri": "https://verifier.example/response",
        "response_mode": "direct_post"
    });
    assert!(matches!(
        parse_request(&http, &params).await,
        Err(RequestError::SchemeRequiresRequestObject { .. })
    ));
}

/// Signs a compact JWT with the given header and payload under the
/// test verifier key — the request-object form for the attestation
/// checks (the header carries what the test names).
fn signed_jwt(header: &serde_json::Value, payload: &serde_json::Value) -> String {
    let jwk: jose_rs::jwk::Jwk =
        serde_json::from_value(verifier_jwk()).expect("the verifier JWK parses");
    let signer = {
        let software = jose_rs::jwk::jwk_to_software_key(&jwk).expect("the key converts");
        kryptering::SoftwareSigner::new(
            kryptering::SignatureAlgorithm::Ecdsa(
                kryptering::EcCurve::P256,
                kryptering::HashAlgorithm::Sha256,
            ),
            software,
        )
        .expect("the signer builds")
    };
    let h = wmp_core::token::base64url_unpadded(header.to_string().as_bytes())
        .as_str()
        .to_owned();
    let p = wmp_core::token::base64url_unpadded(payload.to_string().as_bytes())
        .as_str()
        .to_owned();
    let tbs = format!("{h}.{p}");
    let signature = kryptering::Signer::sign(&signer, tbs.as_bytes()).expect("the request signs");
    format!("{tbs}.{}", wmp_core::token::base64url_unpadded(&signature))
}

/// The verifier attestation JWT (OpenID4VP 1.0 §5.9.3.4): `iss`,
/// `sub`, `cnf.jwk` — the public form of the test verifier key —
/// and the `redirect_uris` the attestation names.
fn attestation_jwt(subject: &str) -> String {
    let public: serde_json::Value = {
        let mut jwk = verifier_jwk();
        jwk.as_object_mut()
            .expect("the JWK is an object")
            .remove("d");
        jwk
    };
    let header = serde_json::json!({ "alg": "ES256", "typ": "jwt" });
    let payload = serde_json::json!({
        "iss": "https://attester.example",
        "sub": subject,
        "cnf": { "jwk": public },
        "redirect_uris": ["https://verifier.example/response"],
    });
    let h = wmp_core::token::base64url_unpadded(header.to_string().as_bytes())
        .as_str()
        .to_owned();
    let p = wmp_core::token::base64url_unpadded(payload.to_string().as_bytes())
        .as_str()
        .to_owned();
    // The attestation's own signature is the PDP's to verify (the
    // engine checks the REQUEST against cnf.jwk); a placeholder
    // stands in the third segment.
    format!("{h}.{p}.YXR0ZXN0YXRpb24")
}

/// A signed request object for the verifier_attestation scheme: the
/// header carries the attestation in its `jwt` parameter, the
/// payload the given client_id.
fn attested_request_object(attestation: &str, client_id: &str) -> String {
    let header = serde_json::json!({
        "typ": "oauth-authz-req+jwt",
        "alg": "ES256",
        "kid": "vp-verifier-key-1",
        "jwt": attestation,
    });
    let payload = serde_json::json!({
        "client_id": client_id,
        "nonce": "nonce-1",
        "response_uri": "https://verifier.example/response",
        "response_mode": "direct_post",
    });
    signed_jwt(&header, &payload)
}

#[tokio::test]
async fn an_x509_san_dns_request_without_the_signed_form_refuses() {
    // §5: the DNS binding rides a signed request object whose x5c
    // chain names the certificate; the plain params form refuses.
    let http = FakeHttp {
        body: Vec::new(),
        status: 200,
    };
    let params = serde_json::json!({
        "client_id": "x509_san_dns:verifier.example",
        "nonce": "n",
        "response_uri": "https://verifier.example/response",
        "response_mode": "direct_post",
    });
    assert!(matches!(
        parse_request(&http, &params).await,
        Err(RequestError::SchemeRequiresRequestObject { .. })
    ));
}

#[tokio::test]
async fn a_verifier_attestation_request_with_a_matching_subject_parses() {
    let http = FakeHttp {
        body: Vec::new(),
        status: 200,
    };
    let client_id = "verifier_attestation:attested-verifier-1";
    let jwt = attested_request_object(&attestation_jwt("attested-verifier-1"), client_id);
    let params = serde_json::json!({ "request": jwt });
    let request = parse_request(&http, &params).await.expect("parse");
    assert_eq!(request.client_id, client_id);
    assert_eq!(
        request.client_id_scheme,
        ClientIdScheme::VerifierAttestation
    );
}

#[tokio::test]
async fn a_verifier_attestation_request_with_a_mismatched_subject_refuses() {
    let http = FakeHttp {
        body: Vec::new(),
        status: 200,
    };
    // The attestation names another verifier than the client_id.
    let client_id = "verifier_attestation:attested-verifier-1";
    let jwt = attested_request_object(&attestation_jwt("someone-else"), client_id);
    let params = serde_json::json!({ "request": jwt });
    assert!(matches!(
        parse_request(&http, &params).await,
        Err(RequestError::AttestationSubjectMismatch { .. })
    ));
}

#[tokio::test]
async fn a_verifier_attestation_request_signed_by_another_key_refuses() {
    let http = FakeHttp {
        body: Vec::new(),
        status: 200,
    };
    // The request JWT is signed by a key the attestation's cnf does
    // not name: the binding that makes the attestation speak for
    // this request is absent.
    let client_id = "verifier_attestation:attested-verifier-1";
    let header = serde_json::json!({
        "typ": "oauth-authz-req+jwt",
        "alg": "ES256",
        "jwt": attestation_jwt("attested-verifier-1"),
    });
    let payload = serde_json::json!({
        "client_id": client_id,
        "nonce": "nonce-1",
        "response_uri": "https://verifier.example/response",
        "response_mode": "direct_post",
    });
    // A fresh key signs — not the attestation's cnf key.
    let other = jose_rs::jwk::generate::generate_ec("P-256").expect("the other key");
    let software = jose_rs::jwk::jwk_to_software_key(&other).expect("the key converts");
    let signer = kryptering::SoftwareSigner::new(
        kryptering::SignatureAlgorithm::Ecdsa(
            kryptering::EcCurve::P256,
            kryptering::HashAlgorithm::Sha256,
        ),
        software,
    )
    .expect("the signer builds");
    let h = wmp_core::token::base64url_unpadded(header.to_string().as_bytes())
        .as_str()
        .to_owned();
    let p = wmp_core::token::base64url_unpadded(payload.to_string().as_bytes())
        .as_str()
        .to_owned();
    let tbs = format!("{h}.{p}");
    let signature = kryptering::Signer::sign(&signer, tbs.as_bytes()).expect("signs");
    let jwt = format!("{tbs}.{}", wmp_core::token::base64url_unpadded(&signature));

    let params = serde_json::json!({ "request": jwt });
    assert!(matches!(
        parse_request(&http, &params).await,
        Err(RequestError::AttestationSignature)
    ));
}

#[tokio::test]
async fn a_verifier_attestation_request_without_the_attestation_refuses() {
    let http = FakeHttp {
        body: Vec::new(),
        status: 200,
    };
    // Plain params: no header, no attestation.
    let params = serde_json::json!({
        "client_id": "verifier_attestation:attested-verifier-1",
        "nonce": "nonce-1",
        "response_uri": "https://verifier.example/response",
        "response_mode": "direct_post",
    });
    assert!(matches!(
        parse_request(&http, &params).await,
        Err(RequestError::VerifierAttestationRequired)
    ));
}
