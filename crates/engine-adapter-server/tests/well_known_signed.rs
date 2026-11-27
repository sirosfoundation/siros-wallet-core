//! The well-known document's two forms (issue #100, CS-15 §7.2): the
//! plain JSON for the default request, and the signed `application/jwt`
//! attestation on `Accept: application/jwt` — the SAME document, signed
//! under the participant certificate's key, the chain in the `x5c`
//! header, verifiable without the TLS session (the eDelivery profile's
//! trust model reads the document as attestation). The participant_id
//! field names who the endpoint is (`x509:san:dns:…`).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use engine_adapter_server::{config::Config, EngineServer};
use tower::ServiceExt;

/// A participant certificate for `participant.example` (the SAN DNS the
/// `x509:san:dns:` identifier form carries) and its key, as the
/// deployment's PEM pair: the chain PEM, the key PEM, the leaf DER.
fn participant_material() -> (String, String, Vec<u8>) {
    let params =
        rcgen::CertificateParams::new(vec!["participant.example".to_owned()]).expect("params");
    let key_pair = rcgen::KeyPair::generate().expect("the P-256 key");
    let cert = params.self_signed(&key_pair).expect("the certificate");
    (cert.pem(), key_pair.serialize_pem(), cert.der().to_vec())
}

/// GETs the well-known route with an optional `Accept`, answering the
/// status, the content type and the body.
async fn get_configuration(
    server: &Arc<EngineServer>,
    accept: Option<&str>,
) -> (StatusCode, Option<String>, Vec<u8>) {
    let app = engine_adapter_server::transport::router(server.clone());
    let mut request = Request::builder()
        .method("GET")
        .uri("/.well-known/wmp-configuration");
    if let Some(accept) = accept {
        request = request.header("accept", accept);
    }
    let response = app
        .oneshot(request.body(Body::empty()).expect("build request"))
        .await
        .expect("serve");
    let status = response.status();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("read body")
        .to_vec();
    (status, content_type, body)
}

fn server_with_material(
    participant_id: &str,
    material: Option<(String, String)>,
) -> Arc<EngineServer> {
    let (cert_pem, key_pem) = material.unwrap_or_default();
    Arc::new(EngineServer::new(Config {
        participant_id: participant_id.to_owned(),
        participant_cert_pem: cert_pem,
        participant_key_pem: key_pem,
        ..Config::default()
    }))
}

/// The plain document carries the configured `participant_id` — CS-15
/// §7.2: the field is MUST, the `x509:san:dns:` form.
#[tokio::test]
async fn the_plain_document_carries_the_participant_id() {
    let server = server_with_material("x509:san:dns:participant.example", None);
    let (status, content_type, body) = get_configuration(&server, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(content_type.as_deref(), Some("application/json"));
    let document: serde_json::Value = serde_json::from_slice(&body).expect("the document is JSON");
    assert_eq!(
        document.get("participant_id").and_then(|v| v.as_str()),
        Some("x509:san:dns:participant.example"),
        "CS-15 §7.2: the well-known names WHO the endpoint is"
    );
}

/// The signed form on `Accept: application/jwt`: the same document,
/// under the chain — the x5c carries the configured certificate, the
/// payload equals the plain document, the signature verifies under the
/// chain's leaf, exactly what a counterpart's parser does with it
/// (CS-15 §7.2: verifiable via the certificate's x5c chain).
#[tokio::test]
async fn the_signed_form_answers_the_same_document_under_the_chain() {
    let (cert_pem, key_pem, leaf_der) = participant_material();
    let server = server_with_material(
        "x509:san:dns:participant.example",
        Some((cert_pem, key_pem)),
    );

    let (status, content_type, body) = get_configuration(&server, Some("application/jwt")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(content_type.as_deref(), Some("application/jwt"));
    let jwt = String::from_utf8(body).expect("the JWT is text");

    // The protected header: the x5c's leaf IS the configured certificate
    // (RFC 7515 §4.1.6: standard-alphabet base64 DER).
    let header: serde_json::Value = serde_json::from_slice(
        &jose_rs::base64url::decode(jwt.split('.').next().unwrap_or_default())
            .expect("the header decodes"),
    )
    .expect("the header is JSON");
    let x5c = header
        .get("x5c")
        .and_then(|v| v.as_array())
        .and_then(|chain| chain.first())
        .and_then(|v| v.as_str())
        .expect("the chain rides the header");
    assert_eq!(
        x5c,
        BASE64_STANDARD.encode(&leaf_der),
        "the x5c leaf is the configured participant certificate"
    );

    // The signature verifies under the leaf's own key — parsed from the
    // certificate the header carries, the counterpart's position.
    let verifying =
        jose_rs::jwk::cert::public_jwk_from_certificate_der(&leaf_der).expect("the leaf parses");
    jose_rs::jws::compact::verify_with_jwk(&verifying, &jwt)
        .expect("CS-15 §7.2: the document verifies via the certificate's x5c chain");

    // The payload is the same document the plain form serves.
    let plain = get_configuration(&server, None).await;
    let plain_document: serde_json::Value =
        serde_json::from_slice(&plain.2).expect("the plain document is JSON");
    let payload: serde_json::Value = serde_json::from_slice(
        &jose_rs::base64url::decode(jwt.split('.').nth(1).unwrap_or_default())
            .expect("the payload decodes"),
    )
    .expect("the payload is JSON");
    assert_eq!(
        payload, plain_document,
        "the signed form is the SAME document"
    );
}

/// The signed form without the signing material answers `406`: the
/// deployment cannot produce the attestation, and the unsigned document
/// in its place would hand the checker a body it cannot verify.
#[tokio::test]
async fn the_signed_form_without_signing_material_refuses() {
    let server = server_with_material("x509:san:dns:participant.example", None);
    let (status, content_type, _) = get_configuration(&server, Some("application/jwt")).await;
    assert_eq!(status, StatusCode::NOT_ACCEPTABLE);
    assert_eq!(content_type.as_deref(), Some("text/plain; charset=utf-8"));
}

/// The default request still answers the plain JSON with the material
/// configured: the negotiation is per-request, never a deployment mode.
#[tokio::test]
async fn the_default_request_answers_plain_json_with_the_material_configured() {
    let (cert_pem, key_pem, _) = participant_material();
    let server = server_with_material(
        "x509:san:dns:participant.example",
        Some((cert_pem, key_pem)),
    );
    let (status, content_type, _) = get_configuration(&server, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(content_type.as_deref(), Some("application/json"));
}
