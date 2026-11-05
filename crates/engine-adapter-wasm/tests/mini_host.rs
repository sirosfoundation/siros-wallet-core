//! The mini host's keys: the registered client key signs the client
//! assertion, and the fixture issuer's key signs the held mDL.

#![cfg(target_arch = "wasm32")]

use wasm_bindgen_test::wasm_bindgen_test;

use engine_adapter_wasm::mini::MiniHost;
use engine_ports::{Host, SignParams, VpParams, VpSelection};

/// The P-256 ES256 verifier over a public JWK.
fn es256_verifier(public: &jose_rs::jwk::Jwk) -> kryptering::SoftwareVerifier {
    let key = jose_rs::jwk::jwk_to_software_key(public).expect("the public converts");
    kryptering::SoftwareVerifier::new(
        kryptering::SignatureAlgorithm::Ecdsa(
            kryptering::EcCurve::P256,
            kryptering::HashAlgorithm::Sha256,
        ),
        key,
    )
    .expect("the verifier")
}

/// The client key the plan registers (the OIDF suite's fixture
/// shape): the host must sign the assertion with THIS key when
/// the ask names the registered kid, and the signature must
/// verify against the key's public members.
#[wasm_bindgen_test]
async fn the_client_key_signs_the_assertion_ask() {
    let jwk = r#"{"kty": "EC", "x": "ktT77AqMntawPyU772lBg8nd7cwENrYyOL_KWbYN8Jc", "y": "67lPXEq5gJdimDYD0AacxLfRfIm2-fSNd3HBqyXXvBI", "crv": "P-256", "d": "KJEKZo2PQq6E40P6HMenViCVBRXoWD2FDyevRsJnlG0", "kid": "client-key-1", "use": "sig", "alg": "ES256"}"#;
    let host = MiniHost::new("123456".to_owned(), Some(jwk.to_owned()), None, None)
        .expect("the mini host builds");
    let tbs = "header.payload";
    let sign = host
        .request_sign(SignParams {
            flow_id: "flow-1".to_owned(),
            to_sign: tbs.as_bytes().to_vec(),
            key_id: Some("client-key-1".to_owned()),
            algorithm: "ES256".to_owned(),
        })
        .await
        .expect("the client key signs");
    assert_eq!(sign.signature.len(), 64, "the raw JOSE signature");

    // The signature must verify with the client key's public half.
    let public: jose_rs::jwk::Jwk = serde_json::from_value(serde_json::json!({
        "kty": "EC",
        "x": "ktT77AqMntawPyU772lBg8nd7cwENrYyOL_KWbYN8Jc",
        "y": "67lPXEq5gJdimDYD0AacxLfRfIm2-fSNd3HBqyXXvBI",
        "crv": "P-256",
        "kid": "client-key-1",
    }))
    .expect("the public JWK");
    let verifier = es256_verifier(&public);
    let ok = kryptering::Verifier::verify(&verifier, tbs.as_bytes(), &sign.signature)
        .expect("verify runs");
    assert!(ok, "the assertion signature verifies with the client key");
}

/// The held mDL the host presents: its issuerAuth is ES256 and
/// verifies under the fixture issuer's key — the key the x5c leaf
/// certificate carries — the same Sig_structure the verifier side
/// (Multipaz, the suites) builds.
#[wasm_bindgen_test]
async fn the_issued_mdl_verifies_under_the_issuer_key() {
    let issuer_text = r#"{"kty": "EC", "crv": "P-256", "x": "vbralm3AYpmqPjRNS-r91bxdJMoBIwGMfX9wBFs_j5g", "y": "GxYJ_Mi0seMhvJ7bpavbL_lJKN0SCwHKcWUbZh78AcA", "d": "ms8Mq5Zd4EfJvAnvrFhJgikMWvsti4YYUiAF--d12EI", "kid": "mini-pid-signing-1", "use": "sig", "alg": "ES256", "x5c": ["MIIDLjCCAhagAwIBAgIUaq8n9cw4pH90JI8n0X0CFJNCmlIwDQYJKoZIhvcNAQELBQAwgYQxCzAJBgNVBAYTAlNFMQ0wCwYDVQQIDARUZXN0MRUwEwYDVQQHDAxNaW5pIFRlc3RpbmcxGTAXBgNVBAoMEE1pbmkgV2FsbGV0IFRlc3QxETAPBgNVBAsMCFRlc3QgUEtJMSEwHwYDVQQDDBhNaW5pIFdhbGxldCBUZXN0IFJvb3QgQ0EwHhcNMjYxMTA1MDk0MjA5WhcNMjgxMTA0MDk0MjA5WjCBhTELMAkGA1UEBhMCU0UxDTALBgNVBAgMBFRlc3QxFTATBgNVBAcMDE1pbmkgVGVzdGluZzEZMBcGA1UECgwQTWluaSBXYWxsZXQgVGVzdDEbMBkGA1UECwwSQ3JlZGVudGlhbCBTaWduaW5nMRgwFgYDVQQDDA9taW5pLXBpZC1pc3N1ZXIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS9utqWbcBimao+NE1L6v3VvF0kygEjAYx9f3AEWz+PmBsWCfzItLHjIbye26Wr2y/5SSjdEgsBynFlG2Ye/AHAo2AwXjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQUnpSlTdowQyMshALAnWJ83QaYyi0wHwYDVR0jBBgwFoAUDVgyA7wrtOk4hCwqQXGM/goAkl8wDQYJKoZIhvcNAQELBQADggEBAF8LQN+4cY+MvQJcXyF1W7QB9j+DgOk8OD+f3TOBQPexk3tKYLznDmgei4dZKdcX7Kd1hXh1SQN/HCwKJEho5fuv4JO33Dyksazuz6nAKmnKcFGiXGLPmC5rMLqY1/TotsTEbtXLIddsBz7c0r13wZggac5Mq6GahNc+tF2X0jDuAdGW1DKKo5mCB5GhDVuBBMQ+dG8wT3lEwyEs2rUhVjswv64gr1o+O7lPbFBF7k9FxOaCIGMM2X8Mp/wdSOXWY6ozSMD9kLjULBTyGrvfhmtxilCMPI4j3K2O1p+Ve1LYC08A9a5I+n9ivVxMIt2o1d+yJg9pWtf67pnR8a8HIAg="]}"#;
    let issuer: jose_rs::jwk::Jwk =
        serde_json::from_str(issuer_text).expect("the fixture issuer JWK");
    let host = MiniHost::new(
        "123456".to_owned(),
        None,
        Some(issuer_text.to_owned()),
        None,
    )
    .expect("the mini host builds");

    // The mDL presentation: a DeviceResponse (ISO/IEC 18013-5,
    // 8.3.2.1.2.2) whose document carries the issuerSigned as issued.
    let vp = host
        .request_vp(VpParams {
            flow_id: "flow-mdl-1".to_owned(),
            audience: "x509_san_dns:verifier.example".to_owned(),
            nonce: "nonce-mdl-1".to_owned(),
            selections: vec![VpSelection {
                credential_query_id: "mdl".to_owned(),
                credential_id: "mini-mdl".to_owned(),
                disclosed_claims: vec![r#"["org.iso.18013.5.1","family_name"]"#.to_owned()],
            }],
            response_uri: "https://verifier.example/response".to_owned(),
            verifier_jwk_thumbprint: String::new(),
            verifier_session_id: String::new(),
            transaction_data: Vec::new(),
            // The mini host has no transport handle.
            selection_handle: None,
        })
        .await
        .expect("the mDL presents");
    let response =
        siros_codec::base64url::decode(&vp.vp_token).expect("the DeviceResponse decodes");
    let response = siros_codec::cbor::decode(&response).expect("the DeviceResponse is CBOR");
    let issuer_signed = response
        .get("documents")
        .and_then(|documents| documents.as_array())
        .and_then(|documents| documents.first())
        .and_then(|document| document.get("issuerSigned"))
        .expect("the document's issuerSigned");
    let issuer_signed = siros_codec::base64url::encode(issuer_signed.raw());
    let parsed = siros_mdoc::Mdoc::parse(issuer_signed.as_str()).expect("the mDL parses back");

    // The issuerAuth's algorithm: ES256, the COSE identifier -7
    // (RFC 9053 §2) — major type 1 encodes -1-n, so -7 is content 6.
    // Multipaz's verifier maps the identifier directly; -8 is
    // EdDSA and the ES256 signature fails its check.
    assert_eq!(parsed.issuer_auth().algorithm().value(), -7);

    // The issuerAuth verifies under the issuer key over the
    // Sig_structure the reader reconstructs (RFC 9052 §4.4).
    let verifier = es256_verifier(&issuer);
    let verified = kryptering::Verifier::verify(
        &verifier,
        parsed.issuer_auth().sig_structure().as_bytes(),
        parsed.issuer_auth().signature(),
    )
    .expect("the verification runs");
    assert!(verified, "the mDL issuerAuth verifies under the issuer key");
}
