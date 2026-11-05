//! The mini host's keys and presentations: the registered client key
//! signs the client assertion, the fixture issuer's key signs the held
//! mDL, and the device key binds the presented PID.

#![cfg(target_arch = "wasm32")]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use coset::AsCborValue as _;
use sha2::{Digest, Sha256};
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

/// The presentation ask for one selection of `credential_id`.
fn vp_params(credential_id: &str, claims: &[&str]) -> VpParams {
    VpParams {
        flow_id: "flow-vp-1".to_owned(),
        audience: "x509_san_dns:verifier.example".to_owned(),
        nonce: "nonce-vp-1".to_owned(),
        selections: vec![VpSelection {
            credential_query_id: "query".to_owned(),
            credential_id: credential_id.to_owned(),
            disclosed_claims: claims.iter().map(|claim| (*claim).to_owned()).collect(),
        }],
        response_uri: "https://verifier.example/response".to_owned(),
        verifier_jwk_thumbprint: String::new(),
        verifier_session_id: String::new(),
        transaction_data: Vec::new(),
        // The mini host has no transport handle.
        selection_handle: None,
    }
}

/// The member `name` of a CBOR map.
fn member<'v>(map: &'v ciborium::Value, name: &str) -> &'v ciborium::Value {
    map.as_map()
        .and_then(|members| members.iter().find(|(key, _)| key.as_text() == Some(name)))
        .map(|(_, value)| value)
        .unwrap_or_else(|| panic!("the map has no {name}: {map:?}"))
}

/// The data item `#6.24(bstr .cbor item)` embeds (RFC 8949 §3.4.5.1).
fn unembedded(tagged: &ciborium::Value) -> ciborium::Value {
    let Some((24, ciborium::Value::Bytes(bytes))) = tagged.as_tag() else {
        panic!("no tag 24 over a byte string: {tagged:?}");
    };
    ciborium::de::from_reader(bytes.as_slice()).expect("the embedded item is CBOR")
}

/// The JSON a base64url segment encodes.
fn decoded(segment: &str) -> serde_json::Value {
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .expect("a base64url segment");
    serde_json::from_slice(&bytes).expect("a JSON segment")
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

/// The held mDL the host presents authenticates under the fixture
/// issuer's key (ISO/IEC 18013-5, 9.3.1): its issuerAuth is an ES256
/// COSE_Sign1 (the identifier -7, RFC 9053 §2.1, which Multipaz maps
/// directly) carrying the issuer's x5chain (label 33, RFC 9360), whose
/// signature verifies under the key the x5c leaf certificate carries
/// over the Sig_structure coset rebuilds (RFC 9052 §4.4); the MSO names
/// the document's docType, and its valueDigests hold the SHA-256 of
/// each disclosed IssuerSignedItemBytes (9.1.2.5).
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
        .request_vp(vp_params(
            "mini-mdl",
            &[r#"["org.iso.18013.5.1","family_name"]"#],
        ))
        .await
        .expect("the mDL presents");
    let response = URL_SAFE_NO_PAD
        .decode(&vp.vp_token)
        .expect("the DeviceResponse is base64url");
    let response: ciborium::Value =
        ciborium::de::from_reader(response.as_slice()).expect("the DeviceResponse is CBOR");
    let document = member(&response, "documents")
        .as_array()
        .and_then(|documents| documents.first())
        .expect("the DeviceResponse's document");
    let issuer_signed = member(document, "issuerSigned");

    let issuer_auth =
        coset::CoseSign1::from_cbor_value(member(issuer_signed, "issuerAuth").clone())
            .expect("issuerAuth is a COSE_Sign1");
    assert_eq!(
        issuer_auth.protected.header.alg,
        Some(coset::Algorithm::Assigned(coset::iana::Algorithm::ES256))
    );
    assert!(
        issuer_auth
            .unprotected
            .rest
            .iter()
            .any(|(label, _)| *label == coset::Label::Int(33)),
        "issuerAuth carries the x5chain"
    );
    let verified = kryptering::Verifier::verify(
        &es256_verifier(&issuer),
        &issuer_auth.tbs_data(b""),
        &issuer_auth.signature,
    )
    .expect("the verification runs");
    assert!(verified, "the mDL issuerAuth verifies under the issuer key");

    let mso = unembedded(
        &ciborium::de::from_reader(issuer_auth.payload.as_deref().expect("the MSO"))
            .expect("the payload is CBOR"),
    );
    assert_eq!(member(&mso, "docType"), member(document, "docType"));
    let items = member(member(issuer_signed, "nameSpaces"), "org.iso.18013.5.1")
        .as_array()
        .expect("the namespace's items");
    let digests = member(member(&mso, "valueDigests"), "org.iso.18013.5.1")
        .as_map()
        .expect("the namespace's digests");
    assert_eq!(items.len(), 1, "the one item the path names");
    for item in items {
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(item, &mut encoded).expect("the item encodes");
        let digest_id = member(&unembedded(item), "digestID").clone();
        let listed = digests
            .iter()
            .find(|(id, _)| *id == digest_id)
            .and_then(|(_, digest)| digest.as_bytes())
            .expect("the MSO lists the item's digest");
        assert_eq!(listed.as_slice(), Sha256::digest(&encoded).as_slice());
    }
}

/// RFC 9901 §4 and §4.3: the presented PID holds the issuer JWT and the
/// disclosure of the claim each path names, each followed by `~`, each
/// disclosure digest-listed in the JWT's `_sd` (§4.2.3); the KB-JWT's
/// `sd_hash` is SHA-256 (sha2, independent of the signer's digest) over
/// exactly those bytes, its `aud` and `nonce` the verifier's, its `iat`
/// the presentation time, and the PID's `cnf.jwk`, the device key, signs
/// its own header and payload. A path into a claim's object (OpenID4VP
/// §7.2) presents that claim's disclosure. A claim the PID does not
/// hold, and a claim that is no §7 path, are refused.
#[wasm_bindgen_test]
async fn the_key_binding_covers_the_presented_disclosures() {
    let host = MiniHost::new("123456".to_owned(), None, None, None).expect("the mini host builds");
    let before = (js_sys::Date::now() / 1000.0).floor() as u64;
    let vp = host
        .request_vp(vp_params("mini-pid", &[r#"["family_name"]"#]))
        .await
        .expect("the PID presents");
    let after = (js_sys::Date::now() / 1000.0).ceil() as u64;

    let (presented, kb_jwt) = vp
        .vp_token
        .rsplit_once('~')
        .map(|(head, kb_jwt)| (format!("{head}~"), kb_jwt.to_owned()))
        .expect("the KB-JWT follows the last ~");
    let mut segments = presented.trim_end_matches('~').split('~');
    let jwt = segments.next().expect("the issuer JWT leads");
    let disclosures: Vec<&str> = segments.collect();
    let [_, issuer_payload, _] = jwt.split('.').collect::<Vec<_>>()[..] else {
        panic!("the issuer JWT is no compact JWS: {jwt}");
    };
    let issuer_payload = decoded(issuer_payload);
    let listed = issuer_payload["_sd"].as_array().expect("the _sd digests");
    let [disclosure] = disclosures[..] else {
        panic!("one disclosure per named claim: {disclosures:?}");
    };
    assert_eq!(decoded(disclosure)[1], "family_name");
    assert!(listed.contains(&serde_json::json!(
        URL_SAFE_NO_PAD.encode(Sha256::digest(disclosure.as_bytes()))
    )));

    let [header, payload, signature] = kb_jwt.split('.').collect::<Vec<_>>()[..] else {
        panic!("the KB-JWT is no compact JWS: {kb_jwt}");
    };
    assert_eq!(
        decoded(header),
        serde_json::json!({"typ": "kb+jwt", "alg": "ES256"})
    );
    let payload_json = decoded(payload);
    assert_eq!(payload_json["aud"], "x509_san_dns:verifier.example");
    assert_eq!(payload_json["nonce"], "nonce-vp-1");
    assert_eq!(
        payload_json["sd_hash"],
        URL_SAFE_NO_PAD.encode(Sha256::digest(presented.as_bytes()))
    );
    let iat = payload_json["iat"].as_u64().expect("iat is a NumericDate");
    assert!(
        (before..=after).contains(&iat),
        "{iat} in {before}..={after}"
    );
    let holder: jose_rs::jwk::Jwk =
        serde_json::from_value(issuer_payload["cnf"]["jwk"].clone()).expect("the PID's cnf.jwk");
    let verified = kryptering::Verifier::verify(
        &es256_verifier(&holder),
        format!("{header}.{payload}").as_bytes(),
        &URL_SAFE_NO_PAD.decode(signature).expect("base64url"),
    )
    .expect("the verification runs");
    assert!(verified, "the device key signs the KB-JWT");

    let nested = host
        .request_vp(vp_params("mini-pid", &[r#"["place_of_birth","locality"]"#]))
        .await
        .expect("a path into place_of_birth presents");
    let disclosures: Vec<&str> = nested.vp_token.split('~').collect();
    let [_, disclosure, _] = disclosures[..] else {
        panic!("one disclosure: {disclosures:?}");
    };
    assert_eq!(decoded(disclosure)[1], "place_of_birth");

    for claim in [r#"["no_such_claim"]"#, "family_name"] {
        let refused = host.request_vp(vp_params("mini-pid", &[claim])).await;
        assert!(refused.is_err(), "{claim}");
    }
}
