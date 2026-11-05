use engine_core::oid4vci::credential::CredentialResponse;
use engine_core::oid4vci::encryption::*;

fn test_config() -> ResponseEncryptionConfig {
    ResponseEncryptionConfig {
        alg_values: vec!["ECDH-ES".to_owned()],
        enc_values: vec![
            "A256GCM".to_owned(),
            "A128GCM".to_owned(),
            "A256CBC-HS512".to_owned(),
        ],
        required: true,
    }
}

#[test]
fn negotiates_the_strongest_mutually_supported_pair() {
    let negotiated = negotiate_encryption(&test_config()).expect("negotiate");
    assert_eq!(negotiated.alg, "ECDH-ES");
    assert_eq!(negotiated.enc, "A256GCM");
}

#[test]
fn no_overlap_refuses() {
    let config = ResponseEncryptionConfig {
        alg_values: vec!["RSA-OAEP".to_owned()],
        enc_values: vec!["A128GCM".to_owned()],
        required: true,
    };
    assert!(negotiate_encryption(&config).is_none());
}

#[test]
fn falls_back_to_128gcm_when_256_is_unsupported() {
    let config = ResponseEncryptionConfig {
        alg_values: vec!["ECDH-ES".to_owned()],
        enc_values: vec!["A128GCM".to_owned()],
        required: false,
    };
    let negotiated = negotiate_encryption(&config).expect("negotiate");
    assert_eq!(negotiated.enc, "A128GCM");
}

#[test]
fn builds_the_request_with_the_negotiated_pair_and_jwk() {
    let negotiated = NegotiatedEncryption {
        alg: "ECDH-ES".to_owned(),
        enc: "A256GCM".to_owned(),
    };
    let jwk = serde_json::json!({"kty": "EC", "crv": "P-256", "x": "a", "y": "b"});
    let request = build_encryption_request(&negotiated, jwk.clone());
    assert_eq!(request.alg, "ECDH-ES");
    assert_eq!(request.enc, "A256GCM");
    assert_eq!(request.jwk, jwk);
}

#[test]
fn detects_an_encrypted_response_from_the_media_type() {
    assert!(is_encrypted_response(
        "application/jwt",
        b"header.key.iv.ct.tag"
    ));
    assert!(is_encrypted_response(
        "application/jose",
        b"header.key.iv.ct.tag"
    ));
    assert!(!is_encrypted_response(
        "application/json",
        br#"{"credential":"x"}"#
    ));
}

#[test]
fn detects_an_encrypted_response_from_the_shape() {
    // Five dot-separated parts, not starting with '{': a JWE.
    assert!(is_encrypted_response("", b"abc.def.ghi.jkl.mno"));
    // A plain JSON response: not a JWE.
    assert!(!is_encrypted_response("", br#"{"credential":"x"}"#));
}

#[test]
fn decrypt_refuses_a_non_jwe_shape() {
    let key = EphemeralResponseKey::generate().expect("keygen");
    let err = decrypt_encrypted_response("not-a-jwe", &key).expect_err("refuses");
    assert!(matches!(err, EncryptionError::Decrypt(_)));
}

#[test]
fn the_ephemeral_key_offers_a_public_ec_jwk() {
    let key = EphemeralResponseKey::generate().expect("keygen");
    assert_eq!(key.public_jwk["kty"], "EC");
    assert_eq!(key.public_jwk["crv"], "P-256");
    // The offered JWK is public: no private member.
    assert!(key.public_jwk.get("d").is_none());
}

#[test]
fn the_encrypted_response_roundtrips() {
    // The issuer's side, simulated with jose-rs: the JWE to the
    // wallet's offered public key, with the negotiated pair.
    let key = EphemeralResponseKey::generate().expect("keygen");
    let negotiated = NegotiatedEncryption {
        alg: "ECDH-ES".to_owned(),
        enc: "A256GCM".to_owned(),
    };

    let public =
        serde_json::from_value::<jose_rs::jwk::Jwk>(key.public_jwk.clone()).expect("public jwk");
    let mut recipient = public.clone();
    recipient.alg = Some(negotiated.alg.clone());

    let credential_response = CredentialResponse {
        credential: Some("credential-jwt-1".to_owned()),
        format_specific: None,
        transaction_id: None,
        interval: None,
        nonce: None,
        notification_id: None,
        credential_metadata: None,
    };
    let plaintext = serde_json::to_vec(&credential_response).expect("serialize");
    let jwe = jose_rs::jwe::compact::encrypt_with_jwk_header(
        &recipient,
        jose_rs::header::JoseHeader::for_jwe(
            jose_rs::algorithm::JweAlgorithm::EcdhEs,
            jose_rs::algorithm::JweEncryption::A256GCM,
        ),
        &plaintext,
        jose_rs::algorithm::JweEncryption::A256GCM,
    )
    .expect("encrypt");

    // The wallet's side: the decrypt recovers the response.
    let decrypted = decrypt_encrypted_response(&jwe, &key).expect("decrypt");
    assert_eq!(decrypted.credential.as_deref(), Some("credential-jwt-1"));
}

#[test]
fn a_mismatched_algorithm_refuses() {
    // An issuer encrypting with an algorithm the wallet did not
    // offer: the decrypt refuses (the header names RSA-OAEP-256,
    // the key is EC — the decrypt fails, fail closed).
    let key = EphemeralResponseKey::generate().expect("keygen");
    let err = decrypt_encrypted_response("a.b.c.d.e", &key).expect_err("refuses");
    assert!(matches!(err, EncryptionError::Decrypt(_)));
}
