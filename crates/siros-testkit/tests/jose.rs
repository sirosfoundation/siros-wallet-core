//! The doubles' cryptography against published vectors: RFC 6979's deterministic ES256 and RFC
//! 7518 Appendix C's ECDH-ES key agreement; and a JWE round trip through `RequestDecryption`.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use siros_openid4vp::host::{DecryptFailed, RequestDecryption};
use siros_openid4vp::jose::{CompactJwe, PublicJwk, VerificationKey};
use siros_openid4vp::json::Node;
use siros_testkit::TestRequestDecryption;
use siros_testkit::jose::{
    DECRYPTS, VERIFIER_SECRET, concat_kdf, encrypt_to, p256_point, scalar_jwk, sign, verifier_key,
    verifies,
};

/// An EC P-256 JWK of base64url coordinates.
fn jwk(x: &str, y: &str) -> Node<'static> {
    Node::parse(&format!(
        r#"{{"kty":"EC","crv":"P-256","x":"{x}","y":"{y}"}}"#
    ))
    .expect("a JWK")
    .into_owned()
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

fn b64(text: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(text).expect("base64url")
}

#[test]
fn es256_signs_as_rfc_6979_a_2_5_says_and_verifies() {
    // RFC 6979 A.2.5, P-256 with SHA-256, message "sample".
    let r = "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716";
    let s = "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8";
    let signature = b64(&sign(&VERIFIER_SECRET, "sample").expect("signs"));
    assert_eq!(signature, hex(&format!("{r}{s}")));
    let ux = hex("60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6");
    let uy = hex("7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299");
    let key = VerificationKey::of(
        PublicJwk::parse(jwk(
            &URL_SAFE_NO_PAD.encode(ux),
            &URL_SAFE_NO_PAD.encode(&uy),
        ))
        .expect("U"),
    );
    assert_eq!(key, verifier_key().expect("key"));
    assert!(verifies(&key, b"sample", &signature));
    assert!(!verifies(&key, b"samplf", &signature));
    // SEC 1 §3.2.2.1: U with its y's last bit flipped is off the curve, which the double refuses
    // as a point before any signature.
    let mut above = uy;
    if let Some(last) = above.last_mut() {
        *last ^= 1;
    }
    let off = jwk(
        &URL_SAFE_NO_PAD.encode(hex(
            "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
        )),
        &URL_SAFE_NO_PAD.encode(above),
    );
    assert!(p256_point(&off).is_none());
}

#[test]
fn ecdh_es_derives_rfc_7518_appendix_cs_key() {
    let bob = p256::SecretKey::from_slice(&b64("VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"))
        .expect("Bob's key");
    let alice = p256_point(&jwk(
        "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
        "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
    ))
    .expect("Alice's ephemeral key");
    let key = concat_kdf(&bob, &alice, "A128GCM", b"Alice", b"Bob").expect("A128GCM");
    assert_eq!(key, b64("VqqN6vgjbSBcIijNcacQGg"));
}

#[test]
fn a_jwe_to_the_posted_key_decrypts_and_one_to_another_key_does_not() {
    let module = TestRequestDecryption;
    let posted = Node::Object(
        module
            .ephemeral_key()
            .expect("key")
            .public()
            .object()
            .clone(),
    );
    for (enc, zip) in [("A128GCM", false), ("A256GCM", true)] {
        let jwe = encrypt_to(&posted, enc, zip, b"eyJ.payload.sig").expect("encrypts");
        let parsed = CompactJwe::parse(&jwe, &DECRYPTS).expect("a JWE");
        let key = module.ephemeral_key().expect("key");
        assert_eq!(
            module.decrypt(key, &parsed).expect("decrypts"),
            b"eyJ.payload.sig"
        );
    }
    let other = scalar_jwk(9).expect("another key");
    let jwe = encrypt_to(&other, "A128GCM", false, b"eyJ.payload.sig").expect("encrypts");
    let parsed = CompactJwe::parse(&jwe, &DECRYPTS).expect("a JWE");
    let key = module.ephemeral_key().expect("key");
    assert_eq!(module.decrypt(key, &parsed), Err(DecryptFailed));
}
