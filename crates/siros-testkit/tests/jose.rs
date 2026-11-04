//! The doubles' cryptography against published vectors: RFC 6979's deterministic ES256 and RFC
//! 7518 Appendix C's ECDH-ES key agreement; and a JWE round trip through `RequestDecryption`.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use siros_openid4vp::host::{DecryptFailed, RequestDecryption};
use siros_openid4vp::jose::{CompactJwe, VerificationKey};
use siros_testkit::TestRequestDecryption;
use siros_testkit::jose::{VERIFIER_SECRET, concat_kdf, encrypt_to, sign, verifier_key, verifies};

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
    let key =
        VerificationKey::p256(ux.try_into().expect("x"), uy.try_into().expect("y")).expect("U");
    assert_eq!(key, verifier_key().expect("key"));
    let signature: [u8; 64] = signature.try_into().expect("64 octets");
    assert!(verifies(&key, b"sample", &signature));
    assert!(!verifies(&key, b"samplf", &signature));
}

#[test]
fn ecdh_es_derives_rfc_7518_appendix_cs_key() {
    let bob = p256::SecretKey::from_slice(&b64("VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"))
        .expect("Bob's key");
    let alice = VerificationKey::p256(
        b64("gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0")
            .try_into()
            .expect("x"),
        b64("SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps")
            .try_into()
            .expect("y"),
    )
    .expect("Alice's ephemeral key");
    let key = concat_kdf(&bob, alice.key(), "A128GCM", b"Alice", b"Bob").expect("A128GCM");
    assert_eq!(key, b64("VqqN6vgjbSBcIijNcacQGg"));
}

#[test]
fn a_jwe_to_the_posted_key_decrypts_and_one_to_another_key_does_not() {
    let module = TestRequestDecryption;
    let jwk = module.ephemeral_key().expect("key").jwk().expect("jwk");
    for (enc, zip) in [("A128GCM", false), ("A256GCM", true)] {
        let jwe = encrypt_to(&jwk, enc, zip, b"eyJ.payload.sig").expect("encrypts");
        let parsed = CompactJwe::parse(&jwe).expect("a JWE");
        let key = module.ephemeral_key().expect("key");
        assert_eq!(
            module.decrypt(key, &parsed).expect("decrypts"),
            b"eyJ.payload.sig"
        );
    }
    let other = p256::SecretKey::from_slice(&[9u8; 32]).expect("another key");
    let other = siros_openid4vp::host::EphemeralKey::new(other)
        .jwk()
        .expect("jwk");
    let jwe = encrypt_to(&other, "A128GCM", false, b"eyJ.payload.sig").expect("encrypts");
    let parsed = CompactJwe::parse(&jwe).expect("a JWE");
    let key = module.ephemeral_key().expect("key");
    assert_eq!(module.decrypt(key, &parsed), Err(DecryptFailed));
}
