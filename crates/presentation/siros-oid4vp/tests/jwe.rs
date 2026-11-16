//! An encrypted response decrypts to its payload under the verifier's key, with JWE code
//! written here from RFC 7516 and RFC 7518.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod support;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use siros_codec::base64url;
use siros_oid4vp::{
    ErrorCode, IntakeState, Origin, PostBody, PostParameters, Presentation, ResponseMode,
    Submission, VerifiedRequest,
};
use support::*;

/// The verifier's encryption key.
fn recipient() -> SecretKey {
    SecretKey::from_bytes(&[21; 32].into()).unwrap()
}

fn recipient_jwk(kid: Option<&str>) -> Value {
    let point = recipient().public_key().to_encoded_point(false);
    let mut jwk = json!({
        "kty": "EC", "crv": "P-256", "alg": "ECDH-ES", "use": "enc",
        "x": b64(point.x().unwrap()), "y": b64(point.y().unwrap()),
    });
    if let Some(kid) = kid {
        jwk["kid"] = kid.into();
    }
    jwk
}

/// The JWE Compact Serialization `jwe` decrypted with `recipient` (RFC 7516, Section 5.2):
/// its protected header and its plaintext.
fn decrypt(jwe: &str, recipient: &SecretKey) -> (Value, Vec<u8>) {
    let parts: Vec<&str> = jwe.split('.').collect();
    let [protected, encrypted_key, iv, ciphertext, tag] = parts[..] else {
        panic!("five parts: {jwe}")
    };
    // RFC 7518, Section 4.6: Direct Key Agreement has an empty JWE Encrypted Key.
    assert_eq!(encrypted_key, "");
    let header: Value = serde_json::from_slice(&base64url::decode(protected).unwrap()).unwrap();
    assert_eq!(header["alg"], "ECDH-ES");
    let epk = &header["epk"];
    assert_eq!((&epk["kty"], &epk["crv"]), (&json!("EC"), &json!("P-256")));
    let point = [
        vec![4],
        base64url::decode(epk["x"].as_str().unwrap()).unwrap(),
        base64url::decode(epk["y"].as_str().unwrap()).unwrap(),
    ]
    .concat();
    let epk = PublicKey::from_sec1_bytes(&point).unwrap();
    let z = p256::ecdh::diffie_hellman(recipient.to_nonzero_scalar(), epk.as_affine());
    let enc = header["enc"].as_str().unwrap();
    let bits: u32 = match enc {
        "A128GCM" => 128,
        "A256GCM" => 256,
        other => panic!("enc {other}"),
    };
    // RFC 7518, Section 4.6.2: one round of Concat KDF over Z and OtherInfo, with the empty
    // PartyUInfo and PartyVInfo of a header without `apu` and `apv`.
    assert!(header.get("apu").is_none() && header.get("apv").is_none());
    let mut round = Sha256::new();
    round.update([0, 0, 0, 1]);
    round.update(z.raw_secret_bytes());
    round.update((enc.len() as u32).to_be_bytes());
    round.update(enc.as_bytes());
    round.update([0, 0, 0, 0, 0, 0, 0, 0]);
    round.update(bits.to_be_bytes());
    let digest = round.finalize();
    let cek = &digest[..bits as usize / 8];
    let iv: [u8; 12] = base64url::decode(iv).unwrap().try_into().unwrap();
    let iv = Nonce::from(iv);
    let sealed = [
        base64url::decode(ciphertext).unwrap(),
        base64url::decode(tag).unwrap(),
    ]
    .concat();
    let payload = Payload {
        msg: &sealed,
        aad: protected.as_bytes(),
    };
    let plaintext = match bits {
        128 => Aes128Gcm::new_from_slice(cek)
            .unwrap()
            .decrypt(&iv, payload),
        _ => Aes256Gcm::new_from_slice(cek)
            .unwrap()
            .decrypt(&iv, payload),
    }
    .unwrap();
    (header, plaintext)
}

/// An unsigned DC API request for `dc_api.jwt`, with `client_metadata` holding the
/// recipient's key and, when given, `encrypted_response_enc_values_supported`.
fn dc_api_request(kid: Option<&str>, enc: Option<Value>) -> VerifiedRequest {
    let mut metadata = json!({"jwks": {"keys": [recipient_jwk(kid)]}});
    if let Some(enc) = enc {
        metadata["encrypted_response_enc_values_supported"] = enc;
    }
    let data = json!({
        "response_type": "vp_token", "response_mode": "dc_api.jwt", "nonce": "n-0S6_WzA2Mj",
        "dcql_query": query(), "client_metadata": metadata,
    });
    let state = IntakeState::dc_api(
        &dc_api("openid4vp-v1-unsigned", data),
        Origin::new("https://verifier.example"),
        now(),
    );
    let host = Host::trusting();
    run(state, |e| host.answer(e)).unwrap().0
}

/// A `redirect_uri` client's request for `direct_post.jwt`.
fn direct_post_request() -> VerifiedRequest {
    let metadata = json!({"jwks": {"keys": [recipient_jwk(Some("k1"))]}}).to_string();
    let query = query().to_string();
    let uri = authorization_uri(&[
        ("client_id", "redirect_uri:https://verifier.example/post"),
        ("response_type", "vp_token"),
        ("response_mode", "direct_post.jwt"),
        ("nonce", "n-0S6_WzA2Mj"),
        ("state", "s-1"),
        ("dcql_query", &query),
        ("client_metadata", &metadata),
    ]);
    let state = IntakeState::redirect(&uri, formats(), now(), &mut Rng(31));
    let host = Host::trusting();
    run(state, |e| host.answer(e)).unwrap().0
}

/// The JWE a submission carries: `data.response`, or the form parameter `response`.
fn jwe_of(submission: Submission) -> String {
    match submission {
        Submission::DcApi(_) => dc_api_jwe(&submission),
        Submission::Post(post) => {
            let PostParameters::Jwt(jwe) = post.parameters() else {
                panic!("direct_post.jwt, got {post:?}")
            };
            let PostBody::Form(body) = post.body() else {
                panic!("form parameters")
            };
            assert_eq!(
                form(body.as_str()),
                [("response".to_owned(), jwe.as_str().to_owned())]
            );
            jwe.as_str().to_owned()
        }
    }
}

#[test]
fn a_produced_response_decrypts_to_its_payload() {
    let presentations = || {
        vec![(
            query_id("pid"),
            vec![Presentation::text("eyJ...~WyJ...~".into())],
        )]
    };
    let vp_token = json!({"pid": ["eyJ...~WyJ...~"]});
    let cases = [
        (
            dc_api_request(Some("k1"), None),
            ResponseMode::DcApiJwt,
            "A128GCM",
            Some("k1"),
            false,
        ),
        (
            dc_api_request(None, Some(json!(["A128CBC-HS256", "A256GCM", "A128GCM"]))),
            ResponseMode::DcApiJwt,
            "A256GCM",
            None,
            false,
        ),
        (
            direct_post_request(),
            ResponseMode::DirectPostJwt,
            "A128GCM",
            Some("k1"),
            false,
        ),
        (
            direct_post_request(),
            ResponseMode::DirectPostJwt,
            "A128GCM",
            Some("k1"),
            true,
        ),
    ];
    for (seed, (request, mode, enc, kid, refusal)) in cases.into_iter().enumerate() {
        let mut rng = Rng(100 + seed as u64);
        let (submission, expected) = if refusal {
            let submission = request
                .error_submission(ErrorCode::AccessDenied, &mut rng)
                .unwrap();
            (
                submission,
                json!({"error": "access_denied", "state": "s-1"}),
            )
        } else {
            let token = request.vp_token(presentations()).unwrap();
            let mut expected = json!({"vp_token": vp_token});
            if let Some(state) = request.state() {
                expected["state"] = state.as_str().into();
            }
            (token.submission(&mut rng).unwrap(), expected)
        };
        assert_eq!(submission.mode(), mode, "case {seed}");
        let (header, plaintext) = decrypt(&jwe_of(submission), &recipient());
        assert_eq!(header["enc"], enc, "case {seed}");
        assert_eq!(
            header.get("kid").and_then(Value::as_str),
            kid,
            "case {seed}"
        );
        let payload: Value = serde_json::from_slice(&plaintext).unwrap();
        assert_eq!(payload, expected, "case {seed}");
    }
}
