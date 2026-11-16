//! A `direct_post.cwt` response decrypts to its CBOR Authorization Response under the
//! verifier's key, with COSE code written here from RFC 9052 and RFC 9053.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod support;

use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::aes::Aes192;
use aes_gcm::{Aes128Gcm, Aes256Gcm, AesGcm, Nonce};
use ciborium::Value as Cbor;
use hmac::{Hmac, Mac};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{EncodedPoint, PublicKey, SecretKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use siros_oid4vp::{
    ErrorCode, Handover, IntakeState, JwkThumbprint, PostBody, Presentation, ResponseMode,
    Submission, VerifiedRequest,
};
use support::*;

const RESPONSE_URI: &str = "https://verifier.example/post";

fn recipient() -> SecretKey {
    SecretKey::from_bytes(&[23; 32].into()).unwrap()
}

fn coordinates() -> (String, String) {
    let point = recipient().public_key().to_encoded_point(false);
    (b64(point.x().unwrap()), b64(point.y().unwrap()))
}

/// A `redirect_uri` client's request for `direct_post.cwt`.
fn request(kid: Option<&str>, enc: Option<Value>) -> VerifiedRequest {
    let (x, y) = coordinates();
    let mut key =
        json!({"kty": "EC", "crv": "P-256", "alg": "ECDH-ES", "use": "enc", "x": x, "y": y});
    if let Some(kid) = kid {
        key["kid"] = kid.into();
    }
    let mut metadata = json!({"jwks": {"keys": [key]}});
    if let Some(enc) = enc {
        metadata["encrypted_response_enc_values_supported"] = enc;
    }
    let query = json!({"credentials": [
        {"id": "nym", "format": "zkp_req",
         "meta": {"source_format": "mso_mdoc", "doctype_value": "eu.europa.ec.eudi.nym_auth.1"},
         "_req": [{"fn_id": "pseudonym", "return": "tag"}]},
        {"id": "pid", "format": "dc+sd-jwt", "meta": {"vct_values": ["urn:pid"]},
         "claims": [{"path": ["given_name"]}]}
    ]})
    .to_string();
    let metadata = metadata.to_string();
    let uri = authorization_uri(&[
        ("client_id", &format!("redirect_uri:{RESPONSE_URI}")),
        ("response_type", "vp_token"),
        ("response_mode", "direct_post.cwt"),
        ("nonce", "n-0S6_WzA2Mj"),
        ("state", "s-1"),
        ("dcql_query", &query),
        ("client_metadata", &metadata),
    ]);
    let state = IntakeState::redirect(&uri, formats(), now(), &mut Rng(41));
    let host = Host::trusting();
    let (request, _) = run(state, |e| host.answer(e)).unwrap();
    assert_eq!(request.response_mode(), ResponseMode::DirectPostCwt);
    request
}

/// SOURCE: `zkp_req.md`, Section 4, the example `ZkpPresentation`.
fn zkp_presentation() -> Cbor {
    Cbor::Map(vec![
        (
            Cbor::Text("system_id".into()),
            Cbor::Text("urn:example:system:v1".into()),
        ),
        (
            Cbor::Text("proof_backend".into()),
            Cbor::Text("example-backend-v1".into()),
        ),
        (Cbor::Text("proof".into()), Cbor::Bytes(vec![0x9f, 0x3a])),
        (
            Cbor::Text("results".into()),
            Cbor::Map(vec![(
                Cbor::Text("tag".into()),
                Cbor::Bytes(vec![0x5f, 0x2a]),
            )]),
        ),
    ])
}

fn encode(value: &Cbor) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).unwrap();
    out
}

fn get<'a>(map: &'a Cbor, key: &Cbor) -> Option<&'a Cbor> {
    map.as_map()
        .unwrap()
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v)
}

fn int(n: i64) -> Cbor {
    Cbor::Integer(n.into())
}

/// What a `COSE_Encrypt` carries.
struct Opened {
    plaintext: Cbor,
    alg: i64,
    kid: Option<Vec<u8>>,
}

/// A `COSE_Encrypt` to `recipient` by ECDH-ES + HKDF-256 direct key agreement, opened (RFC 9052,
/// Sections 5.1 and 5.3; RFC 9053, Sections 4.1, 5.1, 5.2 and 6.3).
fn decrypt(body: &[u8], recipient: &SecretKey) -> Opened {
    let message: Cbor = ciborium::from_reader(body).unwrap();
    let Cbor::Tag(96, message) = message else {
        panic!("COSE_Encrypt tag 96: {message:?}")
    };
    let [Cbor::Bytes(protected), unprotected, Cbor::Bytes(ciphertext), Cbor::Array(recipients)] =
        &message.as_array().unwrap()[..]
    else {
        panic!("COSE_Encrypt: {message:?}")
    };
    let header: Cbor = ciborium::from_reader(&protected[..]).unwrap();
    let alg: i64 = get(&header, &int(1))
        .unwrap()
        .as_integer()
        .unwrap()
        .try_into()
        .unwrap();
    let (key_len, bits) = match alg {
        1 => (16, 128),
        2 => (24, 192),
        3 => (32, 256),
        other => panic!("alg {other}"),
    };
    let iv = get(unprotected, &int(5))
        .unwrap()
        .as_bytes()
        .unwrap()
        .clone();

    let [Cbor::Array(layer)] = &recipients[..] else {
        panic!("one recipient")
    };
    let [Cbor::Bytes(recipient_protected), recipient_unprotected, Cbor::Bytes(empty)] = &layer[..]
    else {
        panic!("recipient: {layer:?}")
    };
    assert!(
        empty.is_empty(),
        "direct key agreement has no recipient ciphertext"
    );
    let recipient_header: Cbor = ciborium::from_reader(&recipient_protected[..]).unwrap();
    assert_eq!(get(&recipient_header, &int(1)), Some(&int(-25)));
    let epk = get(recipient_unprotected, &int(-1)).unwrap();
    assert_eq!(get(epk, &int(1)), Some(&int(2)), "EC2");
    assert_eq!(get(epk, &int(-1)), Some(&int(1)), "P-256");
    let x = get(epk, &int(-2)).unwrap().as_bytes().unwrap();
    let y = get(epk, &int(-3)).unwrap().as_bytes().unwrap();
    let point = EncodedPoint::from_affine_coordinates(x[..].into(), y[..].into(), false);
    let epk = PublicKey::from_sec1_bytes(point.as_bytes()).unwrap();
    let kid = get(recipient_unprotected, &int(4)).map(|k| k.as_bytes().unwrap().clone());

    // RFC 9053, Section 5.2: the COSE_KDF_Context of direct key agreement.
    let nil = || Cbor::Array(vec![Cbor::Null, Cbor::Null, Cbor::Null]);
    let context = encode(&Cbor::Array(vec![
        int(alg),
        nil(),
        nil(),
        Cbor::Array(vec![int(bits), Cbor::Bytes(recipient_protected.clone())]),
    ]));
    // RFC 5869: HKDF-Extract without salt, then one block of HKDF-Expand.
    let z = p256::ecdh::diffie_hellman(recipient.to_nonzero_scalar(), epk.as_affine());
    let mut extract = <Hmac<Sha256> as Mac>::new_from_slice(&[0; 32]).unwrap();
    extract.update(z.raw_secret_bytes());
    let prk = extract.finalize().into_bytes();
    let mut expand = <Hmac<Sha256> as Mac>::new_from_slice(&prk).unwrap();
    expand.update(&context);
    expand.update(&[1]);
    let okm = expand.finalize().into_bytes();
    let cek = &okm[..key_len];

    // RFC 9052, Section 5.3: Enc_structure, empty external AAD.
    let aad = encode(&Cbor::Array(vec![
        Cbor::Text("Encrypt".into()),
        Cbor::Bytes(protected.clone()),
        Cbor::Bytes(Vec::new()),
    ]));
    let iv: [u8; 12] = iv.try_into().unwrap();
    let nonce = Nonce::from(iv);
    let payload = Payload {
        msg: ciphertext,
        aad: &aad,
    };
    let plaintext = match alg {
        1 => Aes128Gcm::new_from_slice(cek)
            .unwrap()
            .decrypt(&nonce, payload),
        2 => AesGcm::<Aes192, U12>::new_from_slice(cek)
            .unwrap()
            .decrypt(&nonce, payload),
        _ => Aes256Gcm::new_from_slice(cek)
            .unwrap()
            .decrypt(&nonce, payload),
    }
    .unwrap();
    Opened {
        plaintext: ciborium::from_reader(&plaintext[..]).unwrap(),
        alg,
        kid,
    }
}

/// A map's entries in key order, as the deterministic encoding writes them.
fn entries(map: &Cbor) -> Vec<(Cbor, Cbor)> {
    let mut entries = map.as_map().unwrap().clone();
    entries.sort_by_key(|(key, _)| encode(key));
    entries
}

/// The JWK SHA-256 Thumbprint of the recipient's key (RFC 7638, Section 3.2).
fn thumbprint() -> JwkThumbprint {
    let (x, y) = coordinates();
    let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    JwkThumbprint::new(Sha256::digest(canonical.as_bytes()).into())
}

#[test]
fn a_produced_cwt_response_decrypts_to_its_authorization_response() {
    let pid = "eyJ...~WyJ...~";
    let presentations = || {
        vec![
            (
                query_id("nym"),
                vec![Presentation::cbor_map(encode(&zkp_presentation())).unwrap()],
            ),
            (query_id("pid"), vec![Presentation::text(pid.into())]),
        ]
    };
    let state = (Cbor::Text("state".into()), Cbor::Text("s-1".into()));
    let vp_token = Cbor::Map(vec![
        (
            Cbor::Text("vp_token".into()),
            Cbor::Map(vec![
                (
                    Cbor::Text("nym".into()),
                    Cbor::Array(vec![zkp_presentation()]),
                ),
                (
                    Cbor::Text("pid".into()),
                    Cbor::Array(vec![Cbor::Text(pid.into())]),
                ),
            ]),
        ),
        state.clone(),
    ]);
    let refusal = Cbor::Map(vec![
        (
            Cbor::Text("error".into()),
            Cbor::Text("access_denied".into()),
        ),
        state,
    ]);
    let cases = [
        (request(Some("k1"), None), 1, Some(b"k1".to_vec()), false),
        (
            request(None, Some(json!(["A128CBC-HS256", "A192GCM"]))),
            2,
            None,
            false,
        ),
        (
            request(Some("k1"), Some(json!(["A256GCM"]))),
            3,
            Some(b"k1".to_vec()),
            true,
        ),
    ];
    for (seed, (request, alg, kid, refuse)) in cases.into_iter().enumerate() {
        let mut rng = Rng(200 + seed as u64);
        let (submission, expected) = if refuse {
            let submission = request
                .error_submission(ErrorCode::AccessDenied, &mut rng)
                .unwrap();
            (submission, &refusal)
        } else {
            let token = request.vp_token(presentations()).unwrap();
            (token.submission(&mut rng).unwrap(), &vp_token)
        };
        let Submission::Post(post) = submission else {
            panic!("a POST")
        };
        assert_eq!(post.response_uri().as_str(), RESPONSE_URI);
        assert_eq!(post.mode(), ResponseMode::DirectPostCwt, "case {seed}");
        let PostBody::Cwt(message) = post.body() else {
            panic!("a COSE_Encrypt body")
        };
        let opened = decrypt(message.as_bytes(), &recipient());
        assert_eq!(opened.alg, alg, "case {seed}");
        assert_eq!(opened.kid, kid, "case {seed}");
        assert_eq!(entries(&opened.plaintext), entries(expected), "case {seed}");

        // zkp_req.md, Section 6.2: the handover binds the key the response was encrypted to.
        let expected_handover = Handover::redirect(
            &format!("redirect_uri:{RESPONSE_URI}"),
            "n-0S6_WzA2Mj",
            Some(&thumbprint()),
            RESPONSE_URI,
        );
        assert_eq!(request.handover(), expected_handover, "case {seed}");
    }
}
