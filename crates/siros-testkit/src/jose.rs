//! JOSE with real cryptography, for the doubles of HAIP's `verify` and of `RequestDecryption`,
//! and for the Verifier's side of the tests: ES256 signatures (RFC 7518 §3.4, deterministic
//! under RFC 6979) and ECDH-ES JWEs with A128GCM or A256GCM (RFC 7518 §4.6, §5.3), `zip` DEF
//! (RFC 7516 §4.1.3).

use std::borrow::Cow;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::{Coordinates, ToSec1Point};
use p256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};
use siros_openid4vp::detail;
use siros_openid4vp::host::{DecryptFailed, EphemeralKey, KeyHandle, RequestDecryption};
use siros_openid4vp::jose::{CompactJwe, JweAlgorithms, PublicJwk, VerificationKey};
use siros_openid4vp::json::Node;
use siros_openid4vp::plugins::Fault;
use siros_openid4vp::request::{ContentEncryption, Curve, KeyAgreement};

use crate::FAULT;

/// RFC 6979 A.2.5's P-256 private key: the test Verifier's signing key.
pub const VERIFIER_SECRET: [u8; 32] = [
    0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21, 0x57, 0x67, 0xb1, 0xd6, 0x93,
    0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12, 0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f, 0x67, 0x21,
];

/// The scalar the [`TestRequestDecryption`] double draws: SHA-256 of
/// `siros-testkit wallet ephemeral key`.
const WALLET_EPHEMERAL: [u8; 32] = [
    0x87, 0xf8, 0x5d, 0xe7, 0xd2, 0x36, 0x83, 0x9c, 0x1a, 0xa0, 0x04, 0x13, 0xe5, 0xcb, 0x6d, 0x8a,
    0x75, 0x2e, 0xbe, 0xc8, 0x62, 0x84, 0x96, 0x52, 0xd4, 0xbc, 0xff, 0xa0, 0x8d, 0x21, 0x6f, 0x26,
];

/// The Verifier's ephemeral scalar for the JWEs it encrypts: SHA-256 of
/// `siros-testkit verifier ephemeral key`.
const VERIFIER_EPHEMERAL: [u8; 32] = [
    0xc2, 0xb2, 0xc2, 0xdc, 0xc1, 0x21, 0x37, 0x53, 0x53, 0x37, 0x77, 0x25, 0x8e, 0x48, 0x64, 0x46,
    0x8c, 0x11, 0x3a, 0xa5, 0x1c, 0xe8, 0x42, 0xab, 0x7b, 0x49, 0xa5, 0x5f, 0x3e, 0x5f, 0xac, 0xd8,
];

fn secret(bytes: &[u8; 32]) -> Result<SecretKey, Fault> {
    SecretKey::from_slice(bytes).map_err(|e| Fault::caused(FAULT, detail!("a test scalar"), e))
}

/// The public JWK of a P-256 key: `kty` `EC`, `crv` `P-256`, `x`, `y` (RFC 7518 §6.2.1).
///
/// # Errors
///
/// The point is the identity, which no key of a scalar is.
pub fn p256_jwk(public: &PublicKey) -> Result<PublicJwk, Fault> {
    let point = public.to_sec1_point(false);
    let Coordinates::Uncompressed { x, y } = point.coordinates() else {
        return Err(Fault::new(
            FAULT,
            detail!("the key's point has no coordinates"),
        ));
    };
    let text = |value: String| Node::String(Cow::Owned(value));
    let jwk = Node::object([
        (Cow::Borrowed("kty"), text("EC".to_owned())),
        (Cow::Borrowed("crv"), text("P-256".to_owned())),
        (Cow::Borrowed("x"), text(URL_SAFE_NO_PAD.encode(x))),
        (Cow::Borrowed("y"), text(URL_SAFE_NO_PAD.encode(y))),
    ])
    .map_err(|e| Fault::caused(FAULT, detail!("a P-256 JWK"), e))?;
    PublicJwk::parse(jwk).map_err(|e| Fault::caused(FAULT, detail!("a P-256 JWK"), e))
}

/// The public JWK of the P-256 scalar of 32 octets of one value: a key the tests did not post.
///
/// # Errors
///
/// The octets are no scalar of P-256.
pub fn scalar_jwk(octet: u8) -> Result<Node<'static>, Fault> {
    let public = p256_jwk(&secret(&[octet; 32])?.public_key())?;
    Ok(Node::Object(public.object().clone()))
}

/// The P-256 point of a JWK's `x` and `y`, 32 octets each (RFC 7518 §6.2.1.2, §6.2.1.3): SEC 1
/// §2.3.4's uncompressed point, which p256 refuses off the curve.
#[must_use]
pub fn p256_point(jwk: &Node<'_>) -> Option<PublicKey> {
    let member = |name: &str| jwk.get(name).and_then(Node::as_str);
    if member("kty") != Some("EC") || member("crv") != Some("P-256") {
        return None;
    }
    let coordinate = |name: &str| -> Option<[u8; 32]> {
        URL_SAFE_NO_PAD.decode(member(name)?).ok()?.try_into().ok()
    };
    let point: Vec<u8> = [4u8]
        .iter()
        .chain(&coordinate("x")?)
        .chain(&coordinate("y")?)
        .copied()
        .collect();
    PublicKey::from_sec1_bytes(&point).ok()
}

/// The P-256 point of a public JWK.
fn jwk_point(jwk: &PublicJwk) -> Option<PublicKey> {
    p256_point(&Node::Object(jwk.object().clone()))
}

/// The test Verifier's public key.
///
/// # Errors
///
/// The constant is no scalar of P-256, a bug of the kit.
pub fn verifier_key() -> Result<VerificationKey, Fault> {
    Ok(VerificationKey::of(p256_jwk(
        &secret(&VERIFIER_SECRET)?.public_key(),
    )?))
}

/// The ES256 signature of the signing input under a key: R and S, base64url.
///
/// # Errors
///
/// The scalar is no key of P-256.
pub fn sign(key: &[u8; 32], signing_input: &str) -> Result<String, Fault> {
    let signer = SigningKey::from(secret(key)?);
    let signature: Signature = signer.sign(signing_input.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

/// A compact JWS of the header and the payload, as written, signed with ES256 under the key.
///
/// # Errors
///
/// The scalar is no key of P-256.
pub fn compact_jws(key: &[u8; 32], header: &str, payload: &str) -> Result<String, Fault> {
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(payload)
    );
    let signature = sign(key, &input)?;
    Ok(format!("{input}.{signature}"))
}

/// Whether an ES256 signature verifies under a P-256 JWK, as HAIP's `verify` checks it: a key
/// of another curve, or a point off P-256, verifies nothing.
#[must_use]
pub fn verifies(key: &VerificationKey, signing_input: &[u8], signature: &[u8]) -> bool {
    match (jwk_point(key.jwk()), Signature::from_slice(signature)) {
        (Some(public), Ok(signature)) => VerifyingKey::from(public)
            .verify(signing_input, &signature)
            .is_ok(),
        _ => false,
    }
}

/// What the decryption double decrypts: keys on P-256, ECDH-ES, A256GCM and A128GCM (HAIP §5).
pub const DECRYPTS: JweAlgorithms = match JweAlgorithms::new(
    &[Curve::P_256],
    &[KeyAgreement::ECDH_ES],
    &[ContentEncryption::A256GCM, ContentEncryption::A128GCM],
) {
    Some(stated) => stated,
    #[allow(
        clippy::panic,
        reason = "a panic in a constant fails the build (E0080)"
    )]
    None => panic!("each list states one or more"),
};

/// The handle of the one key the decryption double draws.
const EPHEMERAL_HANDLE: u64 = 1;

/// The decryption double: a fixed ephemeral key, and RFC 7516 §5.2's decryption of an ECDH-ES
/// JWE under it.
#[derive(Debug, Clone, Copy, Default)]
pub struct TestRequestDecryption;

impl RequestDecryption for TestRequestDecryption {
    fn decrypts(&self) -> JweAlgorithms {
        DECRYPTS
    }

    fn ephemeral_key(&self) -> Result<EphemeralKey, Fault> {
        let public = p256_jwk(&secret(&WALLET_EPHEMERAL)?.public_key())?;
        Ok(EphemeralKey::new(public, KeyHandle::new(EPHEMERAL_HANDLE)))
    }

    fn decrypt(&self, key: EphemeralKey, jwe: &CompactJwe<'_>) -> Result<Vec<u8>, DecryptFailed> {
        if key.handle().id() != EPHEMERAL_HANDLE {
            return Err(DecryptFailed);
        }
        let secret = secret(&WALLET_EPHEMERAL).map_err(|_| DecryptFailed)?;
        decrypt(&secret, jwe).ok_or(DecryptFailed)
    }
}

/// RFC 7516 §5.2 for ECDH-ES (RFC 7518 §4.6): the content key agreed with `epk` and derived by
/// the Concat KDF, the AES-GCM tag checked over the protected header, a DEF `zip` inflated.
fn decrypt(secret: &SecretKey, jwe: &CompactJwe<'_>) -> Option<Vec<u8>> {
    let [protected, encrypted_key, iv, ciphertext, tag] =
        jwe.as_str().split('.').collect::<Vec<_>>()[..]
    else {
        return None;
    };
    if !encrypted_key.is_empty() {
        return None;
    }
    let header = jwe.header();
    let point = p256_point(header.get("epk")?)?;
    let enc = header.get("enc")?.as_str()?;
    let party = |name: &str| match header.get(name) {
        None => Some(Vec::new()),
        Some(value) => URL_SAFE_NO_PAD.decode(value.as_str()?).ok(),
    };
    let content_key = concat_kdf(secret, &point, enc, &party("apu")?, &party("apv")?)?;
    let mut sealed = URL_SAFE_NO_PAD.decode(ciphertext).ok()?;
    sealed.extend(URL_SAFE_NO_PAD.decode(tag).ok()?);
    let iv = URL_SAFE_NO_PAD.decode(iv).ok()?;
    let payload = Payload {
        msg: &sealed,
        aad: protected.as_bytes(),
    };
    let plaintext = match enc {
        "A128GCM" => Aes128Gcm::new_from_slice(&content_key)
            .ok()?
            .decrypt(iv.as_slice().try_into().ok()?, payload)
            .ok()?,
        "A256GCM" => Aes256Gcm::new_from_slice(&content_key)
            .ok()?
            .decrypt(iv.as_slice().try_into().ok()?, payload)
            .ok()?,
        _ => return None,
    };
    match header.get("zip").map(Node::as_str) {
        None => Some(plaintext),
        Some(Some("DEF")) => miniz_oxide::inflate::decompress_to_vec(&plaintext).ok(),
        Some(_) => None,
    }
}

/// RFC 7518 §4.6.2: the Concat KDF over the shared secret, `enc` as the AlgorithmID, PartyUInfo,
/// PartyVInfo and the key length; one SHA-256 round covers 128 and 256 bits. `None` for another
/// `enc`.
#[must_use]
pub fn concat_kdf(
    secret: &SecretKey,
    public: &PublicKey,
    enc: &str,
    apu: &[u8],
    apv: &[u8],
) -> Option<Vec<u8>> {
    let bits: u32 = match enc {
        "A128GCM" => 128,
        "A256GCM" => 256,
        _ => return None,
    };
    let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), public.as_affine());
    let length = |data: &[u8]| u32::try_from(data.len()).map(u32::to_be_bytes).ok();
    let digest = Sha256::new()
        .chain_update(1u32.to_be_bytes())
        .chain_update(shared.raw_secret_bytes())
        .chain_update(length(enc.as_bytes())?)
        .chain_update(enc.as_bytes())
        .chain_update(length(apu)?)
        .chain_update(apu)
        .chain_update(length(apv)?)
        .chain_update(apv)
        .chain_update(bits.to_be_bytes())
        .finalize();
    digest.get(..(bits / 8) as usize).map(<[u8]>::to_vec)
}

/// A compact JWE of the plaintext to a P-256 JWK under ECDH-ES and `enc`, as a Verifier encrypts
/// a Request Object to the posted key; `zip` compresses it with DEF first. The Verifier's
/// ephemeral key and the IV are fixed.
///
/// # Errors
///
/// The JWK is no P-256 key, or `enc` neither A128GCM nor A256GCM.
pub fn encrypt_to(jwk: &Node<'_>, enc: &str, zip: bool, plaintext: &[u8]) -> Result<String, Fault> {
    let fault = |what: &'static str| Fault::new(FAULT, detail!("the JWE's {what}", what = what));
    let recipient = p256_point(jwk).ok_or_else(|| fault("key"))?;
    let ephemeral = secret(&VERIFIER_EPHEMERAL)?;
    let point = ephemeral.public_key().to_sec1_point(false);
    let Coordinates::Uncompressed { x, y } = point.coordinates() else {
        return Err(fault("ephemeral key"));
    };
    let text = |value: String| Node::String(Cow::Owned(value));
    let epk = Node::object([
        (Cow::Borrowed("kty"), text("EC".to_owned())),
        (Cow::Borrowed("crv"), text("P-256".to_owned())),
        (Cow::Borrowed("x"), text(URL_SAFE_NO_PAD.encode(x))),
        (Cow::Borrowed("y"), text(URL_SAFE_NO_PAD.encode(y))),
    ])
    .map_err(|_| fault("epk"))?;
    let mut members = vec![
        (Cow::Borrowed("alg"), text("ECDH-ES".to_owned())),
        (Cow::Borrowed("enc"), text(enc.to_owned())),
        (Cow::Borrowed("epk"), epk),
    ];
    if zip {
        members.push((Cow::Borrowed("zip"), text("DEF".to_owned())));
    }
    let header = Node::object(members).map_err(|_| fault("header"))?;
    let protected = URL_SAFE_NO_PAD.encode(header.python_compact().to_string());
    let content_key =
        concat_kdf(&ephemeral, &recipient, enc, &[], &[]).ok_or_else(|| fault("content key"))?;
    let compressed;
    let message = if zip {
        compressed = miniz_oxide::deflate::compress_to_vec(plaintext, 6);
        compressed.as_slice()
    } else {
        plaintext
    };
    let iv = [7u8; 12];
    let payload = Payload {
        msg: message,
        aad: protected.as_bytes(),
    };
    let sealed = match enc {
        "A128GCM" => Aes128Gcm::new_from_slice(&content_key)
            .map_err(|_| fault("content key"))?
            .encrypt(&iv.into(), payload),
        "A256GCM" => Aes256Gcm::new_from_slice(&content_key)
            .map_err(|_| fault("content key"))?
            .encrypt(&iv.into(), payload),
        _ => return Err(fault("enc")),
    }
    .map_err(|_| fault("ciphertext"))?;
    let (ciphertext, tag) = sealed
        .split_at_checked(sealed.len().saturating_sub(16))
        .ok_or_else(|| fault("ciphertext"))?;
    Ok(format!(
        "{protected}..{}.{}.{}",
        URL_SAFE_NO_PAD.encode(iv),
        URL_SAFE_NO_PAD.encode(ciphertext),
        URL_SAFE_NO_PAD.encode(tag)
    ))
}
