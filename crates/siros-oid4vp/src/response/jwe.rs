//! The encrypted response: a JWE with `ECDH-ES` key agreement and AES GCM (RFC 7516; RFC 7518,
//! Sections 4.6 and 5.3; OpenID4VP 1.0, Section 8.3), in the Compact Serialization.

use rand_core::CryptoRngCore;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use siros_codec::base64url;

use super::aead::{self, ContentKey};
use super::submission::Jwe;
use super::{EncryptionFault, ResponseError};
use crate::verified::{ContentEncryption, Encryption};

/// The Concat KDF of RFC 7518, Section 4.6.2, for the Direct Key Agreement mode: the content
/// encryption key of `enc` from the ECDH output `shared_secret`, with the PartyUInfo
/// `party_u` and PartyVInfo `party_v` (the decoded `apu` and `apv`).
///
/// # Errors
///
/// [`ResponseError::EncryptionFailed`] when a part is longer than a 32-bit length allows.
pub fn concat_kdf(
    shared_secret: &[u8],
    enc: ContentEncryption,
    party_u: &[u8],
    party_v: &[u8],
) -> Result<ContentKey, ResponseError> {
    let len = |part: &[u8]| {
        u32::try_from(part.len())
            .map_err(|_| ResponseError::EncryptionFailed(EncryptionFault::KdfInput))
    };
    let mut round = Sha256::new();
    // One round: SHA-256 yields 256 bits, and no `enc` here needs more.
    round.update(1u32.to_be_bytes());
    round.update(shared_secret);
    for part in [enc.as_str().as_bytes(), party_u, party_v] {
        round.update(len(part)?.to_be_bytes());
        round.update(part);
    }
    // SuppPubInfo: the key length in bits.
    round.update(enc.key_bits().to_be_bytes());
    ContentKey::of(enc, &round.finalize())
}

/// `payload` encrypted to the chosen key, with an ephemeral key and an IV from `rng`.
pub(super) fn encrypt(
    encryption: &Encryption,
    payload: &[u8],
    rng: &mut impl CryptoRngCore,
) -> Result<Jwe, ResponseError> {
    let agreement = aead::agree(encryption, rng)?;
    let z: &[u8] = agreement.shared.raw_secret_bytes();
    let cek = concat_kdf(z, encryption.enc, &[], &[])?;
    let mut epk = Map::new();
    epk.insert("kty".into(), "EC".into());
    epk.insert("crv".into(), "P-256".into());
    epk.insert(
        "x".into(),
        String::from(base64url::encode(&agreement.x)).into(),
    );
    epk.insert(
        "y".into(),
        String::from(base64url::encode(&agreement.y)).into(),
    );
    let mut header = Map::new();
    header.insert("alg".into(), "ECDH-ES".into());
    header.insert("enc".into(), encryption.enc.as_str().into());
    header.insert("epk".into(), Value::Object(epk));
    if let Some(kid) = &encryption.kid {
        header.insert("kid".into(), kid.as_str().into());
    }
    let protected = base64url::encode(Value::Object(header).to_string().as_bytes());
    let iv = aead::iv(rng);
    // RFC 7516, Section 5.1, step 14: the AAD is the encoded protected header.
    let sealed = aead::seal(
        encryption.enc,
        &cek,
        iv,
        protected.as_str().as_bytes(),
        payload,
    )?;
    // The JWE Encrypted Key is empty in Direct Key Agreement (RFC 7518, Section 4.6).
    Ok(Jwe::new(format!(
        "{protected}..{}.{}.{}",
        base64url::encode(&iv),
        base64url::encode(&sealed.ciphertext),
        base64url::encode(&sealed.tag)
    )))
}
