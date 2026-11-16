//! The encrypted CBOR response of `direct_post.cwt` (`zkp_req.md`, Section 6.2): a tagged
//! `COSE_Encrypt` (RFC 9052, Section 5.1) to one recipient by ECDH-ES + HKDF-256 direct key
//! agreement (RFC 9053, Section 6.3).

use hkdf::Hkdf;
use rand_core::CryptoRngCore;
use sha2::Sha256;
use siros_codec::cbor::Value as Cbor;

use super::aead::{self, ContentKey};
use super::submission::CoseEncrypt;
use super::{EncryptionFault, ResponseError};
use crate::verified::{ContentEncryption, Encryption};

/// The CBOR tag of `COSE_Encrypt` (RFC 9052, Section 2).
const COSE_ENCRYPT: u64 = 96;

/// COSE labels: `alg` (1), `kid` (4) and `IV` (5) of RFC 9052, Section 3.1.
const ALG: u64 = 1;
const KID: u64 = 4;
const IV: u64 = 5;

/// Negative labels and values, as the `n` of `Cbor::Negative(n)` that writes `-1 - n`: the
/// `ephemeral key` label -1 (RFC 9053, Section 6.4.1) and `ECDH-ES + HKDF-256` -25 (RFC 9053,
/// Section 6.3.1).
const EPHEMERAL_KEY: u64 = 0;
const ECDH_ES_HKDF_256: u64 = 24;

/// The recipient's protected header `{1: -25}`, encoded.
fn recipient_protected() -> Vec<u8> {
    Cbor::Map(vec![(
        Cbor::Unsigned(ALG),
        Cbor::Negative(ECDH_ES_HKDF_256),
    )])
    .encode()
}

/// The content encryption key of `enc` from the ECDH output `shared_secret`, for direct key
/// agreement by ECDH-ES + HKDF-256: HKDF with SHA-256, no salt, and as info the
/// `COSE_KDF_Context` (RFC 9053, Section 5.2) of `enc`, nil PartyU and PartyV, and the
/// recipient's protected header `{1: -25}`.
///
/// # Errors
///
/// [`ResponseError::EncryptionFailed`] when HKDF refuses the length.
pub fn cose_kdf(shared_secret: &[u8], enc: ContentEncryption) -> Result<ContentKey, ResponseError> {
    let party = || Cbor::Array(vec![Cbor::Null, Cbor::Null, Cbor::Null]);
    let context = Cbor::Array(vec![
        Cbor::Unsigned(enc.cose_alg()),
        party(),
        party(),
        Cbor::Array(vec![
            Cbor::Unsigned(u64::from(enc.key_bits())),
            Cbor::Bytes(recipient_protected()),
        ]),
    ]);
    let mut key = vec![0u8; enc.key_len()];
    Hkdf::<Sha256>::new(None, shared_secret)
        .expand(&context.encode(), &mut key)
        .map_err(|_| ResponseError::EncryptionFailed(EncryptionFault::KdfLength))?;
    ContentKey::of(enc, &key)
}

/// `plaintext` in a `COSE_Encrypt` to the chosen key, with an ephemeral key and an IV from
/// `rng`.
pub(super) fn encrypt(
    encryption: &Encryption,
    plaintext: &[u8],
    rng: &mut impl CryptoRngCore,
) -> Result<CoseEncrypt, ResponseError> {
    let agreement = aead::agree(encryption, rng)?;
    let cek = cose_kdf(agreement.shared.raw_secret_bytes(), encryption.enc)?;
    let protected = Cbor::Map(vec![(
        Cbor::Unsigned(ALG),
        Cbor::Unsigned(encryption.enc.cose_alg()),
    )])
    .encode();
    // RFC 9052, Section 5.3: Enc_structure with an empty external AAD.
    let aad = Cbor::Array(vec![
        Cbor::text("Encrypt"),
        Cbor::Bytes(protected.clone()),
        Cbor::Bytes(Vec::new()),
    ])
    .encode();
    let iv = aead::iv(rng);
    let sealed = aead::seal(encryption.enc, &cek, iv, &aad, plaintext)?;
    // RFC 9053, Section 7.1.1: an EC2 key (1: 2) on P-256 (-1: 1) with x (-2) and y (-3).
    let ephemeral = Cbor::Map(vec![
        (Cbor::Unsigned(1), Cbor::Unsigned(2)),
        (Cbor::Negative(0), Cbor::Unsigned(1)),
        (Cbor::Negative(1), Cbor::Bytes(agreement.x.to_vec())),
        (Cbor::Negative(2), Cbor::Bytes(agreement.y.to_vec())),
    ]);
    let mut unprotected = vec![(Cbor::Negative(EPHEMERAL_KEY), ephemeral)];
    if let Some(kid) = &encryption.kid {
        unprotected.push((
            Cbor::Unsigned(KID),
            Cbor::Bytes(kid.as_str().as_bytes().to_vec()),
        ));
    }
    // Direct key agreement: the recipient's ciphertext is empty.
    let recipient = Cbor::Array(vec![
        Cbor::Bytes(recipient_protected()),
        Cbor::Map(unprotected),
        Cbor::Bytes(Vec::new()),
    ]);
    let message = Cbor::Array(vec![
        Cbor::Bytes(protected),
        Cbor::Map(vec![(Cbor::Unsigned(IV), Cbor::Bytes(iv.to_vec()))]),
        Cbor::Bytes([sealed.ciphertext, sealed.tag].concat()),
        Cbor::Array(vec![recipient]),
    ]);
    Ok(CoseEncrypt::new(
        Cbor::Tag(COSE_ENCRYPT, Box::new(message)).encode(),
    ))
}
