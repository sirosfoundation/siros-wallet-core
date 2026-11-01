//! ES256 verification (RFC 9053, Section 2.1).

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};

use crate::device_key::P256Key;
use siros_codec::signature::Es256Signature;

/// Whether `signature` is an ES256 signature of `message` under `key`. A key that is no curve
/// point, and a signature whose `r` or `s` is zero or not below the group order, verify
/// nothing.
#[must_use]
pub fn es256_verifies(key: &P256Key, message: &[u8], signature: &Es256Signature) -> bool {
    let (Ok(key), Ok(signature)) = (
        VerifyingKey::from_sec1_bytes(&key.sec1()),
        Signature::from_slice(signature.as_bytes()),
    ) else {
        return false;
    };
    key.verify(message, &signature).is_ok()
}
