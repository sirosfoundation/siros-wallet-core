//! The digest of a request as received, which the matcher and phase 2 each compute.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

/// base64url (no padding) of SHA-256 over the parts of the received form, each preceded by its
/// byte length as 8 big-endian bytes. The parts, by form: over the DC API, the Origin, a flag byte
/// (0 unsigned, 1 signed, 2 multisigned), then the parameters of an unsigned request, or the
/// JWS text and its payload of a signed one; by URI, the URI, the byte 0x10, and the Request
/// Object (the body, or a JWE body's plaintext). The flag byte separates the domains.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RequestDigest(String);

impl RequestDigest {
    pub(crate) fn of(parts: &[&[u8]]) -> Self {
        let hash = parts.iter().fold(Sha256::new(), |hash, part| {
            hash.chain_update((part.len() as u64).to_be_bytes())
                .chain_update(part)
        });
        Self(URL_SAFE_NO_PAD.encode(hash.finalize()))
    }

    /// The digest's text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
