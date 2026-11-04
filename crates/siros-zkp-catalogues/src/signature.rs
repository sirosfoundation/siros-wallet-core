//! The ES256 signature value (RFC 7518, Section 3.4; RFC 9053, Section 2.1).

/// An ES256 signature: `r ‖ s`, 64 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Es256Signature([u8; 64]);

/// Bytes of this length, where an ES256 signature has 64.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("an ES256 signature of {0} bytes")]
pub struct SignatureLength(pub usize);

impl Es256Signature {
    /// The signature `r ‖ s`.
    #[must_use]
    pub fn new(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// The signature `bytes`.
    ///
    /// # Errors
    ///
    /// [`SignatureLength`] for bytes of another length than 64.
    pub fn parse(bytes: &[u8]) -> Result<Self, SignatureLength> {
        <[u8; 64]>::try_from(bytes)
            .map(Self)
            .map_err(|_| SignatureLength(bytes.len()))
    }

    /// `r ‖ s`.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

/// Whether `signature` is `key`'s ES256 signature of `message` (RFC 7518, Section 3.4).
#[cfg(feature = "credential")]
#[must_use]
pub fn es256_verifies(
    key: &siros_mdoc::stored::P256Key,
    message: &[u8],
    signature: &Es256Signature,
) -> bool {
    use p256::ecdsa::signature::Verifier as _;
    let (Ok(key), Ok(signature)) = (
        p256::ecdsa::VerifyingKey::from_sec1_bytes(&key.sec1()),
        p256::ecdsa::Signature::from_slice(signature.as_bytes()),
    ) else {
        return false;
    };
    key.verify(message, &signature).is_ok()
}
