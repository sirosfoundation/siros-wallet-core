//! The COSE structures a key signs and the ES256 signature over them (RFC 9052, Section 4.4;
//! RFC 9053, Section 2.1), and the session they bind (ISO/IEC 18013-5, 9.1.5.1).

use sha2::{Digest, Sha256};

/// A COSE algorithm identifier (RFC 9053).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CoseAlgorithm(i64);

impl CoseAlgorithm {
    /// ES256: ECDSA with P-256 and SHA-256 (RFC 9053, Section 2.1).
    pub const ES256: Self = Self(-7);

    /// The algorithm `value`.
    #[must_use]
    pub fn new(value: i64) -> Self {
        Self(value)
    }

    /// The identifier.
    #[must_use]
    pub fn value(self) -> i64 {
        self.0
    }
}

/// A COSE `Sig_structure`: the bytes a `COSE_Sign1` signature covers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SigStructure(Vec<u8>);

impl SigStructure {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The encoded structure.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The SHA-256 of the structure: the message hash of an ES256 signature over it.
    #[must_use]
    pub fn digest(&self) -> MessageDigest {
        MessageDigest(Sha256::digest(&self.0).into())
    }
}

/// The SHA-256 of a [`SigStructure`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MessageDigest([u8; 32]);

impl MessageDigest {
    /// The digest.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The encoded `SessionTranscript` of the session a device signature binds.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionTranscript(Vec<u8>);

impl SessionTranscript {
    /// The encoded `SessionTranscript` `encoded`.
    #[must_use]
    pub fn new(encoded: Vec<u8>) -> Self {
        Self(encoded)
    }

    /// The encoding.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
