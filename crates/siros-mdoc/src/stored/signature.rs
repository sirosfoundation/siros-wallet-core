//! The COSE structures a key signs and the ES256 signature over them (RFC 9052, Section 4.4;
//! RFC 9053, Section 2.1).

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

/// A signature algorithm a device key states: the polymorphic ECDSA and EdDSA identifiers (RFC 9053
/// §2.1, §2.2) and their fully-specified forms on the curves of ISO/IEC 18013-5 Table 22 (RFC 9864
/// §2). An identifier outside them, an ECDH one for instance, restricts its key to something other
/// than signing (RFC 9052 §7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureAlgorithm {
    /// ES256.
    Es256,
    /// ES384.
    Es384,
    /// ES512.
    Es512,
    /// EdDSA.
    EdDsa,
    /// ESP256.
    Esp256,
    /// ESP384.
    Esp384,
    /// ESP512.
    Esp512,
    /// ESB256.
    Esb256,
    /// ESB320.
    Esb320,
    /// ESB384.
    Esb384,
    /// ESB512.
    Esb512,
    /// Ed25519.
    Ed25519,
    /// Ed448.
    Ed448,
}

impl SignatureAlgorithm {
    const ALL: [Self; 13] = [
        Self::Es256,
        Self::Es384,
        Self::Es512,
        Self::EdDsa,
        Self::Esp256,
        Self::Esp384,
        Self::Esp512,
        Self::Esb256,
        Self::Esb320,
        Self::Esb384,
        Self::Esb512,
        Self::Ed25519,
        Self::Ed448,
    ];

    /// The algorithm of a COSE identifier; `None` for an identifier of anything else.
    #[must_use]
    pub fn parse(value: i64) -> Option<Self> {
        Self::ALL.into_iter().find(|alg| alg.value() == value)
    }

    /// The COSE identifier.
    #[must_use]
    pub const fn value(self) -> i64 {
        match self {
            Self::Es256 => -7,
            Self::Es384 => -35,
            Self::Es512 => -36,
            Self::EdDsa => -8,
            Self::Esp256 => -9,
            Self::Esp384 => -51,
            Self::Esp512 => -52,
            Self::Esb256 => -265,
            Self::Esb320 => -266,
            Self::Esb384 => -267,
            Self::Esb512 => -268,
            Self::Ed25519 => -19,
            Self::Ed448 => -53,
        }
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
