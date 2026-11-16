//! The hash algorithms `_sd_alg` may name (RFC 9901, Sections 4.1.1 and 9.4), and the digests
//! they give.

use sha2::{Digest as _, Sha256, Sha384, Sha512};
use siros_codec::base64url;

/// A hash algorithm of the IANA "Named Information Hash Algorithm" registry that Section 9.4
/// deems fit. The truncated `sha-256-*` entries are unfit.
#[derive(Clone, Copy)]
pub(crate) enum HashAlg {
    Sha256,
    Sha384,
    Sha512,
}

/// A digest as an SD-JWT writes it: the base64url text of a hash (Section 4.2.3). A digest the
/// payload lists is kept as written; a decoy may be any string.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Digest(String);

impl Digest {
    /// The digest `text`, as written.
    #[must_use]
    pub fn new(text: &str) -> Self {
        Self(text.to_owned())
    }

    /// The digest a payload lists, as written.
    pub(crate) fn listed(text: String) -> Self {
        Self(text)
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl HashAlg {
    /// The algorithm of the case-sensitive Hash Name String `name`.
    pub(crate) fn from_name(name: &str) -> Option<Self> {
        match name {
            "sha-256" => Some(Self::Sha256),
            "sha-384" => Some(Self::Sha384),
            "sha-512" => Some(Self::Sha512),
            _ => None,
        }
    }

    /// The digest of `input` (Section 4.2.3).
    pub(crate) fn digest(self, input: &[u8]) -> Digest {
        let encoded = match self {
            Self::Sha256 => base64url::encode(&Sha256::digest(input)),
            Self::Sha384 => base64url::encode(&Sha384::digest(input)),
            Self::Sha512 => base64url::encode(&Sha512::digest(input)),
        };
        Digest(encoded.into())
    }
}
