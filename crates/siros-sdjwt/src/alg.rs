//! The hash algorithms `_sd_alg` may name (RFC 9901 §4.1.1, §9.4), and the digests they give.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest as _, Sha256, Sha384, Sha512};
use siros_explain::{IntoArg, Kind};

/// A hash algorithm of the IANA "Named Information Hash Algorithm" registry §9.4 deems fit. The
/// truncated `sha-256-*` entries are unfit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HashAlg {
    Sha256,
    Sha384,
    Sha512,
}

/// A digest as an SD-JWT writes it: the base64url text of a hash (§4.2.3), kept as written; a
/// decoy may be any string.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Digest(String);

impl Digest {
    /// The digest `text`, as written.
    #[must_use]
    pub fn new(text: &str) -> Self {
        Self(text.to_owned())
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl IntoArg for Digest {
    type Kind = <String as IntoArg>::Kind;

    fn arg(&self) -> <Self::Kind as Kind>::Of<'_> {
        self.0.arg()
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

    /// The digest of `input` (§4.2.3).
    pub(crate) fn digest(self, input: &[u8]) -> Digest {
        Digest(match self {
            Self::Sha256 => URL_SAFE_NO_PAD.encode(Sha256::digest(input)),
            Self::Sha384 => URL_SAFE_NO_PAD.encode(Sha384::digest(input)),
            Self::Sha512 => URL_SAFE_NO_PAD.encode(Sha512::digest(input)),
        })
    }
}
