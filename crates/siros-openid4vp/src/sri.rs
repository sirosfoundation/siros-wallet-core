//! W3C Subresource Integrity metadata (§3.3.5), for the plug-ins that verify resources.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::rows::SriMetadata;

/// Integrity metadata for content with sha256, the algorithm the response claims use.
#[must_use]
pub fn integrity(content: &[u8]) -> SriMetadata {
    SriMetadata::written(format!(
        "sha256-{}",
        STANDARD.encode(Sha256::digest(content))
    ))
}

/// An SRI hash algorithm, weakest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Algorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl Algorithm {
    fn parse(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "sha256" => Some(Self::Sha256),
            "sha384" => Some(Self::Sha384),
            "sha512" => Some(Self::Sha512),
            _ => None,
        }
    }

    fn digest(self, content: &[u8]) -> String {
        match self {
            Self::Sha256 => STANDARD.encode(Sha256::digest(content)),
            Self::Sha384 => STANDARD.encode(Sha384::digest(content)),
            Self::Sha512 => STANDARD.encode(Sha512::digest(content)),
        }
    }
}

/// Whether content matches integrity metadata: the strongest algorithm present decides, any of
/// its digests may match. Metadata without a supported token matches nothing: every caller
/// requires the check, so absent metadata cannot pass it.
#[must_use]
pub fn matches(content: &[u8], metadata: &SriMetadata) -> bool {
    let tokens: Vec<(Algorithm, &str)> = metadata
        .as_str()
        .split_whitespace()
        .filter_map(|token| {
            let expression = token
                .split_once('?')
                .map_or(token, |(expression, _)| expression);
            let (name, digest) = expression.split_once('-')?;
            Some((Algorithm::parse(name)?, digest))
        })
        .collect();
    let Some(strongest) = tokens.iter().map(|(algorithm, _)| *algorithm).max() else {
        return false;
    };
    tokens
        .iter()
        .any(|(algorithm, digest)| *algorithm == strongest && strongest.digest(content) == *digest)
}
