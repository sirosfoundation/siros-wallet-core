//! Integrity metadata (W3C Subresource Integrity, Section 3): the `#integrity` claims of
//! SD-JWT VC (Section 7), the `#integrity` siblings of payload images, and the fragments of the
//! URLs an SVG document references.

use siros_codec::base64;

use crate::hash::HashAlg;

/// The digests of the strongest algorithm an integrity metadata string names (SRI, Section
/// 3.3.4): at least one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Integrity {
    alg: HashAlg,
    digests: Vec<Vec<u8>>,
}

/// Why integrity metadata refuses a document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}", self.code())]
pub enum IntegrityFault {
    /// The metadata has no expression of SHA-256, SHA-384 or SHA-512, or one whose value is
    /// not the base64 of a digest of its algorithm.
    Malformed,
    /// The document's digest is none the metadata lists (SRI, Section 3.3.5).
    Mismatch,
}

impl IntegrityFault {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Malformed => "integrity_malformed",
            Self::Mismatch => "integrity_mismatch",
        }
    }
}

impl Integrity {
    /// The integrity metadata `text`: whitespace-separated `alg-base64` expressions, each with
    /// optional `?` options (SRI, Section 3.1).
    ///
    /// # Errors
    ///
    /// [`IntegrityFault::Malformed`].
    pub fn parse(text: &str) -> Result<Self, IntegrityFault> {
        let expressions = text
            .split_ascii_whitespace()
            .filter_map(expression)
            .map(|(alg, value)| {
                base64::decode(value)
                    .ok()
                    .filter(|digest| digest.len() == alg.len())
                    .map(|digest| (alg, digest))
                    .ok_or(IntegrityFault::Malformed)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let alg = expressions
            .iter()
            .map(|(alg, _)| *alg)
            .max()
            .ok_or(IntegrityFault::Malformed)?;
        Ok(Self {
            alg,
            digests: expressions
                .into_iter()
                .filter(|(a, _)| *a == alg)
                .map(|(_, digest)| digest)
                .collect(),
        })
    }

    /// Refuses `document` unless its digest is one the metadata lists (SRI, Section 3.3.5).
    ///
    /// # Errors
    ///
    /// [`IntegrityFault::Mismatch`].
    pub fn check(&self, document: &[u8]) -> Result<(), IntegrityFault> {
        if self.digests.contains(&self.alg.digest(document)) {
            Ok(())
        } else {
            Err(IntegrityFault::Mismatch)
        }
    }
}

/// The algorithm and the base64 value of the SRI token `token`, its options aside; `None` for
/// a token of an algorithm this wallet does not compute.
fn expression(token: &str) -> Option<(HashAlg, &str)> {
    let expression = token.split('?').next().unwrap_or(token);
    let (name, value) = expression.split_once('-')?;
    Some((HashAlg::sri_named(name)?, value))
}
