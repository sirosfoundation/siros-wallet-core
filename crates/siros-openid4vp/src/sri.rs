//! W3C Subresource Integrity metadata (§3.3), for the plug-ins that verify resources or attest
//! them.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::ids::InvalidId;

/// Integrity metadata for content with sha256, the algorithm the response claims use.
#[must_use]
pub fn integrity(content: &[u8]) -> String {
    format!("sha256-{}", STANDARD.encode(Sha256::digest(content)))
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

/// W3C SRI §3.3's integrity metadata: hash expressions separated by white space, an option after
/// `?` taking no part. At least one names a supported algorithm, and the digest of each that does
/// is a `base64-value` of CSP3's grammar; an unsupported algorithm's expression is passed over
/// (§3.3.3). Only [`Integrity::parse`] makes one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Integrity(String);

/// The expressions of supported algorithms: each algorithm with its digest.
fn expressions(metadata: &str) -> impl Iterator<Item = (Algorithm, &str)> {
    metadata.split_whitespace().filter_map(|token| {
        let expression = token
            .split_once('?')
            .map_or(token, |(expression, _)| expression);
        let (name, digest) = expression.split_once('-')?;
        Some((Algorithm::parse(name)?, digest))
    })
}

/// CSP3's `base64-value`: `1*( ALPHA / DIGIT / "+" / "/" / "-" / "_" )*2( "=" )`.
fn base64_value(digest: &str) -> bool {
    let body = digest.trim_end_matches('=');
    !body.is_empty()
        && digest.len() - body.len() <= 2
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+/-_".contains(&b))
}

impl Integrity {
    /// The metadata a text writes, kept as written.
    ///
    /// # Errors
    ///
    /// The text names no supported algorithm, or a supported algorithm's digest is no
    /// `base64-value`.
    pub fn parse(text: &str) -> Result<Self, InvalidId> {
        let mut supported = expressions(text).peekable();
        if supported.peek().is_some() && supported.all(|(_, digest)| base64_value(digest)) {
            Ok(Self(text.to_owned()))
        } else {
            Err(InvalidId {
                what: "W3C SRI integrity metadata",
                value: text.to_owned(),
            })
        }
    }

    /// The metadata as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether content matches: the strongest algorithm present decides, any of its digests may
    /// match (§3.3.5).
    #[must_use]
    pub fn matches(&self, content: &[u8]) -> bool {
        let Some(strongest) = expressions(&self.0).map(|(algorithm, _)| algorithm).max() else {
            return false;
        };
        let computed = strongest.digest(content);
        expressions(&self.0).any(|(algorithm, digest)| algorithm == strongest && computed == digest)
    }
}

/// Whether content matches a text of integrity metadata. A text [`Integrity::parse`] refuses
/// matches nothing: every caller requires the check, so absent metadata cannot pass it.
#[must_use]
pub fn matches(content: &[u8], metadata: &str) -> bool {
    Integrity::parse(metadata).is_ok_and(|integrity| integrity.matches(content))
}
