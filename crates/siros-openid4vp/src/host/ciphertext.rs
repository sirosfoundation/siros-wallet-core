//! The JWE `Haip::encrypt_jwe` returns ([`SealedJwe`]), made only by its `parse`, which refuses
//! another form ([`NotSealed`]).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use siros_explain::Explain;

use crate::json::{JsonError, Node};

/// A JWE in compact serialization (RFC 7516 §7.1), as `Haip::encrypt_jwe` returns it: five
/// base64url parts without padding, the first a protected header that is a JSON object with
/// unique member names. Only [`SealedJwe::parse`] makes one.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(transparent)]
pub struct SealedJwe(String);

impl SealedJwe {
    /// The JWE of a compact serialization.
    ///
    /// # Errors
    ///
    /// A part that is no base64url without padding, another count of parts than five, or a
    /// protected header that is no JSON object with unique member names.
    pub fn parse(text: String) -> Result<Self, NotSealed> {
        let parts = text
            .split('.')
            .enumerate()
            .map(|(part, encoded)| {
                URL_SAFE_NO_PAD
                    .decode(encoded)
                    .map_err(|cause| NotSealed::JweBase64 { part, cause })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let [protected, _, _, _, _] = parts.as_slice() else {
            return Err(NotSealed::JweParts { parts: parts.len() });
        };
        let header = std::str::from_utf8(protected).map_err(NotSealed::JweHeaderUtf8)?;
        match Node::parse(header).map_err(NotSealed::JweHeader)? {
            Node::Object(_) => Ok(Self(text)),
            _ => Err(NotSealed::JweHeaderObject),
        }
    }

    /// The compact serialization.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The compact serialization, owned.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

/// A JWE `Haip::encrypt_jwe` returned that breaks its form's rule: the module broke its contract.
#[derive(Debug, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.sealed")]
pub enum NotSealed {
    /// A JWE of another count of parts than five (RFC 7516 §7.1).
    #[error("the JWE has {parts} parts, and a compact serialization has five")]
    JweParts {
        /// The parts.
        parts: usize,
    },
    /// A JWE part that is no base64url without padding (RFC 7516 §2).
    #[error("part {part} of the JWE is no base64url without padding")]
    JweBase64 {
        /// The part's position.
        part: usize,
        /// base64's reason.
        #[source]
        #[explain(skip)]
        cause: base64::DecodeError,
    },
    /// A protected header whose octets are no UTF-8 text.
    #[error("the JWE's protected header is no UTF-8 text")]
    JweHeaderUtf8(
        #[source]
        #[explain(skip)]
        std::str::Utf8Error,
    ),
    /// A protected header that is no JSON text with unique member names (RFC 7516 §4).
    #[error("the JWE's protected header is no JSON text with unique member names")]
    JweHeader(
        #[source]
        #[explain(name = "cause")]
        JsonError,
    ),
    /// A protected header that is no JSON object (RFC 7516 §4).
    #[error("the JWE's protected header is no JSON object")]
    JweHeaderObject,
}
