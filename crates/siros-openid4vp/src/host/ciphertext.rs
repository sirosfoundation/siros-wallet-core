//! The modules' ciphertexts, each made only by its `parse`, which refuses another form
//! ([`NotSealed`]): a compact JWE ([`SealedJwe`]) and a tagged `COSE_Encrypt` ([`SealedCose`]);
//! and the content encryptions a `COSE_Encrypt` carries ([`CoseEnc`]).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use siros_explain::Explain;

use crate::cbor::cose::{CoseShape, read_encrypt};
use crate::cbor::{CborError, Value, decode};
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

/// A tagged `COSE_Encrypt` (RFC 9052 §5.1, tag 96), as `CoseEncrypt::encrypt_cose` returns it:
/// one CBOR data item with distinct keys at every depth, whose structure coset reads. Only
/// [`SealedCose::parse`] makes one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedCose(Vec<u8>);

impl SealedCose {
    /// The `COSE_Encrypt` of one CBOR data item tagged 96 with distinct keys at every depth,
    /// whose content is a `COSE_Encrypt` structure.
    ///
    /// # Errors
    ///
    /// The bytes are no such data item, or its content no `COSE_Encrypt`.
    pub fn parse(bytes: Vec<u8>) -> Result<Self, NotSealed> {
        let Value::Tag(96, structure) = decode(&bytes).map_err(NotSealed::Cbor)? else {
            return Err(NotSealed::Untagged);
        };
        read_encrypt(*structure)
            .map(|_structure| Self(bytes))
            .map_err(NotSealed::Structure)
    }

    /// The bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// A module's ciphertext that breaks its form's rule: the module broke its contract.
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
    /// The bytes are no CBOR data item the wallet reads.
    #[error("the ciphertext is no CBOR data item the wallet reads")]
    Cbor(
        #[source]
        #[explain(name = "cause")]
        CborError,
    ),
    /// The data item is no tag 96.
    #[error("the ciphertext is no item tagged 96 (COSE_Encrypt)")]
    Untagged,
    /// The tagged content is no `COSE_Encrypt` structure (RFC 9052 §5.1).
    #[error("the ciphertext's content is no COSE_Encrypt structure")]
    Structure(
        #[source]
        #[explain(name = "cause")]
        CoseShape,
    ),
}

/// An AES-GCM content encryption a `COSE_Encrypt` carries (RFC 9053 §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CoseEnc {
    /// A128GCM (1).
    A128Gcm,
    /// A192GCM (2).
    A192Gcm,
    /// A256GCM (3).
    A256Gcm,
}

impl CoseEnc {
    /// The algorithm's value in IANA's COSE Algorithms registry.
    #[must_use]
    pub const fn id(self) -> i64 {
        match self {
            Self::A128Gcm => 1,
            Self::A192Gcm => 2,
            Self::A256Gcm => 3,
        }
    }

    /// The algorithm's name, as RFC 9053 §4.1 and RFC 7518 §5.1 write it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::A128Gcm => "A128GCM",
            Self::A192Gcm => "A192GCM",
            Self::A256Gcm => "A256GCM",
        }
    }
}
