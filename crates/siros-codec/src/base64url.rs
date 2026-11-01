//! base64url without padding (RFC 4648, Section 5), as OpenID4VP writes bytes in JSON.

use std::fmt;

use crate::sextets::{self, Base64Error};

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Text that is base64url without padding and with zero trailing bits: the one encoding of its
/// bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Base64Url {
    text: String,
    bytes: Vec<u8>,
}

impl Base64Url {
    /// The text `text`.
    ///
    /// # Errors
    ///
    /// [`Base64Error`]: the first rule `text` breaks.
    pub fn parse(text: &str) -> Result<Self, Base64Error> {
        Ok(Self {
            bytes: decode(text)?,
            text: text.to_owned(),
        })
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The bytes the text encodes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The text, owned.
    #[must_use]
    pub fn into_string(self) -> String {
        self.text
    }
}

impl fmt::Display for Base64Url {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl From<Base64Url> for String {
    fn from(encoded: Base64Url) -> Self {
        encoded.text
    }
}

impl PartialEq<str> for Base64Url {
    fn eq(&self, other: &str) -> bool {
        self.text == other
    }
}

impl PartialEq<&str> for Base64Url {
    fn eq(&self, other: &&str) -> bool {
        self.text == *other
    }
}

/// The encoding of `bytes`.
#[must_use]
pub fn encode(bytes: &[u8]) -> Base64Url {
    Base64Url {
        text: encode_text(bytes),
        bytes: bytes.to_vec(),
    }
}

fn encode_text(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk.first().copied().unwrap_or(0),
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..=chunk.len() {
            let sextet = (n >> (18 - 6 * i)) & 0x3f;
            out.push(char::from(
                ALPHABET.get(sextet as usize).copied().unwrap_or(b'A'),
            ));
        }
    }
    out
}

/// The bytes of `text`, which must be base64url without padding and with zero trailing bits.
///
/// # Errors
///
/// [`Base64Error`]: the first rule `text` breaks.
pub fn decode(text: &str) -> Result<Vec<u8>, Base64Error> {
    let bytes = text.as_bytes();
    // A tail of exactly one character carries no byte: no encoder produces it.
    if bytes.len() % 4 == 1 {
        return Err(Base64Error::Length);
    }
    sextets::decode(bytes, sextet)
}

fn sextet(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}
