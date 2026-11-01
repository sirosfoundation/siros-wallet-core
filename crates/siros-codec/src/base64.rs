//! base64 with padding (RFC 4648, Section 4), as JOSE writes certificates in `x5c` (RFC 7515,
//! Section 4.1.6).

use crate::sextets::{self, Base64Error};

/// The bytes of `text`, which must be base64 with its padding and with zero trailing bits.
///
/// # Errors
///
/// [`Base64Error`]: the first rule `text` breaks.
pub fn decode(text: &str) -> Result<Vec<u8>, Base64Error> {
    let bytes = text.as_bytes();
    if bytes.len() % 4 != 0 {
        return Err(Base64Error::Length);
    }
    let pad = bytes.iter().rev().take_while(|&&c| c == b'=').count();
    if pad > 2 {
        return Err(Base64Error::Padding);
    }
    let body = bytes.get(..bytes.len() - pad).ok_or(Base64Error::Padding)?;
    sextets::decode(body, sextet)
}

fn sextet(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}
