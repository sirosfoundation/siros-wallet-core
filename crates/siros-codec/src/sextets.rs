//! The decoding the two base64 alphabets share (RFC 4648, Sections 4 and 5): six bits per
//! character, eight per byte, and zero bits after the last byte.

/// Why text is not base64 in the strict form this crate reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}", self.code())]
pub enum Base64Error {
    /// The length is one no encoder produces: for the padded form, not a multiple of four; for
    /// the unpadded form, one more than a multiple of four.
    Length,
    /// The padded form ends in more than two `=`.
    Padding,
    /// The byte at this offset is outside the alphabet.
    #[error("{code} at byte {0}", code = self.code())]
    Alphabet(usize),
    /// Bits after the last byte are set: the text is not the one encoding of its bytes.
    TrailingBits,
}

impl Base64Error {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Length => "base64_length",
            Self::Padding => "base64_padding",
            Self::Alphabet(_) => "base64_alphabet",
            Self::TrailingBits => "base64_trailing_bits",
        }
    }
}

/// The bytes `body` encodes, each character read by `sextet`.
pub(crate) fn decode(
    body: &[u8],
    sextet: impl Fn(u8) -> Option<u8>,
) -> Result<Vec<u8>, Base64Error> {
    let mut out = Vec::with_capacity(body.len() / 4 * 3 + 2);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for (at, &c) in body.iter().enumerate() {
        acc = (acc << 6) | u32::from(sextet(c).ok_or(Base64Error::Alphabet(at))?);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    if bits > 0 && acc & ((1 << bits) - 1) != 0 {
        return Err(Base64Error::TrailingBits);
    }
    Ok(out)
}
