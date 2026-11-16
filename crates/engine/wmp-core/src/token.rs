//! Resumption tokens: generation from caller-supplied entropy, and
//! constant-time comparison.

/// The entropy of a resumption token: 192 bits, above the 128-bit minimum of
/// core §4.5.2 — mirroring `wmp.resumptionTokenBytes` in go-wmp.
pub const RESUMPTION_TOKEN_BYTES: usize = 24;

/// Creates a fresh unguessable resumption token from `entropy`: 192 bits,
/// base64url without padding.
///
/// go-wmp samples `crypto/rand` itself; this crate has no ambient
/// randomness, so the caller supplies the entropy (an operating-system RNG in
/// production adapters, fixed bytes in tests).
pub fn new_resumption_token(entropy: [u8; RESUMPTION_TOKEN_BYTES]) -> String {
    encode_base64url(&entropy)
}

/// Compares two tokens in constant time for equal lengths. Use it for every
/// resumption-token comparison — mirroring `wmp.TokensEqual`.
pub fn tokens_equal(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Unpadded base64url (`RFC 4648` §5, without `=`), as used by resumption
/// tokens and request identifiers.
pub fn base64url_unpadded(bytes: &[u8]) -> String {
    encode_base64url(bytes)
}

fn encode_base64url(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        // Slice patterns, not indexing: every byte is bound by the pattern,
        // and `chunks(3)` only ever yields one of these three shapes.
        match chunk {
            [b0, b1, b2] => {
                let n = (u32::from(*b0) << 16) | (u32::from(*b1) << 8) | u32::from(*b2);
                out.push(six_to_char(((n >> 18) & 0x3f) as u8));
                out.push(six_to_char(((n >> 12) & 0x3f) as u8));
                out.push(six_to_char(((n >> 6) & 0x3f) as u8));
                out.push(six_to_char((n & 0x3f) as u8));
            }
            [b0, b1] => {
                let n = (u32::from(*b0) << 16) | (u32::from(*b1) << 8);
                out.push(six_to_char(((n >> 18) & 0x3f) as u8));
                out.push(six_to_char(((n >> 12) & 0x3f) as u8));
                out.push(six_to_char(((n >> 6) & 0x3f) as u8));
            }
            [b0] => {
                let n = u32::from(*b0) << 16;
                out.push(six_to_char(((n >> 18) & 0x3f) as u8));
                out.push(six_to_char(((n >> 12) & 0x3f) as u8));
            }
            _ => {}
        }
    }
    out
}

/// The base64url character for a 6-bit value (`v & 0x3f`): the URL-safe
/// alphabet `A`–`Z`, `a`–`z`, `0`–`9`, `-`, `_`.
fn six_to_char(v: u8) -> char {
    let v = v & 0x3f;
    if v < 26 {
        (b'A' + v) as char
    } else if v < 52 {
        (b'a' + (v - 26)) as char
    } else if v < 62 {
        (b'0' + (v - 52)) as char
    } else if v == 62 {
        '-'
    } else {
        '_'
    }
}
