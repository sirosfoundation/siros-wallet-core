//! Test utilities shared across the oid4vp tests: base64url encoding.

/// Minimal base64url encoding (unpadded), for test fixtures.
pub fn base64url(bytes: &[u8]) -> String {
    fn six_to_char(v: u8) -> char {
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
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk.first().copied().unwrap_or_default();
        let b1 = chunk.get(1).copied().unwrap_or_default();
        let b2 = chunk.get(2).copied().unwrap_or_default();
        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | b2 as u32;
        out.push(six_to_char(((n >> 18) & 0x3f) as u8));
        out.push(six_to_char(((n >> 12) & 0x3f) as u8));
        if chunk.len() > 1 {
            out.push(six_to_char(((n >> 6) & 0x3f) as u8));
        }
        if chunk.len() > 2 {
            out.push(six_to_char((n & 0x3f) as u8));
        }
    }
    out
}
