//! `application/x-www-form-urlencoded`: the query of an authorization request URI, and the
//! parameters a `request_uri_method=post` request and a `direct_post` response carry.

use std::fmt;

use rustc_hash::FxHashMap;

use crate::intake::FormFault;

/// Form parameters in the `application/x-www-form-urlencoded` encoding, every byte outside the
/// unreserved set of RFC 3986, Section 2.3 percent-encoded.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FormBody(String);

impl FormBody {
    /// The encoded parameters.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for FormBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The parameters of a form-encoded string, each name once.
///
/// # Errors
///
/// [`FormFault`]: a name repeats, a percent-escape is malformed, or a decoded name or value is
/// not UTF-8.
pub(crate) fn parse(text: &str) -> Result<FxHashMap<String, String>, FormFault> {
    let mut out = FxHashMap::default();
    for pair in text.split('&').filter(|p| !p.is_empty()) {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        if out.insert(decode(name)?, decode(value)?).is_some() {
            return Err(FormFault::RepeatedName);
        }
    }
    Ok(out)
}

/// The form parameters `pairs`, in order.
pub(crate) fn encode(pairs: &[(&str, &str)]) -> FormBody {
    FormBody(
        pairs
            .iter()
            .map(|(name, value)| format!("{}={}", escape(name), escape(value)))
            .collect::<Vec<_>>()
            .join("&"),
    )
}

/// `text` with every byte outside the unreserved set percent-encoded.
fn escape(text: &str) -> String {
    text.bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
                char::from(byte).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

/// The text `text` encodes: `+` a space, `%` and two hexadecimal digits a byte.
fn decode(text: &str) -> Result<String, FormFault> {
    let mut bytes = Vec::with_capacity(text.len());
    let mut iter = text.bytes();
    while let Some(byte) = iter.next() {
        match byte {
            b'+' => bytes.push(b' '),
            b'%' => {
                let mut digit = || iter.next().and_then(hex).ok_or(FormFault::Escape);
                let high = digit()?;
                let low = digit()?;
                bytes.push(high << 4 | low);
            }
            other => bytes.push(other),
        }
    }
    String::from_utf8(bytes).map_err(|error| FormFault::NotUtf8(error.utf8_error()))
}

fn hex(digit: u8) -> Option<u8> {
    char::from(digit)
        .to_digit(16)
        .and_then(|d| u8::try_from(d).ok())
}
