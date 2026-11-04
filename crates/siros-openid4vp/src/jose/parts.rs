//! The pieces a JOSE serialization is made of: base64url parts without padding (RFC 7515 §2),
//! their UTF-8 text, and the JSON objects they hold.

use std::borrow::Cow;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::json::{JsonError, Node, Object};

/// A part's octets: base64url without padding, trailing bits zero.
pub(super) fn decode(part: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(part)
}

/// The UTF-8 text of decoded octets; refused as no JSON text otherwise.
pub(super) fn utf8(octets: &[u8]) -> Result<Cow<'_, str>, JsonError> {
    std::str::from_utf8(octets)
        .map(Cow::Borrowed)
        .map_err(|e| JsonError::Syntax(e.to_string()))
}

/// The JSON object of a text, each name once at every level, owning its strings.
pub(super) fn object(text: &str) -> Result<Object<'static>, JsonError> {
    match Node::parse(text)? {
        Node::Object(members) => Ok(members.into_owned()),
        _ => Err(JsonError::Syntax("no JSON object".to_owned())),
    }
}
