//! The Verifier's reply to a direct post (Section 8.2).

use serde_json::Value;
use siros_codec::json::JsonTextError;

use super::{ReplyFault, ResponseError};
use crate::bound;

/// The Verifier's reply to a [`Post`](super::Post): a JSON object, with the `redirect_uri` the
/// wallet sends the user agent to when present (Section 8.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    redirect_uri: Option<RedirectUri>,
}

impl Reply {
    /// The most bytes of a reply this parse takes.
    pub const MAX_BYTES: usize = 64 * 1024;

    /// The reply whose body is `body`. Members other than `redirect_uri` are ignored.
    ///
    /// # Errors
    ///
    /// [`ResponseError::ReplyUnreadable`] for a body longer than [`Self::MAX_BYTES`] or no JSON
    /// object, and [`ResponseError::RedirectUriInvalid`] for a `redirect_uri` that is no
    /// absolute URI.
    pub fn parse(body: &[u8]) -> Result<Self, ResponseError> {
        let unreadable = ResponseError::ReplyUnreadable;
        bound::within(body, Self::MAX_BYTES)
            .map_err(|fault| unreadable(ReplyFault::TooLarge(fault)))?;
        let reply: Value = serde_json::from_slice(body)
            .map_err(|error| unreadable(ReplyFault::NotJson(JsonTextError::of(&error))))?;
        let Value::Object(reply) = reply else {
            return Err(unreadable(ReplyFault::NotObject));
        };
        let redirect_uri = match reply.get("redirect_uri") {
            None => None,
            Some(Value::String(uri)) => {
                Some(RedirectUri::parse(uri).ok_or(ResponseError::RedirectUriInvalid)?)
            }
            Some(_) => return Err(ResponseError::RedirectUriInvalid),
        };
        Ok(Self { redirect_uri })
    }

    /// `redirect_uri`, when the reply has one.
    #[must_use]
    pub fn redirect_uri(&self) -> Option<&RedirectUri> {
        self.redirect_uri.as_ref()
    }
}

/// The `redirect_uri` of a Verifier's reply: an absolute URI (RFC 3986, Section 4.3).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RedirectUri(String);

impl RedirectUri {
    /// The URI `uri`: `scheme ":" …` with `scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`
    /// (RFC 3986, Section 3.1), something after the colon, and no whitespace or control
    /// character.
    fn parse(uri: &str) -> Option<Self> {
        let (scheme, rest) = uri.split_once(':')?;
        let mut chars = scheme.bytes();
        let absolute = chars.next().is_some_and(|c| c.is_ascii_alphabetic())
            && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'-' | b'.'))
            && !rest.is_empty()
            && !uri
                .bytes()
                .any(|b| b.is_ascii_whitespace() || b.is_ascii_control());
        absolute.then(|| Self(uri.to_owned()))
    }

    /// The URI.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
