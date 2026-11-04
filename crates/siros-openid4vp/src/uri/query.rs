//! The read of an Authorization Request URI's query (RFC 6749 Appendix B) through
//! serde_urlencoded, which hands the pairs to [`QueryRead`]'s `Deserialize` without checks of its
//! own.

use std::borrow::Cow;
use std::fmt;

use serde::de::{self, MapAccess, Visitor};

use crate::arrival::{Unreadable, UriError};

/// What serde_urlencoded reads from an Authorization Request URI's query: the four parameters
/// the core reads, as decoded, or the first name given twice (U4). A parameter without a value
/// is read as omitted (RFC 6749 §3.1), so it counts toward no repetition; every other name is
/// ignored, its value unread. serde_urlencoded's error holds a message alone, so the repetition
/// travels as the value, and the read stops at it.
#[derive(Debug)]
pub(super) enum QueryRead<'a> {
    /// Each name once.
    Read {
        client_id: Option<Cow<'a, str>>,
        request_uri: Option<Cow<'a, str>>,
        method: Option<Cow<'a, str>>,
        request: bool,
    },
    /// The first name given twice, known or unknown.
    Repeated(Cow<'a, str>),
}

/// The read of a query: serde_urlencoded's error (U3), or what [`QueryRead`] holds.
pub(super) fn read(query: &str) -> Result<QueryRead<'_>, Unreadable> {
    serde_urlencoded::from_str(query).map_err(|e| Unreadable::Uri(UriError::Form(e.to_string())))
}

/// A name or a value of the query, borrowed when it holds no escape.
struct Part<'a>(Cow<'a, str>);

impl<'de> de::Deserialize<'de> for Part<'de> {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Text;
        impl<'de> Visitor<'de> for Text {
            type Value = Part<'de>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a decoded name or value")
            }
            fn visit_borrowed_str<E: de::Error>(self, v: &'de str) -> Result<Part<'de>, E> {
                Ok(Part(Cow::Borrowed(v)))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Part<'de>, E> {
                Ok(Part(Cow::Owned(v.to_owned())))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Part<'de>, E> {
                Ok(Part(Cow::Owned(v)))
            }
        }
        deserializer.deserialize_str(Text)
    }
}

impl<'de> de::Deserialize<'de> for QueryRead<'de> {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Pairs;
        impl<'de> Visitor<'de> for Pairs {
            type Value = QueryRead<'de>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an application/x-www-form-urlencoded query")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<QueryRead<'de>, M::Error> {
                let mut seen: Vec<Cow<'de, str>> = Vec::new();
                let mut client_id = None;
                let mut request_uri = None;
                let mut method = None;
                let mut request = false;
                while let Some(Part(name)) = map.next_key()? {
                    let Part(value) = map.next_value()?;
                    if value.is_empty() {
                        continue;
                    }
                    if seen.contains(&name) {
                        return Ok(QueryRead::Repeated(name));
                    }
                    match name.as_ref() {
                        "client_id" => client_id = Some(value),
                        "request_uri" => request_uri = Some(value),
                        "request_uri_method" => method = Some(value),
                        "request" => request = true,
                        _ => {}
                    }
                    seen.push(name);
                }
                Ok(QueryRead::Read {
                    client_id,
                    request_uri,
                    method,
                    request,
                })
            }
        }
        deserializer.deserialize_map(Pairs)
    }
}
