//! The strict JSON reader.

use std::fmt;

use serde::de::{Deserialize, Deserializer, MapAccess, Visitor};
use serde_json::value::RawValue;
use serde_json::Number;

use super::JsonTextError;

/// The deepest nesting of objects and arrays a document may have.
pub const MAX_DEPTH: usize = 64;

/// The most heap bytes the reader allocates per byte of text: the slots of arrays or of
/// objects, whichever take more, a copy of each number's text, and serde_json's stack of the
/// levels it skips. Each value but the outermost takes a slot in the vector serde_json reads it
/// into and another in the vector this reader holds it in. A vector grows from four slots,
/// doubling when full, and with the vectors it outgrew holds at most four slots per value on an
/// allocator that never frees. serde_json reads each nested array or object again and keeps a
/// byte per enclosing level of each value it skips: at most twice the levels, [`MAX_DEPTH`],
/// that a byte lies in.
///
/// 209 bytes on wasm32 and 241 on a 64-bit target.
pub const HEAP_PER_BYTE: usize = max(ARRAY_PER_BYTE, OBJECT_PER_BYTE) + 1 + 2 * MAX_DEPTH;

/// The heap bytes of arrays per byte of text: four slots of each vector per value, and a value
/// and its separator take two bytes at least. 80 bytes on wasm32 and 112 on a 64-bit target.
const ARRAY_PER_BYTE: usize = 2 * (size_of::<&RawValue>() + size_of::<Json>());

/// The heap bytes of objects per byte of text: four slots per member of the vector serde_json
/// reads the members into, one of the vector this reader holds them in, and one of the names it
/// sorts to find a repeat; a member and its separator take five bytes at least. 28 bytes on
/// wasm32 and 50 on a 64-bit target.
const OBJECT_PER_BYTE: usize = (4 * size_of::<(String, &RawValue)>()
    + size_of::<(String, Json)>()
    + size_of::<(&str, usize)>())
.div_ceil(5);

/// The longest text the reader reads: its values then take at most `isize::MAX` heap bytes, the
/// most one allocation holds. 10,275,041 bytes on wasm32.
pub const MAX_TEXT: usize = match (isize::MAX as usize).checked_div(HEAP_PER_BYTE) {
    Some(bytes) => bytes,
    None => 0,
};

/// The greater of `a` and `b`.
const fn max(a: usize, b: usize) -> usize {
    if a > b {
        a
    } else {
        b
    }
}

/// One JSON value.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A number.
    Number(JsonNumber),
    /// A string.
    String(String),
    /// An array.
    Array(Vec<Json>),
    /// An object: its members in document order, each name once.
    Object(Vec<(String, Json)>),
}

/// A JSON number: the text its writer chose, which denotes a finite binary64 value.
#[derive(Debug, Clone, PartialEq)]
pub struct JsonNumber {
    text: String,
    number: Number,
}

impl JsonNumber {
    /// The text the writer chose.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The number the text denotes.
    #[must_use]
    pub fn number(&self) -> &Number {
        &self.number
    }

    /// The number the text denotes, taken.
    #[must_use]
    pub fn into_number(self) -> Number {
        self.number
    }

    /// Whether the value has no fractional part: a JSON Schema `integer`.
    #[must_use]
    pub fn is_integer(&self) -> bool {
        self.number.is_i64()
            || self.number.is_u64()
            || self
                .number
                .as_f64()
                .is_some_and(|value| value.fract() == 0.0)
    }
}

/// Why bytes are no JSON value this reader holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum ReadFault {
    /// The bytes are no JSON text.
    #[error(transparent)]
    Text(JsonTextError),
    /// A number has no finite binary64 value.
    #[error("a number beyond binary64")]
    NumberUnrepresentable,
    /// Objects and arrays nest deeper than [`MAX_DEPTH`].
    #[error("nested deeper than {MAX_DEPTH}")]
    TooDeep,
    /// The text is longer than [`MAX_TEXT`].
    #[error("longer than {MAX_TEXT} bytes")]
    TooLong,
}

/// Why bytes are no JSON value whose objects name each member once.
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
pub enum JsonFault {
    /// The bytes are no JSON value this reader holds.
    #[error(transparent)]
    Read(ReadFault),
    /// An object repeats this member name.
    #[error("member {0:?} repeated")]
    RepeatedMember(String),
}

impl Json {
    /// The value `bytes` encode, alone and in UTF-8: members in document order, each object
    /// naming each member once.
    ///
    /// # Errors
    ///
    /// [`JsonFault`]: text longer than [`MAX_TEXT`] first, then a text fault anywhere in the
    /// bytes; else the first, in document order, of a number beyond binary64, nesting deeper
    /// than [`MAX_DEPTH`], and a member name an object repeats.
    pub fn parse_unique(bytes: &[u8]) -> Result<Self, JsonFault> {
        if bytes.len() > MAX_TEXT {
            return Err(JsonFault::Read(ReadFault::TooLong));
        }
        let raw: &RawValue = serde_json::from_slice(bytes).map_err(text)?;
        value(raw, 0)
    }

    /// The value of the member `name`, when this is an object that has one.
    #[must_use]
    pub fn member(&self, name: &str) -> Option<&Self> {
        match self {
            Self::Object(members) => members
                .iter()
                .find(|(member, _)| member == name)
                .map(|(_, value)| value),
            Self::Null | Self::Bool(_) | Self::Number(_) | Self::String(_) | Self::Array(_) => None,
        }
    }
}

/// The fault of serde_json's `error`.
fn text(error: serde_json::Error) -> JsonFault {
    JsonFault::Read(ReadFault::Text(JsonTextError::of(&error)))
}

/// The value `raw` holds, `depth` levels below the document. The document's syntax is read
/// already: serde_json reads each part again only for its value, from its bytes, through the
/// one reader the document took.
fn value(raw: &RawValue, depth: usize) -> Result<Json, JsonFault> {
    let text_of = raw.get();
    let bytes = text_of.as_bytes();
    match bytes.first() {
        Some(b'{') => {
            let depth = nested(depth)?;
            let Members(members) = serde_json::from_slice(bytes).map_err(text)?;
            object(&members, depth).map(Json::Object)
        }
        Some(b'[') => {
            let depth = nested(depth)?;
            let items: Vec<&RawValue> = serde_json::from_slice(bytes).map_err(text)?;
            let items = items
                .into_iter()
                .map(|raw| value(raw, depth))
                .collect::<Result<_, JsonFault>>()?;
            Ok(Json::Array(items))
        }
        Some(b'"') => Ok(Json::String(serde_json::from_slice(bytes).map_err(text)?)),
        Some(b't') => Ok(Json::Bool(true)),
        Some(b'f') => Ok(Json::Bool(false)),
        Some(b'n') => Ok(Json::Null),
        // serde_json read the text as a number of RFC 8259, Section 6; its value may lie beyond
        // binary64.
        _ => match serde_json::from_slice::<Number>(bytes) {
            Ok(number) => Ok(Json::Number(JsonNumber {
                text: text_of.to_owned(),
                number,
            })),
            Err(_) => Err(JsonFault::Read(ReadFault::NumberUnrepresentable)),
        },
    }
}

/// The members of an object, `members` as the document writes them, each name once, the
/// values `depth` levels below the document.
///
/// # Errors
///
/// [`JsonFault`]: the first in document order of a fault of a value and a name that repeats one
/// before it. The names read before a fault, or all of them at the object's end, sorted once
/// find the earliest repeat: O(n log n) comparisons for `n` names, whatever the names.
fn object(members: &[(String, &RawValue)], depth: usize) -> Result<Vec<(String, Json)>, JsonFault> {
    let mut names: Vec<(&str, usize)> = Vec::with_capacity(members.len());
    let mut object = Vec::with_capacity(members.len());
    for (at, (name, raw)) in members.iter().enumerate() {
        // A member's name comes before its value in the document.
        names.push((name, at));
        match value(raw, depth) {
            Ok(value) => object.push((name.clone(), value)),
            Err(fault) => return Err(first_repeat(&mut names).unwrap_or(fault)),
        }
    }
    match first_repeat(&mut names) {
        Some(repeat) => Err(repeat),
        None => Ok(object),
    }
}

/// The refusal of the earliest name of `names`, each with its position, that repeats a name
/// before it. Sorted, the names fall into runs of one name in order of position.
fn first_repeat(names: &mut [(&str, usize)]) -> Option<JsonFault> {
    names.sort_unstable();
    names
        .windows(2)
        .filter_map(|pair| match pair {
            [(first, _), (repeat, at)] if first == repeat => Some((*at, *repeat)),
            _ => None,
        })
        .min_by_key(|(at, _)| *at)
        .map(|(_, name)| JsonFault::RepeatedMember(name.to_owned()))
}

/// The depth of a value inside an object or array at `depth`.
fn nested(depth: usize) -> Result<usize, JsonFault> {
    if depth < MAX_DEPTH {
        Ok(depth + 1)
    } else {
        Err(JsonFault::Read(ReadFault::TooDeep))
    }
}

/// The members of an object as the document writes them, each value as its text.
struct Members<'a>(Vec<(String, &'a RawValue)>);

impl<'de> Deserialize<'de> for Members<'de> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(MembersVisitor)
    }
}

struct MembersVisitor;

impl<'de> Visitor<'de> for MembersVisitor {
    type Value = Members<'de>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        std::iter::from_fn(|| map.next_entry::<String, &'de RawValue>().transpose())
            .collect::<Result<_, _>>()
            .map(Members)
    }
}
