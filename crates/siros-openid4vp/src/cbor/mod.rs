//! CBOR as the wallet reads it: one RFC 8949 data item with nothing after it, each map holding
//! each key once at every depth (RFC 8949 §5.6.1); and the conversions between the core's JSON
//! and CBOR (RFC 8949 §6). [`cose`] reads COSE structures and re-exports coset for plug-ins'
//! phase-2 code.

pub mod cose;
mod read;

use std::borrow::Cow;
use std::io;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
pub use ciborium::Value;
use ciborium::value::Integer;
use siros_explain::Explain;

use crate::json::{JsonError, Node, Number};
pub use crate::plugins::members::Item;
use read::{DEPTH, Lengths, Reader};

/// Why bytes are no CBOR data item the wallet reads, or a value does not convert.
#[derive(Debug, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.cbor")]
pub enum CborError {
    /// The bytes end inside the data item.
    #[error("the bytes end inside the data item")]
    Truncated,
    /// A head RFC 8949 §3 makes not well-formed: additional information 28 to 30, an indefinite
    /// length on an integer, a tag or a string chunk, a break where an item belongs, a chunk of
    /// another major type, or a simple value below 32 in two bytes.
    #[error("the head at byte {0} is not well-formed")]
    Malformed(#[explain(name = "at")] usize),
    /// A text string, or a chunk of one, that is no UTF-8.
    #[error("the text at byte {0} is no UTF-8")]
    Utf8(#[explain(name = "at")] usize),
    /// Arrays, maps and tags nested deeper than the reading admits.
    #[error("the data item nests deeper than {0} levels")]
    Depth(#[explain(name = "levels")] usize),
    /// An indefinite length, or the break that ends one, where the reading admits definite
    /// lengths alone.
    #[error("the head at byte {0} has an indefinite length")]
    Indefinite(#[explain(name = "at")] usize),
    /// `undefined` (23) or an unassigned simple value, which ciborium's `Value` cannot hold.
    #[error("the simple value {0}")]
    Simple(#[explain(name = "value")] u8),
    /// Bytes after the data item.
    #[error("{0} bytes after the data item")]
    Trailing(#[explain(name = "bytes")] usize),
    /// A map holds one key twice under RFC 8949 §5.6.1's equivalence, at any depth.
    #[error("a map holds the key {0:?} twice")]
    RepeatedKey(#[explain(skip)] Value),
    /// ciborium could not write the value.
    #[error("the value does not encode")]
    Encode(
        #[source]
        #[explain(skip)]
        ciborium::ser::Error<io::Error>,
    ),
    /// An integer beyond CBOR's major types 0 and 1 (-2^64 to 2^64-1).
    #[error("the integer {0} is beyond CBOR's major types 0 and 1")]
    IntegerRange(#[explain(name = "number")] String),
    /// A JSON number beyond the double range.
    #[error("the number {0} is beyond the double range")]
    DoubleRange(#[explain(name = "number")] String),
    /// A map key other than a text string, which a JSON object cannot name.
    #[error("the map key {0:?} is no text a JSON object can name")]
    Key(#[explain(skip)] Value),
    /// A map whose text keys a JSON object cannot hold.
    #[error("a map converts to no JSON object")]
    Object(
        #[source]
        #[explain(name = "cause")]
        JsonError,
    ),
    /// A value of a kind ciborium adds after 0.2.2.
    #[error("the CBOR value {0:?} is of an unknown kind")]
    Unknown(#[explain(skip)] Value),
}

/// One data item: well-formed, nothing after it, no map holding a key twice at any depth. Each
/// tag stays as written, a bignum among them.
///
/// # Errors
///
/// The bytes are no data item ciborium's `Value` holds, bytes follow it, or a map repeats a key.
pub fn decode(bytes: &[u8]) -> Result<Value, CborError> {
    read(Reader::new(bytes, DEPTH, Lengths::Any))
}

/// One data item as [`decode`] reads it, with definite lengths alone (RFC 8949 §4.2.1) and
/// nested at most `depth` levels.
///
/// # Errors
///
/// [`decode`]'s, an indefinite length ([`CborError::Indefinite`]), and nesting deeper than
/// `depth` ([`CborError::Depth`]).
pub fn decode_definite(bytes: &[u8], depth: usize) -> Result<Value, CborError> {
    read(Reader::new(bytes, depth, Lengths::Definite))
}

fn read(mut reader: Reader<'_>) -> Result<Value, CborError> {
    let value = reader.item(0)?;
    if !reader.rest().is_empty() {
        return Err(CborError::Trailing(reader.rest().len()));
    }
    distinct_keys(&value)?;
    Ok(value)
}

/// The value's encoding: definite lengths, the shortest heads (RFC 8949 §4.1).
///
/// # Errors
///
/// ciborium cannot write the value.
pub fn encode(value: &Value) -> Result<Vec<u8>, CborError> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out).map_err(CborError::Encode)?;
    Ok(out)
}

/// The deterministic encoding of RFC 8949 §4.2.1: the shortest heads, definite lengths, each
/// float in its shortest form that keeps its value, and each map's keys in the bytewise
/// lexicographic order of their encodings.
///
/// # Errors
///
/// A map holds one key twice under that encoding, or ciborium cannot write a scalar.
pub fn encode_deterministic(value: &Value) -> Result<Vec<u8>, CborError> {
    let mut out = Vec::new();
    write(value, Floats::AsGiven, &mut out)?;
    Ok(out)
}

/// `#6.24(bstr .cbor item)`: an embedded data item, its bytes kept as written (RFC 8949
/// §3.4.5.1).
#[must_use]
pub fn embedded(bytes: Vec<u8>) -> Value {
    Value::Tag(24, Box::new(Value::Bytes(bytes)))
}

/// Every map in the value, at any depth, holds each key once. A key's own maps are checked as
/// its form is written.
fn distinct_keys(value: &Value) -> Result<(), CborError> {
    match value {
        Value::Array(items) => items.iter().try_for_each(distinct_keys),
        Value::Tag(_, inner) => distinct_keys(inner),
        Value::Map(pairs) => {
            let mut keys = pairs
                .iter()
                .map(|(key, item)| {
                    distinct_keys(item)?;
                    Keyed::of(key)
                })
                .collect::<Result<Vec<_>, CborError>>()?;
            keys.sort_by(|a, b| a.form.cmp(&b.form));
            once(keys.iter())
        }
        _ => Ok(()),
    }
}

/// A map key and its form.
struct Keyed<'v> {
    form: Vec<u8>,
    key: &'v Value,
}

impl<'v> Keyed<'v> {
    fn of(key: &'v Value) -> Result<Self, CborError> {
        Ok(Self {
            form: key_form(key)?,
            key,
        })
    }
}

/// Keys sorted by form, each form once.
fn once<'a, 'v: 'a>(sorted: impl Iterator<Item = &'a Keyed<'v>>) -> Result<(), CborError> {
    let mut previous: Option<&Keyed<'_>> = None;
    for keyed in sorted {
        if previous.is_some_and(|before| before.form == keyed.form) {
            return Err(CborError::RepeatedKey(keyed.key.clone()));
        }
        previous = Some(keyed);
    }
    Ok(())
}

/// A key's form under RFC 8949 §5.6.1: the encoding of the key with -0.0 as 0.0, a NaN without
/// its sign, and each map's pairs in the order of their keys' forms. Equal forms make one key.
///
/// # Errors
///
/// A map inside the key holds a key twice, or ciborium cannot write a scalar.
pub fn key_form(key: &Value) -> Result<Vec<u8>, CborError> {
    form(key)
}

fn form(value: &Value) -> Result<Vec<u8>, CborError> {
    let mut out = Vec::new();
    write(value, Floats::Normal, &mut out)?;
    Ok(out)
}

/// How [`write`] writes a float.
#[derive(Debug, Clone, Copy)]
enum Floats {
    /// As given.
    AsGiven,
    /// -0.0 as 0.0, a NaN without its sign: a key's form.
    Normal,
}

/// Appends the value's deterministic encoding, its floats as `floats` says. Each map's keys get
/// their forms once, which the map's own form copies: the work grows with the size times the
/// nesting.
fn write(value: &Value, floats: Floats, out: &mut Vec<u8>) -> Result<(), CborError> {
    match value {
        Value::Float(float) => {
            let float = match floats {
                Floats::AsGiven => *float,
                Floats::Normal => normal(*float),
            };
            out.extend(encode(&Value::Float(float))?);
        }
        Value::Bytes(bytes) => {
            head(2, bytes.len() as u64, out);
            out.extend_from_slice(bytes);
        }
        Value::Text(text) => {
            head(3, text.len() as u64, out);
            out.extend_from_slice(text.as_bytes());
        }
        Value::Array(items) => {
            head(4, items.len() as u64, out);
            for item in items {
                write(item, floats, out)?;
            }
        }
        Value::Tag(tag, inner) => {
            head(6, *tag, out);
            write(inner, floats, out)?;
        }
        Value::Map(pairs) => {
            let mut entries = pairs
                .iter()
                .map(|(key, item)| {
                    let mut written = Vec::new();
                    write(item, floats, &mut written)?;
                    Ok(Pair {
                        key: Keyed::of(key)?,
                        item: written,
                    })
                })
                .collect::<Result<Vec<_>, CborError>>()?;
            entries.sort_by(|a, b| a.key.form.cmp(&b.key.form));
            once(entries.iter().map(|pair| &pair.key))?;
            head(5, entries.len() as u64, out);
            for pair in entries {
                out.extend(pair.key.form);
                out.extend(pair.item);
            }
        }
        other => out.extend(encode(other)?),
    }
    Ok(())
}

/// A map pair with the forms of its key and its item.
struct Pair<'v> {
    key: Keyed<'v>,
    item: Vec<u8>,
}

/// -0.0 as 0.0, a NaN without its sign.
fn normal(float: f64) -> f64 {
    if float == 0.0 {
        0.0
    } else if float.is_nan() {
        f64::from_bits(float.to_bits() & !(1 << 63))
    } else {
        float
    }
}

/// A head with the shortest argument (RFC 8949 §4.2.1).
fn head(major: u8, argument: u64, out: &mut Vec<u8>) {
    let major = major << 5;
    match (
        u8::try_from(argument),
        u16::try_from(argument),
        u32::try_from(argument),
    ) {
        (Ok(small), _, _) if small < 24 => out.push(major | small),
        (Ok(byte), _, _) => out.extend([major | 24, byte]),
        (_, Ok(short), _) => {
            out.push(major | 25);
            out.extend(short.to_be_bytes());
        }
        (_, _, Ok(word)) => {
            out.push(major | 26);
            out.extend(word.to_be_bytes());
        }
        _ => {
            out.push(major | 27);
            out.extend(argument.to_be_bytes());
        }
    }
}

/// RFC 8949 §6.2 for the core's JSON: an integer as Python's `json` reads one (written without a
/// fraction or exponent) becomes an integer, another number a double, an object a map of text
/// keys in member order.
///
/// # Errors
///
/// An integer is beyond CBOR's major types 0 and 1, or a number beyond the double range.
pub fn of_json(node: &Node<'_>) -> Result<Value, CborError> {
    Ok(match node {
        Node::Null => Value::Null,
        Node::Bool(value) => Value::Bool(*value),
        Node::Number(number) if number.is_integer() => {
            let range = || CborError::IntegerRange(number.text().to_owned());
            let value: i128 = number.text().parse().map_err(|_| range())?;
            Value::Integer(Integer::try_from(value).map_err(|_| range())?)
        }
        Node::Number(number) => Value::Float(
            number
                .to_double()
                .ok_or_else(|| CborError::DoubleRange(number.text().to_owned()))?,
        ),
        Node::String(text) => Value::Text(text.to_string()),
        Node::Array(items) => Value::Array(items.iter().map(of_json).collect::<Result<_, _>>()?),
        Node::Object(object) => Value::Map(
            object
                .members()
                .iter()
                .map(|member| {
                    Ok((
                        Value::Text(member.name.to_string()),
                        of_json(&member.value)?,
                    ))
                })
                .collect::<Result<_, CborError>>()?,
        ),
    })
}

/// How a byte string becomes text: RFC 8949 §3.4.5.2's tags 21 to 23, base64url without padding
/// otherwise (§6.1).
#[derive(Debug, Clone, Copy)]
enum Hint {
    Base64Url,
    Base64,
    Base16,
}

impl Hint {
    fn text(self, bytes: &[u8]) -> String {
        match self {
            Self::Base64Url => URL_SAFE_NO_PAD.encode(bytes),
            Self::Base64 => STANDARD.encode(bytes),
            Self::Base16 => bytes.iter().map(|byte| format!("{byte:02X}")).collect(),
        }
    }
}

/// RFC 8949 §6.1 into the core's JSON: integers and finite doubles as numbers, a non-finite
/// double as null, byte strings in base64url (or a tag's hint), bignums as base64url text ("~"
/// first for a negative one), other tags as their content, maps of text keys as objects.
///
/// # Errors
///
/// A map key is no text, a map's keys make no JSON object, or a value is of an unknown kind.
pub fn to_json(value: &Value) -> Result<Node<'static>, CborError> {
    view(value, Hint::Base64Url)
}

fn view(value: &Value, hint: Hint) -> Result<Node<'static>, CborError> {
    Ok(match value {
        Value::Integer(integer) => Node::integer(i128::from(*integer)),
        Value::Float(float) => Number::of_double(*float).map_or(Node::Null, Node::Number),
        Value::Bytes(bytes) => Node::String(Cow::Owned(hint.text(bytes))),
        Value::Text(text) => Node::String(Cow::Owned(text.clone())),
        Value::Bool(value) => Node::Bool(*value),
        Value::Null => Node::Null,
        Value::Tag(2, inner) if inner.is_bytes() => view(inner, Hint::Base64Url)?,
        Value::Tag(3, inner) => match inner.as_ref() {
            Value::Bytes(bytes) => {
                Node::String(Cow::Owned(format!("~{}", URL_SAFE_NO_PAD.encode(bytes))))
            }
            other => view(other, hint)?,
        },
        Value::Tag(21, inner) => view(inner, Hint::Base64Url)?,
        Value::Tag(22, inner) => view(inner, Hint::Base64)?,
        Value::Tag(23, inner) => view(inner, Hint::Base16)?,
        Value::Tag(_, inner) => view(inner, hint)?,
        Value::Array(items) => Node::Array(
            items
                .iter()
                .map(|item| view(item, hint))
                .collect::<Result<_, _>>()?,
        ),
        Value::Map(pairs) => Node::object(
            pairs
                .iter()
                .map(|(key, item)| match key {
                    Value::Text(name) => Ok((Cow::Owned(name.clone()), view(item, hint)?)),
                    other => Err(CborError::Key(other.clone())),
                })
                .collect::<Result<Vec<_>, CborError>>()?,
        )
        .map_err(CborError::Object)?,
        other => return Err(CborError::Unknown(other.clone())),
    })
}
