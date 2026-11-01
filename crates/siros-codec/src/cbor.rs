//! A strict CBOR reader and a deterministic CBOR writer (RFC 8949).
//!
//! The reader takes untrusted input. It accepts one data item with definite lengths and nothing
//! after it, or a CBOR sequence of such items (RFC 8742). It keeps the encoded bytes of every
//! item, because a digest or a signature covers an item as it was written. It refuses
//! floating-point numbers, indefinite lengths, simple values other than `false`, `true`, `null`
//! and `undefined`, a map key that repeats, nesting deeper than [`MAX_DEPTH`], and input longer
//! than [`MAX_INPUT`].
//!
//! The writer emits the core deterministic encoding of RFC 8949, Section 4.2.1: shortest heads,
//! definite lengths, and map keys sorted by their encoded bytes.

use std::str::Utf8Error;

/// The deepest nesting the reader accepts.
pub const MAX_DEPTH: usize = 32;

/// The most heap bytes the reader allocates per byte of input. Each item but the outermost
/// starts at its own byte and takes a slot of [`Item`] in the vector of its array, map or
/// sequence, or in the box of its tag. A vector grows as its items decode: from four slots,
/// doubling when full. It holds at most twice the slots it fills, or four for one item, and the
/// vectors it outgrew hold as many again on an allocator that never frees: four slots per item.
/// The duplicate check of a map sorts a slice of each key's encoding in a vector of the map's
/// size, which the sort leaves as it is, and a key and its value take two bytes at least.
///
/// 100 bytes on wasm32 (an `Item` of 24 bytes, a slice of 8) and 200 on a 64-bit target (48
/// and 16).
pub const HEAP_PER_BYTE: usize = 4 * size_of::<Item<'static>>() + size_of::<&[u8]>() / 2;

/// The longest input the reader decodes: its items then take at most `isize::MAX` heap bytes,
/// the most one allocation holds. 21,474,836 bytes on wasm32.
pub const MAX_INPUT: usize = match (isize::MAX as usize).checked_div(HEAP_PER_BYTE) {
    Some(bytes) => bytes,
    None => 0,
};

/// Why bytes are not one CBOR item the reader accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CborError {
    /// The input ends inside an item.
    #[error("CBOR item is truncated")]
    Truncated,
    /// Bytes follow the item.
    #[error("bytes follow the CBOR item")]
    TrailingBytes,
    /// An encoding the reader refuses, named by [`Unsupported`].
    #[error("unsupported CBOR encoding")]
    Unsupported(#[source] Unsupported),
    /// A text string is not UTF-8.
    #[error("CBOR text is not UTF-8")]
    InvalidUtf8(#[source] Utf8Error),
    /// A map has the same key twice.
    #[error("CBOR map repeats a key")]
    DuplicateKey,
    /// Arrays, maps and tags nest deeper than [`MAX_DEPTH`].
    #[error("CBOR nests too deeply")]
    TooDeep,
    /// The input is longer than [`MAX_INPUT`].
    #[error("CBOR input is longer than the reader decodes")]
    TooLong,
}

/// An encoding the reader refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum Unsupported {
    /// Additional information 31: an indefinite length, or the break that ends one.
    #[error("additional information 31: an indefinite length, or the break that ends one")]
    IndefiniteLength,
    /// Additional information 28 to 30, which RFC 8949 reserves.
    #[error("additional information 28 to 30, which RFC 8949 reserves")]
    ReservedInfo,
    /// A floating-point number.
    #[error("a floating-point number")]
    Float,
    /// A simple value other than `false`, `true`, `null` and `undefined`.
    #[error("a simple value other than `false`, `true`, `null` and `undefined`")]
    SimpleValue,
}

impl CborError {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Truncated => "cbor_truncated",
            Self::TrailingBytes => "cbor_trailing_bytes",
            Self::Unsupported(_) => "cbor_unsupported",
            Self::InvalidUtf8(_) => "cbor_invalid_utf8",
            Self::DuplicateKey => "cbor_duplicate_key",
            Self::TooDeep => "cbor_too_deep",
            Self::TooLong => "cbor_too_long",
        }
    }
}

/// One decoded item and the bytes it was encoded in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item<'a> {
    raw: &'a [u8],
    kind: Kind<'a>,
}

/// A decoded item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind<'a> {
    /// Major type 0.
    Unsigned(u64),
    /// Major type 1: the value is `-1 - n`.
    Negative(u64),
    /// Major type 2.
    Bytes(&'a [u8]),
    /// Major type 3.
    Text(&'a str),
    /// Major type 4.
    Array(Vec<Item<'a>>),
    /// Major type 5, entries in their encoded order.
    Map(Vec<(Item<'a>, Item<'a>)>),
    /// Major type 6.
    Tag(u64, Box<Item<'a>>),
    /// `false` or `true`.
    Bool(bool),
    /// `null`.
    Null,
    /// `undefined`.
    Undefined,
}

impl<'a> Item<'a> {
    /// The item's encoding, head included.
    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }

    /// The decoded item.
    pub fn kind(&self) -> &Kind<'a> {
        &self.kind
    }

    /// The byte string's content.
    pub fn as_bytes(&self) -> Option<&'a [u8]> {
        match self.kind {
            Kind::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// The text string's content.
    pub fn as_text(&self) -> Option<&'a str> {
        match self.kind {
            Kind::Text(t) => Some(t),
            _ => None,
        }
    }

    /// The array's elements.
    pub fn as_array(&self) -> Option<&[Item<'a>]> {
        match &self.kind {
            Kind::Array(items) => Some(items),
            _ => None,
        }
    }

    /// The map's entries.
    pub fn as_map(&self) -> Option<&[(Item<'a>, Item<'a>)]> {
        match &self.kind {
            Kind::Map(entries) => Some(entries),
            _ => None,
        }
    }

    /// The tagged item, when this is tag `tag`.
    pub fn untag(&self, tag: u64) -> Option<&Item<'a>> {
        match &self.kind {
            Kind::Tag(t, inner) if *t == tag => Some(inner),
            _ => None,
        }
    }

    /// The value of the map entry whose key is the text `key`.
    pub fn get(&self, key: &str) -> Option<&Item<'a>> {
        self.as_map()?
            .iter()
            .find(|(k, _)| k.as_text() == Some(key))
            .map(|(_, v)| v)
    }

    /// The value of the map entry whose key is the integer `key`.
    pub fn get_int(&self, key: i64) -> Option<&Item<'a>> {
        self.as_map()?
            .iter()
            .find(|(k, _)| k.as_int() == Some(key))
            .map(|(_, v)| v)
    }

    /// The value of an integer item that fits `i64`.
    pub fn as_int(&self) -> Option<i64> {
        match self.kind {
            Kind::Unsigned(n) => i64::try_from(n).ok(),
            Kind::Negative(n) => i64::try_from(n).ok().map(|n| -1 - n),
            _ => None,
        }
    }
}

/// Decodes `bytes` as exactly one item.
///
/// # Errors
///
/// [`CborError`]: the first rule the item breaks, [`CborError::TooLong`] first.
pub fn decode(bytes: &[u8]) -> Result<Item<'_>, CborError> {
    let mut reader = Reader::of(bytes)?;
    let item = reader.item(0)?;
    if reader.at != bytes.len() {
        return Err(CborError::TrailingBytes);
    }
    Ok(item)
}

/// Decodes `bytes` as a CBOR sequence (RFC 8742): items one after another up to the last byte,
/// each complete.
///
/// # Errors
///
/// [`CborError`]: [`CborError::TooLong`] first, then the first item that does not decode,
/// [`CborError::Truncated`] for one the input ends inside.
pub fn decode_sequence(bytes: &[u8]) -> Result<Vec<Item<'_>>, CborError> {
    let mut reader = Reader::of(bytes)?;
    let mut items = Vec::new();
    while reader.at < bytes.len() {
        items.push(reader.item(0)?);
    }
    Ok(items)
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    /// A reader at the start of `bytes`.
    fn of(bytes: &'a [u8]) -> Result<Self, CborError> {
        if bytes.len() > MAX_INPUT {
            return Err(CborError::TooLong);
        }
        Ok(Self { bytes, at: 0 })
    }

    /// The next byte.
    fn byte(&mut self) -> Result<u8, CborError> {
        let byte = *self.bytes.get(self.at).ok_or(CborError::Truncated)?;
        self.at += 1;
        Ok(byte)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CborError> {
        let end = self.at.checked_add(n).ok_or(CborError::Truncated)?;
        let out = self.bytes.get(self.at..end).ok_or(CborError::Truncated)?;
        self.at = end;
        Ok(out)
    }

    /// The next head.
    fn head(&mut self) -> Result<Head, CborError> {
        let first = self.byte()?;
        let (major, info) = (Major::of(first), first & 0x1f);
        let width = match info {
            0..=23 => {
                return Ok(Head {
                    major,
                    info,
                    argument: u64::from(info),
                })
            }
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            31 => return Err(CborError::Unsupported(Unsupported::IndefiniteLength)),
            _ => return Err(CborError::Unsupported(Unsupported::ReservedInfo)),
        };
        let argument = self
            .take(width)?
            .iter()
            .fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
        Ok(Head {
            major,
            info,
            argument,
        })
    }

    fn length(&self, argument: u64) -> Result<usize, CborError> {
        let n = usize::try_from(argument).map_err(|_| CborError::Truncated)?;
        // Every element takes at least one byte: a longer claim cannot be satisfied.
        if n > self.bytes.len().saturating_sub(self.at) {
            return Err(CborError::Truncated);
        }
        Ok(n)
    }

    fn item(&mut self, depth: usize) -> Result<Item<'a>, CborError> {
        if depth > MAX_DEPTH {
            return Err(CborError::TooDeep);
        }
        let start = self.at;
        let head = self.head()?;
        let kind = self.body(head, depth)?;
        let raw = self.bytes.get(start..self.at).ok_or(CborError::Truncated)?;
        Ok(Item { raw, kind })
    }

    fn body(&mut self, head: Head, depth: usize) -> Result<Kind<'a>, CborError> {
        let argument = head.argument;
        match head.major {
            Major::Unsigned => Ok(Kind::Unsigned(argument)),
            Major::Negative => Ok(Kind::Negative(argument)),
            Major::Bytes => {
                let n = self.length(argument)?;
                Ok(Kind::Bytes(self.take(n)?))
            }
            Major::Text => {
                let n = self.length(argument)?;
                let text = std::str::from_utf8(self.take(n)?).map_err(CborError::InvalidUtf8)?;
                Ok(Kind::Text(text))
            }
            Major::Array => self.array(argument, depth),
            Major::Map => self.map(argument, depth),
            Major::Tag => Ok(Kind::Tag(argument, Box::new(self.item(depth + 1)?))),
            Major::Simple => simple(head),
        }
    }

    /// The array of the `argument` items that follow. The vector grows as they decode.
    fn array(&mut self, argument: u64, depth: usize) -> Result<Kind<'a>, CborError> {
        let n = self.length(argument)?;
        let mut items = Vec::new();
        for _ in 0..n {
            items.push(self.item(depth + 1)?);
        }
        Ok(Kind::Array(items))
    }

    /// The map of the `argument` entries that follow, each key once. The vector grows as they
    /// decode.
    fn map(&mut self, argument: u64, depth: usize) -> Result<Kind<'a>, CborError> {
        let n = self.length(argument)?;
        let mut entries = Vec::new();
        for _ in 0..n {
            let key = self.item(depth + 1)?;
            let value = self.item(depth + 1)?;
            entries.push((key, value));
        }
        distinct_keys(&entries)?;
        Ok(Kind::Map(entries))
    }
}

/// Checks that the keys of `entries` differ. Their encodings sorted once, a repeated key lies
/// next to its first: `sort_unstable` takes O(n log n) comparisons for `n` keys, whatever the
/// keys, and allocates nothing.
fn distinct_keys(entries: &[(Item<'_>, Item<'_>)]) -> Result<(), CborError> {
    let mut keys: Vec<&[u8]> = Vec::with_capacity(entries.len());
    keys.extend(entries.iter().map(|(key, _)| key.raw));
    keys.sort_unstable();
    if keys.windows(2).any(|pair| matches!(pair, [a, b] if a == b)) {
        return Err(CborError::DuplicateKey);
    }
    Ok(())
}

/// The item of major type 7 that `head` starts.
fn simple(head: Head) -> Result<Kind<'static>, CborError> {
    match head.argument {
        20 => Ok(Kind::Bool(false)),
        21 => Ok(Kind::Bool(true)),
        22 => Ok(Kind::Null),
        23 => Ok(Kind::Undefined),
        _ if (25..=27).contains(&head.info) => Err(CborError::Unsupported(Unsupported::Float)),
        _ => Err(CborError::Unsupported(Unsupported::SimpleValue)),
    }
}

/// The head of an item: its major type, its additional information, and its argument.
#[derive(Clone, Copy)]
struct Head {
    major: Major,
    info: u8,
    argument: u64,
}

/// A major type (RFC 8949, Section 3.1).
#[derive(Clone, Copy)]
enum Major {
    Unsigned,
    Negative,
    Bytes,
    Text,
    Array,
    Map,
    Tag,
    Simple,
}

impl Major {
    /// The major type of the initial byte `first`.
    fn of(first: u8) -> Self {
        match first >> 5 {
            0 => Self::Unsigned,
            1 => Self::Negative,
            2 => Self::Bytes,
            3 => Self::Text,
            4 => Self::Array,
            5 => Self::Map,
            6 => Self::Tag,
            _ => Self::Simple,
        }
    }

    /// The high three bits of an initial byte of this type.
    fn bits(self) -> u8 {
        let number = match self {
            Self::Unsigned => 0,
            Self::Negative => 1,
            Self::Bytes => 2,
            Self::Text => 3,
            Self::Array => 4,
            Self::Map => 5,
            Self::Tag => 6,
            Self::Simple => 7,
        };
        number << 5
    }
}

/// A value to encode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// Major type 0.
    Unsigned(u64),
    /// Major type 1: the value is `-1 - n`.
    Negative(u64),
    /// Major type 2.
    Bytes(Vec<u8>),
    /// Major type 3.
    Text(String),
    /// Major type 4.
    Array(Vec<Value>),
    /// Major type 5. The writer sorts the entries.
    Map(Vec<(Value, Value)>),
    /// Major type 6.
    Tag(u64, Box<Value>),
    /// `false` or `true`.
    Bool(bool),
    /// `null`.
    Null,
    /// An item already encoded, written as it is.
    Encoded(Vec<u8>),
}

impl Value {
    /// A text value.
    pub fn text(s: &str) -> Self {
        Self::Text(s.to_owned())
    }

    /// An owned copy of a decoded item.
    pub fn from_item(item: &Item<'_>) -> Self {
        match &item.kind {
            Kind::Unsigned(n) => Self::Unsigned(*n),
            Kind::Negative(n) => Self::Negative(*n),
            Kind::Bytes(b) => Self::Bytes(b.to_vec()),
            Kind::Text(t) => Self::text(t),
            Kind::Array(items) => Self::Array(items.iter().map(Self::from_item).collect()),
            Kind::Map(entries) => Self::Map(
                entries
                    .iter()
                    .map(|(k, v)| (Self::from_item(k), Self::from_item(v)))
                    .collect(),
            ),
            Kind::Tag(tag, inner) => Self::Tag(*tag, Box::new(Self::from_item(inner))),
            Kind::Bool(b) => Self::Bool(*b),
            Kind::Null => Self::Null,
            Kind::Undefined => Self::Encoded(vec![0xf7]),
        }
    }

    /// The deterministic encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut Vec<u8>) {
        match self {
            Self::Unsigned(n) => head(out, Major::Unsigned, *n),
            Self::Negative(n) => head(out, Major::Negative, *n),
            Self::Bytes(b) => {
                head(out, Major::Bytes, len(b.len()));
                out.extend_from_slice(b);
            }
            Self::Text(t) => {
                head(out, Major::Text, len(t.len()));
                out.extend_from_slice(t.as_bytes());
            }
            Self::Array(items) => {
                head(out, Major::Array, len(items.len()));
                items.iter().for_each(|i| i.write(out));
            }
            Self::Map(entries) => write_map(entries, out),
            Self::Tag(tag, inner) => {
                head(out, Major::Tag, *tag);
                inner.write(out);
            }
            Self::Bool(b) => out.push(if *b { 0xf5 } else { 0xf4 }),
            Self::Null => out.push(0xf6),
            Self::Encoded(bytes) => out.extend_from_slice(bytes),
        }
    }
}

fn write_map(entries: &[(Value, Value)], out: &mut Vec<u8>) {
    let mut encoded: Vec<(Vec<u8>, Vec<u8>)> = entries
        .iter()
        .map(|(k, v)| (k.encode(), v.encode()))
        .collect();
    encoded.sort();
    head(out, Major::Map, len(encoded.len()));
    for (k, v) in encoded {
        out.extend_from_slice(&k);
        out.extend_from_slice(&v);
    }
}

fn len(n: usize) -> u64 {
    // usize is at most 64 bits on every target Rust supports.
    n as u64
}

/// Writes a head with the shortest argument.
fn head(out: &mut Vec<u8>, major: Major, argument: u64) {
    let m = major.bits();
    let bytes = argument.to_be_bytes();
    let (info, width) = match argument {
        0..=23 => (argument as u8, 0),
        24..=0xff => (24, 1),
        0x100..=0xffff => (25, 2),
        0x1_0000..=0xffff_ffff => (26, 4),
        _ => (27, 8),
    };
    out.push(m | info);
    out.extend_from_slice(bytes.get(8 - width..).unwrap_or_default());
}
