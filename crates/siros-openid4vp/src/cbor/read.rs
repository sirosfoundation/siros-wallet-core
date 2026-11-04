//! One data item read into ciborium's `Value` (RFC 8949 §3), each tag kept as written: a bignum
//! stays tag 2 or 3 over its bytes. `undefined` and the unassigned simple values have no `Value`
//! and are refused.

use ciborium::value::{Integer, Value};

use super::CborError;

/// The deepest nesting of arrays, maps and tags read.
const DEPTH: usize = 256;

/// `undefined` (RFC 8949 §3.3).
const UNDEFINED: u8 = 23;

/// A head's argument (RFC 8949 §3).
enum Argument {
    /// Additional information 0 to 27: a value or a length.
    Definite(u64),
    /// Additional information 31: an indefinite length.
    Indefinite,
}

/// The bytes holding a data item, and the part not read yet.
pub(super) struct Reader<'b> {
    bytes: &'b [u8],
    rest: &'b [u8],
}

impl<'b> Reader<'b> {
    pub(super) fn new(bytes: &'b [u8]) -> Self {
        Self { bytes, rest: bytes }
    }

    /// The bytes not read yet.
    pub(super) fn rest(&self) -> &'b [u8] {
        self.rest
    }

    fn offset(&self) -> usize {
        self.bytes.len().saturating_sub(self.rest.len())
    }

    fn take(&mut self, count: u64) -> Result<&'b [u8], CborError> {
        let count = usize::try_from(count).map_err(|_| CborError::Truncated)?;
        let (taken, rest) = self
            .rest
            .split_at_checked(count)
            .ok_or(CborError::Truncated)?;
        self.rest = rest;
        Ok(taken)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], CborError> {
        let (taken, rest) = self.rest.split_first_chunk().ok_or(CborError::Truncated)?;
        self.rest = rest;
        Ok(*taken)
    }

    /// Reads a break (`0xff`) when one comes next.
    fn at_break(&mut self) -> bool {
        match self.rest.split_first() {
            Some((0xff, rest)) => {
                self.rest = rest;
                true
            }
            _ => false,
        }
    }

    /// `count` items each take a byte at least; more than the bytes left cannot be read.
    fn count(&self, count: u64) -> Result<usize, CborError> {
        usize::try_from(count)
            .ok()
            .filter(|count| *count <= self.rest.len())
            .ok_or(CborError::Truncated)
    }

    fn argument(&mut self, info: u8, at: usize) -> Result<Argument, CborError> {
        Ok(Argument::Definite(match info {
            0..=23 => u64::from(info),
            24 => u64::from(u8::from_be_bytes(self.fixed()?)),
            25 => u64::from(u16::from_be_bytes(self.fixed()?)),
            26 => u64::from(u32::from_be_bytes(self.fixed()?)),
            27 => u64::from_be_bytes(self.fixed()?),
            31 => return Ok(Argument::Indefinite),
            _ => return Err(CborError::Malformed(at)),
        }))
    }

    /// One data item at `depth` levels of nesting.
    pub(super) fn item(&mut self, depth: usize) -> Result<Value, CborError> {
        let at = self.offset();
        let [initial] = self.fixed()?;
        let (major, info) = (initial >> 5, initial & 0x1f);
        if major == 7 {
            return self.other(info, at);
        }
        Ok(match (major, self.argument(info, at)?) {
            (0, Argument::Definite(value)) => Value::Integer(value.into()),
            (1, Argument::Definite(value)) => {
                let value = -1 - i128::from(value);
                Value::Integer(
                    Integer::try_from(value)
                        .map_err(|_| CborError::IntegerRange(value.to_string()))?,
                )
            }
            (2, Argument::Definite(length)) => Value::Bytes(self.take(length)?.to_vec()),
            (2, Argument::Indefinite) => {
                let mut bytes = Vec::new();
                while let Some(chunk) = self.chunk(major)? {
                    bytes.extend_from_slice(chunk.bytes);
                }
                Value::Bytes(bytes)
            }
            (3, Argument::Definite(length)) => {
                Value::Text(Chunk::read(self.take(length)?, at).text()?.to_owned())
            }
            (3, Argument::Indefinite) => {
                let mut text = String::new();
                while let Some(chunk) = self.chunk(major)? {
                    text.push_str(chunk.text()?);
                }
                Value::Text(text)
            }
            (4, length) => Value::Array(self.array(length, deeper(depth)?)?),
            (5, length) => Value::Map(self.map(length, deeper(depth)?)?),
            (6, Argument::Definite(tag)) => Value::Tag(tag, Box::new(self.item(deeper(depth)?)?)),
            _ => return Err(CborError::Malformed(at)),
        })
    }

    /// Major type 7: false, true, null and the floats.
    fn other(&mut self, info: u8, at: usize) -> Result<Value, CborError> {
        Ok(match info {
            20 => Value::Bool(false),
            21 => Value::Bool(true),
            22 => Value::Null,
            0..=19 | UNDEFINED => return Err(CborError::Simple(info)),
            24 => match u8::from_be_bytes(self.fixed()?) {
                simple @ 32.. => return Err(CborError::Simple(simple)),
                _ => return Err(CborError::Malformed(at)),
            },
            25 => Value::Float(half(u16::from_be_bytes(self.fixed()?))),
            26 => Value::Float(f64::from(f32::from_be_bytes(self.fixed()?))),
            27 => Value::Float(f64::from_be_bytes(self.fixed()?)),
            _ => return Err(CborError::Malformed(at)),
        })
    }

    /// The next chunk of an indefinite-length string: a definite-length string of its major type
    /// (RFC 8949 §3.2.3), or none at the break.
    fn chunk(&mut self, major: u8) -> Result<Option<Chunk<'b>>, CborError> {
        if self.at_break() {
            return Ok(None);
        }
        let at = self.offset();
        let [initial] = self.fixed()?;
        match self.argument(initial & 0x1f, at)? {
            Argument::Definite(length) if initial >> 5 == major => {
                Ok(Some(Chunk::read(self.take(length)?, at)))
            }
            _ => Err(CborError::Malformed(at)),
        }
    }

    fn array(&mut self, length: Argument, depth: usize) -> Result<Vec<Value>, CborError> {
        match length {
            Argument::Definite(count) => {
                (0..self.count(count)?).map(|_| self.item(depth)).collect()
            }
            Argument::Indefinite => {
                let mut items = Vec::new();
                while !self.at_break() {
                    items.push(self.item(depth)?);
                }
                Ok(items)
            }
        }
    }

    fn map(&mut self, length: Argument, depth: usize) -> Result<Vec<(Value, Value)>, CborError> {
        match length {
            Argument::Definite(count) => (0..self.count(count.saturating_mul(2))? / 2)
                .map(|_| Ok((self.item(depth)?, self.item(depth)?)))
                .collect(),
            Argument::Indefinite => {
                let mut pairs = Vec::new();
                while !self.at_break() {
                    pairs.push((self.item(depth)?, self.item(depth)?));
                }
                Ok(pairs)
            }
        }
    }
}

/// A string's bytes and the offset of its head.
struct Chunk<'b> {
    bytes: &'b [u8],
    at: usize,
}

impl<'b> Chunk<'b> {
    fn read(bytes: &'b [u8], at: usize) -> Self {
        Self { bytes, at }
    }

    /// The chunk as text: each chunk of a text string is UTF-8 on its own.
    fn text(&self) -> Result<&'b str, CborError> {
        std::str::from_utf8(self.bytes).map_err(|_| CborError::Utf8(self.at))
    }
}

/// The depth of an array's, a map's or a tag's content.
fn deeper(depth: usize) -> Result<usize, CborError> {
    if depth < DEPTH {
        Ok(depth + 1)
    } else {
        Err(CborError::Depth)
    }
}

/// A half-precision float's value (RFC 8949 Appendix D), a NaN keeping its sign and payload.
fn half(bits: u16) -> f64 {
    let sign = if bits & 0x8000 == 0 { 1.0 } else { -1.0 };
    let exponent = (bits >> 10) & 0x1f;
    let mantissa = bits & 0x3ff;
    match (exponent, mantissa) {
        (0, _) => sign * f64::from(mantissa) * f64::powi(2.0, -24),
        (31, 0) => sign * f64::INFINITY,
        (31, _) => f64::from_bits(
            (u64::from(bits & 0x8000) << 48) | (0x7ff << 52) | (u64::from(mantissa) << 42),
        ),
        _ => sign * f64::from(mantissa + 1024) * f64::powi(2.0, i32::from(exponent) - 25),
    }
}
