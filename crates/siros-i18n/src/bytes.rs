//! The byte form of a compiled placeholder, which a format module's load half writes and its
//! render half reads, and of a package's entries. Integers are unsigned LEB128, texts their byte
//! length and UTF-8 bytes.

#[cfg(feature = "render")]
use crate::error::RenderError;
#[cfg(any(
    feature = "number",
    feature = "currency",
    feature = "offset",
    feature = "date",
    feature = "list"
))]
use crate::format::FormatId;

/// Writes a compiled placeholder, a package's entry, or a precomputed text's key.
#[cfg(feature = "render")]
#[derive(Debug, Default)]
pub(crate) struct Writer {
    bytes: Vec<u8>,
}

#[cfg(feature = "render")]
impl Writer {
    /// One byte.
    pub(crate) fn byte(&mut self, byte: u8) {
        self.bytes.push(byte);
    }

    /// An unsigned integer.
    pub(crate) fn number(&mut self, mut value: u64) {
        while value >= 0x80 {
            self.bytes.push((value & 0x7f) as u8 | 0x80);
            value >>= 7;
        }
        self.bytes.push(value as u8);
    }

    /// A signed integer, zigzag-encoded.
    #[cfg(all(
        feature = "load",
        any(feature = "number", feature = "currency", feature = "offset")
    ))]
    pub(crate) fn signed(&mut self, value: i64) {
        self.number(((value << 1) ^ (value >> 63)) as u64);
    }

    /// A count of items, or a length.
    pub(crate) fn count(&mut self, count: usize) {
        self.number(count as u64);
    }

    /// A text.
    pub(crate) fn text(&mut self, text: &str) {
        self.run(text.as_bytes());
    }

    /// A length-prefixed run of bytes.
    pub(crate) fn run(&mut self, bytes: &[u8]) {
        self.count(bytes.len());
        self.bytes.extend_from_slice(bytes);
    }

    /// Bytes, as given.
    pub(crate) fn raw(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    /// A flag.
    #[cfg(all(
        feature = "load",
        any(
            feature = "number",
            feature = "currency",
            feature = "offset",
            feature = "list"
        )
    ))]
    pub(crate) fn flag(&mut self, flag: bool) {
        self.byte(u8::from(flag));
    }

    /// A length-prefixed part, written by `write`.
    #[cfg(all(
        feature = "load",
        any(feature = "number", feature = "currency", feature = "offset")
    ))]
    pub(crate) fn part(&mut self, write: impl FnOnce(&mut Self)) {
        let mut part = Self::default();
        write(&mut part);
        self.count(part.bytes.len());
        self.bytes.extend_from_slice(&part.bytes);
    }

    /// The bytes written.
    pub(crate) fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

/// Reads a compiled placeholder or a package's entry; every read past its end or of a malformed
/// item is the reader's `malformed` error: [`RenderError::Compiled`] for a placeholder.
#[cfg(feature = "render")]
#[derive(Debug, Clone)]
pub(crate) struct Reader<'a, E = RenderError> {
    bytes: &'a [u8],
    malformed: E,
}

#[cfg(feature = "render")]
impl<'a> Reader<'a> {
    /// A reader of a compiled placeholder of `format`.
    #[cfg(any(
        feature = "number",
        feature = "currency",
        feature = "offset",
        feature = "date",
        feature = "list"
    ))]
    pub(crate) const fn new(bytes: &'a [u8], format: FormatId) -> Self {
        Self::of(bytes, RenderError::Compiled(format.as_str()))
    }
}

#[cfg(feature = "render")]
impl<'a, E: Clone> Reader<'a, E> {
    /// A reader that refuses a malformed item with `malformed`.
    pub(crate) const fn of(bytes: &'a [u8], malformed: E) -> Self {
        Self { bytes, malformed }
    }

    /// The refusal of a malformed item.
    pub(crate) fn malformed(&self) -> E {
        self.malformed.clone()
    }

    /// Whether every byte was read.
    pub(crate) const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// The next `length` bytes.
    pub(crate) fn take(&mut self, length: usize) -> Result<&'a [u8], E> {
        let taken = self.bytes.get(..length).ok_or(self.malformed())?;
        self.bytes = self.bytes.get(length..).unwrap_or_default();
        Ok(taken)
    }

    /// A length-prefixed run of bytes.
    pub(crate) fn run(&mut self) -> Result<&'a [u8], E> {
        let length = self.count()?;
        self.take(length)
    }

    /// One byte.
    pub(crate) fn byte(&mut self) -> Result<u8, E> {
        let (&first, rest) = self.bytes.split_first().ok_or(self.malformed())?;
        self.bytes = rest;
        Ok(first)
    }

    /// An unsigned integer.
    pub(crate) fn number(&mut self) -> Result<u64, E> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = self.byte()?;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(self.malformed())
    }

    /// A signed integer.
    #[cfg(any(feature = "number", feature = "currency", feature = "offset"))]
    pub(crate) fn signed(&mut self) -> Result<i64, E> {
        let value = self.number()?;
        Ok(((value >> 1) as i64) ^ -((value & 1) as i64))
    }

    /// A count of items, or a length.
    pub(crate) fn count(&mut self) -> Result<usize, E> {
        usize::try_from(self.number()?).map_err(|_| self.malformed())
    }

    /// A flag.
    #[cfg(any(
        feature = "number",
        feature = "currency",
        feature = "offset",
        feature = "list"
    ))]
    pub(crate) fn flag(&mut self) -> Result<bool, E> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(self.malformed()),
        }
    }

    /// A text.
    pub(crate) fn text(&mut self) -> Result<&'a str, E> {
        let text = self.run()?;
        std::str::from_utf8(text).map_err(|_| self.malformed())
    }

    /// A length-prefixed part, as a reader of its own.
    #[cfg(any(feature = "number", feature = "currency", feature = "offset"))]
    pub(crate) fn part(&mut self) -> Result<Self, E> {
        let part = self.run()?;
        Ok(Self::of(part, self.malformed()))
    }
}
