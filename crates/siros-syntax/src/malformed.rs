//! The crate's one format error, and the reader every `parse` reads its literal with.

use siros_explain::Explain;

/// A text that is no literal of the type `of`: `at` is the offset of the first byte that leaves the
/// literal form, the text's length when the text ends early. A field whose value the type refuses
/// is refused at its first byte: the day of `2026-02-30`, the hour of `24:00`, the sign of `-0` and
/// of `+00:00`, the first letter of a code ISO 4217 does not list, the seconds of a leap second
/// RFC 3339 places elsewhere. A number past its type's range is refused at the digit that passes
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error, Explain)]
#[error("no {of} literal: the text leaves the form at byte {at}")]
#[explain(id = "malformed")]
pub struct Malformed {
    /// The type the text is no literal of: `Count`, `Decimal`, `Currency`, `Amount`, `Date`,
    /// `Time`, `Offset`, `OffsetTime` or `DateTime`.
    pub of: &'static str,
    /// The byte offset where the text leaves the form.
    pub at: usize,
}

/// A literal being read: its bytes, the offset of the next one, and the type it is a literal of.
pub(crate) struct Reader<'t> {
    bytes: &'t [u8],
    at: usize,
    of: &'static str,
}

impl<'t> Reader<'t> {
    /// `text`, as a literal of `of`.
    pub(crate) const fn new(text: &'t str, of: &'static str) -> Self {
        Self {
            bytes: text.as_bytes(),
            at: 0,
            of,
        }
    }

    /// The offset of the next byte.
    pub(crate) const fn at(&self) -> usize {
        self.at
    }

    /// The refusal at `at`.
    pub(crate) const fn refuse(&self, at: usize) -> Malformed {
        Malformed { of: self.of, at }
    }

    /// The refusal at the next byte.
    pub(crate) const fn here(&self) -> Malformed {
        self.refuse(self.at)
    }

    /// The next byte, unread.
    pub(crate) fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    /// Reads `byte` when it is next.
    pub(crate) fn take(&mut self, byte: u8) -> bool {
        let next = self.peek() == Some(byte);
        if next {
            self.at += 1;
        }
        next
    }

    /// Reads `byte`; refused at the next byte when another is there.
    pub(crate) fn expect(&mut self, byte: u8) -> Result<(), Malformed> {
        if self.take(byte) {
            Ok(())
        } else {
            Err(self.here())
        }
    }

    /// Reads the next byte when `accept` takes it.
    pub(crate) fn next_if(&mut self, accept: impl FnOnce(&u8) -> bool) -> Option<u8> {
        let byte = self.peek().filter(accept)?;
        self.at += 1;
        Some(byte)
    }

    /// Reads one ASCII digit when one is next: its value.
    pub(crate) fn digit(&mut self) -> Option<u8> {
        self.next_if(u8::is_ascii_digit).map(|digit| digit - b'0')
    }

    /// Reads two ASCII digits: their value, 00 to 99.
    pub(crate) fn two(&mut self) -> Result<u8, Malformed> {
        let tens = self.digit().ok_or_else(|| self.here())?;
        let ones = self.digit().ok_or_else(|| self.here())?;
        Ok(tens * 10 + ones)
    }

    /// Reads four ASCII digits: their value, 0000 to 9999.
    pub(crate) fn four(&mut self) -> Result<u16, Malformed> {
        let high = self.two()?;
        let low = self.two()?;
        Ok(u16::from(high) * 100 + u16::from(low))
    }

    /// Refused at the next byte unless every byte is read.
    pub(crate) const fn end(&self) -> Result<(), Malformed> {
        if self.at == self.bytes.len() {
            Ok(())
        } else {
            Err(self.here())
        }
    }
}

/// Reads all of `text` as a literal of `of` with `read`.
pub(crate) fn parse<T>(
    text: &str,
    of: &'static str,
    read: impl FnOnce(&mut Reader<'_>) -> Result<T, Malformed>,
) -> Result<T, Malformed> {
    let mut reader = Reader::new(text, of);
    let value = read(&mut reader)?;
    reader.end()?;
    Ok(value)
}
