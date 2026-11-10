//! ISO 4217's currencies, read from List One when the crate builds.

use std::fmt::{self, Write as _};

use crate::malformed::{Malformed, Reader, parse};

mod table {
    include!(concat!(env!("OUT_DIR"), "/iso4217.rs"));
}

/// An ISO 4217 currency: an alphabetic code of List One, the crate's `list-one.xml`, which the
/// build script reads into rows of the code packed in 15 bits and the minor units, ascending by
/// code. Its literal is its alphabetic code: `EUR`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Currency {
    packed: u16,
    minor: u8,
}

impl Currency {
    /// The currency whose alphabetic code `text` is.
    ///
    /// # Errors
    ///
    /// [`Malformed`] for a text other than three uppercase ASCII letters, and at the first letter
    /// for a code List One does not list.
    pub fn parse(text: &str) -> Result<Self, Malformed> {
        parse(text, "Currency", Self::read)
    }

    /// The currency at the reader.
    pub(crate) fn read(reader: &mut Reader<'_>) -> Result<Self, Malformed> {
        let start = reader.at();
        let mut packed = 0u16;
        for _ in 0..3 {
            let letter = reader
                .next_if(u8::is_ascii_uppercase)
                .ok_or_else(|| reader.here())?;
            packed = packed * 32 + u16::from(letter - b'A');
        }
        let row = table::CURRENCIES
            .binary_search_by_key(&packed, |&[high, low, _]| u16::from_be_bytes([high, low]))
            .ok()
            .and_then(|index| table::CURRENCIES.get(index));
        let &[_, _, minor] = row.ok_or_else(|| reader.refuse(start))?;
        Ok(Self { packed, minor })
    }

    /// The alphabetic code's letters.
    #[must_use]
    pub const fn code(self) -> [u8; 3] {
        [
            b'A' + ((self.packed >> 10) & 31) as u8,
            b'A' + ((self.packed >> 5) & 31) as u8,
            b'A' + (self.packed & 31) as u8,
        ]
    }

    /// The minor units List One gives; `None` for its `N.A.`.
    #[must_use]
    pub const fn minor_units(self) -> Option<u8> {
        if self.minor == 255 {
            None
        } else {
            Some(self.minor)
        }
    }
}

/// Its literal: the alphabetic code.
impl fmt::Display for Currency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.code()
            .into_iter()
            .try_for_each(|letter| f.write_char(char::from(letter)))
    }
}
