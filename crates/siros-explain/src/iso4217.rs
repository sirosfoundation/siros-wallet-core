//! ISO 4217's currencies, remapped from `iso_currency`'s table when the crate builds.

mod table {
    include!(concat!(env!("OUT_DIR"), "/iso4217.rs"));
}

/// An ISO 4217 currency: an entry of `iso_currency`'s table, which the build script remaps into
/// each alphabetic code packed in 15 bits, ascending, and its minor units.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Currency {
    packed: u16,
    minor: u8,
}

impl Currency {
    /// The currency with this alphabetic code; `None` when ISO 4217 lists none.
    #[must_use]
    pub fn from_code(code: &str) -> Option<Self> {
        let [a, b, c] = code.as_bytes() else {
            return None;
        };
        let packed = [a, b, c].iter().try_fold(0u16, |v, &&x| {
            x.is_ascii_uppercase().then(|| v * 32 + u16::from(x - b'A'))
        })?;
        let index = table::CODES.binary_search(&packed).ok()?;
        table::MINOR.get(index).map(|&minor| Self { packed, minor })
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

    /// The minor units ISO 4217 lists; `None` for a currency without them.
    #[must_use]
    pub const fn minor_units(self) -> Option<u8> {
        if self.minor == 255 {
            None
        } else {
            Some(self.minor)
        }
    }
}
