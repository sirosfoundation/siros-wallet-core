//! The names and identifiers of an mdoc's items (ISO/IEC 18013-5, 8.3.2.1.2.2 and 9.1.2.4).

siros_codec::text_value!(
    /// `NameSpace`: a namespace of data elements.
    NameSpace
);

siros_codec::text_value!(
    /// `DataElementIdentifier`: an element's identifier within its namespace.
    ElementIdentifier
);

/// `DigestID`: the number `valueDigests` lists an item's digest under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DigestId(u64);

impl DigestId {
    /// The identifier `value`.
    #[must_use]
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    /// The number.
    #[must_use]
    pub fn value(self) -> u64 {
        self.0
    }
}

impl core::fmt::Display for DigestId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}
