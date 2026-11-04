//! The positions that refusals and errors name.

/// Declares a position among the items of one list: a number, from 0.
#[macro_export]
macro_rules! position {
    ($(#[$doc:meta])* $new:vis $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(usize);

        impl $name {
            /// The position `value`.
            #[must_use]
            $new const fn new(value: usize) -> Self {
                Self(value)
            }

            /// The position, from 0.
            #[must_use]
            pub const fn value(self) -> usize {
                self.0
            }
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                ::core::write!(f, "{}", self.0)
            }
        }
    };
}

crate::position!(
    /// The position of a certificate in an issuer chain: 0 for the chain's first certificate.
    pub ChainIndex
);

crate::position!(
    /// The position of an entry in a trust store record.
    pub EntryIndex
);

crate::position!(
    /// The position of a certificate among the `certificates` of a trust store entry.
    pub CertificateIndex
);
