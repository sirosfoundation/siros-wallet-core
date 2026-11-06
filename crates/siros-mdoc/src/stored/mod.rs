//! A stored mdoc as its issuer wrote it (ISO/IEC 18013-5, 8.3.2.1.2.2 and 9.1.2): the base64url
//! of an `IssuerSigned`, a `Document` or a `DeviceResponse` of one document; its items, each
//! matching its digest in the MSO; the MSO's document type, device key, key authorizations and
//! validity; `issuerAuth`'s algorithm, `x5chain` and `Sig_structure`; and the data the device key
//! signs for `DeviceAuthentication`. The reader checks no signature: the app checks the issuer's
//! with its cryptography, and siros-trust the chain.

/// Declares a text of any content whose role is its type.
macro_rules! text_value {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(String);

        impl $name {
            /// The value `text`.
            #[must_use]
            pub fn new(text: &str) -> Self {
                Self(text.to_owned())
            }

            /// The value.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl ::core::cmp::PartialEq<str> for $name {
            fn eq(&self, other: &str) -> bool {
                self.0 == other
            }
        }

        impl ::core::cmp::PartialEq<&str> for $name {
            fn eq(&self, other: &&str) -> bool {
                self.0 == *other
            }
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

/// Declares a position among the items of one list: a number, from 0.
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

pub(crate) use {position, text_value};

mod device;
mod device_key;
mod error;
mod issuer_auth;
mod item;
mod key_authorizations;
mod mdoc;
mod mso;
mod names;
mod signature;

pub use device::{DeviceNameSpaces, device_signing_input};
pub use device_key::{DeviceKey, P256Key, PointError};
pub use error::{
    AlgorithmFault, ArrayIndex, CborError, DeviceKeyFault, DocTypeFault, EnvelopeFault,
    IssuerAuthFault, ItemFault, ItemMember, KeyAuthorizationsFault, MdocError, MemberFault,
    NameFault, NameSpacesFault, NamesFault, PayloadFault, ValidityFault, ValidityTime,
    ValueDigestsFault,
};
pub use issuer_auth::{CertificateChain, IssuerAuth};
pub use key_authorizations::KeyAuthorizations;
pub use mdoc::{IssuerNameSpace, IssuerSignedItem, StoredMdoc};
pub use mso::{DigestAlgorithm, ItemDigest, Mso, Validity};
pub use names::{DigestId, DocType, ElementIdentifier, NameSpace};
pub use signature::{CoseAlgorithm, MessageDigest, SigStructure};
