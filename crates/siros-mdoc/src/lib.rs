//! ISO/IEC 18013-5 mdocs for the SIROS wallet core.
//!
//! [`Mdoc::parse`] reads a stored credential: base64url of an `IssuerSigned`, a `Document`, or a
//! `DeviceResponse` with one document. An [`Mdoc`] holds the document type, the namespaces with
//! their items, `issuerAuth` and the MSO. Each `IssuerSignedItemBytes` and `issuerAuth` keep the
//! bytes the issuer wrote. Parsing refuses a credential whose `Document` names another
//! `docType` than its MSO, or whose items do not have the digests `valueDigests` lists.
//!
//! [`Mdoc::disclose`] selects items and takes the `DeviceSigned` elements the response carries.
//! It refuses an element the MSO's `KeyAuthorizations` do not authorize (OpenID4VP 1.0, B.2.1).
//! The [`Disclosure`] gives the data the device key signs and, with that signature, the
//! `DeviceResponse`. [`device_signing_input`] gives the same data from a session transcript, a
//! document type and the `DeviceSigned` namespaces alone.
//!
//! The feature `crypto` adds ES256 verification ([`es256_verifies`]).

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::cognitive_complexity)]
// Nothing panics outside the tests. scripts/check_panic_sites.py refuses an
// allow of these lints there and finds the panics they cannot see.
#![cfg_attr(
    not(test),
    deny(
        clippy::panic,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::indexing_slicing,
        clippy::disallowed_methods
    )
)]

mod device;
mod device_key;
mod disclosure;
mod error;
mod issuer_auth;
mod key_authorizations;
mod mdoc;
mod mso;
mod names;
mod signature;

#[cfg(feature = "crypto")]
mod es256;

pub use device::{device_signing_input, DeviceNameSpaces, DeviceSignedElement};
pub use device_key::{P256Key, PointError};
pub use disclosure::{Disclosure, ElementId};
pub use error::{
    AlgorithmFault, DeviceKeyFault, DisclosureError, DocTypeFault, EnvelopeFault, IssuerAuthFault,
    ItemFault, ItemMember, KeyAuthorizationsFault, MdocError, NameFault, NameSpacesFault,
    NamesFault, PayloadFault, ValidityFault, ValidityTime, ValueDigestsFault,
};
pub use issuer_auth::IssuerAuth;
pub use key_authorizations::KeyAuthorizations;
pub use mdoc::{IssuerNameSpace, IssuerSignedItem, Mdoc};
pub use mso::{DigestAlgorithm, ItemDigest, Mso, Validity};
pub use names::{DigestId, ElementIdentifier, NameSpace};
pub use signature::{CoseAlgorithm, MessageDigest, SessionTranscript, SigStructure};

#[cfg(feature = "crypto")]
pub use es256::es256_verifies;
