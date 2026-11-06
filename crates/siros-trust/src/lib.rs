//! Issuer trust for the SIROS wallet core: the trust store, issuer chains, and the `Facts` the
//! core matches a Credential Query's `trusted_authorities` against (OpenID4VP 1.0, Section
//! 6.1.1).
//!
//! | Requirement | API |
//! | --- | --- |
//! | TR1: the store, constructible only by parsing its record | [`TrustStore::parse`] |
//! | TR2: the issuer chain, its certificates and their AuthorityKeyIdentifier keyIdentifiers | [`IssuerChain::parse`], [`Certificate`] |
//! | TR3: path validation, which returns the refusal of a chain without a path: the path rules of RFC 5280 over the [`extensions`] TR3 processes, and direct trust in a store certificate byte-identical to the chain's first; the anchor a path ends at | [`IssuerChain::validate_path`], [`TrustStore::anchor`] |
//! | TR5: the facts the wallet records at registration | [`IssuerFacts::at`], [`IssuerFacts::facts`] |
//! | N3: the witness of the core's admission of an issuer for one query | [`AdmittedIssuer::resolve`] |

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(unused_results)]
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
// No attribute can allow these lints, in the tests either.
#![forbid(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unreachable,
    clippy::todo,
    clippy::unimplemented
)]

mod admitted;
mod authority;
mod certificate;
mod chain;
pub mod extensions;
mod facts;
mod ids;
mod path;
mod position;
mod store;

pub use admitted::{AdmittedIssuer, Unadmitted};
pub use authority::{KeyIdentifier, KeyIdentifierError, StoreAuthority, StoreType};
pub use certificate::{
    Certificate, CertificateError, DistinguishedName, IssuanceRefusal, KeyIdentifierFault,
    NameField, PublicKeyFault,
};
pub use chain::{ChainError, IssuerChain};
pub use extensions::{CertSigning, CertificateRole, PathLength};
pub use facts::{ChainRefusal, IssuerFacts};
pub use ids::{AuthorityType, AuthorityValue, QueryId};
pub use path::{OnPath, PathRefusal};
pub use position::{CertificateIndex, ChainIndex, EntryIndex};
pub use store::{EntryError, MemberFault, StoreEntry, StoreError, TrustStore, Unanchored};
