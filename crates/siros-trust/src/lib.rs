//! Issuer trust for the SIROS wallet core (§4.18): the trust store, issuer chains, and the
//! resolution of a Credential Query's `trusted_authorities` (OpenID4VP 1.0, Section 6.1.1)
//! into an admission of a credential's issuer.
//!
//! | Requirement | API |
//! | --- | --- |
//! | TR1: the store, constructible only by parsing its record | [`TrustStore::parse`] |
//! | TR2: the issuer chain, its certificates and their AuthorityKeyIdentifier keyIdentifiers | [`IssuerChain::parse`], [`Certificate`] |
//! | TR3: the resolution, per Credential Query and issuer at a time, into the [`AdmittedIssuer`] witness; a malformed `aki` value makes the query invalid; path validation, which returns the refusal of a chain without a path: the path rules of RFC 5280 over the [`extensions`] TR3 processes, and direct trust in a store certificate byte-identical to the chain's first; the anchor a path ends at | [`QueryAuthorities::of`], [`AdmittedIssuer::resolve`], [`IssuerChain::validate_path`], [`TrustStore::anchor`] |
//! | TR5: the facts the wallet records at registration, and the picker's admission from them alone | [`IssuerFacts::at`], [`Admission::of`] over [`IssuerFacts`] |
//!
//! One rule serves both sides: [`QueryAuthorities::admit`] over an [`Issuer`]. The wallet's
//! issuer is the chain and the store at a time, the picker's the recorded [`IssuerFacts`].
//!
//! Without the feature `chain` the crate holds the rule, the authorities and the facts, for the
//! credential picker (K2, TR5). It builds with Rust 1.82 and holds no X.509 or ECDSA code.

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

mod admission;
mod authority;
mod facts;

pub use admission::{Admission, Ground, Issuer, Refusal, Unadmitted};
pub use authority::{
    AkiError, Authority, AuthorityError, KeyIdentifier, KeyIdentifierError, QueryAuthorities,
    StoreAuthority, StoreType,
};
pub use facts::{FactRefusal, IssuerFacts};

#[cfg(feature = "chain")]
mod admitted;
#[cfg(feature = "chain")]
mod certificate;
#[cfg(feature = "chain")]
mod chain;
#[cfg(feature = "chain")]
pub mod extensions;
#[cfg(feature = "chain")]
mod path;
#[cfg(feature = "chain")]
mod position;
#[cfg(feature = "chain")]
mod store;

#[cfg(feature = "chain")]
pub use admitted::{AdmittedIssuer, ChainRefusal};
#[cfg(feature = "chain")]
pub use certificate::{
    Certificate, CertificateError, DistinguishedName, IssuanceRefusal, KeyIdentifierFault,
    NameField, PublicKeyFault, ValidityTime,
};
#[cfg(feature = "chain")]
pub use chain::{ChainError, IssuerChain};
#[cfg(feature = "chain")]
pub use extensions::{CertSigning, CertificateRole, PathLength};
#[cfg(feature = "chain")]
pub use path::{OnPath, PathRefusal};
#[cfg(feature = "chain")]
pub use position::{CertificateIndex, ChainIndex, EntryIndex};
#[cfg(feature = "chain")]
pub use store::{EntryError, StoreEntry, StoreError, TrustStore, Unanchored};
