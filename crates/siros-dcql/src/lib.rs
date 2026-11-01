//! Digital Credentials Query Language (DCQL), as defined by
//! [OpenID for Verifiable Presentations 1.0][oid4vp] §6.
//!
//! A DCQL query is how a verifier states what it wants. It carries a list of
//! [`CredentialQuery`] entries — each constrained by format, type and claims —
//! and optionally a list of [`CredentialSetQuery`] entries expressing which
//! *combinations* of those would satisfy the request. A query is constructed only by parsing.
//!
//! [`execute`] evaluates such a query against anything implementing
//! [`Credential`], with format and metadata matching delegated to a
//! [`Policy`] — §6.1 defines `meta` per credential format, so a generic
//! engine cannot interpret it. The crate does no I/O and has no opinion about
//! how credentials are stored, which is what lets the same engine run inside
//! a WebAssembly sandbox, in a Kotlin wallet, and in a Swift one.
//!
//! # Layout
//!
//! [`query`] is the wire model (§6.1–6.3), [`id`] its identifiers (§6.1, §6.3), [`meta`] the
//! text values of `format` and `meta`, [`authority`] its `trusted_authorities` (§6.1.1),
//! [`path`] resolves claims path pointers over any claim tree (§7), and [`eval`] performs
//! selection (§6.4).
//!
//! # Shared vocabulary
//!
//! The request vocabulary the SIROS wallet core's components share is defined here, once:
//! [`QueryId`], [`ClaimPath`], the credential type identifiers [`DocType`] and [`Vct`], and
//! [`TrustedAuthorities`] with its [`AuthorityType`] and [`AuthorityValue`]. The crate depends
//! on no other workspace crate, so that it publishes on its own.
//!
//! [oid4vp]: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html

#![deny(missing_docs)]
#![deny(unsafe_code)]
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

/// Declares a position in a list of the query or a pointer: a number from 0.
macro_rules! position {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(usize);

        impl $name {
            /// The position `value`.
            #[must_use]
            pub const fn new(value: usize) -> Self {
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
                write!(f, "{}", self.0)
            }
        }
    };
}

pub(crate) use position;

pub mod authority;
mod combinations;
pub mod eval;
pub mod id;
pub mod meta;
pub mod path;
pub mod query;
mod result;

pub use authority::{
    AuthorityType, AuthorityValue, TrustedAuthorities, TrustedAuthority, TrustedAuthorityError,
};
pub use combinations::{Combination, Combinations, Dropped};
pub use eval::{execute, select_claims, Credential, CryptographicBinding, ExactFormat, Policy};
pub use id::{ClaimId, ClaimIdError, QueryId, QueryIdError};
pub use meta::{CredentialFormat, CredentialRef, DocType, Vct};
pub use path::{
    mdoc_components, resolve, resolve_json, ClaimNode, ClaimPath, ClaimPathError, ComponentIndex,
    Lookup, PathComponent, PathError,
};
pub use query::{
    ClaimMember, ClaimOption, ClaimsQuery, CredentialMember, CredentialQuery, CredentialSetQuery,
    DcqlQuery, FormFault, HolderBinding, Member, Multiplicity, Position, QueryError,
    QueryTextError, SetMember, SetRequirement,
};
pub use result::{
    Candidate, ClaimPathRefusal, QueryMatch, QueryResult, Satisfaction, SelectedClaim,
};
