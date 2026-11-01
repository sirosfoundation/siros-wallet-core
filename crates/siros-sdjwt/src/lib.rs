//! SD-JWT VC for the SIROS wallet core (RFC 9901).
//!
//! | Step | API | Requirement |
//! | --- | --- | --- |
//! | Read a stored credential | [`SdJwt::parse`] | S1: the checks of RFC 9901, Section 7.1 |
//! | Walk its claims | [`SdJwt::claims`], [`Object`], [`Claim`], [`ClaimValue`], [`Element`] | S2: issued array positions |
//! | Resolve a claims path pointer | [`SdJwt::root`] gives the [`Node`] that [`siros_dcql::resolve`] walks | Q4 |
//! | Select disclosures | [`SdJwt::select`] gives a [`Presentation`] | S3 |
//! | Bind the presentation to a key | [`Presentation::key_binding`] gives a [`KeyBinding`] | S4 |
//!
//! The issuer JWT is kept verbatim, with its `x5c` header parameter ([`SdJwt::x5c`]). Its
//! signature and the validity claims (Section 7.1, steps 2.a to 2.c and 6) are the caller's to
//! check.
//!
//! The host signs [`KeyBinding::signing_input`] with ES256 and returns the signature, which
//! [`KeyBinding::assemble`] turns into the SD-JWT+KB.
//!
//! Types that hold claim values or salts implement no `Debug`, which keeps them out of logs
//! (R-G6).
//!
//! Nothing here panics on any input.

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(unused_results)]
#![deny(clippy::cognitive_complexity)]
#![deny(clippy::let_underscore_must_use, clippy::let_underscore_untyped)]
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

mod alg;
mod error;
mod key_binding;
mod node;
mod process;
mod sd_jwt;
mod select;
mod tree;

pub use alg::Digest;
pub use error::{
    DisclosureFault, EncodedJsonFault, IssuerJwtFault, KeyBindingError, ParseError, Placement,
    ReservedFault, SdAlgFault, X5cError, X5cIndex,
};
pub use key_binding::{Audience, BeforeEpoch, KbNonce, KeyBinding, NumericDate, Presentation};
pub use node::{Children, Node, NodeValue};
pub use process::MAX_DEPTH;
pub use sd_jwt::SdJwt;
pub use tree::{Claim, ClaimValue, DisclosureId, Element, Object};
