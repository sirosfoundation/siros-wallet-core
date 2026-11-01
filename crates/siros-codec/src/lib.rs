//! The encodings every SIROS wallet core crate shares: a strict CBOR reader and deterministic
//! writer, the strict JSON reader (feature `json`), unpadded base64url, the padded
//! base64 of JOSE certificates, the calendar dates and UTC times of CBOR's `full-date` and
//! `tdate`, the ES256 signature value, and the `https` URL.
//!
//! It also holds the internals several components share: [`MemberFault`](member::MemberFault),
//! the member fault of a decoded structure; the [`position!`] and [`text_value!`] macros that
//! declare value newtypes; and [`CertificateChain`](chain::CertificateChain), the DER
//! certificate chain an mdoc `x5chain` and an `x5c` carry.
//!
//! Nothing here panics on any input: the matcher runs this code inside the credential picker,
//! where a trap reads as "no matching credential".

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

mod value;

pub mod base64;
pub mod base64url;
pub mod cbor;
pub mod chain;
pub mod date;
pub mod json;
pub mod member;
mod sextets;
pub mod signature;
pub mod url;

pub use sextets::Base64Error;
