//! An error the wallet words. [`Explain`] gives an error's stable identifier and its named
//! arguments; the wallet's MessageFormat 2 wording (siros-i18n's `Context`) resolves the pair into
//! the End-User's text. The error's `Display` is its English line for logs.
//!
//! Each crate that derives `Explain` names its scope once, at its root, with [`scope!`]. Its error
//! ids are `err.<scope>.<id>`. `#[derive(Explain)]` (feature `derive`) writes the trait beside
//! `#[derive(thiserror::Error)]`: a named field is an argument under its name, and a cause or a
//! skipped field is none. An id given twice in one crate fails the build. With the feature `check`,
//! each derived id registers a `check::Row` for the wallet's completeness test.
//!
//! ```
//! use siros_explain::Explain;
//!
//! siros_explain::scope!("ts12");
//!
//! #[derive(Debug, thiserror::Error, Explain)]
//! enum Refused {
//!     #[error("the amount {amount} {currency} exceeds the limit")]
//!     #[explain(id = "over_limit")]
//!     OverLimit {
//!         amount: u64,
//!         currency: &'static str,
//!         #[source]
//!         cause: std::fmt::Error,
//!     },
//! }
//!
//! fn main() {
//!     let refused = Refused::OverLimit { amount: 1200, currency: "EUR", cause: std::fmt::Error };
//!     let mut args = Vec::new();
//!     refused.args(&mut |key, value| args.push((key, value.to_string())));
//!     assert_eq!(refused.id(), "err.ts12.over_limit");
//!     assert_eq!(args, [("amount", "1200".to_owned()), ("currency", "EUR".to_owned())]);
//! }
//! ```
//!
//! # Features
//!
//! - `derive` (default): `#[derive(Explain)]`.
//! - `check`: `check::rows()`, one `check::Row` per derived id of every crate the binary links.
//!   Test builds turn it on; a build without it holds no row.

#![forbid(unsafe_code)]
#![deny(missing_docs, unused_must_use, unused_results)]
#![deny(
    clippy::let_underscore_must_use,
    clippy::let_underscore_untyped,
    clippy::disallowed_types
)]
#![deny(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::unreachable,
    clippy::todo,
    clippy::unimplemented,
    clippy::indexing_slicing,
    clippy::disallowed_methods
)]

#[cfg(feature = "check")]
pub mod check;

use core::fmt::Display;
use std::error::Error;

#[cfg(feature = "derive")]
pub use siros_explain_derive::Explain;

/// An error with a stable identifier and named arguments, which the wallet's wording resolves into
/// the End-User's text.
///
/// # Implementing
///
/// Derive it beside `#[derive(thiserror::Error)]`. A hand-written impl forwards to the error it
/// wraps, as the one for `Box<dyn Explain>` does.
pub trait Explain: Error + Send + Sync + 'static {
    /// `err.<scope>.<id>`: stable across releases; a changed meaning takes a new id.
    fn id(&self) -> &'static str;
    /// Gives `arg` each argument: its key and its value.
    fn args(&self, arg: &mut dyn FnMut(&'static str, &dyn Display));
}

/// A plug-in's error crosses the boundary boxed: its source is the boxed error's.
impl Error for Box<dyn Explain> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        (**self).source()
    }
}

/// The boxed error's id and arguments.
impl Explain for Box<dyn Explain> {
    fn id(&self) -> &'static str {
        (**self).id()
    }

    fn args(&self, arg: &mut dyn FnMut(&'static str, &dyn Display)) {
        (**self).args(arg);
    }
}

/// Names the crate's scope, once, at the root of each crate that derives `Explain` (or siros-i18n's
/// `Message`): its error ids are `err.<scope>.<id>`, its statement ids `<scope>.<id>`. The derives
/// read the scope through the crate-private `crate::__siros_scope!`, so a crate without it fails to
/// build at its first derive.
#[macro_export]
macro_rules! scope {
    ($scope:literal) => {
        #[doc(hidden)]
        #[allow(
            unused_macros,
            reason = "a crate's derives may all sit behind its features"
        )]
        macro_rules! __siros_scope {
            (err $id:literal) => {
                ::core::concat!("err.", $scope, ".", $id)
            };
            (msg $id:literal) => {
                ::core::concat!($scope, ".", $id)
            };
        }
        #[doc(hidden)]
        #[allow(
            unused_imports,
            reason = "a crate's derives may all sit behind its features"
        )]
        pub(crate) use __siros_scope;
    };
}

/// One row of [`check::rows`]: the derive's expansion registers one per id. It expands to nothing
/// in a build without `check`, so a deriving crate follows this crate's feature.
#[doc(hidden)]
#[cfg(feature = "check")]
#[macro_export]
macro_rules! __row {
    ($id:expr, [$($key:literal),* $(,)?]) => {
        $crate::check::__inventory::submit! {
            $crate::check::Row { id: $id, keys: &[$($key),*] }
        }
    };
}

/// One row of `check::rows`: nothing in a build without `check`.
#[doc(hidden)]
#[cfg(not(feature = "check"))]
#[macro_export]
macro_rules! __row {
    ($($row:tt)*) => {};
}
