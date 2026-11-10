//! The wallet core's messages and their wording. A [`Message`] is an id and arguments: every
//! siros-explain error, and every statement that derives `Message`. A [`Context`] holds the
//! wallet's wording in one locale: modules of Unicode MessageFormat 2 messages, each a W3C message
//! resource whose sections prefix its ids and whose `[formats.<format>]` sections define the
//! options of the format functions. [`Context::resolve`] resolves a message into a [`Text`], its
//! spans styled by the wording's markup (`{#strong}`, `{#emphasis}`, `{#underline}`).
//!
//! Every argument is text: its value's `Display`. A placeholder without a function writes it as
//! given; the functions parse it. `:number` and `:integer` take a number literal and show the
//! fraction digits it is written with; `:currency` takes a number and a `currency` option, from a
//! literal or an argument; `:siros:date`, `:siros:time` and `:siros:datetime` take siros-syntax's
//! ISO 8601 literals. Each function family is a feature: `number` (`:number`, `:integer`),
//! `currency` (`:currency`, `:percent`), `offset` (`:offset`) and `date`; `:string` is always in.
//! `siros-cldr` writes the format sections of a language from CLDR 49.0.0.
//!
//! [`escape`] writes a text as a resource value that resolves to it: a converter writes each
//! issuer text through it.
//!
//! ```
//! use siros_i18n::{Context, Message};
//!
//! siros_i18n::scope!("wallet");
//!
//! #[derive(Message)]
//! #[message(id = "asks")]
//! struct Asks {
//!     name: String,
//! }
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let source = "@locale en\n@dir ltr\n---\n[wallet]\n\
//!                   asks = {$name} asks for your {#strong}age{/strong}\n";
//!     let context = Context::new().module(source)?;
//!     let text = context.resolve(&Asks { name: "Example Bank".to_owned() })?;
//!     assert_eq!(text.to_string(), "\u{2068}Example Bank\u{2069} asks for your age");
//!     assert_eq!(text.spans().len(), 2);
//!     Ok(())
//! }
//! ```
//!
//! # Features
//!
//! - `number`, `currency`, `offset`, `date` (default): the function families.
//! - `derive` (default): `#[derive(Message)]`.
//! - `check`: [`Context::check`], over one row per derived error and statement of every crate the
//!   binary links. Test builds turn it on; a build without it holds no row.
//! - `conformance`: MF2's test functions `:test:function`, `:test:select` and `:test:format`,
//!   which siros-i18n's conformance tests call. A wording that calls one fails to load in a
//!   build without it.

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

siros_explain::scope!("i18n");

#[cfg(feature = "check")]
pub mod check;
mod compile;
mod context;
#[cfg(feature = "date")]
mod date;
#[cfg(any(
    feature = "number",
    feature = "currency",
    feature = "offset",
    feature = "date",
    feature = "conformance"
))]
mod digit;
mod error;
mod escape;
mod format;
mod locale;
mod message;
mod mf2;
#[cfg(any(feature = "number", feature = "currency", feature = "offset"))]
mod numeric;
mod resource;
mod string;
#[cfg(feature = "conformance")]
mod test_functions;
mod text;

pub use context::{Bidi, Context};
pub use error::{CheckError, FormatRule, LoadError, Refusal, ResolveError, SyntaxRule};
pub use escape::escape;
pub use locale::{InvalidTag, LocaleTag};
pub use message::Message;
pub use siros_explain::scope;
#[cfg(feature = "derive")]
pub use siros_i18n_derive::Message;
pub use text::{Span, Style, Styles, Text};

/// One row of [`check::rows`]: `#[derive(Message)]`'s expansion registers one per id. It expands
/// to nothing in a build without `check`, so a deriving crate follows this crate's feature.
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
