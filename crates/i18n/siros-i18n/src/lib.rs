//! The wallet core's messages and their wording. A [`Message`] is an id and arguments: every
//! siros-explain error, and every statement that derives `Message`. A [`Context`] holds the
//! wallet's wording in one locale: modules of Unicode MessageFormat 2 messages, each a W3C message
//! resource whose sections prefix its ids or configure its formatters. [`Context::resolve`] resolves a message into a [`Text`], its
//! spans styled by the wording's markup (`{#strong}`, `{#emphasis}`, `{#underline}`).
//!
//! Every function beyond `:string`, which writes a value's `Display`, comes from a [`Formatter`]
//! the context's [`Builder`] is given: it reads the sections of the modules it claims, defines
//! functions under names a call writes as `:name`, and gives the function a value of each type
//! takes where the wording names none (a placeholder `{$x}`, a declaration `.input {$x}`, a
//! selector `.match $x`). A type no formatter claims takes `:string`. siros-i18n-formats ships a
//! general pattern formatter configured by the locale files.
//!
//! An option's value is a literal or a variable's value (MF2's Option Resolution): an argument's
//! text, a literal, or the text of the operand of the call a declaration binds. The load refuses
//! an option of MF2's `u:` namespace.
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
//! - `derive` (default): `#[derive(Message)]`.
//! - `check`: `Context::check`, over one row per derived error and statement of every crate the
//!   binary links. Test builds turn it on; a build without it holds no row.

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

mod args;
mod chain;
#[cfg(feature = "check")]
pub mod check;
mod compile;
mod context;
mod error;
mod escape;
mod format;
mod formatter;
mod locale;
mod message;
mod messages;
mod mf2;
mod resource;
mod scope;
mod seen;
mod string;
mod text;

pub use context::{Bidi, Builder, Context};
pub use error::{CheckError, FormatRule, LoadError, Refusal, ResolveError, SyntaxRule};
pub use escape::escape;
pub use locale::{InvalidTag, LocaleTag};
pub use formatter::{Direction, Formatter, FunctionId, Selection, Setting};
pub use message::Message;
pub use siros_explain::{Arg, scope};
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
