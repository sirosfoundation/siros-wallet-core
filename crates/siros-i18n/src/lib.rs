//! The wallet core's messages and their wording. A [`Message`] is an id and arguments: every
//! siros-explain error, and every statement that derives `Message`. A [`Context`] holds the
//! wallet's wording in one locale: modules of Unicode MessageFormat 2 messages, each a W3C message
//! resource whose sections prefix its ids and whose `[formats.<format>]` sections define the
//! options of the format functions. [`Context::resolve`] resolves a message into a [`Text`], its
//! spans styled by the wording's markup (`{#strong}`, `{#emphasis}`, `{#underline}`).
//!
//! An argument takes the functions its type registers in the context's [`Formatters`]:
//! [`Formatters::formatter`] lets a call name a function on the type, and
//! [`Formatters::default_formatter`] also makes the function that of a placeholder `{$x}`, a
//! declaration `.input {$x}` and a selector `.match $x` that name none. Every type takes
//! `:string`, which writes its value's `Display`, and takes it by default where it registers no
//! other. A function reads the value's `Display`: `:number` and `:integer` take a number literal
//! and show the fraction digits it is written with; `:currency` takes a number and a `currency`
//! option, an ISO 4217 code of siros-syntax's table; `:siros:date`, `:siros:time` and
//! `:siros:datetime` take siros-syntax's ISO 8601 literals. Each function family is a feature:
//! `number` (`:number`, `:integer`), `currency` (`:currency`, `:percent`), `offset` (`:offset`) and
//! `date`; `:string` is always in. `siros-cldr` writes the format sections of a language from
//! CLDR 49.0.0.
//!
//! An option's value is a literal or a variable's value (MF2's Option Resolution): an argument's
//! text, a literal, or the value of the call a declaration binds, which is the operand's text for
//! `:string` and the date functions and the number, without an exponent, for the numeric
//! functions. `u:dir` takes `ltr`, `rtl`, `auto` or `inherit`; a variable's other value refuses
//! the message at resolution.
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
//! - `nfc` (default): MF2's Unicode Normalization Form C of names, variant keys and the literals
//!   `:string` selects on, and of the keys of a message's arguments, and
//!   `Context::module_in_nfc`. A build without it holds each as written: it resolves a module
//!   `module_in_nfc` loads to the texts a build with it resolves. Text and arguments' values stay
//!   as written in both.
//! - `check`: `Context::check`, over one row per derived error and statement of every crate the
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

mod args;
mod chain;
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
mod formats;
mod locale;
mod message;
mod messages;
mod mf2;
mod normal;
#[cfg(any(feature = "number", feature = "currency", feature = "offset"))]
mod numeric;
mod registry;
mod resource;
mod scope;
mod seen;
mod string;
#[cfg(feature = "conformance")]
mod test_functions;
mod text;

pub use context::{Bidi, Context};
pub use error::{
    CheckError, FormatRule, LoadError, Refusal, RegisterError, ResolveError, SyntaxRule,
};
pub use escape::escape;
pub use locale::{InvalidTag, LocaleTag};
pub use message::Message;
pub use registry::Formatters;
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
