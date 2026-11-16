//! A general pattern formatter for siros-i18n. A value type exposes its fields in code
//! ([`Fields`]); the locale files say how they read: `[tables]` of texts and maps, and
//! `[formats.<name>]` sections, each of which defines the function `:<name>` over the types of
//! one name. Give the [`Patterns`] to a context's builder, then load the modules:
//!
//! ```
//! use siros_i18n::{Context, Message};
//! use siros_i18n_formats::Patterns;
//! use siros_syntax::{Date, Decimal};
//!
//! siros_i18n::scope!("wallet");
//!
//! #[derive(Message)]
//! #[message(id = "paid")]
//! struct Paid {
//!     sum: Decimal,
//!     on: Date,
//! }
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let formats = "@locale de\n@dir ltr\n---\n\
//!         [tables]\n\
//!         digits = 0123456789\n\
//!         decimal = ,\n\
//!         group = .\n\
//!         grouping = 1\n\
//!         minus = -\n\
//!         plus = +\n\
//!         months.long =\n  1 Januar\n  2 Februar\n  3 März\n\n\
//!         [formats.number]\n\
//!         of = number\n\
//!         default = yes\n\
//!         maximumFractionDigits = 2\n\
//!         pattern = {sign}{int:group=3}{frac}\n\n\
//!         [formats.date]\n\
//!         of = date\n\
//!         default = yes\n\
//!         pattern = {day}. {month:table=months.long} {year}\n";
//!     let context = Context::builder()
//!         .formatter(Patterns::standard())
//!         .build()
//!         .module(formats)?
//!         .module("@locale de\n@dir ltr\n---\n[wallet]\npaid = {$sum} am {$on}\n")?;
//!     let paid = Paid {
//!         sum: Decimal::parse("1234.567")?,
//!         on: Date::parse("2026-03-05")?,
//!     };
//!     assert_eq!(context.resolve(&paid)?.to_string(), "1.234,57 am 5. März 2026");
//!     Ok(())
//! }
//! ```
//!
//! # `[tables]`
//!
//! Each setting is a table: its text, and, when every line is a key, a space and a text, a map.
//! A table is defined once in a context. `digits` (the ten digit characters, zero first),
//! `minus`, `plus`, `group`, `decimal`, `grouping` (the fewest digits, 1 to 9, of the highest
//! group of a grouped integer), `plural.cardinal` and `plural.ordinal` (CLDR plural rules, one
//! `<category>: <condition>` per line) are the tables the number placeholders read.
//!
//! # `[formats.<name>]`
//!
//! - `of` (required): the name of the types the format takes.
//! - `default`: `yes` makes the format the one its types take where the wording names no
//!   function; one format per name of types is.
//! - `option.<name>`: an option a call may give, its values listed, the default first. A pattern
//!   writes its value as `{<name>}` and tests it.
//! - `pattern` (required): one pattern per line, each after an optional guard; the first line
//!   whose guard holds writes the value. A placeholder writes a field with operations; the
//!   number placeholders write the type's number field, rounded once by the numeric options.
//! - MF2's numeric options (spec/functions/number.md), for types with a number field: their
//!   defaults, which a call's options override. A setting's text may hold placeholders of the
//!   value's fields. The format selects when it sets `select`.
//!
//! ```text
//! line        = ["[" test *(" " test) "]" [" "]] pattern
//! pattern     = *(text / "\{" / "\}" / "\\" / placeholder)
//! placeholder = "{" name [":" op *("," op)] "}"
//! test        = ["!"] name ("=" value / "<" int / "<=" int / ">" int / ">=" int / "?" / "@" table)
//! ```
//!
//! | name | written as | operations |
//! | :-- | :-- | :-- |
//! | `sign` | the `minus` or `plus` table by `signDisplay`, or nothing | |
//! | `int` | the integer digits | `group=<n>`, `second=<n>`: grouping sizes; `sep=<table>` |
//! | `frac` | the decimal separator and the fraction digits, when there are some | `sep=<table>` |
//! | an integer field | its digits | `pad=<n>`, `last=<n>`, `table=<a>\|<b>` |
//! | a text field | its text | `table=<a>\|<b>` |
//! | a declared option | its value | |
//!
//! `table=` writes the entry of the field's text in the first listed table that has it or a `*`
//! entry, else the field's text. A test compares a name's text (`=`), an integer field's value
//! (`<`, `<=`, `>`, `>=`), holds for a field the value has (`?`) or for a text that is a key of a
//! table (`@`); `!` negates it. `sign` tests as `none`, `minus` or `plus`, and `plural` as the
//! number's cardinal plural category.
//!
//! A call names a format as its function, `{$sum :number maximumFractionDigits=0}`; a call's
//! option the format does not take is refused when the module loads for a literal, and when the
//! message resolves for a variable's value. A selector on a format that sets `select` matches an
//! exact number literal first, then the plural category.

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

mod digit;
mod fields;
mod format;
mod number;
mod pattern;
mod patterns;
mod table;

pub use fields::{Field, Fields, Kind};
pub use number::decimal::Number;
pub use patterns::Patterns;
