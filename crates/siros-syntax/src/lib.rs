//! Values in their literal forms, and the lists that hold values.
//!
//! [`Count`], [`Decimal`], [`Currency`], [`Amount`], [`Date`], [`Time`], [`Offset`],
//! [`OffsetTime`] and [`DateTime`] each write their literal with `Display` (`1234.5`, `EUR`,
//! `42.50 EUR`, `2026-09-02`, `12:30:15.5+02:00`), and `parse` accepts exactly what `Display`
//! writes: a value is its literal. A text outside the form is [`Malformed`], with the byte where it
//! leaves the form. [`Keyed`] holds values under distinct keys, [`AllOf`] one or more values, and
//! [`checked!`] makes a value of a type whose rule a `const fn` holds when the crate builds.
//!
//! ```
//! use siros_syntax::{Amount, Date, Malformed};
//!
//! let amount = Amount::parse("42.50 EUR")?;
//! assert_eq!((amount.value().units(), amount.value().scale()), (4250, 2));
//! assert_eq!(amount.to_string(), "42.50 EUR");
//! assert_eq!(Date::parse("2026-02-29"), Err(Malformed { of: "Date", at: 8 }));
//! # Ok::<(), Malformed>(())
//! ```

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

siros_explain::scope!("syntax");

mod calendar;
mod checked;
mod iso4217;
mod keyed;
mod list;
mod malformed;
mod value;

pub use calendar::{Date, DateTime, Fraction, Offset, OffsetTime, Second, Time};
pub use iso4217::Currency;
pub use keyed::{Entry, Keyed, Repeated};
pub use list::AllOf;
pub use malformed::Malformed;
pub use value::{Amount, Count, Decimal};
