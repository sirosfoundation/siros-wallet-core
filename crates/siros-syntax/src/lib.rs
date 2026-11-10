#![doc = include_str!("../README.md")]
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
pub use value::{Amount, Count, Decimal, Digits};
