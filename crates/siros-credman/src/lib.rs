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

siros_explain::scope!("credman");

mod cluster;
mod delegation;
mod emit;
mod entry;
mod field;
mod read;
#[cfg(feature = "register")]
pub mod register;
mod registration;

pub use delegation::{
    Delegation, Fulfilment, HostDisplay, Presentable, SetFacts, TransactionData, WalletDisplay,
    WalletDisplayNeeded,
};
pub use emit::{
    Emission, Emitted, EntryId, NotEmitted, PaymentShown, Shown, StandardShown, Unshown, emit,
};
pub use entry::{CredmanEntry, EntryIcon, PaymentEntry, StandardEntry};
pub use field::{Extent, FIELD_MAX, Field, FieldName, FieldText, NoName};
pub use read::{Malformed, ReadError, Registration};
pub use registration::{Base, ContextError, Kind};
