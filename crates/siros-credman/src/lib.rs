//! Android Credential Manager's entries for the SIROS wallet core's matcher. The core composes
//! each consent entry as platform-neutral data; this crate lays it out as Credential Manager's
//! Standard entry (`AddEntryToSet`) or Payment entry (`AddPaymentEntryToSetV2`), its rows as
//! fields, and decides each set's delegation:
//!
//! - [`CredmanEntry::of`]: a consent entry's Standard or Payment entry; [`Field::of`]: a row's
//!   field.
//! - [`WalletDisplay::of`] (A9): whether a set needs the wallet's display. [`Delegation::of`]
//!   (K4): the delegation the matcher sends for every entry of the set.
//!   [`Fulfilment::check`] (A9): the background fulfilment of a set that needs the wallet's
//!   display is refused with `access_denied`.

#![forbid(unsafe_code)]
#![deny(missing_docs, unused_must_use, unused_results)]
#![deny(
    clippy::let_underscore_must_use,
    clippy::let_underscore_untyped,
    clippy::disallowed_types
)]
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

mod delegation;
mod entry;
mod field;

use siros_explain::{Message, Messages};

pub use delegation::{
    Delegation, Fulfilment, HostDisplay, Presentable, SetFacts, WalletDisplay, WalletDisplayNeeded,
};
pub use entry::{CredmanEntry, EntryIcon, PaymentEntry, StandardEntry};
pub use field::{Extent, FIELD_MAX, Field, FieldName, FieldText, NoName};

/// The crate's messages: those its error types declare.
pub struct CrateMessages;

impl Messages for CrateMessages {
    fn messages() -> Vec<Message> {
        [NoName::messages(), WalletDisplayNeeded::messages()].concat()
    }
}
