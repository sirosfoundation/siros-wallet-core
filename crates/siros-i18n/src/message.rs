//! What a context resolves: an id and its arguments.

use siros_explain::{Arg, Explain};

/// A text the wallet words: its id, which a context's modules word, and its arguments, each a
/// key the wording reads and a value whose `Display` is the argument's text. Numbers, dates and
/// amounts give their literal form (`1234.5`, `2026-09-02`, `EUR`), which the wording's
/// functions format.
///
/// Every [`Explain`] error is a message: its id `err.<scope>.<id>` and its arguments.
///
/// # Implementing
///
/// Derive it (`#[derive(Message)]`, feature `derive`) on a statement: a struct, or each variant
/// of an enum, carries `#[message(id = "…")]`, and its id is `<scope>.<id>` in the scope the
/// crate's [`scope!`](crate::scope) names. A named field is an argument under its name; a field
/// marked `#[message(skip)]` is none, and a tuple field must be one. An `Option<T>` field gives
/// its value when `Some` and `""` when `None`. An id names one statement of its crate. A type
/// that derives `Explain` is a message already, and deriving both fails to build.
///
/// A context asks for a key as its wording spells it, byte for byte.
pub trait Message {
    /// The id the context's modules word.
    fn id(&self) -> &str;
    /// The argument `key` names; `None` for a key the message has no argument under.
    fn arg(&self, key: &str) -> Option<&dyn Arg>;
}

/// An error's id and its arguments.
impl<E: Explain + ?Sized> Message for E {
    fn id(&self) -> &str {
        Explain::id(self)
    }

    fn arg(&self, key: &str) -> Option<&dyn Arg> {
        Explain::arg(self, key)
    }
}
