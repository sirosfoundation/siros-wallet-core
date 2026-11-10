//! `:string` (spec/functions/string.md): it formats its operand's text as given and selects the
//! key equal to it. It ignores the options a call writes, as spec/functions/README.md permits.
//!
//! The parse holds keys as [`normal`] holds them, and a selector compares a literal held the
//! same way ("Selection": the operand's value in NFC). A selector over an argument compares the
//! argument's text as given.

use std::borrow::Cow;

use crate::chain::{Chain, Failure, Refused, Root};
use crate::error::Refusal;
use crate::format::Function;
use crate::normal::{Hold, normal};
use crate::scope::Scope;

/// Checks a chain of `:string` calls: an operand, and calls of `:string` alone.
///
/// # Errors
///
/// [`Refusal::Operand`] for a chain without an operand or with a call of another function.
pub(crate) fn check(chain: &Chain<'_>) -> Result<(), Refused> {
    if chain.root == Root::None || chain.calls().any(|call| call.function != Function::String) {
        return Err(Refusal::Operand.into());
    }
    Ok(())
}

/// Checks a chain of `:string` calls for its use as a selector: as [`check`], and a literal it
/// compares `hold` holds.
///
/// # Errors
///
/// The refusal of [`check`], and [`Refused::Unnormalized`] for a literal `hold` refuses.
pub(crate) fn selecting(chain: &Chain<'_>, hold: Hold) -> Result<(), Refused> {
    check(chain)?;
    match chain.root {
        Root::Literal(text) => hold.check(text).map_err(Refused::Unnormalized),
        Root::None | Root::Argument(_) => Ok(()),
    }
}

/// The operand's text: a literal as written, an argument's text as given.
///
/// # Errors
///
/// [`Failure::Operand`] for a chain without an operand, and [`Failure::Unresolved`] for an
/// argument the message does not give.
pub(crate) fn value<'m>(chain: &Chain<'m>, scope: &Scope<'m>) -> Result<&'m str, Failure> {
    match chain.root {
        Root::None => Err(Failure::Operand),
        Root::Literal(text) => Ok(text),
        Root::Argument(key) => scope.argument(key),
    }
}

/// The text a selector compares its keys to: a literal as [`normal`] holds it, an argument's
/// text as given.
///
/// # Errors
///
/// [`Failure`] as [`value`].
pub(crate) fn selected<'m>(chain: &Chain<'m>, scope: &Scope<'m>) -> Result<Cow<'m, str>, Failure> {
    match chain.root {
        Root::None => Err(Failure::Operand),
        Root::Literal(text) => Ok(normal(text)),
        Root::Argument(key) => scope.argument(key).map(Cow::Borrowed),
    }
}
