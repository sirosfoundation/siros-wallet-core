//! `:string` (spec/functions/string.md): it formats its operand's text as given and selects the
//! key equal to it. It ignores the options a call writes, as spec/functions/README.md permits.

use crate::chain::{Chain, Failure, Refused, Root};
use crate::error::Refusal;
use crate::format::Function;
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
