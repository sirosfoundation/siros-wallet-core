//! `:string` (spec/functions/string.md): it formats its operand's text as given and selects the
//! key equal to it. It ignores the options a call writes, as spec/functions/README.md permits.
//!
//! The parse holds keys as [`normal`] holds them, and a selector compares a literal held the
//! same way ("Selection": the operand's value in NFC). A selector over an argument compares the
//! argument's text as given.

use std::borrow::Cow;

use crate::error::Refusal;
use crate::format::{Chain, Env, Failure, Function, Refused, Root, Use};
use crate::normal::{Hold, normal};

/// Checks a chain of `:string` calls for its use: an operand, a call of `:string` alone, and a
/// selector's literal `hold` holds.
///
/// # Errors
///
/// [`Refused::Call`] with [`Refusal::Operand`] for a chain without an operand or with a call of
/// another function, and [`Refused::Unnormalized`] for a selector's literal `hold` refuses.
pub(crate) fn check(chain: &Chain<'_>, at: Use, hold: Hold) -> Result<(), Refused> {
    if chain.calls().any(|call| call.function != Function::String) {
        return Err(Refusal::Operand.into());
    }
    match chain.root {
        Root::None => Err(Refusal::Operand.into()),
        Root::Literal(text) if at == Use::Select => hold.check(text).map_err(Refused::Unnormalized),
        Root::Literal(_) | Root::Argument(_) => Ok(()),
    }
}

/// The operand's text: a literal as written, an argument's text as given.
///
/// # Errors
///
/// [`Failure::Unresolved`] for an argument the message does not give.
pub(crate) fn value<'m>(chain: &Chain<'m>, env: &Env<'_, 'm>) -> Result<&'m str, Failure> {
    match chain.root {
        Root::None => Err(Failure::Operand),
        Root::Literal(text) => Ok(text),
        Root::Argument(key) => env.argument(key),
    }
}

/// The keys equal to the text a selector compares.
///
/// # Errors
///
/// [`Failure::Unresolved`] for an argument the message does not give.
pub(crate) fn select<'k>(
    chain: &Chain<'_>,
    env: &Env<'_, '_>,
    keys: &'k [String],
) -> Result<Vec<&'k str>, Failure> {
    let compared = match chain.root {
        Root::None => return Err(Failure::Operand),
        Root::Literal(text) => normal(text),
        Root::Argument(key) => Cow::Borrowed(env.argument(key)?),
    };
    Ok(keys
        .iter()
        .filter(|key| key.as_str() == compared.as_ref())
        .map(String::as_str)
        .collect())
}
