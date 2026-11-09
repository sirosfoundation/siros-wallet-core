//! `:string` (spec/functions/string.md): it formats its operand's text as given and selects the
//! key equal to it. It ignores the options a call writes, as spec/functions/README.md permits.
//!
//! The parser holds keys in NFC. A selector over a literal compares the literal's NFC form; one
//! over an argument compares the argument's text as given.

use unicode_normalization::UnicodeNormalization;

use crate::error::Refusal;
use crate::format::{Argument, Chain, Failure, Function, Root};

/// A compiled `:string` call: its operand.
#[derive(Debug, Clone)]
pub(crate) enum Compiled {
    /// A literal: as written, and in NFC.
    Literal { text: String, normalized: String },
    /// The argument of this key.
    Argument(String),
}

/// Compiles a chain of `:string` calls.
///
/// # Errors
///
/// [`Refusal::Operand`] for a chain without an operand or with a call of another function.
pub(crate) fn compile(chain: &Chain) -> Result<Compiled, Refusal> {
    if chain.calls().any(|call| call.function != Function::String) {
        return Err(Refusal::Operand);
    }
    match &chain.root {
        Root::None => Err(Refusal::Operand),
        Root::Literal(text) => Ok(Compiled::Literal {
            text: text.clone(),
            normalized: text.nfc().collect(),
        }),
        Root::Argument(key) => Ok(Compiled::Argument(key.clone())),
    }
}

impl Compiled {
    /// The text formatted.
    ///
    /// # Errors
    ///
    /// [`Failure::Unresolved`] for an argument the message does not give.
    pub(crate) fn format<'a>(&'a self, argument: &Argument<'a>) -> Result<&'a str, Failure> {
        match self {
            Self::Literal { text, .. } => Ok(text),
            Self::Argument(key) => argument(key).ok_or_else(|| Failure::Unresolved(key.clone())),
        }
    }

    /// The keys equal to the text a selector compares.
    ///
    /// # Errors
    ///
    /// [`Failure::Unresolved`] for an argument the message does not give.
    pub(crate) fn select<'k>(
        &self,
        argument: &Argument<'_>,
        keys: &'k [String],
    ) -> Result<Vec<&'k str>, Failure> {
        let compared = match self {
            Self::Literal { normalized, .. } => normalized.as_str(),
            Self::Argument(key) => argument(key).ok_or_else(|| Failure::Unresolved(key.clone()))?,
        };
        Ok(keys
            .iter()
            .filter(|key| *key == compared)
            .map(String::as_str)
            .collect())
    }
}
