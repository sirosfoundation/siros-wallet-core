//! MF2's test functions `:test:function`, `:test:select` and `:test:format`
//! (message-format-wg `test/README.md`, "Test Functions"), which the conformance suite calls.
//! Builds with `conformance` compile them in.
//!
//! Each takes a number literal, from the message or an argument, and the literal options
//! `decimalPlaces` (`0` or `1`) and `fails` (`never`, `always`, `format` or `select`), which a
//! call takes over from the `:test:*` call of its operand. A value formats as its integer part,
//! with its first fraction digit under `decimalPlaces=1`; it selects the keys `1`, and `1.0` under
//! `decimalPlaces=1`, when it is one.

use crate::error::Refusal;
use crate::format::{Argument, Chain, Failure, Function, OptionValue, Root};
use crate::mf2::number::NumberLiteral;

/// How a message uses an expression's value at one site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Use {
    /// A placeholder formats it.
    Format,
    /// A selector selects on it.
    Select,
}

/// A compiled call: its operand and its `decimalPlaces`.
#[derive(Debug, Clone)]
pub(crate) struct Compiled {
    root: Root,
    places: Places,
}

/// `decimalPlaces`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Places {
    Zero,
    One,
}

/// A chain's resolved `decimalPlaces` and `fails`.
#[derive(Debug, Clone, Copy)]
struct State {
    places: Places,
    fails_format: bool,
    fails_select: bool,
}

/// Whether `text` is a `number-literal`.
fn number_literal(text: &str) -> bool {
    NumberLiteral::parse(text).is_some()
}

/// Compiles a chain of test function calls for its use at one site.
///
/// # Errors
///
/// [`Refusal::Operand`] for an operand other than a number literal or an argument, or a call of
/// another function; [`Refusal::Option`] for an option value the functions refuse, or `fails`
/// that fails the use; [`Refusal::Formatter`] for `:test:select` in a placeholder;
/// [`Refusal::Selector`] for `:test:format`, or `fails` that fails selection, in a selector.
pub(crate) fn compile(chain: &Chain, at: Use) -> Result<Compiled, Refusal> {
    match &chain.root {
        Root::None => return Err(Refusal::Operand),
        Root::Literal(text) if !number_literal(text) => return Err(Refusal::Operand),
        Root::Literal(_) | Root::Argument(_) => {}
    }
    let mut state = State {
        places: Places::Zero,
        fails_format: false,
        fails_select: false,
    };
    for call in chain.calls() {
        if !matches!(
            call.function,
            Function::Test | Function::TestSelect | Function::TestFormat
        ) {
            return Err(Refusal::Operand);
        }
        for (name, value) in &call.options {
            let refuse = || Refusal::Option {
                option: name.clone(),
            };
            let text = match value {
                OptionValue::Literal(text) | OptionValue::Local(text) => text.as_str(),
                OptionValue::Argument(_) => return Err(refuse()),
            };
            match (name.as_str(), text) {
                ("decimalPlaces", "0") => state.places = Places::Zero,
                ("decimalPlaces", "1") => state.places = Places::One,
                ("fails", "never") => {}
                ("fails", "always") => (state.fails_format, state.fails_select) = (true, true),
                ("fails", "format") => state.fails_format = true,
                ("fails", "select") => state.fails_select = true,
                ("decimalPlaces" | "fails", _) => return Err(refuse()),
                _ => {}
            }
        }
    }
    let outer = chain.outer.function;
    match at {
        Use::Format if outer == Function::TestSelect => return Err(Refusal::Formatter),
        Use::Format if state.fails_format => {
            return Err(Refusal::Option {
                option: "fails".to_owned(),
            });
        }
        Use::Select if outer == Function::TestFormat || state.fails_select => {
            return Err(Refusal::Selector);
        }
        Use::Format | Use::Select => {}
    }
    Ok(Compiled {
        root: chain.root.clone(),
        places: state.places,
    })
}

impl Compiled {
    /// The operand's value.
    fn number(&self, argument: &Argument<'_>) -> Result<f64, Failure> {
        let text = match &self.root {
            Root::None => return Err(Failure::Operand),
            Root::Literal(text) => text.as_str(),
            Root::Argument(key) => argument(key).ok_or_else(|| Failure::Unresolved(key.clone()))?,
        };
        if !number_literal(text) {
            return Err(Failure::Operand);
        }
        text.parse().map_err(|_| Failure::Operand)
    }

    /// The value formatted.
    ///
    /// # Errors
    ///
    /// [`Failure`] for an operand other than a number literal, or an argument not given.
    pub(crate) fn format(&self, argument: &Argument<'_>) -> Result<String, Failure> {
        let value = self.number(argument)?;
        let sign = if value < 0.0 { "-" } else { "" };
        let whole = value.abs().floor();
        Ok(match self.places {
            Places::Zero => format!("{sign}{whole}"),
            Places::One => {
                let digit = ((value.abs() - whole) * 10.0).floor();
                format!("{sign}{whole}.{digit}")
            }
        })
    }

    /// The keys the value matches, best first.
    ///
    /// # Errors
    ///
    /// [`Failure`] as [`Compiled::format`].
    pub(crate) fn select<'k>(
        &self,
        argument: &Argument<'_>,
        keys: &'k [String],
    ) -> Result<Vec<&'k str>, Failure> {
        if self.number(argument)? != 1.0 {
            return Ok(Vec::new());
        }
        let accepted: &[&str] = match self.places {
            Places::Zero => &["1"],
            Places::One => &["1.0", "1"],
        };
        Ok(accepted
            .iter()
            .flat_map(|text| keys.iter().filter(move |key| key == text))
            .map(String::as_str)
            .collect())
    }
}
