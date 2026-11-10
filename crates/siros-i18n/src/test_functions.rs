//! MF2's test functions `:test:function`, `:test:select` and `:test:format`
//! (message-format-wg `test/README.md`, "Test Functions"), which the conformance suite calls.
//! Builds with `conformance` compile them in.
//!
//! Each takes a number literal, from the message or an argument, and the options `decimalPlaces`
//! (`0` or `1`) and `fails` (`never`, `always`, `format` or `select`), which a call takes over
//! from the `:test:*` call of its operand. A value formats as its integer part, with its first
//! fraction digit under `decimalPlaces=1`; it selects the keys `1`, and `1.0` under
//! `decimalPlaces=1`, when it is one. An option's value is the input's text.

use crate::chain::{Chain, Failure, Refused, Root, Scope, Texts, Use};
use crate::error::Refusal;
use crate::format::Function;
use crate::mf2::number::NumberLiteral;

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

impl State {
    /// The state the options with their texts set, in order; the error is the option whose text
    /// the functions refuse. The functions ignore other options.
    fn of<'t>(options: impl IntoIterator<Item = (&'t str, &'t str)>) -> Result<Self, &'t str> {
        let mut state = Self {
            places: Places::Zero,
            fails_format: false,
            fails_select: false,
        };
        for (name, text) in options {
            match (name, text) {
                ("decimalPlaces", "0") => state.places = Places::Zero,
                ("decimalPlaces", "1") => state.places = Places::One,
                ("fails", "never") => {}
                ("fails", "always") => (state.fails_format, state.fails_select) = (true, true),
                ("fails", "format") => state.fails_format = true,
                ("fails", "select") => state.fails_select = true,
                ("decimalPlaces" | "fails", _) => return Err(name),
                _ => {}
            }
        }
        Ok(state)
    }

    /// The state of resolved calls.
    ///
    /// # Errors
    ///
    /// [`Failure::Option`] for an option text the functions refuse.
    fn resolved(texts: &Texts<'_>) -> Result<Self, Failure> {
        let options = texts.calls().flat_map(|call| call.options.iter().copied());
        Self::of(options).map_err(|option| Failure::Option(option.to_owned()))
    }
}

/// Whether `text` is a `number-literal`.
fn number_literal(text: &str) -> bool {
    NumberLiteral::parse(text).is_some()
}

/// What the load fixes of a chain of test function calls: the state its fixed option texts set,
/// and whether it fixes every option.
///
/// # Errors
///
/// [`Refusal::Operand`] for an operand other than a number literal or an argument, or a call of
/// another function; [`Refusal::Option`] for an option text the functions refuse.
fn fixed(chain: &Chain) -> Result<(State, bool), Refused> {
    match &chain.root {
        Root::None => return Err(Refusal::Operand.into()),
        Root::Literal(text) if !number_literal(text) => return Err(Refusal::Operand.into()),
        Root::Literal(_) | Root::Argument(_) => {}
    }
    if chain.calls().any(|call| {
        !matches!(
            call.function,
            Function::Test | Function::TestSelect | Function::TestFormat
        )
    }) {
        return Err(Refusal::Operand.into());
    }
    let fixed = chain.calls().flat_map(|call| {
        call.options()
            .filter_map(|(name, value)| Some((name, value.fixed()?)))
    });
    let state = State::of(fixed).map_err(refuse)?;
    Ok((state, chain.fixed_texts()?.is_some()))
}

fn refuse(option: &str) -> Refusal {
    Refusal::Option {
        option: option.to_owned(),
    }
}

/// Checks a chain of test function calls for its use. Options whose texts the load fixes are
/// checked now, and `fails` against the use when the load fixes every option.
///
/// # Errors
///
/// The refusals of an operand, a call or an option text; [`Refusal::Formatter`] for
/// `:test:select` in a placeholder, and [`Refusal::Option`] for `fails` that fails formatting
/// there.
pub(crate) fn check(chain: &Chain, at: Use) -> Result<(), Refused> {
    let (state, every) = fixed(chain)?;
    match at {
        Use::Format if chain.outer.function == Function::TestSelect => {
            Err(Refusal::Formatter.into())
        }
        Use::Format if every && state.fails_format => Err(refuse("fails").into()),
        Use::Format | Use::Value => Ok(()),
    }
}

/// Checks a chain of test function calls for its use as a selector, as [`check`].
///
/// # Errors
///
/// The refusals of an operand, a call or an option text; [`Refusal::Selector`] for
/// `:test:format`, or `fails` that fails selection.
pub(crate) fn selecting(chain: &Chain) -> Result<(), Refused> {
    let (state, every) = fixed(chain)?;
    if chain.outer.function == Function::TestFormat || (every && state.fails_select) {
        return Err(Refusal::Selector.into());
    }
    Ok(())
}

/// The operand's text, a number literal.
fn input<'m>(chain: &'m Chain, scope: &Scope<'m>) -> Result<&'m str, Failure> {
    let text = match &chain.root {
        Root::None => return Err(Failure::Operand),
        Root::Literal(text) => text,
        Root::Argument(key) => scope.argument(key)?,
    };
    if number_literal(text) {
        Ok(text)
    } else {
        Err(Failure::Operand)
    }
}

/// The input as an option's value: its text.
///
/// # Errors
///
/// [`Failure`] for an operand other than a number literal, an option text the functions refuse,
/// or an argument not given.
pub(crate) fn value<'m>(
    chain: &'m Chain,
    texts: &Texts<'_>,
    scope: &Scope<'m>,
) -> Result<&'m str, Failure> {
    State::resolved(texts).and_then(|_| input(chain, scope))
}

/// The operand's value and the resolved state.
fn number(chain: &Chain, texts: &Texts<'_>, scope: &Scope<'_>) -> Result<(f64, State), Failure> {
    let state = State::resolved(texts)?;
    let value = input(chain, scope)?.parse().map_err(|_| Failure::Operand)?;
    Ok((value, state))
}

/// The value formatted.
///
/// # Errors
///
/// [`Failure`] for an operand other than a number literal, an option text the functions refuse,
/// `fails` that fails formatting, or an argument not given.
pub(crate) fn format(
    chain: &Chain,
    texts: &Texts<'_>,
    scope: &Scope<'_>,
) -> Result<String, Failure> {
    let (value, state) = number(chain, texts, scope)?;
    if state.fails_format {
        return Err(Failure::Option("fails".to_owned()));
    }
    let sign = if value < 0.0 { "-" } else { "" };
    let whole = value.abs().floor();
    Ok(match state.places {
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
/// [`Failure`] as [`format`], with `fails` that fails selection.
pub(crate) fn selected(
    chain: &Chain,
    texts: &Texts<'_>,
    scope: &Scope<'_>,
) -> Result<&'static [&'static str], Failure> {
    let (value, state) = number(chain, texts, scope)?;
    if state.fails_select {
        return Err(Failure::Option("fails".to_owned()));
    }
    if value != 1.0 {
        return Ok(&[]);
    }
    Ok(match state.places {
        Places::Zero => &["1"],
        Places::One => &["1.0", "1"],
    })
}
