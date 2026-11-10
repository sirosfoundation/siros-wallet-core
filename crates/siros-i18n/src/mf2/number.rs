//! MF2's `number-literal` (spec/functions/number.md): the operand text `:number`, `:integer` and
//! the test functions take.
//!
//! ```text
//! number-literal = ["-"] (%x30 / (%x31-39 *DIGIT)) ["." 1*DIGIT] [%i"e" ["-" / "+"] 1*DIGIT]
//! ```

use crate::digit::Digit;

/// A `number-literal`'s parts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NumberLiteral {
    /// Whether it starts with `-`.
    pub(crate) negative: bool,
    /// The integer digits, one or more.
    pub(crate) whole: Vec<Digit>,
    /// The fraction digits; none without a `.`.
    pub(crate) fraction: Vec<Digit>,
    /// The exponent: whether it is negative, and its digits, one or more.
    pub(crate) exponent: Option<(bool, Vec<Digit>)>,
}

impl NumberLiteral {
    /// The parts of `text`; `None` for a text the grammar does not match.
    pub(crate) fn parse(text: &str) -> Option<Self> {
        let (negative, rest) = match text.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, text),
        };
        let (mantissa, exponent) = match rest.split_once(['e', 'E']) {
            Some((mantissa, exponent)) => (mantissa, Some(exponent)),
            None => (rest, None),
        };
        let (whole, fraction) = match mantissa.split_once('.') {
            Some((whole, fraction)) => (digits(whole)?, digits(fraction)?),
            None => (digits(mantissa)?, Vec::new()),
        };
        if matches!(whole.as_slice(), [Digit::Zero, _, ..]) {
            return None;
        }
        let exponent = match exponent {
            None => None,
            Some(power) => {
                let (negative, power) = match power.strip_prefix('-') {
                    Some(power) => (true, power),
                    None => (false, power.strip_prefix('+').unwrap_or(power)),
                };
                Some((negative, digits(power)?))
            }
        };
        Some(Self {
            negative,
            whole,
            fraction,
            exponent,
        })
    }
}

/// `1*DIGIT`.
fn digits(text: &str) -> Option<Vec<Digit>> {
    let digits = text.chars().map(Digit::of).collect::<Option<Vec<_>>>()?;
    (!digits.is_empty()).then_some(digits)
}
