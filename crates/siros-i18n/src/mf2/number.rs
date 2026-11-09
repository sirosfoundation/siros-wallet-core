//! MF2's `number-literal` (spec/functions/number.md): the operand text `:number`, `:integer` and
//! the test functions take.
//!
//! ```text
//! number-literal = ["-"] (%x30 / (%x31-39 *DIGIT)) ["." 1*DIGIT] [%i"e" ["-" / "+"] 1*DIGIT]
//! ```

/// A `number-literal`'s parts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NumberLiteral<'a> {
    /// Whether it starts with `-`.
    pub(crate) negative: bool,
    /// The integer digits, one or more.
    pub(crate) whole: &'a str,
    /// The fraction digits; empty without a `.`.
    pub(crate) fraction: &'a str,
    /// The exponent: whether it is negative, and its digits, one or more.
    pub(crate) exponent: Option<(bool, &'a str)>,
}

impl<'a> NumberLiteral<'a> {
    /// The parts of `text`; `None` for a text the grammar does not match.
    pub(crate) fn parse(text: &'a str) -> Option<Self> {
        let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
        let (negative, rest) = match text.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, text),
        };
        let (mantissa, exponent) = match rest.split_once(['e', 'E']) {
            Some((mantissa, exponent)) => (mantissa, Some(exponent)),
            None => (rest, None),
        };
        let (whole, fraction) = match mantissa.split_once('.') {
            Some((whole, fraction)) if digits(fraction) => (whole, fraction),
            Some(_) => return None,
            None => (mantissa, ""),
        };
        if !digits(whole) || (whole.len() > 1 && whole.starts_with('0')) {
            return None;
        }
        let exponent = match exponent {
            None => None,
            Some(power) => {
                let (negative, power) = match power.strip_prefix('-') {
                    Some(power) => (true, power),
                    None => (false, power.strip_prefix('+').unwrap_or(power)),
                };
                if !digits(power) {
                    return None;
                }
                Some((negative, power))
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
