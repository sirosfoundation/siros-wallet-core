//! Claims path pointers: "a non-empty array of strings, nulls and non-negative integers"
//! (OpenID4VP 1.0 §7; OpenID4VCI 1.0 Appendix C.1 for a JSON-based Credential). A pointer is
//! parsed where it enters, into keys, indices and nulls.

use std::num::IntErrorKind;

use serde_json::{Number, Value};

/// One component of a claims path pointer (OpenID4VP 1.0 §7.1).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PathComponent {
    /// Selects the member of an object with this key: a JSON string.
    Key(String),
    /// Selects the element of an array at this position, from 0: a JSON number whose value is a
    /// non-negative integer.
    Index(u64),
    /// Selects every element of an array: JSON `null`.
    AllElements,
}

/// A claims path pointer: one component or more. Two pointers are equal when their components
/// are, whatever the spelling of their indices.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ClaimsPath(Vec<PathComponent>);

impl ClaimsPath {
    /// The pointer the JSON value `value` writes.
    pub(crate) fn parse(value: &Value) -> Result<Self, ClaimsPathError> {
        let Value::Array(items) = value else {
            return Err(ClaimsPathError::NotArray);
        };
        if items.is_empty() {
            return Err(ClaimsPathError::Empty);
        }
        items
            .iter()
            .enumerate()
            .map(|(at, item)| {
                PathComponent::parse(item).map_err(|why| ClaimsPathError::Component { at, why })
            })
            .collect::<Result<_, _>>()
            .map(Self)
    }
}

impl PathComponent {
    /// The component the JSON value `value` writes.
    fn parse(value: &Value) -> Result<Self, ComponentError> {
        match value {
            Value::String(key) => Ok(Self::Key(key.clone())),
            Value::Number(number) => index_of(number).map(Self::Index),
            Value::Null => Ok(Self::AllElements),
            Value::Bool(_) | Value::Array(_) | Value::Object(_) => Err(ComponentError::WrongType),
        }
    }
}

/// The index a JSON number writes: its value, when that is an integer from 0 to 2^64 − 1.
///
/// The number's decimal text decides (RFC 8259 §6), digit by digit, so no rounding turns a
/// fraction into an integer: `1`, `1.0` and `10e-1` are the index 1, `-0` is the index 0, and
/// `1.0000000000000001` is a fraction.
fn index_of(number: &Number) -> Result<u64, ComponentError> {
    let text = number.to_string();
    // serde_json holds the text of a JSON number; any other text is no number.
    let NumberText {
        negative,
        whole,
        fraction,
        exponent,
    } = NumberText::split(&text).ok_or(ComponentError::WrongType)?;
    // The value is `digits` × 10^(`exponent` − `fraction.len()`).
    let digits = [whole, fraction].concat();
    let significant = digits.trim_start_matches('0');
    if significant.is_empty() {
        // Zero, whatever its sign and exponent.
        return Ok(0);
    }
    if negative {
        return Err(ComponentError::Negative);
    }
    // A nonzero value times a power of ten beyond i64 is above every index, or a fraction.
    let exponent = exponent
        .parse::<i64>()
        .map_err(|error| match error.kind() {
            IntErrorKind::PosOverflow => ComponentError::OutOfRange,
            IntErrorKind::NegOverflow => ComponentError::Fraction,
            _ => ComponentError::WrongType,
        })?;
    // `significant` is `kept` × 10^`zeros`, and `kept` ends in a nonzero digit.
    let kept = significant.trim_end_matches('0');
    let zeros = significant.len() - kept.len();
    let scale = i128::from(exponent) + zeros as i128 - fraction.len() as i128;
    if scale < 0 {
        // 10 does not divide `kept`.
        return Err(ComponentError::Fraction);
    }
    let kept = kept.parse::<u64>().map_err(|error| match error.kind() {
        IntErrorKind::PosOverflow => ComponentError::OutOfRange,
        _ => ComponentError::WrongType,
    })?;
    u32::try_from(scale)
        .ok()
        .and_then(|scale| 10_u64.checked_pow(scale))
        .and_then(|power| kept.checked_mul(power))
        .ok_or(ComponentError::OutOfRange)
}

/// The parts of a JSON number's text (RFC 8259 §6): `[-] whole [. fraction] [e [+|-] digits]`.
struct NumberText<'a> {
    /// The text starts with a minus sign.
    negative: bool,
    /// The digits before the decimal point.
    whole: &'a str,
    /// The digits after the decimal point, empty when there is none.
    fraction: &'a str,
    /// The exponent with its sign, `0` when there is none.
    exponent: &'a str,
}

impl<'a> NumberText<'a> {
    /// The parts of `text`, or `None` when `text` is no JSON number.
    fn split(text: &'a str) -> Option<Self> {
        let (negative, magnitude) = match text.strip_prefix('-') {
            Some(magnitude) => (true, magnitude),
            None => (false, text),
        };
        let (mantissa, exponent) = match magnitude.split_once(['e', 'E']) {
            Some((mantissa, exponent)) => {
                let digits = exponent.strip_prefix(['+', '-']).unwrap_or(exponent);
                (mantissa, is_digits(digits).then_some(exponent)?)
            }
            None => (magnitude, "0"),
        };
        let (whole, fraction) = match mantissa.split_once('.') {
            Some((whole, fraction)) => (whole, is_digits(fraction).then_some(fraction)?),
            None => (mantissa, ""),
        };
        is_digits(whole).then_some(Self {
            negative,
            whole,
            fraction,
            exponent,
        })
    }
}

/// Whether `text` is one ASCII digit or more.
fn is_digits(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit())
}

/// Why a JSON value is no claims path pointer (OpenID4VP 1.0 §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ClaimsPathError {
    /// The value is no array.
    #[error("the path is no array")]
    NotArray,
    /// The array is empty.
    #[error("the path is an empty array")]
    Empty,
    /// A component is no key, index or null.
    #[error("path component {at} is {why}")]
    Component {
        /// The component's position in the array, from 0.
        at: usize,
        /// Why it is no key, index or null.
        why: ComponentError,
    },
}

/// Why a JSON value is no component of a claims path pointer (OpenID4VP 1.0 §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ComponentError {
    /// No string, `null` or number.
    #[error("no string, null or number")]
    WrongType,
    /// A number whose value has a nonzero fractional part.
    #[error("a fraction")]
    Fraction,
    /// A number below zero.
    #[error("a negative number")]
    Negative,
    /// An integer above 2^64 − 1, the largest index.
    #[error("an integer above 2^64 - 1")]
    OutOfRange,
}
