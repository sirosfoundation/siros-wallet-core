//! Python's `repr` of the value `json` reads, for logs, and of a finite double.

use std::fmt;

use super::Node;
use crate::refusal::Quoted;

impl<'a> Node<'a> {
    /// The value as Python's `repr` writes the value `json` reads: `None`, `True` and `False`,
    /// a string as `repr` quotes it, an integer by value, another number as the double's
    /// `repr`, a list's items and a dict's `key: value` pairs between `", "`.
    #[must_use]
    pub fn python_repr(&self) -> PythonRepr<'_, 'a> {
        PythonRepr(self)
    }
}

/// A [`Node`] written as Python's `repr` writes the value `json` reads.
pub struct PythonRepr<'n, 'a>(&'n Node<'a>);

impl fmt::Display for PythonRepr<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Node::Null => f.write_str("None"),
            Node::Bool(value) => f.write_str(if *value { "True" } else { "False" }),
            Node::Number(number) => match (number.integer(), number.double()) {
                (Some(digits), _) => f.write_str(digits),
                (None, Some(value)) => match FiniteDouble::of(value) {
                    Some(finite) => write!(f, "{finite}"),
                    None if value.is_nan() => f.write_str("nan"),
                    None => f.write_str(if value > 0.0 { "inf" } else { "-inf" }),
                },
                (None, None) => f.write_str(number.text()),
            },
            Node::String(text) => write!(f, "{}", Quoted(text)),
            Node::Array(items) => {
                f.write_str("[")?;
                for (k, item) in items.iter().enumerate() {
                    if k > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{}", item.python_repr())?;
                }
                f.write_str("]")
            }
            Node::Object(object) => {
                f.write_str("{")?;
                for (k, member) in object.members().iter().enumerate() {
                    if k > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{}: ", Quoted(&member.name))?;
                    write!(f, "{}", member.value.python_repr())?;
                }
                f.write_str("}")
            }
        }
    }
}

/// A finite double. Its `Display` is Python's `repr`, which RFC 8259 §6's grammar holds: the
/// shortest digits that read back, fixed notation for decimal exponents from -4 to 15 with at
/// least one fractional digit, scientific notation otherwise.
#[derive(Debug, Clone, Copy)]
pub(super) struct FiniteDouble(f64);

impl FiniteDouble {
    /// The value, when it is finite.
    pub(super) const fn of(value: f64) -> Option<Self> {
        if value.is_finite() {
            Some(Self(value))
        } else {
            None
        }
    }
}

impl fmt::Display for FiniteDouble {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scientific = format!("{:e}", self.0);
        let (mantissa, exponent) = scientific.split_once('e').ok_or(fmt::Error)?;
        let exponent: i32 = exponent.parse().map_err(|_| fmt::Error)?;
        let (sign, mantissa) = mantissa
            .strip_prefix('-')
            .map_or(("", mantissa), |m| ("-", m));
        let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
        if (-4..16).contains(&exponent) {
            let point = exponent + 1;
            let shift = point.unsigned_abs() as usize;
            let fixed = if point <= 0 {
                format!("0.{}{digits}", "0".repeat(shift))
            } else if shift >= digits.len() {
                format!("{digits}{}.0", "0".repeat(shift - digits.len()))
            } else {
                let whole: String = digits.chars().take(shift).collect();
                let fraction: String = digits.chars().skip(shift).collect();
                format!("{whole}.{fraction}")
            };
            write!(f, "{sign}{fixed}")
        } else {
            let mut chars = digits.chars();
            let first: String = chars.by_ref().take(1).collect();
            let rest = chars.as_str();
            let fraction = if rest.is_empty() {
                String::new()
            } else {
                format!(".{rest}")
            };
            let exponent_sign = if exponent < 0 { '-' } else { '+' };
            write!(
                f,
                "{sign}{first}{fraction}e{exponent_sign}{:02}",
                exponent.unsigned_abs()
            )
        }
    }
}
