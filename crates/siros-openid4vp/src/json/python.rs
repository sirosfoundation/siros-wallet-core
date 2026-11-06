//! RFC 8259 JSON with `json.dumps`'s separators and `ensure_ascii`, each number as received, and
//! Python's `repr` of the value `json` reads, for logs.

use std::fmt;

use super::Node;
use crate::refusal::Quoted;

impl<'a> Node<'a> {
    /// RFC 8259 text with `", "` and `": "` between items and each number as received
    /// (RFC 8259 §6).
    #[must_use]
    pub fn python_text(&self) -> PythonJson<'_, 'a> {
        self.python_json(Separators::SPACED, Escaping::Unicode)
    }

    /// [`Node::python_text`] without the spaces after `,` and `:`.
    #[must_use]
    pub fn python_compact(&self) -> PythonJson<'_, 'a> {
        self.python_json(Separators::COMPACT, Escaping::Unicode)
    }

    /// [`Node::python_text`] with every character beyond ASCII a `\u` escape of its UTF-16 code
    /// units.
    #[must_use]
    pub fn python_ascii(&self) -> PythonJson<'_, 'a> {
        self.python_json(Separators::SPACED, Escaping::Ascii)
    }

    /// The value as Python's `repr` writes the value `json` reads: `None`, `True` and `False`,
    /// a string as `repr` quotes it, an integer by value, another number as the double's
    /// `repr`, a list's items and a dict's `key: value` pairs between `", "`.
    #[must_use]
    pub fn python_repr(&self) -> PythonRepr<'_, 'a> {
        PythonRepr(self)
    }

    /// The value as a message names it: a string's text, another value as [`Node::python_text`]
    /// writes it.
    #[must_use]
    pub fn written_text(&self) -> String {
        self.as_str()
            .map_or_else(|| self.python_text().to_string(), str::to_owned)
    }

    /// The value as a template or a compact message names it: a string's text, another value as
    /// [`Node::python_compact`] writes it.
    #[must_use]
    pub fn written_compact(&self) -> String {
        self.as_str()
            .map_or_else(|| self.python_compact().to_string(), str::to_owned)
    }

    const fn python_json(&self, separators: Separators, escaping: Escaping) -> PythonJson<'_, 'a> {
        PythonJson {
            node: self,
            separators,
            escaping,
        }
    }
}

/// What Python's `json.dumps` writes after an item and after a member name.
#[derive(Debug, Clone, Copy)]
struct Separators {
    item: &'static str,
    name: &'static str,
}

impl Separators {
    /// The default: `", "` and `": "`.
    const SPACED: Self = Self {
        item: ", ",
        name: ": ",
    };
    /// `separators=(",", ":")`.
    const COMPACT: Self = Self {
        item: ",",
        name: ":",
    };
}

/// How Python's `json.dumps` writes characters beyond ASCII: its `ensure_ascii`.
#[derive(Debug, Clone, Copy)]
enum Escaping {
    /// As they are (`ensure_ascii=False`).
    Unicode,
    /// As `\u` escapes of their UTF-16 code units (`ensure_ascii=True`, the default).
    Ascii,
}

/// A [`Node`] as RFC 8259 text, with one of `json.dumps`'s separators and `ensure_ascii` settings.
pub struct PythonJson<'n, 'a> {
    node: &'n Node<'a>,
    separators: Separators,
    escaping: Escaping,
}

impl PythonJson<'_, '_> {
    fn string(&self, f: &mut fmt::Formatter<'_>, text: &str) -> fmt::Result {
        let quoted = quote(text);
        match self.escaping {
            Escaping::Unicode => f.write_str(&quoted),
            Escaping::Ascii => quoted.chars().try_for_each(|c| {
                if c.is_ascii() {
                    write!(f, "{c}")
                } else {
                    let mut units = [0u16; 2];
                    c.encode_utf16(&mut units)
                        .iter()
                        .try_for_each(|unit| write!(f, "\\u{unit:04x}"))
                }
            }),
        }
    }

    const fn nested<'m, 'b>(&self, node: &'m Node<'b>) -> PythonJson<'m, 'b> {
        node.python_json(self.separators, self.escaping)
    }
}

impl fmt::Display for PythonJson<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.node {
            Node::Null => f.write_str("null"),
            Node::Bool(value) => f.write_str(if *value { "true" } else { "false" }),
            Node::Number(number) => f.write_str(number.text()),
            Node::String(text) => self.string(f, text),
            Node::Array(items) => {
                f.write_str("[")?;
                for (k, item) in items.iter().enumerate() {
                    if k > 0 {
                        f.write_str(self.separators.item)?;
                    }
                    write!(f, "{}", self.nested(item))?;
                }
                f.write_str("]")
            }
            Node::Object(object) => {
                f.write_str("{")?;
                for (k, member) in object.members().iter().enumerate() {
                    if k > 0 {
                        f.write_str(self.separators.item)?;
                    }
                    self.string(f, &member.name)?;
                    f.write_str(self.separators.name)?;
                    write!(f, "{}", self.nested(&member.value))?;
                }
                f.write_str("}")
            }
        }
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

/// A JSON string with the escapes both `serde_json` and Python's `json` write.
#[must_use]
pub fn quote(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if u32::from(c) < 0x20 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

impl fmt::Display for FiniteDouble {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scientific = format!("{:e}", self.0);
        let (mantissa, exponent) = scientific
            .split_once('e')
            .unwrap_or((scientific.as_str(), "0"));
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
                let (whole, fraction) = digits
                    .split_at_checked(shift)
                    .unwrap_or((digits.as_str(), ""));
                format!("{whole}.{fraction}")
            };
            write!(f, "{sign}{fixed}")
        } else {
            let (first, rest) = digits.split_at_checked(1).unwrap_or((digits.as_str(), ""));
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
