//! RFC 8259 JSON text with `json.dumps`'s separators and `ensure_ascii`, each number as received
//! (RFC 8259 §6).

use std::fmt;

use super::Node;

impl<'a> Node<'a> {
    /// RFC 8259 text with `", "` and `": "` between items and each number as received
    /// (RFC 8259 §6).
    #[must_use]
    pub fn json_spaced(&self) -> WrittenJson<'_, 'a> {
        self.written_json(Separators::SPACED, Escaping::Unicode)
    }

    /// [`Node::json_spaced`] without the spaces after `,` and `:`.
    #[must_use]
    pub fn json_compact(&self) -> WrittenJson<'_, 'a> {
        self.written_json(Separators::COMPACT, Escaping::Unicode)
    }

    /// [`Node::json_spaced`] with every character beyond ASCII a `\u` escape of its UTF-16 code
    /// units.
    #[must_use]
    pub fn json_ascii(&self) -> WrittenJson<'_, 'a> {
        self.written_json(Separators::SPACED, Escaping::Ascii)
    }

    /// The value as a message names it: a string's text, another value as [`Node::json_spaced`]
    /// writes it.
    #[must_use]
    pub fn written_text(&self) -> String {
        self.as_str()
            .map_or_else(|| self.json_spaced().to_string(), str::to_owned)
    }

    /// The value as a template or a compact message names it: a string's text, another value as
    /// [`Node::json_compact`] writes it.
    #[must_use]
    pub fn written_compact(&self) -> String {
        self.as_str()
            .map_or_else(|| self.json_compact().to_string(), str::to_owned)
    }

    const fn written_json(
        &self,
        separators: Separators,
        escaping: Escaping,
    ) -> WrittenJson<'_, 'a> {
        WrittenJson {
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
pub struct WrittenJson<'n, 'a> {
    node: &'n Node<'a>,
    separators: Separators,
    escaping: Escaping,
}

impl WrittenJson<'_, '_> {
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

    const fn nested<'m, 'b>(&self, node: &'m Node<'b>) -> WrittenJson<'m, 'b> {
        node.written_json(self.separators, self.escaping)
    }
}

impl fmt::Display for WrittenJson<'_, '_> {
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

/// A JSON string with the escapes both `serde_json` and Python's `json` write (RFC 8259 §7).
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
