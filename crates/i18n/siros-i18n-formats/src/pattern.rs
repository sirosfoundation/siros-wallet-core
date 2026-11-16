//! A format's patterns: the text a value is written as, its placeholders, and the guards that
//! choose a pattern. A format's `pattern` setting holds one pattern per line; the first line
//! whose guard holds writes the value.
//!
//! ```text
//! line        = ["[" test *(" " test) "]" [" "]] pattern
//! pattern     = *(text / "\{" / "\}" / "\\" / placeholder)
//! placeholder = "{" name [":" op *("," op)] "}"
//! op          = key ["=" value]
//! test        = ["!"] name ("=" value / "<" int / "<=" int / ">" int / ">=" int / "?" / "@" table)
//! ```
//!
//! A name is a field of the format's type, an option the format declares, or one of:
//!
//! - `sign`: the sign the number field shows, `minus`, `plus` or `none`; as a placeholder, the
//!   `minus` or `plus` table, or nothing;
//! - `int`: the number field's integer digits, grouped by `group=<size>` and `second=<size>`
//!   with the `group` table or the one `sep=` names;
//! - `frac`: the `decimal` table, or the one `sep=` names, and the number field's fraction
//!   digits, when it has some;
//! - `plural`, in a test: the cardinal plural category of the number field, rounded.
//!
//! An integer field writes its digits in the `digits` table's characters: `pad=<n>` writes `n`
//! digits or more, `last=<n>` its last `n`. `table=<a>|<b>` writes the entry of the field's text
//! in the first of those tables that has it or a `*` entry, else the field's text. A test `=`
//! compares the text, `<` and the others an integer field's value, `?` holds for a field the value
//! has, `@` for a text that is a key of the table; `!` negates the test.

use siros_i18n::FormatRule;

use crate::fields::{Field, Kind};
use crate::number::options::{Groups, Opt, Shown};
use crate::number::plural::Category;
use crate::table::Tables;

/// What a name stands for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Name {
    Sign,
    Int,
    Frac,
    Plural,
    Field(&'static str, Kind),
    /// A declared option, by its index among the format's.
    Choice(usize),
    Numeric(Opt),
}

/// A placeholder's operations.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Ops {
    pub(crate) pad: u8,
    pub(crate) last: Option<u8>,
    pub(crate) tables: Vec<Box<str>>,
    pub(crate) groups: Option<Groups>,
    pub(crate) sep: Option<Box<str>>,
}

/// A part of a pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Piece {
    Text(String),
    Place(Name, Ops),
}

/// What a test checks of its name's value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Check {
    Equals(Box<str>),
    Less(i64),
    LessEqual(i64),
    Greater(i64),
    GreaterEqual(i64),
    Present,
    In(Box<str>),
}

/// A test of a guard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Test {
    pub(crate) negated: bool,
    pub(crate) name: Name,
    pub(crate) check: Check,
}

/// A pattern line: its guard's tests, and its pieces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Rule {
    pub(crate) tests: Vec<Test>,
    pub(crate) pieces: Vec<Piece>,
}

/// What the names of a format's patterns resolve against, when its section loads.
pub(crate) struct Scope<'a> {
    /// The key of the setting being read.
    pub(crate) key: &'a str,
    /// The fields of each type the format takes.
    pub(crate) types: &'a [&'static [(&'static str, Kind)]],
    /// The names of the options the format declares, and each one's values.
    pub(crate) choices: &'a [(Box<str>, Vec<Box<str>>)],
    pub(crate) tables: &'a Tables,
}

impl Scope<'_> {
    fn text(&self) -> FormatRule {
        FormatRule::Text {
            key: self.key.to_owned(),
        }
    }

    fn unknown(&self, name: &str) -> FormatRule {
        FormatRule::Unknown {
            key: self.key.to_owned(),
            name: name.to_owned(),
        }
    }

    /// The kind of the field `name`, which every type the format takes has as that kind.
    fn field(&self, name: &str) -> Option<(&'static str, Kind)> {
        let mut types = self.types.iter();
        let (field, kind) = types.next()?.iter().find(|(field, _)| *field == name)?;
        types
            .all(|fields| fields.contains(&(field, *kind)))
            .then_some((field, *kind))
    }

    /// Whether every type the format takes has a number field.
    pub(crate) fn numeric(&self) -> bool {
        !self.types.is_empty()
            && self
                .types
                .iter()
                .all(|fields| fields.iter().any(|(_, kind)| *kind == Kind::Number))
    }

    /// The table `name`, which must exist and, for `map`, be a map.
    fn table(&self, name: &str, map: bool) -> Result<(), FormatRule> {
        match self.tables.get(name) {
            Some(table) if !map || table.is_map() => Ok(()),
            Some(_) | None => Err(self.unknown(name)),
        }
    }

    fn name(&self, name: &str) -> Result<Name, FormatRule> {
        let number = || {
            if self.numeric() {
                Ok(())
            } else {
                Err(self.unknown(name))
            }
        };
        Ok(match name {
            "sign" => {
                number()?;
                self.table("minus", false)?;
                self.table("plus", false)?;
                Name::Sign
            }
            "int" => {
                number()?;
                self.digits()?;
                Name::Int
            }
            "frac" => {
                number()?;
                self.digits()?;
                Name::Frac
            }
            "plural" => {
                number()?;
                if self.tables.cardinal().is_none() {
                    return Err(self.unknown("plural.cardinal"));
                }
                Name::Plural
            }
            _ => {
                if let Some((field, kind)) = self.field(name) {
                    Name::Field(field, kind)
                } else if let Some(at) = self.choices.iter().position(|(n, _)| n.as_ref() == name) {
                    Name::Choice(at)
                } else if let Some(opt) = Opt::named(name).filter(|_| self.numeric()) {
                    Name::Numeric(opt)
                } else {
                    return Err(self.unknown(name));
                }
            }
        })
    }

    fn digits(&self) -> Result<(), FormatRule> {
        self.tables
            .numerals()
            .map(drop)
            .ok_or_else(|| self.unknown("digits"))
    }

    /// The operations of a placeholder of `name`.
    fn ops(&self, name: &Name, text: Option<&str>) -> Result<Ops, FormatRule> {
        let mut ops = Ops::default();
        let size = |value: Option<&str>| {
            value
                .and_then(|value| value.parse::<u8>().ok())
                .filter(|n| (1..=99).contains(n))
                .ok_or_else(|| self.text())
        };
        for op in text.into_iter().flat_map(|text| text.split(',')) {
            let (key, value) = match op.split_once('=') {
                Some((key, value)) => (key, Some(value)),
                None => (op, None),
            };
            match (name, key) {
                (Name::Field(_, Kind::Integer), "pad") => ops.pad = size(value)?,
                (Name::Field(_, Kind::Integer), "last") => ops.last = Some(size(value)?),
                (Name::Field(_, Kind::Integer | Kind::Text), "table") => {
                    for table in value.ok_or_else(|| self.text())?.split('|') {
                        self.table(table, true)?;
                        ops.tables.push(table.into());
                    }
                }
                (Name::Int, "group") => {
                    let primary = size(value)?;
                    let secondary = ops.groups.map_or(primary, |groups| groups.secondary);
                    ops.groups = Some(Groups { primary, secondary });
                }
                (Name::Int, "second") => {
                    let secondary = size(value)?;
                    let groups = ops.groups.as_mut().ok_or_else(|| self.text())?;
                    groups.secondary = secondary;
                }
                (Name::Int | Name::Frac, "sep") => {
                    let table = value.ok_or_else(|| self.text())?;
                    self.table(table, false)?;
                    ops.sep = Some(table.into());
                }
                _ => return Err(self.text()),
            }
        }
        if let Name::Field(_, Kind::Integer) = name {
            self.digits()?;
        }
        match (name, &ops) {
            (
                Name::Int,
                Ops {
                    groups: Some(_),
                    sep: None,
                    ..
                },
            ) => {
                self.table("group", false)?;
                self.table("grouping", false)?;
            }
            (
                Name::Int,
                Ops {
                    groups: Some(_), ..
                },
            ) => self.table("grouping", false)?,
            (Name::Frac, Ops { sep: None, .. }) => self.table("decimal", false)?,
            _ => {}
        }
        Ok(ops)
    }

    /// A pattern's pieces; `numbers` admits `sign`, `int` and `frac`.
    pub(crate) fn pieces(&self, text: &str, numbers: bool) -> Result<Vec<Piece>, FormatRule> {
        let mut pieces = Vec::new();
        let mut literal = String::new();
        let mut chars = text.chars();
        while let Some(c) = chars.next() {
            match c {
                '\\' => literal.push(chars.next().ok_or_else(|| self.text())?),
                '{' => {
                    let rest = chars.as_str();
                    let (inner, after) = rest.split_once('}').ok_or_else(|| self.text())?;
                    chars = after.chars();
                    let (name, ops) = match inner.split_once(':') {
                        Some((name, ops)) => (name, Some(ops)),
                        None => (inner, None),
                    };
                    let name = self.name(name)?;
                    let admitted = match name {
                        Name::Sign | Name::Int | Name::Frac => numbers,
                        Name::Field(_, kind) => kind != Kind::Number,
                        Name::Choice(_) => true,
                        Name::Plural | Name::Numeric(_) => false,
                    };
                    if !admitted {
                        return Err(self.text());
                    }
                    let ops = self.ops(&name, ops)?;
                    if !literal.is_empty() {
                        pieces.push(Piece::Text(std::mem::take(&mut literal)));
                    }
                    pieces.push(Piece::Place(name, ops));
                }
                '}' => return Err(self.text()),
                c => literal.push(c),
            }
        }
        if !literal.is_empty() {
            pieces.push(Piece::Text(literal));
        }
        Ok(pieces)
    }

    fn test(&self, text: &str) -> Result<Test, FormatRule> {
        let (negated, text) = match text.strip_prefix('!') {
            Some(text) => (true, text),
            None => (false, text),
        };
        let at = text
            .find(['=', '<', '>', '?', '@'])
            .ok_or_else(|| self.text())?;
        let (name, rest) = text.split_at(at);
        let name = self.name(name)?;
        let integer = |value: &str| value.parse::<i64>().map_err(|_| self.text());
        let check = if let Some(value) = rest.strip_prefix("<=") {
            Check::LessEqual(integer(value)?)
        } else if let Some(value) = rest.strip_prefix(">=") {
            Check::GreaterEqual(integer(value)?)
        } else if let Some(value) = rest.strip_prefix('<') {
            Check::Less(integer(value)?)
        } else if let Some(value) = rest.strip_prefix('>') {
            Check::Greater(integer(value)?)
        } else if let Some(value) = rest.strip_prefix('=') {
            Check::Equals(value.into())
        } else if rest == "?" {
            Check::Present
        } else if let Some(table) = rest.strip_prefix('@') {
            self.table(table, true)?;
            Check::In(table.into())
        } else {
            return Err(self.text());
        };
        let fits = match (&name, &check) {
            (Name::Field(_, Kind::Integer), _) => true,
            (Name::Field(..), Check::Present) => true,
            (Name::Field(_, Kind::Text), Check::Equals(_) | Check::In(_)) => true,
            (Name::Sign, Check::Equals(value)) => {
                matches!(value.as_ref(), "none" | "minus" | "plus")
            }
            (Name::Plural, Check::Equals(value)) => Category::of_keyword(value).is_some(),
            (Name::Choice(at), Check::Equals(value)) => self
                .choices
                .get(*at)
                .is_some_and(|(_, values)| values.iter().any(|v| v == value)),
            (Name::Choice(_), Check::In(_)) => true,
            (Name::Numeric(opt), Check::Equals(value)) => opt.takes(value),
            _ => false,
        };
        if !fits {
            return Err(self.text());
        }
        Ok(Test {
            negated,
            name,
            check,
        })
    }

    /// The pattern lines of `text`.
    pub(crate) fn rules(&self, text: &str) -> Result<Vec<Rule>, FormatRule> {
        let mut rules = Vec::new();
        for line in text.lines() {
            let (tests, pattern) = match line.strip_prefix('[') {
                Some(rest) => {
                    let (guard, pattern) = rest.split_once(']').ok_or_else(|| self.text())?;
                    let tests = guard
                        .split(' ')
                        .filter(|test| !test.is_empty())
                        .map(|test| self.test(test))
                        .collect::<Result<_, _>>()?;
                    (tests, pattern.strip_prefix(' ').unwrap_or(pattern))
                }
                None => (Vec::new(), line),
            };
            rules.push(Rule {
                tests,
                pieces: self.pieces(pattern, true)?,
            });
        }
        if rules.is_empty() {
            return Err(self.text());
        }
        Ok(rules)
    }
}

/// A value's text in a test or a table lookup: an integer's decimal digits.
pub(crate) fn text_of<'f>(field: &'f Field<'_>) -> std::borrow::Cow<'f, str> {
    match field {
        Field::Integer(value) => value.to_string().into(),
        Field::Text(text) => std::borrow::Cow::Borrowed(text.as_ref()),
        Field::Number(number) => number.to_string().into(),
    }
}

impl Check {
    /// Whether a value of `text`, and of `integer` for an integer, passes.
    pub(crate) fn holds(&self, text: Option<&str>, integer: Option<i64>, tables: &Tables) -> bool {
        match self {
            Self::Present => text.is_some(),
            Self::Equals(value) => text == Some(value.as_ref()),
            Self::In(table) => {
                text.is_some_and(|text| tables.get(table).is_some_and(|table| table.has(text)))
            }
            Self::Less(n) => integer.is_some_and(|v| v < *n),
            Self::LessEqual(n) => integer.is_some_and(|v| v <= *n),
            Self::Greater(n) => integer.is_some_and(|v| v > *n),
            Self::GreaterEqual(n) => integer.is_some_and(|v| v >= *n),
        }
    }
}

impl Shown {
    /// The table `{sign}` writes; `None` for no sign.
    pub(crate) const fn table(self) -> Option<&'static str> {
        match self {
            Self::None => None,
            Self::Minus => Some("minus"),
            Self::Plus => Some("plus"),
        }
    }
}
