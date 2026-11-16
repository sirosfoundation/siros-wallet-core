//! A `[formats.<name>]` section: the type it takes, its options, and its patterns; and a value
//! written or selected by it.
//!
//! Its settings:
//!
//! - `of`: the name of the types it takes ([`Fields::NAME`](crate::Fields::NAME));
//! - `default`: `yes` for the format those types take where the wording names none, `no`;
//! - `option.<name>`: an option a call may give, and its values, the default first;
//! - `pattern`: the pattern lines;
//! - for a type with a number field, each of MF2's numeric options (spec/functions/number.md):
//!   `select`, `signDisplay`, `useGrouping`, `minimumIntegerDigits`, `minimumFractionDigits`,
//!   `maximumFractionDigits`, `fractionDigits`, `minimumSignificantDigits`,
//!   `maximumSignificantDigits`, `trailingZeroDisplay`, `roundingPriority`, `roundingIncrement`,
//!   `roundingMode`. Its text may hold placeholders of the value's fields, such as
//!   `{currency:table=currency.digits}`. A call's option overrides the format's; the number
//!   rounds once, by both. A number without fraction digits set keeps those it is written with.
//!   A format selects when it sets `select`.

use siros_i18n::{Direction, FormatRule, Refusal, Selection, Setting};

use crate::fields::{Field, Kind};
use crate::number::decimal::{Fixed, Number};
use crate::number::options::{self, Grouping, Opt, Options, Select, Shown};
use crate::number::plural::{Category, Operands};
use crate::pattern::{Check, Name, Ops, Piece, Rule, Scope, Test, text_of};
use crate::table::Tables;

/// A value a format reads: its fields by name.
pub(crate) trait Record {
    fn field(&self, name: &str) -> Option<Field<'_>>;
}

impl<T: crate::Fields> Record for T {
    fn field(&self, name: &str) -> Option<Field<'_>> {
        crate::Fields::field(self, name)
    }
}

/// A format.
#[derive(Debug)]
pub(crate) struct Format {
    pub(crate) name: Box<str>,
    pub(crate) of: Box<str>,
    pub(crate) default: bool,
    direction: Direction,
    choices: Vec<(Box<str>, Vec<Box<str>>)>,
    numeric: Vec<(Opt, Vec<Piece>)>,
    rules: Vec<Rule>,
    /// The name of the number field of the types it takes; `None` for types without one.
    number: Option<&'static str>,
}

/// The settings of a section, each read once.
struct Settings<'s> {
    settings: &'s [Setting<'s>],
}

impl<'s> Settings<'s> {
    fn get(&self, key: &str) -> Option<&'s str> {
        self.settings
            .iter()
            .find(|setting| setting.key == key)
            .map(|setting| setting.text)
    }

    fn required(&self, key: &str) -> Result<&'s str, FormatRule> {
        self.get(key).ok_or_else(|| FormatRule::Missing {
            key: key.to_owned(),
        })
    }
}

impl Format {
    /// The format `name` of a section's `settings`, in a module of `direction`, which takes the
    /// types of `types` whose name its `of` gives.
    ///
    /// # Errors
    ///
    /// The [`FormatRule`] its settings break.
    pub(crate) fn load(
        name: &str,
        settings: &[Setting<'_>],
        direction: Direction,
        types: &[(&'static str, &'static [(&'static str, Kind)])],
        tables: &Tables,
    ) -> Result<Self, FormatRule> {
        for (at, setting) in settings.iter().enumerate() {
            if settings
                .iter()
                .skip(at + 1)
                .any(|later| later.key == setting.key)
            {
                return Err(FormatRule::Repeated {
                    key: setting.key.to_owned(),
                });
            }
        }
        let settings = Settings { settings };
        let of = settings.required("of")?;
        let fields: Vec<_> = types
            .iter()
            .filter(|(name, _)| *name == of)
            .map(|(_, fields)| *fields)
            .collect();
        if fields.is_empty() {
            return Err(FormatRule::Unknown {
                key: "of".to_owned(),
                name: of.to_owned(),
            });
        }
        let default = match settings.get("default") {
            None | Some("no") => false,
            Some("yes") => true,
            Some(_) => {
                return Err(FormatRule::Text {
                    key: "default".to_owned(),
                });
            }
        };
        let choices = settings
            .settings
            .iter()
            .filter_map(|setting| {
                let name = setting.key.strip_prefix("option.")?;
                let values: Vec<Box<str>> = setting.text.split(' ').map(Into::into).collect();
                let distinct = values.iter().enumerate().all(|(at, value)| {
                    !value.is_empty() && !values.iter().skip(at + 1).any(|v| v == value)
                });
                Some(
                    if distinct && Opt::named(name).is_none() && !name.is_empty() {
                        Ok((Box::from(name), values))
                    } else {
                        Err(FormatRule::Text {
                            key: setting.key.to_owned(),
                        })
                    },
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let scope = |key| Scope {
            key,
            types: &fields,
            choices: &choices,
            tables,
        };
        let numeric_types = scope("of").numeric();
        let mut numeric = Vec::new();
        for setting in settings.settings {
            match setting.key {
                "of" | "default" | "pattern" => {}
                key if key.starts_with("option.") => {}
                key => match Opt::named(key).filter(|_| numeric_types) {
                    Some(opt) => {
                        let pieces = scope(key).pieces(setting.text, false)?;
                        let literal = match pieces.as_slice() {
                            [] => Some(""),
                            [Piece::Text(text)] => Some(text.as_str()),
                            _ => None,
                        };
                        if literal.is_some_and(|text| !opt.takes(text)) {
                            return Err(FormatRule::Text {
                                key: key.to_owned(),
                            });
                        }
                        numeric.push((opt, pieces));
                    }
                    None => {
                        return Err(FormatRule::Undefined {
                            key: key.to_owned(),
                        });
                    }
                },
            }
        }
        let rules = scope("pattern").rules(settings.required("pattern")?)?;
        let number = fields.first().and_then(|fields| {
            fields
                .iter()
                .find(|(_, kind)| *kind == Kind::Number)
                .map(|(name, _)| *name)
        });
        let format = Self {
            name: name.into(),
            of: of.into(),
            default,
            direction,
            choices,
            numeric,
            rules,
            number: number.filter(|_| numeric_types),
        };
        if let Some(select) = format.fixed(Opt::Select) {
            format
                .selection_tables(select, tables)
                .map_err(|_| FormatRule::Unknown {
                    key: "select".to_owned(),
                    name: "plural".to_owned(),
                })?;
        }
        Ok(format)
    }

    /// The text of the format's setting of `opt` when it holds no placeholder.
    fn fixed(&self, opt: Opt) -> Option<&str> {
        self.numeric
            .iter()
            .find(|(given, _)| *given == opt)
            .and_then(|(_, pieces)| match pieces.as_slice() {
                [Piece::Text(text)] => Some(text.as_str()),
                [] => Some(""),
                _ => None,
            })
    }

    /// Whether a call's selection on the format's value selects.
    pub(crate) fn selects(&self) -> bool {
        self.number.is_some() && self.numeric.iter().any(|(opt, _)| *opt == Opt::Select)
    }

    /// Checks the tables a selection by `select` reads.
    fn selection_tables(&self, select: &str, tables: &Tables) -> Result<(), Refusal> {
        let option = || Refusal::Option {
            option: Opt::Select.name().to_owned(),
        };
        match select {
            "plural" => tables.cardinal().map(drop).ok_or_else(option),
            "ordinal" => tables.ordinal().map(drop).ok_or_else(option),
            "exact" => Ok(()),
            _ => Err(option()),
        }
    }

    /// Checks a call's option `name` when its module loads: `text` its literal, `None` for a
    /// variable's value.
    ///
    /// # Errors
    ///
    /// [`Refusal::Option`] for an option the format does not take, a literal it refuses, and
    /// `select` given by a variable: MF2 sets it by a literal alone.
    pub(crate) fn option(
        &self,
        name: &str,
        text: Option<&str>,
        tables: &Tables,
    ) -> Result<(), Refusal> {
        let refused = || Refusal::Option {
            option: name.to_owned(),
        };
        if let Some((_, values)) = self.choices.iter().find(|(n, _)| n.as_ref() == name) {
            return match text {
                Some(text) if !values.iter().any(|value| value.as_ref() == text) => Err(refused()),
                Some(_) | None => Ok(()),
            };
        }
        let opt = Opt::named(name)
            .filter(|_| self.number.is_some())
            .ok_or_else(refused)?;
        match (opt, text) {
            (Opt::Select, None) => Err(refused()),
            (Opt::Select, Some(text)) => self.selection_tables(text, tables),
            (_, Some(text)) if !opt.takes(text) => Err(refused()),
            (_, Some(_) | None) => Ok(()),
        }
    }

    /// Checks a variant key of a selector on the format's value.
    ///
    /// # Errors
    ///
    /// [`Refusal::Selector`] for a format that does not select, and [`Refusal::Key`] for a key
    /// that is neither a number literal nor a plural category.
    pub(crate) fn key(&self, key: &str) -> Result<(), Refusal> {
        if !self.selects() {
            return Err(Refusal::Selector);
        }
        if Number::literal(key).is_some() || Category::of_keyword(key).is_some() {
            Ok(())
        } else {
            Err(Refusal::Key {
                key: key.to_owned(),
            })
        }
    }

    /// The resolution of the format's options and number field over `value`'s fields and the
    /// call's `options`.
    fn resolve<'a>(
        &'a self,
        value: &'a dyn Record,
        options: &[(&'a str, &'a str)],
        tables: &'a Tables,
    ) -> Result<Resolved<'a>, Refusal> {
        let refused = |name: &str| Refusal::Option {
            option: name.to_owned(),
        };
        let mut choices: Vec<&str> = self
            .choices
            .iter()
            .map(|(_, values)| values.first().map_or("", AsRef::as_ref))
            .collect();
        let mut call = Vec::new();
        for &(name, text) in options {
            self.option(name, Some(text), tables)?;
            if let Some(at) = self.choices.iter().position(|(n, _)| n.as_ref() == name) {
                if let Some(choice) = choices.get_mut(at) {
                    *choice = text;
                }
            } else {
                call.push((Opt::named(name).ok_or_else(|| refused(name))?, text));
            }
        }
        let mut written = Vec::with_capacity(self.numeric.len());
        for (opt, pieces) in &self.numeric {
            let mut text = String::new();
            let partial = Resolved {
                value,
                tables,
                choices: choices.clone(),
                numeric: Vec::new(),
                number: None,
            };
            partial.write(pieces, &mut text)?;
            if !opt.takes(&text) {
                return Err(refused(opt.name()));
            }
            written.push((*opt, text));
        }
        let format: Vec<(Opt, &str)> = written
            .iter()
            .map(|(opt, text)| (*opt, text.as_str()))
            .collect();
        let options = Options {
            format: &format,
            call: &call,
        };
        let number = match self.number {
            None => None,
            Some(field) => {
                let Some(Field::Number(number)) = value.field(field) else {
                    return Err(Refusal::Operand);
                };
                Some(Rounded::of(&number, options, tables).map_err(|opt| refused(opt.name()))?)
            }
        };
        let mut numeric: Vec<(Opt, String)> = call
            .iter()
            .map(|(opt, text)| (*opt, (*text).to_owned()))
            .collect();
        for (opt, text) in written {
            if !numeric.iter().any(|(given, _)| *given == opt) {
                numeric.push((opt, text));
            }
        }
        Ok(Resolved {
            value,
            tables,
            choices,
            numeric,
            number,
        })
    }

    /// Writes `value` with the call's `options`.
    ///
    /// # Errors
    ///
    /// [`Refusal::Operand`] for a value no pattern line writes or that lacks a field its line
    /// writes, and [`Refusal::Option`] for an option text the format refuses.
    pub(crate) fn format(
        &self,
        value: &dyn Record,
        options: &[(&str, &str)],
        tables: &Tables,
        out: &mut String,
    ) -> Result<Direction, Refusal> {
        let resolved = self.resolve(value, options, tables)?;
        let rule = self
            .rules
            .iter()
            .find(|rule| rule.tests.iter().all(|test| resolved.holds(test)))
            .ok_or(Refusal::Operand)?;
        resolved.write(&rule.pieces, out)?;
        Ok(self.direction)
    }

    /// What `value` selects with under the call's `options`.
    ///
    /// # Errors
    ///
    /// [`Refusal::Selector`] for a format that does not select, and the refusals of
    /// [`Format::format`].
    pub(crate) fn select(
        &self,
        value: &dyn Record,
        options: &[(&str, &str)],
        tables: &Tables,
    ) -> Result<Selection, Refusal> {
        if !self.selects() {
            return Err(Refusal::Selector);
        }
        let resolved = self.resolve(value, options, tables)?;
        let rounded = resolved.number.ok_or(Refusal::Operand)?;
        let category = match rounded.select {
            None => return Err(Refusal::Selector),
            Some(Select::Exact) => None,
            Some(Select::Plural) => Some(tables.cardinal().ok_or(Refusal::Selector)?),
            Some(Select::Ordinal) => Some(tables.ordinal().ok_or(Refusal::Selector)?),
        }
        .map(|rules| {
            rules
                .category(&Operands::of(&rounded.fixed))
                .keyword()
                .to_owned()
        });
        Ok(Selection::new(
            options::serial(&rounded.fixed, rounded.integer_keys),
            category,
        ))
    }
}

/// A number field rounded by the resolved options.
#[derive(Debug)]
struct Rounded {
    fixed: Fixed,
    shown: Shown,
    grouping: Grouping,
    select: Option<Select>,
    integer_keys: bool,
}

impl Rounded {
    fn of(number: &Number, options: Options<'_>, tables: &Tables) -> Result<Self, Opt> {
        let fixed = options.digits()?.round(number);
        Ok(Self {
            shown: options.sign()?.shown(&fixed),
            grouping: options.grouping(tables.grouping().unwrap_or(1))?,
            select: options.select()?,
            integer_keys: options.integer_keys(),
            fixed,
        })
    }
}

/// A format's options and number field resolved over one value: each declared option's text,
/// each numeric option's, the call's over the format's, and the number rounded.
struct Resolved<'a> {
    value: &'a dyn Record,
    tables: &'a Tables,
    choices: Vec<&'a str>,
    numeric: Vec<(Opt, String)>,
    number: Option<Rounded>,
}

impl Resolved<'_> {
    fn table(&self, name: &str) -> Result<&str, Refusal> {
        self.tables
            .get(name)
            .map(|table| table.text())
            .ok_or(Refusal::Operand)
    }

    fn holds(&self, test: &Test) -> bool {
        let field;
        let (text, integer) = match &test.name {
            Name::Field(name, _) => {
                field = self.value.field(name);
                let integer = match &field {
                    Some(Field::Integer(value)) => Some(*value),
                    _ => None,
                };
                (field.as_ref().map(text_of), integer)
            }
            Name::Choice(at) => (self.choices.get(*at).map(|c| (*c).into()), None),
            Name::Sign => (self.number.as_ref().map(|n| n.shown.name().into()), None),
            Name::Plural => (
                self.number.as_ref().and_then(|n| {
                    let rules = self.tables.cardinal()?;
                    Some(rules.category(&Operands::of(&n.fixed)).keyword().into())
                }),
                None,
            ),
            Name::Numeric(opt) => (
                self.numeric
                    .iter()
                    .find(|(given, _)| given == opt)
                    .map(|(_, text)| text.as_str().into()),
                None,
            ),
            Name::Int | Name::Frac => (None, None),
        };
        let holds = match &test.check {
            Check::Present => match &test.name {
                Name::Field(..) => text.is_some(),
                _ => false,
            },
            check => check.holds(text.as_deref(), integer, self.tables),
        };
        holds != test.negated
    }

    fn write(&self, pieces: &[Piece], out: &mut String) -> Result<(), Refusal> {
        for piece in pieces {
            match piece {
                Piece::Text(text) => out.push_str(text),
                Piece::Place(name, ops) => self.place(name, ops, out)?,
            }
        }
        Ok(())
    }

    fn place(&self, name: &Name, ops: &Ops, out: &mut String) -> Result<(), Refusal> {
        let numerals = || self.tables.numerals().ok_or(Refusal::Operand);
        let number = || self.number.as_ref().ok_or(Refusal::Operand);
        match name {
            Name::Sign => {
                if let Some(table) = number()?.shown.table() {
                    out.push_str(self.table(table)?);
                }
            }
            Name::Int => {
                let number = number()?;
                let groups = match ops.groups {
                    Some(groups) => {
                        Some((groups, self.table(ops.sep.as_deref().unwrap_or("group"))?))
                    }
                    None => None,
                };
                options::write_int(&number.fixed, numerals()?, groups, number.grouping, out);
            }
            Name::Frac => {
                let separator = self.table(ops.sep.as_deref().unwrap_or("decimal"))?;
                options::write_frac(&number()?.fixed, numerals()?, separator, out);
            }
            Name::Field(field, _) => {
                let value = self.value.field(field).ok_or(Refusal::Operand)?;
                let text = text_of(&value);
                if let Some(entry) = ops
                    .tables
                    .iter()
                    .find_map(|table| self.tables.get(table)?.lookup(&text))
                {
                    out.push_str(entry);
                    return Ok(());
                }
                match value {
                    Field::Integer(value) => {
                        if value < 0 {
                            out.push_str(self.table("minus")?);
                        }
                        let value = u128::from(value.unsigned_abs());
                        let value = match ops.last {
                            Some(last) => value % 10u128.pow(u32::from(last)),
                            None => value,
                        };
                        numerals()?.write(value, ops.pad, out);
                    }
                    Field::Text(_) | Field::Number(_) => out.push_str(&text),
                }
            }
            Name::Choice(at) => out.push_str(self.choices.get(*at).ok_or(Refusal::Operand)?),
            Name::Plural | Name::Numeric(_) => return Err(Refusal::Operand),
        }
        Ok(())
    }
}
