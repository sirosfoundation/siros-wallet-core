//! [`Patterns`]: the formatter of the value types it is given, by the tables and formats its
//! modules define.

use std::any::{Any, TypeId};

use siros_explain::Arg;
use siros_i18n::{Direction, FormatRule, Formatter, FunctionId, Refusal, Selection, Setting};
use siros_syntax::{Amount, Count, Date, DateTime, Decimal, OffsetTime, Time};

use crate::fields::{Fields, Kind};
use crate::format::{Format, Record};
use crate::number::decimal::Number;
use crate::table::Tables;

/// A value type the formatter takes.
struct Registered {
    of: TypeId,
    name: &'static str,
    fields: &'static [(&'static str, Kind)],
    cast: fn(&dyn Any) -> Option<&dyn Record>,
    literal: fn(&str) -> Option<Box<dyn Record>>,
}

impl std::fmt::Debug for Registered {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name)
    }
}

fn cast<T: Fields>(value: &dyn Any) -> Option<&dyn Record> {
    value.downcast_ref::<T>().map(|value| value as &dyn Record)
}

fn literal<T: Fields>(text: &str) -> Option<Box<dyn Record>> {
    T::literal(text).map(|value| Box::new(value) as Box<dyn Record>)
}

/// A value a format reads: an argument's, or a literal's, read by its type.
enum Held<'a> {
    Lent(&'a dyn Record),
    Read(Box<dyn Record>),
}

impl Held<'_> {
    fn record(&self) -> &dyn Record {
        match self {
            Self::Lent(record) => *record,
            Self::Read(record) => record.as_ref(),
        }
    }
}

/// A [`Formatter`] of value types by their [`Fields`], configured by its modules' `[tables]` and
/// `[formats.<name>]` sections: each format defines the function `:<name>`. The crate's
/// documentation gives the sections' syntax.
#[derive(Debug, Default)]
pub struct Patterns {
    types: Vec<Registered>,
    tables: Tables,
    formats: Vec<Format>,
}

impl Patterns {
    /// A formatter without value types.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A formatter of this crate's [`Number`] (the first, which reads a literal number
    /// operand), siros-syntax's `Decimal` and `Count` and Rust's integers, all named `number`;
    /// siros-syntax's `Amount`, named `amount`; `Date`, named `date`; `OffsetTime` and `Time`,
    /// named `time`; and `DateTime`, named `datetime`.
    #[must_use]
    pub fn standard() -> Self {
        Self::new()
            .value::<Number>()
            .value::<Decimal>()
            .value::<Count>()
            .value::<u8>()
            .value::<u16>()
            .value::<u32>()
            .value::<u64>()
            .value::<i8>()
            .value::<i16>()
            .value::<i32>()
            .value::<i64>()
            .value::<Amount>()
            .value::<Date>()
            .value::<OffsetTime>()
            .value::<Time>()
            .value::<DateTime>()
    }

    /// The formatter, taking values of `T` too.
    #[must_use]
    pub fn value<T: Fields>(mut self) -> Self {
        self.types.push(Registered {
            of: TypeId::of::<T>(),
            name: T::NAME,
            fields: T::FIELDS,
            cast: cast::<T>,
            literal: literal::<T>,
        });
        self
    }

    fn defined(&self, function: FunctionId) -> Result<&Format, Refusal> {
        usize::try_from(function.0)
            .ok()
            .and_then(|at| self.formats.get(at))
            .ok_or(Refusal::Operand)
    }

    fn registered(&self, of: TypeId) -> Option<&Registered> {
        self.types.iter().find(|registered| registered.of == of)
    }

    /// The value `format` reads of `value`: an argument of a type of its name, or a literal
    /// one of those types reads.
    fn held<'a>(&self, format: &Format, value: &'a dyn Arg) -> Result<Held<'a>, Refusal> {
        let any: &dyn Any = value;
        if let Some(text) = any.downcast_ref::<Box<str>>() {
            return self.read(format, text).map(Held::Read);
        }
        let registered = self
            .registered(any.type_id())
            .filter(|registered| *registered.name == *format.of)
            .ok_or(Refusal::Operand)?;
        (registered.cast)(any)
            .map(Held::Lent)
            .ok_or(Refusal::Operand)
    }

    fn read(&self, format: &Format, text: &str) -> Result<Box<dyn Record>, Refusal> {
        self.types
            .iter()
            .filter(|registered| *registered.name == *format.of)
            .find_map(|registered| (registered.literal)(text))
            .ok_or(Refusal::Operand)
    }
}

impl Formatter for Patterns {
    fn reads(&self, section: &str) -> bool {
        section == "tables" || section.starts_with("formats.")
    }

    fn load(
        &mut self,
        section: &str,
        settings: &[Setting<'_>],
        direction: Direction,
    ) -> Result<(), FormatRule> {
        let Some(name) = section.strip_prefix("formats.") else {
            return self.tables.load(settings);
        };
        if self.formats.iter().any(|format| *format.name == *name) {
            return Err(FormatRule::Repeated {
                key: section.to_owned(),
            });
        }
        let types: Vec<_> = self
            .types
            .iter()
            .map(|registered| (registered.name, registered.fields))
            .collect();
        let format = Format::load(name, settings, direction, &types, &self.tables)?;
        if format.default
            && self
                .formats
                .iter()
                .any(|other| other.default && other.of == format.of)
        {
            return Err(FormatRule::Repeated {
                key: "default".to_owned(),
            });
        }
        self.formats.push(format);
        Ok(())
    }

    fn function(&self, name: &str) -> Option<FunctionId> {
        let at = self
            .formats
            .iter()
            .position(|format| *format.name == *name)?;
        u32::try_from(at).ok().map(FunctionId)
    }

    fn name(&self, function: FunctionId) -> &str {
        self.defined(function).map_or("", |format| &format.name)
    }

    fn default_for(&self, of: TypeId) -> Option<FunctionId> {
        let name = self.registered(of)?.name;
        let at = self
            .formats
            .iter()
            .position(|format| format.default && *format.of == *name)?;
        u32::try_from(at).ok().map(FunctionId)
    }

    fn takes(&self, function: FunctionId, of: TypeId) -> bool {
        match (self.defined(function), self.registered(of)) {
            (Ok(format), Some(registered)) => *format.of == *registered.name,
            _ => false,
        }
    }

    fn option(&self, function: FunctionId, name: &str, text: Option<&str>) -> Result<(), Refusal> {
        self.defined(function)?.option(name, text, &self.tables)
    }

    fn literal(&self, function: FunctionId, text: &str) -> Result<(), Refusal> {
        self.read(self.defined(function)?, text).map(drop)
    }

    fn key(&self, function: FunctionId, key: &str) -> Result<(), Refusal> {
        self.defined(function)?.key(key)
    }

    fn selects(&self, function: FunctionId) -> bool {
        self.defined(function).is_ok_and(Format::selects)
    }

    fn format(
        &self,
        function: FunctionId,
        value: &dyn Arg,
        options: &[(&str, &str)],
        out: &mut String,
    ) -> Result<Direction, Refusal> {
        let format = self.defined(function)?;
        let held = self.held(format, value)?;
        format.format(held.record(), options, &self.tables, out)
    }

    fn select(
        &self,
        function: FunctionId,
        value: &dyn Arg,
        options: &[(&str, &str)],
    ) -> Result<Selection, Refusal> {
        let format = self.defined(function)?;
        let held = self.held(format, value)?;
        format.select(held.record(), options, &self.tables)
    }
}
