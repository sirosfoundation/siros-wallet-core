//! `:siros:date`, `:siros:time` and `:siros:datetime`, which format a date, a time or both in the
//! Gregorian calendar with the language's CLDR patterns at a `length` (`short`, `medium`, `long`,
//! `full`; Unicode TR35 Part 4, "Date Format Patterns"). An operand is siros-syntax's ISO 8601
//! literal: `:siros:date` takes a date or a date with a time, `:siros:time` a time, its offset
//! optional, or a date with a time, `:siros:datetime` a date with a time. A time without an offset
//! shows at `long` and `full` as at `medium`: those patterns name its zone. A year outside 1950 to
//! 2049 shows in full, and one before 1000 with its era, as ICU4X's `YearStyle::Auto` shows them.

mod parse;
mod write;

use write::Moment;

use siros_syntax::{Date, DateTime, OffsetTime};

use crate::chain::{Chain, Failure, Root, Texts};
use crate::digit::Numerals;
use crate::error::Refusal;
use crate::format::{Direction, Function};
use crate::scope::Scope;

/// The options `[formats.date]` takes.
pub(crate) const OPTIONS: [&str; 22] = [
    "zero",
    "date-short",
    "date-medium",
    "date-long",
    "date-full",
    "time-short",
    "time-medium",
    "time-long",
    "time-full",
    "datetime-short",
    "datetime-medium",
    "datetime-long",
    "datetime-full",
    "months-wide",
    "months-abbreviated",
    "days-wide",
    "days-abbreviated",
    "periods",
    "zone-gmt",
    "zone-hours",
    "year-era",
    "eras",
];

/// What a call formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Date,
    Time,
    DateTime,
}

impl Kind {
    /// The kind of a date function; `None` for another function.
    const fn of(function: Function) -> Option<Self> {
        match function {
            Function::Date => Some(Self::Date),
            Function::Time => Some(Self::Time),
            Function::DateTime => Some(Self::DateTime),
            _ => None,
        }
    }

    /// Whether a call of this kind takes a value written as `written`.
    const fn takes(self, written: &Written) -> bool {
        matches!(
            (self, written),
            (Self::Date, Written::Date(_))
                | (Self::Time, Written::Time(_))
                | (_, Written::DateTime(_))
        )
    }
}

/// An operand's text, read as the ISO 8601 literal it is.
#[derive(Debug, Clone, Copy)]
enum Written {
    Date(Date),
    Time(OffsetTime),
    DateTime(DateTime),
}

impl Written {
    /// The value `text` writes; `None` for a text that is no date, time or date with a time.
    fn of(text: &str) -> Option<Self> {
        DateTime::parse(text)
            .map(Self::DateTime)
            .or_else(|_| Date::parse(text).map(Self::Date))
            .or_else(|_| OffsetTime::parse(text).map(Self::Time))
            .ok()
    }
}

/// A length: `short`, `medium`, `long` or `full`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Length {
    Short,
    Medium,
    Long,
    Full,
}

impl Length {
    fn named(name: &str) -> Option<Self> {
        Some(match name {
            "short" => Self::Short,
            "medium" => Self::Medium,
            "long" => Self::Long,
            "full" => Self::Full,
            _ => return None,
        })
    }
}

/// An hour field's cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cycle {
    /// `h`: 1 to 12.
    H12,
    /// `H`: 0 to 23.
    H23,
    /// `K`: 0 to 11.
    H11,
    /// `k`: 1 to 24.
    H24,
}

/// A field of a date or time pattern (TR35 Part 4, "Date Field Symbol Table"), with its width
/// where the width shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    /// `G` to `GGG`: the era's abbreviated name.
    Era,
    /// `y…`.
    Year(u8),
    /// `M`, `MM`: the month's number.
    Month(u8),
    /// `MMM`: the month's abbreviated name.
    MonthAbbreviated,
    /// `MMMM`: the month's name.
    MonthWide,
    /// `d`, `dd`.
    Day(u8),
    /// `E` to `EEE`: the weekday's abbreviated name.
    WeekdayAbbreviated,
    /// `EEEE`: the weekday's name.
    WeekdayWide,
    /// `h`, `H`, `K`, `k`, each one or two wide.
    Hour(Cycle, u8),
    /// `m`, `mm`.
    Minute(u8),
    /// `s`, `ss`.
    Second(u8),
    /// `S` to nine `S`: the fraction's first digits.
    Fraction(u8),
    /// `a` to `aaa`: the day period.
    Period,
    /// `z` to `zzz`, `O`: the short localized GMT format; `zzzz`, `OOOO`: the long one.
    Zone { long: bool },
}

impl Field {
    /// The field `width` letters `letter` write; `None` for a letter or width the engine does
    /// not format.
    fn of(letter: char, width: u8) -> Option<Self> {
        let narrow = (1..=2).contains(&width).then_some(width);
        Some(match (letter, width) {
            ('G', 1..=3) => Self::Era,
            ('y', _) => Self::Year(width),
            ('M', 3) => Self::MonthAbbreviated,
            ('M', 4) => Self::MonthWide,
            ('M', _) => Self::Month(narrow?),
            ('d', _) => Self::Day(narrow?),
            ('E', 1..=3) => Self::WeekdayAbbreviated,
            ('E', 4) => Self::WeekdayWide,
            ('h', _) => Self::Hour(Cycle::H12, narrow?),
            ('H', _) => Self::Hour(Cycle::H23, narrow?),
            ('K', _) => Self::Hour(Cycle::H11, narrow?),
            ('k', _) => Self::Hour(Cycle::H24, narrow?),
            ('m', _) => Self::Minute(narrow?),
            ('s', _) => Self::Second(narrow?),
            ('S', 1..=9) => Self::Fraction(width),
            ('a', 1..=3) => Self::Period,
            ('z', 1..=3) | ('O', 1) => Self::Zone { long: false },
            ('z' | 'O', 4) => Self::Zone { long: true },
            _ => return None,
        })
    }

    /// Whether it shows the zone.
    const fn zoned(self) -> bool {
        matches!(self, Self::Zone { .. })
    }

    /// Whether it shows a field of the date.
    const fn of_date(self) -> bool {
        matches!(
            self,
            Self::Era
                | Self::Year(_)
                | Self::Month(_)
                | Self::MonthAbbreviated
                | Self::MonthWide
                | Self::Day(_)
                | Self::WeekdayAbbreviated
                | Self::WeekdayWide
        )
    }
}

/// A pattern's item: literal text or a field.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Item<F> {
    Text(String),
    Field(F),
}

/// A pattern of fields `F`.
type Pattern<F> = Vec<Item<F>>;

/// A field of a datetime pattern: `{0}` the time, `{1}` the date.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Glue {
    Time,
    Date,
}

/// A field of the `Gy` pattern, which shows a year before 1000 with its era.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EraField {
    Year(u8),
    Era,
}

/// An hour format of the localized GMT format: the text around the hours, and the text before
/// the minutes when it shows them.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Hours {
    before: String,
    minutes: Option<String>,
    after: String,
}

/// Patterns by length.
#[derive(Debug, Clone)]
struct Lengths<F> {
    short: Pattern<F>,
    medium: Pattern<F>,
    long: Pattern<F>,
    full: Pattern<F>,
}

impl<F> Lengths<F> {
    const fn get(&self, length: Length) -> &Pattern<F> {
        match length {
            Length::Short => &self.short,
            Length::Medium => &self.medium,
            Length::Long => &self.long,
            Length::Full => &self.full,
        }
    }
}

/// Names by position: months, weekdays from Sunday, day periods, eras.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Names(Vec<String>);

impl Names {
    /// Exactly `count` lines, each non-empty.
    fn parse(text: &str, count: usize) -> Option<Self> {
        let lines: Vec<String> = text.lines().map(str::to_owned).collect();
        (lines.len() == count && lines.iter().all(|l| !l.is_empty())).then_some(Self(lines))
    }

    /// The name at `index`.
    ///
    /// # Errors
    ///
    /// [`Failure::Operand`] for an index past the names.
    fn at(&self, index: usize) -> Result<&str, Failure> {
        self.0
            .get(index)
            .map(String::as_str)
            .ok_or(Failure::Operand)
    }
}

/// `[formats.date]`, parsed. A date pattern shows fields of the date alone, a time pattern none
/// of them, and the `short` and `medium` time patterns, which a time without an offset shows at
/// every length, no zone.
#[derive(Debug, Clone)]
pub(crate) struct Parsed {
    numerals: Numerals,
    direction: Direction,
    date: Lengths<Field>,
    time: Lengths<Field>,
    glue: Lengths<Glue>,
    months_wide: Names,
    months_abbreviated: Names,
    days_wide: Names,
    days_abbreviated: Names,
    periods: Names,
    gmt: (String, String),
    hours: [Hours; 2],
    year_era: Pattern<EraField>,
    eras: Names,
}

/// The fields of a pattern.
fn fields<F: Copy>(pattern: &Pattern<F>) -> impl Iterator<Item = F> + '_ {
    pattern.iter().filter_map(|item| match item {
        Item::Field(field) => Some(*field),
        Item::Text(_) => None,
    })
}

/// Checks a chain of date function calls, which a placeholder formats or an option takes the
/// operand's text of. A call takes the `length` of the nearest call that gives one, its own
/// first.
///
/// # Errors
///
/// [`Refusal::Operand`] for a missing operand, a call of another function, or a literal a call
/// does not take; [`Refusal::Option`] for a `length` the load fixes that names no length.
pub(crate) fn check(chain: &Chain<'_>) -> Result<(), Refusal> {
    let kinds = kinds(chain).ok_or(Refusal::Operand)?;
    match chain.root {
        Root::None => return Err(Refusal::Operand),
        Root::Literal(text) => {
            let written = Written::of(text).ok_or(Refusal::Operand)?;
            if !kinds.iter().all(|kind| kind.takes(&written)) {
                return Err(Refusal::Operand);
            }
        }
        Root::Argument(_) => {}
    }
    let given = chain.calls().rev().find_map(|call| call.option("length"));
    match given.and_then(|value| value.fixed()) {
        Some(name) if Length::named(name).is_none() => Err(Refusal::Option {
            option: "length".to_owned(),
        }),
        Some(_) | None => Ok(()),
    }
}

/// The kinds of the chain's calls, innermost first; `None` for a call of another function.
fn kinds(chain: &Chain<'_>) -> Option<Vec<Kind>> {
    chain.calls().map(|call| Kind::of(call.function)).collect()
}

/// The operand's text, the value it writes, which every call of the chain takes, and the kind
/// of the outermost call.
fn written<'m>(chain: &Chain<'m>, scope: &Scope<'m>) -> Result<(&'m str, Written, Kind), Failure> {
    let text = match chain.root {
        Root::None => return Err(Failure::Operand),
        Root::Literal(text) => text,
        Root::Argument(key) => scope.argument(key)?,
    };
    let written = Written::of(text).ok_or(Failure::Operand)?;
    let kinds = kinds(chain).ok_or(Failure::Operand)?;
    match kinds.last() {
        Some(outer) if kinds.iter().all(|kind| kind.takes(&written)) => Ok((text, written, *outer)),
        Some(_) | None => Err(Failure::Operand),
    }
}

/// The length of resolved calls: the nearest call's that gives one, `medium` when none does.
fn length(texts: &Texts<'_>) -> Result<Length, Failure> {
    match texts.calls().rev().find_map(|call| call.option("length")) {
        None => Ok(Length::Medium),
        Some(name) => Length::named(name).ok_or_else(|| Failure::Option("length".to_owned())),
    }
}

/// The operand's text as an option's value.
///
/// # Errors
///
/// [`Failure::Operand`] for a text no call of the chain takes, [`Failure::Option`] for a
/// `length` text that names no length, and [`Failure::Unresolved`] for an argument not given.
pub(crate) fn value<'m>(
    chain: &Chain<'m>,
    texts: &Texts<'_>,
    scope: &Scope<'m>,
) -> Result<&'m str, Failure> {
    let (text, ..) = written(chain, scope)?;
    length(texts).map(|_| text)
}

/// The value formatted with `[formats.date]`'s patterns and names.
///
/// # Errors
///
/// [`Failure::Operand`] for a text no call of the chain takes, or a value that lacks a field
/// its pattern shows; [`Failure::Option`] for a `length` text that names no length, and
/// [`Failure::Unresolved`] for an argument not given.
pub(crate) fn format(
    chain: &Chain<'_>,
    texts: &Texts<'_>,
    scope: &Scope<'_>,
    language: &Parsed,
) -> Result<String, Failure> {
    let (_, written, kind) = written(chain, scope)?;
    let length = length(texts)?;
    let moment = Moment::of(written);
    let mut out = String::new();
    match kind {
        Kind::Date => language.pattern(language.date.get(length), &moment, &mut out)?,
        Kind::Time => language.time(length, &moment, &mut out)?,
        Kind::DateTime => {
            for item in language.glue.get(length) {
                match item {
                    Item::Text(text) => out.push_str(text),
                    Item::Field(Glue::Time) => language.time(length, &moment, &mut out)?,
                    Item::Field(Glue::Date) => {
                        language.pattern(language.date.get(length), &moment, &mut out)?;
                    }
                }
            }
        }
    }
    Ok(out)
}
