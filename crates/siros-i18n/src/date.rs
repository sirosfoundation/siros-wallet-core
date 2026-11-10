//! `:siros:date`, `:siros:time` and `:siros:datetime`, which format a date, a time or both in the
//! Gregorian calendar with the language's CLDR patterns at a `length` (`short`, `medium`, `long`,
//! `full`; Unicode TR35 Part 4, "Date Format Patterns"). An operand is siros-syntax's ISO 8601
//! literal: `:siros:date` takes a date or a date with a time, `:siros:time` a time, its offset
//! optional, or a date with a time, `:siros:datetime` a date with a time. A time without an offset
//! shows at `long` and `full` as at `medium`: those patterns name its zone. A year outside 1950 to
//! 2049 shows in full, and one before 1000 with its era, as ICU4X's `YearStyle::Auto` shows them.

use siros_syntax::{Date, DateTime, Offset, OffsetTime};

use crate::chain::{Chain, Failure, Root, Scope, Texts};
use crate::digit::Numerals;
use crate::error::{FormatRule, Refusal};
use crate::format::{Direction, Function, Options};

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

/// A TR35 pattern: letters `A-Za-z` are fields, `'…'` quotes literal text, `''` an apostrophe.
/// `field` reads each field and its width. `None` for a field `field` refuses or wider than 255
/// letters, and for an unclosed quote.
fn items<F>(text: &str, field: impl Fn(char, u8) -> Option<F>) -> Option<Pattern<F>> {
    let mut items = Vec::new();
    let mut literal = String::new();
    let mut chars = text.chars().peekable();
    let mut quoted = false;
    while let Some(c) = chars.next() {
        if c == '\'' {
            if chars.next_if_eq(&'\'').is_some() {
                literal.push('\'');
            } else {
                quoted = !quoted;
            }
        } else if quoted || !c.is_ascii_alphabetic() {
            literal.push(c);
        } else {
            let mut width: u8 = 1;
            while chars.next_if_eq(&c).is_some() {
                width = width.checked_add(1)?;
            }
            let read = field(c, width)?;
            if !literal.is_empty() {
                items.push(Item::Text(std::mem::take(&mut literal)));
            }
            items.push(Item::Field(read));
        }
    }
    if quoted {
        return None;
    }
    if !literal.is_empty() {
        items.push(Item::Text(literal));
    }
    Some(items)
}

/// The fields of a pattern.
fn fields<F: Copy>(pattern: &Pattern<F>) -> impl Iterator<Item = F> + '_ {
    pattern.iter().filter_map(|item| match item {
        Item::Field(field) => Some(*field),
        Item::Text(_) => None,
    })
}

/// A datetime pattern: `{0}` the time, `{1}` the date, each once, the rest literal after TR35's
/// quoting.
fn glue(text: &str) -> Option<Pattern<Glue>> {
    let mut items = Vec::new();
    let mut rest = text;
    while let Some((before, mark)) = rest.split_once('{') {
        items.extend(self::items(before, |_, _| None::<Glue>)?);
        let (field, after) = match (mark.strip_prefix("0}"), mark.strip_prefix("1}")) {
            (Some(after), _) => (Glue::Time, after),
            (None, Some(after)) => (Glue::Date, after),
            (None, None) => return None,
        };
        items.push(Item::Field(field));
        rest = after;
    }
    items.extend(self::items(rest, |_, _| None::<Glue>)?);
    let count = |wanted: Glue| fields(&items).filter(|field| *field == wanted).count();
    (count(Glue::Time) == 1 && count(Glue::Date) == 1).then_some(items)
}

/// A year with its era (CLDR's `Gy` skeleton): one `y` and one `G`, the rest literal.
fn year_era(text: &str) -> Option<Pattern<EraField>> {
    let items = items(text, |c, width| match (c, width) {
        ('y', _) => Some(EraField::Year(width)),
        ('G', 1..=3) => Some(EraField::Era),
        _ => None,
    })?;
    let years = fields(&items)
        .filter(|f| matches!(f, EraField::Year(_)))
        .count();
    let eras = fields(&items).filter(|f| *f == EraField::Era).count();
    (years == 1 && eras == 1).then_some(items)
}

/// An hour format's positive and negative patterns, `;` between them.
fn hour_format(text: &str) -> Option<[Hours; 2]> {
    let (positive, negative) = text.split_once(';')?;
    Some([hours(positive)?, hours(negative)?])
}

/// The field of an hour pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HourField {
    Hours,
    Minutes,
}

/// An hour pattern: `H` or `HH`, then optionally a literal and `mm`.
fn hours(text: &str) -> Option<Hours> {
    let items = items(text, |c, width| match (c, width) {
        ('H', 1..=2) => Some(HourField::Hours),
        ('m', 2) => Some(HourField::Minutes),
        _ => None,
    })?;
    let mut before = String::new();
    let mut between = None;
    let mut after = String::new();
    let mut read: Vec<HourField> = Vec::new();
    for item in items {
        match item {
            Item::Text(text) if read.is_empty() => before.push_str(&text),
            Item::Text(text) => after.push_str(&text),
            Item::Field(HourField::Hours) if read.is_empty() => read.push(HourField::Hours),
            Item::Field(HourField::Minutes) if read == [HourField::Hours] => {
                between = Some(std::mem::take(&mut after));
                read.push(HourField::Minutes);
            }
            Item::Field(_) => return None,
        }
    }
    (!read.is_empty()).then_some(Hours {
        before,
        minutes: between,
        after,
    })
}

/// The localized GMT format: the text around `{0}`, which stands once.
fn gmt(text: &str) -> Option<(String, String)> {
    let (before, after) = text.split_once("{0}")?;
    (!after.contains("{0}")).then(|| (before.to_owned(), after.to_owned()))
}

impl Parsed {
    /// The section's options.
    ///
    /// # Errors
    ///
    /// [`FormatRule`] for an option the section lacks or whose text the grammar refuses.
    pub(crate) fn parse(options: Options<'_>) -> Result<Self, FormatRule> {
        let pattern = |name, accept: fn(Field) -> bool| {
            options.parse(name, |text| {
                items(text, Field::of).filter(|pattern| fields(pattern).all(accept))
            })
        };
        let date = |name| pattern(name, Field::of_date);
        let zoned = |name| pattern(name, |field| !field.of_date());
        let unzoned = |name| pattern(name, |field| !field.of_date() && !field.zoned());
        let glued = |name| options.parse(name, glue);
        let names = |name, count| options.parse(name, |text| Names::parse(text, count));
        Ok(Self {
            numerals: options.parse("zero", Numerals::parse)?,
            direction: options.direction,
            date: Lengths {
                short: date("date-short")?,
                medium: date("date-medium")?,
                long: date("date-long")?,
                full: date("date-full")?,
            },
            time: Lengths {
                short: unzoned("time-short")?,
                medium: unzoned("time-medium")?,
                long: zoned("time-long")?,
                full: zoned("time-full")?,
            },
            glue: Lengths {
                short: glued("datetime-short")?,
                medium: glued("datetime-medium")?,
                long: glued("datetime-long")?,
                full: glued("datetime-full")?,
            },
            months_wide: names("months-wide", 12)?,
            months_abbreviated: names("months-abbreviated", 12)?,
            days_wide: names("days-wide", 7)?,
            days_abbreviated: names("days-abbreviated", 7)?,
            periods: names("periods", 2)?,
            gmt: options.parse("zone-gmt", gmt)?,
            hours: options.parse("zone-hours", hour_format)?,
            year_era: options.parse("year-era", year_era)?,
            eras: names("eras", 2)?,
        })
    }
}

/// Checks a chain of date function calls, which a placeholder formats or an option takes the
/// operand's text of. A call takes the `length` of the nearest call that gives one, its own
/// first.
///
/// # Errors
///
/// [`Refusal::Operand`] for a missing operand, a call of another function, or a literal a call
/// does not take; [`Refusal::Option`] for a `length` the load fixes that names no length.
pub(crate) fn check(chain: &Chain) -> Result<(), Refusal> {
    let kinds = kinds(chain).ok_or(Refusal::Operand)?;
    match &chain.root {
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
fn kinds(chain: &Chain) -> Option<Vec<Kind>> {
    chain.calls().map(|call| Kind::of(call.function)).collect()
}

/// The operand's text, the value it writes, which every call of the chain takes, and the kind
/// of the outermost call.
fn written<'m>(chain: &'m Chain, scope: &Scope<'m>) -> Result<(&'m str, Written, Kind), Failure> {
    let text = match &chain.root {
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
    chain: &'m Chain,
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
    chain: &Chain,
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

/// A value's calendar fields.
struct Moment {
    date: Option<Date>,
    hour: u8,
    minute: u8,
    second: u8,
    /// The fraction's nanoseconds.
    nanos: u32,
    offset: Option<Offset>,
}

impl Moment {
    /// The fields of a value as its literal writes them.
    fn of(written: Written) -> Self {
        match written {
            Written::Date(date) => Self {
                date: Some(date),
                hour: 0,
                minute: 0,
                second: 0,
                nanos: 0,
                offset: None,
            },
            Written::Time(time) => {
                let at = time.at();
                Self {
                    date: None,
                    hour: at.hour(),
                    minute: at.minute(),
                    second: at.second().map_or(0, |s| s.whole()),
                    nanos: at.second().map_or(0, |s| s.fraction().nanos()),
                    offset: time.offset(),
                }
            }
            Written::DateTime(value) => Self {
                date: Some(value.date()),
                hour: value.hour(),
                minute: value.minute(),
                second: value.second().unwrap_or(0),
                nanos: value.fraction().nanos(),
                offset: value.offset(),
            },
        }
    }
}

/// The day of the week, 0 for Sunday. The count of days runs over years that start in March,
/// so that February's leap day ends its year; a year 400 later has the same calendar, so the
/// count starts 400 years before year 0.
fn weekday(date: Date) -> usize {
    let (month, day) = (u32::from(date.month()), u32::from(date.day()));
    let year = u32::from(date.year()) + 400 - u32::from(month <= 2);
    let from_march = (month + 9) % 12;
    let days =
        year * 365 + year / 4 - year / 100 + year / 400 + (153 * from_march + 2) / 5 + day - 1;
    // Day 0 of the count, 0000-03-01 400 years earlier, is a Wednesday.
    ((days + 3) % 7) as usize
}

/// What a Gregorian year needs beside its last two digits to be read unambiguously, as ICU4X
/// 2.4 decides it (icu_calendar `cal/gregorian.rs`, `YearAmbiguity`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ambiguity {
    /// 1950 to 2049: none.
    Unambiguous,
    /// 1000 to 1949, and from 2050: its century.
    Century,
    /// Before 1000: its era and its century.
    EraAndCentury,
}

impl Ambiguity {
    const fn of(year: u16) -> Self {
        match year {
            ..=999 => Self::EraAndCentury,
            1950..=2049 => Self::Unambiguous,
            _ => Self::Century,
        }
    }
}

/// A year in its era: year 0 is 1 before year 1 (era 0), every later year its own (era 1).
fn in_era(year: u16) -> (usize, u32) {
    match year {
        0 => (0, 1),
        year => (1, u32::from(year)),
    }
}

impl Parsed {
    /// The direction of a formatted value: its section's module's.
    pub(crate) const fn direction(&self) -> Direction {
        self.direction
    }

    /// The time at `length`: a time without an offset at `long` and `full` as at `medium`.
    fn time(&self, length: Length, moment: &Moment, out: &mut String) -> Result<(), Failure> {
        let length = match (moment.offset, length) {
            (None, Length::Long | Length::Full) => Length::Medium,
            _ => length,
        };
        self.pattern(self.time.get(length), moment, out)
    }

    /// The localized GMT format of an offset: `long` pads its hours and writes its minutes.
    fn zone(&self, offset: Offset, long: bool, out: &mut String) {
        let minutes = offset.minutes();
        let [positive, negative] = &self.hours;
        let format = if minutes < 0 { negative } else { positive };
        let (hours, rest) = (
            u32::from(minutes.unsigned_abs() / 60),
            u32::from(minutes.unsigned_abs() % 60),
        );
        let (before, after) = &self.gmt;
        out.push_str(before);
        out.push_str(&format.before);
        self.numerals.write(hours, if long { 2 } else { 1 }, out);
        if let Some(between) = &format.minutes
            && (long || rest != 0)
        {
            out.push_str(between);
            self.numerals.write(rest, 2, out);
        }
        out.push_str(&format.after);
        out.push_str(after);
    }

    fn pattern(
        &self,
        pattern: &Pattern<Field>,
        moment: &Moment,
        out: &mut String,
    ) -> Result<(), Failure> {
        let shows_era = fields(pattern).any(|field| field == Field::Era);
        for item in pattern {
            match item {
                Item::Text(text) => out.push_str(text),
                Item::Field(field) => self.field(*field, moment, shows_era, out)?,
            }
        }
        Ok(())
    }

    /// A year field: its last two digits for `yy`, unless ICU4X's `YearStyle::Auto` needs
    /// more; then the full year, and before year 1000 the year in its era with the era, by the
    /// `Gy` pattern, when the pattern shows no era of its own.
    fn year(&self, year: u16, width: u8, shows_era: bool, out: &mut String) -> Result<(), Failure> {
        match (Ambiguity::of(year), shows_era) {
            (Ambiguity::EraAndCentury, false) => {
                for item in &self.year_era {
                    match item {
                        Item::Text(text) => out.push_str(text),
                        Item::Field(EraField::Year(width)) => {
                            self.numerals.write(in_era(year).1, *width, out);
                        }
                        Item::Field(EraField::Era) => out.push_str(self.eras.at(in_era(year).0)?),
                    }
                }
            }
            (Ambiguity::EraAndCentury, true) => {
                self.numerals
                    .write(in_era(year).1, if width == 2 { 1 } else { width }, out);
            }
            (Ambiguity::Unambiguous, _) if width == 2 => {
                self.numerals.write(u32::from(year) % 100, 2, out);
            }
            (Ambiguity::Century, _) if width == 2 => self.numerals.write(u32::from(year), 1, out),
            (Ambiguity::Unambiguous | Ambiguity::Century, _) => {
                self.numerals.write(u32::from(year), width, out);
            }
        }
        Ok(())
    }

    fn field(
        &self,
        field: Field,
        moment: &Moment,
        shows_era: bool,
        out: &mut String,
    ) -> Result<(), Failure> {
        let date = || moment.date.ok_or(Failure::Operand);
        let month = || Ok::<_, Failure>(usize::from(date()?.month()) - 1);
        match field {
            Field::Era => out.push_str(self.eras.at(in_era(date()?.year()).0)?),
            Field::Year(width) => self.year(date()?.year(), width, shows_era, out)?,
            Field::Month(width) => self.numerals.write(u32::from(date()?.month()), width, out),
            Field::MonthAbbreviated => out.push_str(self.months_abbreviated.at(month()?)?),
            Field::MonthWide => out.push_str(self.months_wide.at(month()?)?),
            Field::Day(width) => self.numerals.write(u32::from(date()?.day()), width, out),
            Field::WeekdayAbbreviated => out.push_str(self.days_abbreviated.at(weekday(date()?))?),
            Field::WeekdayWide => out.push_str(self.days_wide.at(weekday(date()?))?),
            Field::Hour(cycle, width) => {
                let hour = moment.hour;
                let shown = match cycle {
                    Cycle::H12 => (hour + 11) % 12 + 1,
                    Cycle::H23 => hour,
                    Cycle::H11 => hour % 12,
                    Cycle::H24 => (hour + 23) % 24 + 1,
                };
                self.numerals.write(u32::from(shown), width, out);
            }
            Field::Minute(width) => self.numerals.write(u32::from(moment.minute), width, out),
            Field::Second(width) => self.numerals.write(u32::from(moment.second), width, out),
            Field::Fraction(width) => {
                let shown = moment.nanos / 10u32.pow(9 - u32::from(width));
                self.numerals.write(shown, width, out);
            }
            Field::Period => out.push_str(self.periods.at(usize::from(moment.hour >= 12))?),
            Field::Zone { long } => {
                let offset = moment.offset.ok_or(Failure::Operand)?;
                self.zone(offset, long, out);
            }
        }
        Ok(())
    }
}
