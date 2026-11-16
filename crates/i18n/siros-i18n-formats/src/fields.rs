//! The fields a value exposes to the patterns that format it, and the value types this crate
//! gives fields: its [`Number`], siros-syntax's numbers, amounts, dates and times, and Rust's
//! integers.

use std::borrow::Cow;

use siros_explain::Arg;
use siros_syntax::{Amount, Count, Date, DateTime, Decimal, Offset, OffsetTime, Time};

use crate::number::decimal::Number;

/// What a field holds, which decides the operations a placeholder applies to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// A decimal number: a format rounds it once, and `{sign}`, `{int}` and `{frac}` write it.
    /// A value type has one field of this kind at most.
    Number,
    /// An integer: a placeholder pads it, keeps its last digits, or looks it up in a table.
    Integer,
    /// A text: a placeholder writes it or looks it up in a table.
    Text,
}

/// A field's value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Field<'a> {
    /// A [`Kind::Number`] field's.
    Number(Number),
    /// A [`Kind::Integer`] field's.
    Integer(i64),
    /// A [`Kind::Text`] field's.
    Text(Cow<'a, str>),
}

/// A value type a format reads by its fields.
///
/// # Implementing
///
/// Name the schema the type follows and list its fields: a format of `of = <NAME>` takes every
/// type of that name, and its patterns name only the fields every such type lists, of the same
/// kind. Give each field by name; `None` for an optional field the value lacks, such as a time's
/// offset. `literal` reads a literal operand of a message, `{|…| :format}`, when this type is
/// the first registered of its name that reads it.
///
/// ```
/// use std::borrow::Cow;
/// use std::fmt;
///
/// use siros_i18n_formats::{Field, Fields, Kind};
///
/// struct Badge(&'static str);
///
/// impl fmt::Display for Badge {
///     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
///         f.write_str(self.0)
///     }
/// }
///
/// impl Fields for Badge {
///     const NAME: &'static str = "badge";
///     const FIELDS: &'static [(&'static str, Kind)] = &[("code", Kind::Text)];
///
///     fn field(&self, name: &str) -> Option<Field<'_>> {
///         (name == "code").then(|| Field::Text(Cow::Borrowed(self.0)))
///     }
///
///     fn literal(_: &str) -> Option<Self> {
///         None
///     }
/// }
/// ```
pub trait Fields: Arg {
    /// The schema's name, which a format's `of` names.
    const NAME: &'static str;
    /// Each field's name and kind.
    const FIELDS: &'static [(&'static str, Kind)];

    /// The field `name`; `None` for a field the value lacks.
    fn field(&self, name: &str) -> Option<Field<'_>>;

    /// The value a literal operand writes; `None` for a text that writes none.
    fn literal(text: &str) -> Option<Self>
    where
        Self: Sized;
}

/// The fields of a number.
const NUMBER: &[(&str, Kind)] = &[("number", Kind::Number)];

impl Fields for Number {
    const NAME: &'static str = "number";
    const FIELDS: &'static [(&'static str, Kind)] = NUMBER;

    fn field(&self, name: &str) -> Option<Field<'_>> {
        (name == "number").then(|| Field::Number(self.clone()))
    }

    fn literal(text: &str) -> Option<Self> {
        Self::literal(text)
    }
}

impl Fields for Decimal {
    const NAME: &'static str = "number";
    const FIELDS: &'static [(&'static str, Kind)] = NUMBER;

    fn field(&self, name: &str) -> Option<Field<'_>> {
        (name == "number").then(|| Field::Number(Number::of_units(self.units(), self.scale())))
    }

    fn literal(text: &str) -> Option<Self> {
        Self::parse(text).ok()
    }
}

impl Fields for Count {
    const NAME: &'static str = "number";
    const FIELDS: &'static [(&'static str, Kind)] = NUMBER;

    fn field(&self, name: &str) -> Option<Field<'_>> {
        if name != "number" {
            return None;
        }
        Number::of_digits(&self.digits()).map(Field::Number)
    }

    fn literal(text: &str) -> Option<Self> {
        Self::parse(text).ok()
    }
}

/// Rust's integers: numbers.
macro_rules! integers {
    ($($int:ty),*) => {$(
        impl Fields for $int {
            const NAME: &'static str = "number";
            const FIELDS: &'static [(&'static str, Kind)] = NUMBER;

            fn field(&self, name: &str) -> Option<Field<'_>> {
                (name == "number").then(|| Field::Number(Number::of_units(i128::from(*self), 0)))
            }

            fn literal(text: &str) -> Option<Self> {
                text.parse().ok()
            }
        }
    )*};
}

integers!(u8, u16, u32, u64, i8, i16, i32, i64);

impl Fields for Amount {
    const NAME: &'static str = "amount";
    const FIELDS: &'static [(&'static str, Kind)] =
        &[("number", Kind::Number), ("currency", Kind::Text)];

    fn field(&self, name: &str) -> Option<Field<'_>> {
        match name {
            "number" => Some(Field::Number(Number::of_units(
                self.value().units(),
                self.value().scale(),
            ))),
            "currency" => Some(Field::Text(Cow::Owned(self.currency().to_string()))),
            _ => None,
        }
    }

    fn literal(text: &str) -> Option<Self> {
        Self::parse(text).ok()
    }
}

/// A date's fields: the ISO year, month and day, the weekday from 1 for Monday, and the era,
/// 0 before year 1, with the year in it.
const DATE: [(&str, Kind); 6] = [
    ("year", Kind::Integer),
    ("month", Kind::Integer),
    ("day", Kind::Integer),
    ("weekday", Kind::Integer),
    ("era", Kind::Integer),
    ("era-year", Kind::Integer),
];

/// A time's fields: the hour on each cycle (`hour` 0 to 23, `hour12` 1 to 12, `hour11` 0 to
/// 11, `hour24` 1 to 24), the day `period`, 0 before noon and 1 after, the minute and second,
/// and when it has one, its offset in minutes, the offset's hours and minutes without sign, and
/// its sign, 1 below zero and 0 otherwise.
const TIME: [(&str, Kind); 11] = [
    ("hour", Kind::Integer),
    ("hour12", Kind::Integer),
    ("hour11", Kind::Integer),
    ("hour24", Kind::Integer),
    ("period", Kind::Integer),
    ("minute", Kind::Integer),
    ("second", Kind::Integer),
    ("offset", Kind::Integer),
    ("offset-hours", Kind::Integer),
    ("offset-minutes", Kind::Integer),
    ("offset-sign", Kind::Integer),
];

/// The day of the week, 1 for Monday to 7 for Sunday. The count of days runs over years that
/// start in March, so that February's leap day ends its year; a year 400 later has the same
/// calendar, so the count starts 400 years before year 0.
fn weekday(date: Date) -> i64 {
    let (month, day) = (i64::from(date.month()), i64::from(date.day()));
    let year = i64::from(date.year()) + 400 - i64::from(month <= 2);
    let from_march = (month + 9) % 12;
    let days =
        year * 365 + year / 4 - year / 100 + year / 400 + (153 * from_march + 2) / 5 + day - 1;
    // Day 0 of the count, 0000-03-01 400 years earlier, is a Wednesday.
    (days + 2) % 7 + 1
}

fn date_field(date: Date, name: &str) -> Option<Field<'static>> {
    let year = i64::from(date.year());
    Some(Field::Integer(match name {
        "year" => year,
        "month" => i64::from(date.month()),
        "day" => i64::from(date.day()),
        "weekday" => weekday(date),
        "era" => i64::from(year > 0),
        "era-year" if year == 0 => 1,
        "era-year" => year,
        _ => return None,
    }))
}

fn time_field(
    (hour, minute, second): (u8, u8, u8),
    offset: Option<Offset>,
    name: &str,
) -> Option<Field<'static>> {
    let minutes = offset.map(|offset| i64::from(offset.minutes()));
    let hour = i64::from(hour);
    Some(Field::Integer(match name {
        "hour" => hour,
        "hour12" => (hour + 11) % 12 + 1,
        "hour11" => hour % 12,
        "hour24" => (hour + 23) % 24 + 1,
        "period" => i64::from(hour >= 12),
        "minute" => i64::from(minute),
        "second" => i64::from(second),
        "offset" => minutes?,
        "offset-hours" => minutes?.abs() / 60,
        "offset-minutes" => minutes?.abs() % 60,
        "offset-sign" => i64::from(minutes? < 0),
        _ => return None,
    }))
}

fn clock(time: Time) -> (u8, u8, u8) {
    let second = time.second().map_or(0, |second| second.whole());
    (time.hour(), time.minute(), second)
}

impl Fields for Date {
    const NAME: &'static str = "date";
    const FIELDS: &'static [(&'static str, Kind)] = &DATE;

    fn field(&self, name: &str) -> Option<Field<'_>> {
        date_field(*self, name)
    }

    fn literal(text: &str) -> Option<Self> {
        Self::parse(text).ok()
    }
}

impl Fields for OffsetTime {
    const NAME: &'static str = "time";
    const FIELDS: &'static [(&'static str, Kind)] = &TIME;

    fn field(&self, name: &str) -> Option<Field<'_>> {
        time_field(clock(self.at()), self.offset(), name)
    }

    fn literal(text: &str) -> Option<Self> {
        Self::parse(text).ok()
    }
}

impl Fields for Time {
    const NAME: &'static str = "time";
    const FIELDS: &'static [(&'static str, Kind)] = &TIME;

    fn field(&self, name: &str) -> Option<Field<'_>> {
        time_field(clock(*self), None, name)
    }

    fn literal(text: &str) -> Option<Self> {
        Self::parse(text).ok()
    }
}

/// A date and time's fields: a date's, then a time's.
const DATE_TIME: [(&str, Kind); 17] = [
    ("year", Kind::Integer),
    ("month", Kind::Integer),
    ("day", Kind::Integer),
    ("weekday", Kind::Integer),
    ("era", Kind::Integer),
    ("era-year", Kind::Integer),
    ("hour", Kind::Integer),
    ("hour12", Kind::Integer),
    ("hour11", Kind::Integer),
    ("hour24", Kind::Integer),
    ("period", Kind::Integer),
    ("minute", Kind::Integer),
    ("second", Kind::Integer),
    ("offset", Kind::Integer),
    ("offset-hours", Kind::Integer),
    ("offset-minutes", Kind::Integer),
    ("offset-sign", Kind::Integer),
];

impl Fields for DateTime {
    const NAME: &'static str = "datetime";
    const FIELDS: &'static [(&'static str, Kind)] = &DATE_TIME;

    fn field(&self, name: &str) -> Option<Field<'_>> {
        let clock = (self.hour(), self.minute(), self.second().unwrap_or(0));
        date_field(self.date(), name).or_else(|| time_field(clock, self.offset(), name))
    }

    fn literal(text: &str) -> Option<Self> {
        Self::parse(text).ok()
    }
}
