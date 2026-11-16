//! A value's calendar fields, written by `[formats.date]`'s patterns and names.

use siros_syntax::{Date, Offset};

use super::{Cycle, EraField, Field, Item, Length, Parsed, Pattern, Written, fields};
use crate::chain::Failure;
use crate::format::Direction;

/// A value's calendar fields.
pub(super) struct Moment {
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
    pub(super) fn of(written: Written) -> Self {
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
    pub(super) fn time(
        &self,
        length: Length,
        moment: &Moment,
        out: &mut String,
    ) -> Result<(), Failure> {
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

    pub(super) fn pattern(
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
