//! The calendar types: dates, times of day, offsets, and dates with times, where RFC 3339 places
//! a leap second. Each writes its ISO 8601 literal, and parses exactly that literal.

use std::fmt;

use crate::malformed::{Malformed, Reader, parse};

/// A calendar date of the proleptic Gregorian calendar (ISO 8601), from year 0000 to 9999: the
/// years four digits write. Its literal is `YYYY-MM-DD`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Date {
    year: u16,
    month: Month,
    day: u8,
}

/// A month of the Gregorian calendar, numbered from 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
enum Month {
    January = 1,
    February,
    March,
    April,
    May,
    June,
    July,
    August,
    September,
    October,
    November,
    December,
}

impl Month {
    /// The month numbered `number`; `None` outside 1 to 12.
    const fn of(number: u8) -> Option<Self> {
        Some(match number {
            1 => Self::January,
            2 => Self::February,
            3 => Self::March,
            4 => Self::April,
            5 => Self::May,
            6 => Self::June,
            7 => Self::July,
            8 => Self::August,
            9 => Self::September,
            10 => Self::October,
            11 => Self::November,
            12 => Self::December,
            _ => return None,
        })
    }

    /// Its number.
    const fn number(self) -> u8 {
        self as u8
    }

    /// Its days in `year`.
    const fn days(self, year: u16) -> u8 {
        let leap =
            year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
        match self {
            Self::January
            | Self::March
            | Self::May
            | Self::July
            | Self::August
            | Self::October
            | Self::December => 31,
            Self::April | Self::June | Self::September | Self::November => 30,
            Self::February if leap => 29,
            Self::February => 28,
        }
    }
}

impl Date {
    /// The last year a date holds.
    const LAST_YEAR: u16 = 9999;

    /// The date; `None` when it is no calendar date or its year is past 9999.
    #[must_use]
    pub const fn new(year: u16, month: u8, day: u8) -> Option<Self> {
        match Month::of(month) {
            Some(month) if year <= Self::LAST_YEAR && day >= 1 && day <= month.days(year) => {
                Some(Self { year, month, day })
            }
            _ => None,
        }
    }

    /// The date `text` writes.
    ///
    /// # Errors
    ///
    /// [`Malformed`] for a text other than `YYYY-MM-DD`, at the month or the day when it is no
    /// calendar date's.
    pub fn parse(text: &str) -> Result<Self, Malformed> {
        parse(text, "Date", Self::read)
    }

    /// The date at the reader.
    fn read(reader: &mut Reader<'_>) -> Result<Self, Malformed> {
        let year = reader.four()?;
        reader.expect(b'-')?;
        let at = reader.at();
        let month = Month::of(reader.two()?).ok_or_else(|| reader.refuse(at))?;
        reader.expect(b'-')?;
        let at = reader.at();
        let day = reader.two()?;
        if day == 0 || day > month.days(year) {
            return Err(reader.refuse(at));
        }
        Ok(Self { year, month, day })
    }

    /// The year.
    #[must_use]
    pub const fn year(self) -> u16 {
        self.year
    }

    /// The month, from 1.
    #[must_use]
    pub const fn month(self) -> u8 {
        self.month.number()
    }

    /// The day of the month, from 1.
    #[must_use]
    pub const fn day(self) -> u8 {
        self.day
    }

    /// Whether it is its month's last day.
    const fn last(self) -> bool {
        self.day == self.month.days(self.year)
    }

    /// The day before; `None` before year 0.
    const fn before(self) -> Option<Self> {
        if self.day > 1 {
            return Some(Self {
                day: self.day - 1,
                ..self
            });
        }
        match Month::of(self.month.number() - 1) {
            Some(month) => Some(Self {
                month,
                day: month.days(self.year),
                ..self
            }),
            None => match self.year.checked_sub(1) {
                Some(year) => Some(Self {
                    year,
                    month: Month::December,
                    day: 31,
                }),
                None => None,
            },
        }
    }

    /// The day after; `None` after year 9999.
    const fn after(self) -> Option<Self> {
        if !self.last() {
            return Some(Self {
                day: self.day + 1,
                ..self
            });
        }
        match Month::of(self.month.number() + 1) {
            Some(month) => Some(Self {
                month,
                day: 1,
                ..self
            }),
            None if self.year < Self::LAST_YEAR => Some(Self {
                year: self.year + 1,
                month: Month::January,
                day: 1,
            }),
            None => None,
        }
    }
}

/// Its literal: `2026-09-02`.
impl fmt::Display for Date {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:04}-{:02}-{:02}",
            self.year,
            self.month.number(),
            self.day
        )
    }
}

/// A time of day (ISO 8601): 00:00 to 23:59, with its seconds, 00 to 59, when written. A leap
/// second needs the date and the offset that place it: [`DateTime::leap`] makes one. Its literal
/// is `hh:mm`, then `:ss` and the fraction's digits after `.` when written: `12:30:15.5`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Time {
    hour: u8,
    minute: u8,
    second: Option<Second>,
}

impl Time {
    /// The time; `None` beyond 23:59.
    #[must_use]
    pub const fn new(hour: u8, minute: u8, second: Option<Second>) -> Option<Self> {
        if hour > 23 || minute > 59 {
            None
        } else {
            Some(Self {
                hour,
                minute,
                second,
            })
        }
    }

    /// The hour.
    #[must_use]
    pub const fn hour(self) -> u8 {
        self.hour
    }

    /// The minute.
    #[must_use]
    pub const fn minute(self) -> u8 {
        self.minute
    }

    /// The seconds, when written.
    #[must_use]
    pub const fn second(self) -> Option<Second> {
        self.second
    }

    /// The time `text` writes.
    ///
    /// # Errors
    ///
    /// [`Malformed`] for a text other than `hh:mm[:ss[.f…]]`, at the hour, the minute or the
    /// seconds when it is out of range; a leap second is a [`DateTime`]'s.
    pub fn parse(text: &str) -> Result<Self, Malformed> {
        parse(text, "Time", Self::read)
    }

    /// The time at the reader.
    fn read(reader: &mut Reader<'_>) -> Result<Self, Malformed> {
        let Written {
            hour,
            minute,
            second,
        } = Written::read(reader)?;
        let second = match second {
            Some(Seconds {
                whole,
                at,
                fraction,
            }) => Some(Second::new(whole, fraction).ok_or_else(|| reader.refuse(at))?),
            None => None,
        };
        Ok(Self {
            hour,
            minute,
            second,
        })
    }
}

/// Its literal: `12:30:15.5`.
impl fmt::Display for Time {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02}:{:02}", self.hour, self.minute)?;
        match self.second {
            Some(second) => {
                write!(f, ":{:02}", second.whole)?;
                second.fraction.write(f)
            }
            None => Ok(()),
        }
    }
}

/// A time of day as a literal writes it, `hh:mm[:ss[.f…]]`: the hour 00 to 23, the minute 00 to
/// 59 and the seconds 00 to 60, whose 60 only a date and an offset place.
struct Written {
    hour: u8,
    minute: u8,
    second: Option<Seconds>,
}

/// The seconds a literal writes: whole, where they start, and their fraction.
struct Seconds {
    whole: u8,
    at: usize,
    fraction: Fraction,
}

impl Written {
    /// The time of day at the reader.
    fn read(reader: &mut Reader<'_>) -> Result<Self, Malformed> {
        let hour = ranged(reader, 23)?;
        reader.expect(b':')?;
        let minute = ranged(reader, 59)?;
        if !reader.take(b':') {
            return Ok(Self {
                hour,
                minute,
                second: None,
            });
        }
        let at = reader.at();
        let whole = ranged(reader, 60)?;
        let fraction = if reader.take(b'.') {
            Fraction::read(reader)?
        } else {
            Fraction::NONE
        };
        Ok(Self {
            hour,
            minute,
            second: Some(Seconds {
                whole,
                at,
                fraction,
            }),
        })
    }
}

/// Two digits at the reader, up to `last`; refused at the first digit beyond it.
fn ranged(reader: &mut Reader<'_>, last: u8) -> Result<u8, Malformed> {
    let at = reader.at();
    let value = reader.two()?;
    if value > last {
        return Err(reader.refuse(at));
    }
    Ok(value)
}

/// A time of day with its UTC offset when written (RFC 3339 §5.6 `full-time`, the offset
/// optional). Its literal is the time's, then the offset's when written: `12:30+02:00`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OffsetTime {
    at: Time,
    offset: Option<Offset>,
}

impl OffsetTime {
    /// The time at the offset.
    #[must_use]
    pub const fn new(at: Time, offset: Option<Offset>) -> Self {
        Self { at, offset }
    }

    /// The time.
    #[must_use]
    pub const fn at(self) -> Time {
        self.at
    }

    /// The offset, when written.
    #[must_use]
    pub const fn offset(self) -> Option<Offset> {
        self.offset
    }

    /// The time and offset `text` writes.
    ///
    /// # Errors
    ///
    /// [`Malformed`] for a text other than a [`Time`]'s literal and an optional [`Offset`]'s.
    pub fn parse(text: &str) -> Result<Self, Malformed> {
        parse(text, "OffsetTime", |reader| {
            let at = Time::read(reader)?;
            let offset = Offset::optional(reader)?;
            Ok(Self { at, offset })
        })
    }
}

/// Its literal: `12:30+02:00`.
impl fmt::Display for OffsetTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.at)?;
        match self.offset {
            Some(offset) => write!(f, "{offset}"),
            None => Ok(()),
        }
    }
}

/// The seconds of a time of day: whole seconds 0 to 59, and the fraction as written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Second {
    whole: u8,
    fraction: Fraction,
}

impl Second {
    /// The seconds; `None` beyond 59.
    #[must_use]
    pub const fn new(whole: u8, fraction: Fraction) -> Option<Self> {
        if whole > 59 {
            None
        } else {
            Some(Self { whole, fraction })
        }
    }

    /// The whole seconds.
    #[must_use]
    pub const fn whole(self) -> u8 {
        self.whole
    }

    /// The fraction.
    #[must_use]
    pub const fn fraction(self) -> Fraction {
        self.fraction
    }
}

/// A fraction of a second with as many digits as written: up to nine, in nanoseconds that the
/// last digit's place divides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Fraction {
    nanos: u32,
    digits: u8,
}

impl Fraction {
    /// No fraction written.
    pub const NONE: Self = Self {
        nanos: 0,
        digits: 0,
    };

    /// The fraction; `None` beyond nine digits, or when its nanoseconds need more digits than
    /// `digits`.
    #[must_use]
    pub const fn new(nanos: u32, digits: u8) -> Option<Self> {
        if digits > 9
            || nanos >= 1_000_000_000
            || !nanos.is_multiple_of(10u32.pow(9 - digits as u32))
        {
            None
        } else {
            Some(Self { nanos, digits })
        }
    }

    /// The fraction in nanoseconds.
    #[must_use]
    pub const fn nanos(self) -> u32 {
        self.nanos
    }

    /// Its digits as written.
    #[must_use]
    pub const fn digits(self) -> u8 {
        self.digits
    }

    /// The one to nine digits after a second's `.`, at the reader.
    fn read(reader: &mut Reader<'_>) -> Result<Self, Malformed> {
        let (mut value, mut digits) = (0u32, 0u8);
        loop {
            let at = reader.at();
            let Some(digit) = reader.digit() else {
                break;
            };
            if digits == 9 {
                return Err(reader.refuse(at));
            }
            value = value * 10 + u32::from(digit);
            digits += 1;
        }
        if digits == 0 {
            return Err(reader.here());
        }
        let nanos = value * 10u32.pow(u32::from(9 - digits));
        Self::new(nanos, digits).ok_or_else(|| reader.here())
    }

    /// Writes `.` and its digits as written; nothing for no fraction.
    fn write(self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.digits == 0 {
            return Ok(());
        }
        let place = 10u32
            .checked_pow(u32::from(9 - self.digits))
            .ok_or(fmt::Error)?;
        let value = self.nanos.checked_div(place).ok_or(fmt::Error)?;
        write!(f, ".{value:0width$}", width = usize::from(self.digits))
    }
}

/// A UTC offset in minutes. Its literal is `Z` for 0, else `±hh:mm`: `+05:30`, `-08:00`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Offset(i16);

impl Offset {
    /// The offset; `None` beyond ±23:59.
    #[must_use]
    pub const fn new(minutes: i16) -> Option<Self> {
        if minutes <= -1440 || minutes >= 1440 {
            None
        } else {
            Some(Self(minutes))
        }
    }

    /// The minutes east of UTC.
    #[must_use]
    pub const fn minutes(self) -> i16 {
        self.0
    }

    /// The offset `text` writes.
    ///
    /// # Errors
    ///
    /// [`Malformed`] for a text other than `Z` or `±hh:mm` up to ±23:59, and at the sign for
    /// `+00:00` or `-00:00`: UTC is written `Z`.
    pub fn parse(text: &str) -> Result<Self, Malformed> {
        parse(text, "Offset", Self::read)
    }

    /// The offset at the reader.
    fn read(reader: &mut Reader<'_>) -> Result<Self, Malformed> {
        let start = reader.at();
        if reader.take(b'Z') {
            return Ok(Self(0));
        }
        let sign = if reader.take(b'+') {
            1
        } else if reader.take(b'-') {
            -1
        } else {
            return Err(reader.here());
        };
        let hours = ranged(reader, 23)?;
        reader.expect(b':')?;
        let minutes = i16::from(hours) * 60 + i16::from(ranged(reader, 59)?);
        if minutes == 0 {
            return Err(reader.refuse(start));
        }
        Ok(Self(sign * minutes))
    }

    /// The offset at the reader, when one is written there.
    fn optional(reader: &mut Reader<'_>) -> Result<Option<Self>, Malformed> {
        match reader.peek() {
            Some(b'Z' | b'+' | b'-') => Self::read(reader).map(Some),
            _ => Ok(None),
        }
    }
}

/// Its literal: `Z`, `+05:30`.
impl fmt::Display for Offset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 == 0 {
            return f.write_str("Z");
        }
        let sign = if self.0 < 0 { '-' } else { '+' };
        let minutes = self.0.unsigned_abs();
        write!(f, "{sign}{:02}:{:02}", minutes / 60, minutes % 60)
    }
}

/// A date and a time of day (ISO 8601), with its UTC offset when written (RFC 3339 §5.6
/// `date-time`). Its seconds reach 60 only at a leap second, which RFC 3339 §5.7 and Appendix D
/// place at 23:59:60 UTC on a month's last day, shifted by the offset to its local time. Only
/// [`DateTime::new`], [`DateTime::leap`] and [`DateTime::parse`] make one. Its literal is the
/// date's, `T`, the time's, then the offset's when written: `2026-09-02T12:30:15.5+02:00`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DateTime {
    date: Date,
    clock: Clock,
    offset: Option<Offset>,
}

/// A date and time's time of day: a [`Time`], or the minute that holds a leap second, with the
/// leap second's fraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Clock {
    At(Time),
    Leap {
        hour: u8,
        minute: u8,
        fraction: Fraction,
    },
}

impl DateTime {
    /// The date and time.
    #[must_use]
    pub const fn new(date: Date, at: Time, offset: Option<Offset>) -> Self {
        Self {
            date,
            clock: Clock::At(at),
            offset,
        }
    }

    /// The leap second `hour:minute:60` with its fraction, on `date` at `offset`; `None` unless
    /// that instant is 23:59:60 UTC on the last day of its month.
    #[must_use]
    pub const fn leap(
        date: Date,
        hour: u8,
        minute: u8,
        fraction: Fraction,
        offset: Offset,
    ) -> Option<Self> {
        if hour > 23 || minute > 59 {
            return None;
        }
        let utc = hour as i32 * 60 + minute as i32 - offset.0 as i32;
        let day = if utc < 0 {
            date.before()
        } else if utc >= 1440 {
            date.after()
        } else {
            Some(date)
        };
        match day {
            Some(day) if utc.rem_euclid(1440) == 1439 && day.last() => Some(Self {
                date,
                clock: Clock::Leap {
                    hour,
                    minute,
                    fraction,
                },
                offset: Some(offset),
            }),
            _ => None,
        }
    }

    /// The date.
    #[must_use]
    pub const fn date(self) -> Date {
        self.date
    }

    /// The hour.
    #[must_use]
    pub const fn hour(self) -> u8 {
        match self.clock {
            Clock::At(at) => at.hour,
            Clock::Leap { hour, .. } => hour,
        }
    }

    /// The minute.
    #[must_use]
    pub const fn minute(self) -> u8 {
        match self.clock {
            Clock::At(at) => at.minute,
            Clock::Leap { minute, .. } => minute,
        }
    }

    /// The whole seconds, when written: 0 to 59, or 60 at a leap second.
    #[must_use]
    pub const fn second(self) -> Option<u8> {
        match self.clock {
            Clock::At(Time {
                second: Some(second),
                ..
            }) => Some(second.whole),
            Clock::At(Time { second: None, .. }) => None,
            Clock::Leap { .. } => Some(60),
        }
    }

    /// The seconds' fraction as written; [`Fraction::NONE`] without seconds.
    #[must_use]
    pub const fn fraction(self) -> Fraction {
        match self.clock {
            Clock::At(Time {
                second: Some(second),
                ..
            }) => second.fraction,
            Clock::At(Time { second: None, .. }) => Fraction::NONE,
            Clock::Leap { fraction, .. } => fraction,
        }
    }

    /// The offset, when written; a leap second always has one.
    #[must_use]
    pub const fn offset(self) -> Option<Offset> {
        self.offset
    }

    /// The date and time `text` writes.
    ///
    /// # Errors
    ///
    /// [`Malformed`] for a text other than a [`Date`]'s literal, `T`, `hh:mm[:ss[.f…]]` and an
    /// optional [`Offset`]'s; at the seconds for a leap second without an offset or where RFC 3339
    /// places none.
    pub fn parse(text: &str) -> Result<Self, Malformed> {
        parse(text, "DateTime", |reader| {
            let date = Date::read(reader)?;
            reader.expect(b'T')?;
            let Written {
                hour,
                minute,
                second,
            } = Written::read(reader)?;
            let offset = Offset::optional(reader)?;
            let at = match second {
                Some(Seconds {
                    whole: 60,
                    at,
                    fraction,
                }) => {
                    return offset
                        .and_then(|offset| Self::leap(date, hour, minute, fraction, offset))
                        .ok_or_else(|| reader.refuse(at));
                }
                Some(Seconds {
                    whole,
                    at,
                    fraction,
                }) => Time {
                    hour,
                    minute,
                    second: Some(Second::new(whole, fraction).ok_or_else(|| reader.refuse(at))?),
                },
                None => Time {
                    hour,
                    minute,
                    second: None,
                },
            };
            Ok(Self::new(date, at, offset))
        })
    }
}

/// Its literal: `2026-09-02T12:30:15.5+02:00`, `1990-12-31T23:59:60Z`.
impl fmt::Display for DateTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}T", self.date)?;
        match self.clock {
            Clock::At(at) => write!(f, "{at}")?,
            Clock::Leap {
                hour,
                minute,
                fraction,
            } => {
                write!(f, "{hour:02}:{minute:02}:60")?;
                fraction.write(f)?;
            }
        }
        match self.offset {
            Some(offset) => write!(f, "{offset}"),
            None => Ok(()),
        }
    }
}
