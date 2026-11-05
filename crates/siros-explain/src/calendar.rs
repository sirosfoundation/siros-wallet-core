//! The calendar types: dates, times of day, offsets, and dates with times, where RFC 3339 places
//! a leap second.

/// A calendar date of the proleptic Gregorian calendar (ISO 8601).
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
    /// The date; `None` when it is no calendar date.
    #[must_use]
    pub const fn new(year: u16, month: u8, day: u8) -> Option<Self> {
        match Month::of(month) {
            Some(month) if day >= 1 && day <= month.days(year) => Some(Self { year, month, day }),
            _ => None,
        }
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

    /// The day after; `None` after year 65535.
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
            None => match self.year.checked_add(1) {
                Some(year) => Some(Self {
                    year,
                    month: Month::January,
                    day: 1,
                }),
                None => None,
            },
        }
    }
}

/// A time of day (ISO 8601): 00:00 to 23:59, with its seconds, 00 to 59, when written. A leap
/// second needs the date and the offset that place it: [`DateTime::leap`] makes one.
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
}

/// A time of day with its UTC offset when written (RFC 3339 §5.6 `full-time`, the offset
/// optional): what an argument of [`kind::Time`](crate::kind::Time) gives.
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
}

/// A UTC offset in minutes, `Z` being 0.
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
}

/// A date and a time of day (ISO 8601), with its UTC offset when written (RFC 3339 §5.6
/// `date-time`). Its seconds reach 60 only at a leap second, which RFC 3339 §5.7 and Appendix D
/// place at 23:59:60 UTC on a month's last day, shifted by the offset to its local time. Only
/// [`DateTime::new`] and [`DateTime::leap`] make one.
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
}
