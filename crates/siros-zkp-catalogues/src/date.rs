//! Calendar dates and UTC times in the proleptic Gregorian calendar.

use std::cmp::Ordering;
use std::fmt;

/// A calendar date. The year may lie outside `0000..=9999`: date arithmetic needs such years
/// before a system rules them out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Date {
    year: i64,
    month: u8,
    day: u8,
}

impl Date {
    /// 0000-01-01, the first date of the form `YYYY-MM-DD`.
    pub const FIRST: Self = Self {
        year: 0,
        month: 1,
        day: 1,
    };
    /// 9999-12-31, the last date of the form `YYYY-MM-DD`.
    pub const LAST: Self = Self {
        year: 9999,
        month: 12,
        day: 31,
    };

    /// The date, when `day` exists in `month` of `year`.
    pub fn new(year: i64, month: u8, day: u8) -> Option<Self> {
        let valid = (1..=12).contains(&month) && day >= 1 && day <= days_in_month(year, month);
        valid.then_some(Self { year, month, day })
    }

    /// The year.
    pub fn year(self) -> i64 {
        self.year
    }

    /// The month, 1 to 12.
    pub fn month(self) -> u8 {
        self.month
    }

    /// The day of the month.
    pub fn day(self) -> u8 {
        self.day
    }

    /// An RFC 3339 `full-date`: `YYYY-MM-DD`, a year from 0000 to 9999.
    pub fn parse(text: &str) -> Option<Self> {
        let b = text.as_bytes();
        if b.len() != 10 || b.get(4) != Some(&b'-') || b.get(7) != Some(&b'-') {
            return None;
        }
        let year = digits(b.get(0..4)?)?;
        let month = u8::try_from(digits(b.get(5..7)?)?).ok()?;
        let day = u8::try_from(digits(b.get(8..10)?)?).ok()?;
        Self::new(i64::from(year), month, day)
    }

    /// `YYYY-MM-DD`, when the year lies in `0000..=9999`.
    pub fn to_full_date(self) -> Option<String> {
        (0..=9999)
            .contains(&self.year)
            .then(|| format!("{:04}-{:02}-{:02}", self.year, self.month, self.day))
    }

    /// The next day.
    pub fn next(self) -> Self {
        if self.day < days_in_month(self.year, self.month) {
            Self {
                day: self.day + 1,
                ..self
            }
        } else if self.month < 12 {
            Self {
                month: self.month + 1,
                day: 1,
                ..self
            }
        } else {
            Self {
                year: self.year + 1,
                month: 1,
                day: 1,
            }
        }
    }

    /// Days since 1970-01-01 (Howard Hinnant's `days_from_civil`).
    pub fn days(self) -> i64 {
        let m = i64::from(self.month);
        let y = if m <= 2 { self.year - 1 } else { self.year };
        let era = y.div_euclid(400);
        let yoe = y.rem_euclid(400);
        let doy = (153 * ((m + 9) % 12) + 2) / 5 + i64::from(self.day) - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        era * 146_097 + doe - 719_468
    }

    /// The date `days` after 1970-01-01 (Howard Hinnant's `civil_from_days`).
    pub fn from_days(days: i64) -> Self {
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        // Both values are in range by construction: day 1 to 31, month 1 to 12.
        let day = (doy - (153 * mp + 2) / 5 + 1) as u8;
        let month = if mp < 10 { mp + 3 } else { mp - 9 } as u8;
        let year = yoe + era * 400 + i64::from(month <= 2);
        Self { year, month, day }
    }
}

impl Ord for Date {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.year, self.month, self.day).cmp(&(other.year, other.month, other.day))
    }
}

impl PartialOrd for Date {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Date {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

/// Whether `year` is a leap year.
pub fn is_leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_in_month(year: i64, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        _ => 28,
    }
}

fn digits(b: &[u8]) -> Option<u32> {
    b.iter().try_fold(0u32, |acc, c| {
        c.is_ascii_digit().then(|| acc * 10 + u32::from(c - b'0'))
    })
}

/// A UTC time to the second, from 0000-01-01T00:00:00Z to 9999-12-31T23:59:59Z: the range of
/// the 20-character form `YYYY-MM-DDThh:mm:ssZ`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DateTime {
    unix: i64,
}

impl DateTime {
    /// The first second of 0000-01-01.
    pub const MIN_UNIX: i64 = -62_167_219_200;
    /// The last second of 9999-12-31.
    pub const MAX_UNIX: i64 = 253_402_300_799;

    /// The time `unix` seconds after 1970-01-01T00:00:00Z, within the range of the form.
    pub fn from_unix(unix: i64) -> Option<Self> {
        (Self::MIN_UNIX..=Self::MAX_UNIX)
            .contains(&unix)
            .then_some(Self { unix })
    }

    /// Seconds since 1970-01-01T00:00:00Z.
    pub fn unix(self) -> i64 {
        self.unix
    }

    /// The UTC date.
    pub fn date(self) -> Date {
        Date::from_days(self.unix.div_euclid(86_400))
    }

    /// Exactly `YYYY-MM-DDThh:mm:ssZ`, a real UTC second.
    pub fn parse(text: &str) -> Option<Self> {
        let b = text.as_bytes();
        let form = b.len() == 20
            && b.get(10) == Some(&b'T')
            && b.get(13) == Some(&b':')
            && b.get(16) == Some(&b':')
            && b.get(19) == Some(&b'Z');
        if !form {
            return None;
        }
        let date = Date::parse(text.get(0..10)?)?;
        let hour = i64::from(digits(b.get(11..13)?)?);
        let minute = i64::from(digits(b.get(14..16)?)?);
        let second = i64::from(digits(b.get(17..19)?)?);
        if hour > 23 || minute > 59 || second > 59 {
            return None;
        }
        Self::from_unix(date.days() * 86_400 + hour * 3600 + minute * 60 + second)
    }
}

impl fmt::Display for DateTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.unix.rem_euclid(86_400);
        write!(
            f,
            "{}T{:02}:{:02}:{:02}Z",
            self.date(),
            s / 3600,
            s % 3600 / 60,
            s % 60
        )
    }
}
