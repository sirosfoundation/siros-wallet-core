//! ISO 8601 times and dates and times in the extended format (PaSO View, Section 3:
//! `iso_time`, `iso_date_time`).

use std::fmt;

use siros_codec::date::Date;

/// An ISO 8601 time in the extended format: `hh:mm`, then optionally `:ss` and a decimal
/// fraction, then optionally `Z` or a UTC offset `±hh:mm`. A second of 60 is a leap second.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IsoTime(String);

/// An ISO 8601 date and time in the extended format: a calendar date `YYYY-MM-DD`, `T`, and an
/// [`IsoTime`]. `t` and `z` may be lowercase, as RFC 3339, Section 5.6 allows.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IsoDateTime(String);

impl IsoTime {
    /// The time `text`; `None` for text of another form.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        time(text).then(|| Self(text.to_owned()))
    }

    /// The time, as the payload writes it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl IsoDateTime {
    /// The date and time `text`; `None` for text of another form.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let (date, rest) = text.split_once(['T', 't'])?;
        (Date::parse(date).is_some() && time(rest)).then(|| Self(text.to_owned()))
    }

    /// The date and time, as the payload writes them.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for IsoTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Display for IsoDateTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Whether `text` is `hh:mm[:ss[.f]][Z|±hh:mm]`.
fn time(text: &str) -> bool {
    let Some(rest) = two(text, 23).and_then(|rest| rest.strip_prefix(':')) else {
        return false;
    };
    let Some(mut rest) = two(rest, 59) else {
        return false;
    };
    if let Some(seconds) = rest.strip_prefix(':') {
        let Some(after) = two(seconds, 60) else {
            return false;
        };
        rest = match after.strip_prefix('.') {
            Some(fraction) => {
                let digits = fraction.bytes().take_while(u8::is_ascii_digit).count();
                if digits == 0 {
                    return false;
                }
                fraction.get(digits..).unwrap_or_default()
            }
            None => after,
        };
    }
    offset(rest)
}

/// Whether `text` is empty, `Z`, or a sign and `hh:mm`.
fn offset(text: &str) -> bool {
    match text.strip_prefix(['+', '-']) {
        Some(rest) => {
            two(rest, 23)
                .and_then(|rest| rest.strip_prefix(':'))
                .and_then(|rest| two(rest, 59))
                == Some("")
        }
        None => text.is_empty() || text.eq_ignore_ascii_case("z"),
    }
}

/// What follows two digits of a value up to `max` at the start of `text`.
fn two(text: &str, max: u8) -> Option<&str> {
    let (digits, rest) = text.split_at_checked(2)?;
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let value: u8 = digits.parse().ok()?;
    (value <= max).then_some(rest)
}
