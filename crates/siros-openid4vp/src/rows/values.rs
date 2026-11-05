//! Parsing a written value of a kind other than an image, and formatting it once in the display
//! locale. Amounts and currencies are formatted only where the wallet's table has a format (EUR
//! amounts in English); dates, times, booleans and frequencies are localised, English
//! frequencies in the words of their definition (PaSO View §3).

use std::fmt;

use siros_explain::Explain;

use super::Value;
use siros_i18n::Amounts;

use super::env::{TableLocale, WalletText};
use super::https_url::HttpsUrl;
use crate::json::Node;
use crate::refusal::Quoted;

/// A value kind other than an image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FormattedKind {
    /// Plain text.
    Text,
    /// A JSON boolean.
    Boolean,
    /// An ISO 20022 frequency code.
    Frequency,
    /// An ISO 8601 calendar date.
    Date,
    /// An ISO 8601 time.
    Time,
    /// An ISO 8601 date and time.
    DateTime,
    /// An ISO 4217 currency code.
    Currency,
    /// An amount and its ISO 4217 currency.
    CurrencyAmount,
    /// `mini_markdown` text.
    MiniMarkdown,
    /// An https URL.
    Url,
}

impl FormattedKind {
    /// The kind's name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Boolean => "boolean",
            Self::Frequency => "frequency",
            Self::Date => "date",
            Self::Time => "time",
            Self::DateTime => "date_time",
            Self::Currency => "currency",
            Self::CurrencyAmount => "currency_amount",
            Self::MiniMarkdown => "mini_markdown",
            Self::Url => "url",
        }
    }
}

/// A value's parsed form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed {
    /// Plain text: the text itself.
    Text,
    /// A boolean.
    Boolean(bool),
    /// A frequency.
    Frequency(Frequency),
    /// A date.
    Date(Date),
    /// A time.
    Time(Time),
    /// A date and a time.
    DateTime(Date, Time),
    /// A currency.
    Currency(Currency),
    /// An amount.
    CurrencyAmount(Amount),
    /// `mini_markdown` text: the text itself.
    MiniMarkdown,
    /// An https URL.
    Url(HttpsUrl),
}

impl Parsed {
    /// The kind of the value.
    #[must_use]
    pub const fn kind(&self) -> FormattedKind {
        match self {
            Self::Text => FormattedKind::Text,
            Self::Boolean(_) => FormattedKind::Boolean,
            Self::Frequency(_) => FormattedKind::Frequency,
            Self::Date(_) => FormattedKind::Date,
            Self::Time(_) => FormattedKind::Time,
            Self::DateTime(..) => FormattedKind::DateTime,
            Self::Currency(_) => FormattedKind::Currency,
            Self::CurrencyAmount(_) => FormattedKind::CurrencyAmount,
            Self::MiniMarkdown => FormattedKind::MiniMarkdown,
            Self::Url(_) => FormattedKind::Url,
        }
    }
}

/// A value as written in a payload.
#[derive(Debug, Clone, Copy)]
pub enum Written<'a> {
    /// A JSON boolean.
    Boolean(bool),
    /// A JSON string.
    Text(&'a str),
    /// Any other JSON value.
    Other(&'a Node<'a>),
}

impl fmt::Display for Written<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Boolean(value) => f.write_str(if *value { "True" } else { "False" }),
            Self::Text(text) => write!(f, "{}", Quoted(text)),
            Self::Other(node) => write!(f, "{}", node.python_repr()),
        }
    }
}

/// A written value that does not conform to its kind.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "openid4vp")]
#[error("{kind} value {written}: {why}")]
pub struct BadValue {
    /// The kind.
    pub kind: &'static str,
    /// The value as written, quoted.
    pub written: String,
    /// What it lacks.
    pub why: String,
}

impl Value {
    /// A value of a kind other than an image, parsed and formatted.
    pub fn format(
        kind: FormattedKind,
        written: Written<'_>,
        locale: TableLocale,
        amounts: Amounts,
    ) -> Result<Self, BadValue> {
        let bad = |why: &str| BadValue {
            kind: kind.as_str(),
            written: written.to_string(),
            why: why.to_owned(),
        };
        let text = match written {
            Written::Text(text) => text,
            Written::Boolean(value) if kind == FormattedKind::Boolean => {
                let key = if value {
                    WalletText::Yes
                } else {
                    WalletText::No
                };
                return Ok(Value::Formatted {
                    parsed: Parsed::Boolean(value),
                    text: key.in_locale(locale).to_owned(),
                });
            }
            _ if kind == FormattedKind::Boolean => return Err(bad("not a JSON boolean")),
            _ => return Err(bad("not a string")),
        };
        let (parsed, shown) = match kind {
            FormattedKind::Boolean => return Err(bad("not a JSON boolean")),
            FormattedKind::Text => (Parsed::Text, text.to_owned()),
            FormattedKind::MiniMarkdown => (Parsed::MiniMarkdown, text.to_owned()),
            FormattedKind::Frequency => {
                let frequency =
                    Frequency::parse(text).ok_or_else(|| bad("not a frequency code"))?;
                (
                    Parsed::Frequency(frequency),
                    frequency.words(locale).to_owned(),
                )
            }
            FormattedKind::Date => {
                let date = Date::parse(text).ok_or_else(|| bad("not an ISO 8601 calendar date"))?;
                (Parsed::Date(date), date.text(locale))
            }
            FormattedKind::Time => {
                let time = Time::parse(text).ok_or_else(|| bad("not an ISO 8601 time"))?;
                let shown = time.to_string();
                (Parsed::Time(time), shown)
            }
            FormattedKind::DateTime => {
                let (date, time) = text
                    .split_once('T')
                    .and_then(|(date, time)| Some((Date::parse(date)?, Time::parse(time)?)))
                    .ok_or_else(|| bad("not an ISO 8601 date-time"))?;
                let shown = format!("{}, {time}", date.text(locale));
                (Parsed::DateTime(date, time), shown)
            }
            FormattedKind::Currency => {
                let currency = Currency::parse(text)
                    .ok_or_else(|| bad("not an ISO 4217 code of the table"))?;
                (Parsed::Currency(currency), text.to_owned())
            }
            FormattedKind::CurrencyAmount => {
                let amount = Amount::parse(text).map_err(|why| bad(&why))?;
                let shown = amount.text(text, locale, amounts);
                (Parsed::CurrencyAmount(amount), shown)
            }
            FormattedKind::Url => {
                let url = HttpsUrl::parse(text).map_err(|_| bad("not an https URL"))?;
                return Ok(Self::url(url));
            }
        };
        Ok(Value::Formatted {
            parsed,
            text: shown,
        })
    }

    /// An https URL, shown with its host in A-label form.
    #[must_use]
    pub fn url(url: HttpsUrl) -> Self {
        let text = url.ascii().to_owned();
        Value::Formatted {
            parsed: Parsed::Url(url),
            text,
        }
    }
}

/// An ISO 20022 frequency code (PaSO View §3 `frequency`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Frequency(usize);

const FREQUENCIES: [(&str, &str, &str); 12] = [
    ("INDA", "intraday", "untertägig"),
    ("DAIL", "daily", "täglich"),
    ("WEEK", "weekly", "wöchentlich"),
    ("TOWK", "every two weeks", "alle zwei Wochen"),
    ("TWMN", "twice a month", "zweimal im Monat"),
    ("MNTH", "monthly", "monatlich"),
    ("TOMN", "every two months", "alle zwei Monate"),
    ("QUTR", "quarterly", "vierteljährlich"),
    ("FOMN", "every four months", "alle vier Monate"),
    ("SEMI", "twice a year", "halbjährlich"),
    ("YEAR", "yearly", "jährlich"),
    ("TYEA", "every two years", "alle zwei Jahre"),
];

impl Frequency {
    fn parse(code: &str) -> Option<Self> {
        FREQUENCIES
            .iter()
            .position(|(known, ..)| *known == code)
            .map(Self)
    }

    /// The code.
    #[must_use]
    pub fn code(self) -> &'static str {
        FREQUENCIES.get(self.0).map_or("", |(code, ..)| code)
    }

    fn words(self, locale: TableLocale) -> &'static str {
        FREQUENCIES.get(self.0).map_or(
            "",
            |(_, en, de)| if locale == TableLocale::En { en } else { de },
        )
    }
}

/// A proleptic Gregorian calendar date from year 1 to 9999.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Date {
    /// The year.
    pub year: u16,
    /// The month, from 1.
    pub month: u8,
    /// The day of the month, from 1.
    pub day: u8,
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

impl Date {
    /// An extended (`2026-09-02`) or basic (`20260902`) ISO 8601 calendar date.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let parts: [&str; 3] = match text.len() {
            10 if text.get(4..5) == Some("-") && text.get(7..8) == Some("-") => {
                [text.get(..4)?, text.get(5..7)?, text.get(8..)?]
            }
            8 => [text.get(..4)?, text.get(4..6)?, text.get(6..)?],
            _ => return None,
        };
        if !parts
            .iter()
            .all(|part| part.bytes().all(|b| b.is_ascii_digit()))
        {
            return None;
        }
        let [year, month, day] = parts;
        let (year, month, day) = (year.parse().ok()?, month.parse().ok()?, day.parse().ok()?);
        let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
        let length = match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 if leap => 29,
            2 => 28,
            _ => return None,
        };
        ((1..=9999).contains(&year) && (1..=length).contains(&day)).then_some(Self {
            year,
            month,
            day,
        })
    }

    fn text(self, locale: TableLocale) -> String {
        match locale {
            TableLocale::En => {
                let month = MONTHS.get(usize::from(self.month) - 1).unwrap_or(&"");
                format!("{} {month} {}", self.day, self.year)
            }
            TableLocale::De => format!("{:02}.{:02}.{}", self.day, self.month, self.year),
        }
    }
}

/// An ISO 8601 time `hh:mm[:ss[.f]]` with an optional `Z` or `±hh:mm`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Time {
    /// The hour, from 0 to 23.
    pub hour: u8,
    /// The minute, from 0 to 59.
    pub minute: u8,
    /// The second, from 0 to 60, with its decimal fraction as written.
    pub second: Option<(u8, String)>,
    /// The offset from UTC.
    pub offset: Option<Offset>,
}

/// A time's offset from UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Offset {
    /// `Z`.
    Utc,
    /// `+hh:mm`.
    East {
        /// The hours, from 0 to 23.
        hours: u8,
        /// The minutes, from 0 to 59.
        minutes: u8,
    },
    /// `-hh:mm`.
    West {
        /// The hours, from 0 to 23.
        hours: u8,
        /// The minutes, from 0 to 59.
        minutes: u8,
    },
}

impl Time {
    fn parse(text: &str) -> Option<Self> {
        let two = |part: &str, max: u8| -> Option<u8> {
            (part.len() == 2 && part.bytes().all(|b| b.is_ascii_digit()))
                .then(|| part.parse().ok())
                .flatten()
                .filter(|value| *value <= max)
        };
        let (clock, offset) = match text.find(['Z', '+', '-']) {
            Some(at) => (text.get(..at)?, text.get(at..)),
            None => (text, None),
        };
        let offset = match offset {
            None => None,
            Some("Z") => Some(Offset::Utc),
            Some(written) => {
                let (hh, mm) = written.get(1..)?.split_once(':')?;
                let (hours, minutes) = (two(hh, 23)?, two(mm, 59)?);
                Some(if written.starts_with('+') {
                    Offset::East { hours, minutes }
                } else {
                    Offset::West { hours, minutes }
                })
            }
        };
        let mut parts = clock.splitn(3, ':');
        let hour = two(parts.next()?, 23)?;
        let minute = two(parts.next()?, 59)?;
        let second = match parts.next() {
            None => None,
            Some(rest) => {
                let (second, fraction) = rest.split_at_checked(2)?;
                let fraction_ok = fraction.is_empty()
                    || (fraction.starts_with('.')
                        && fraction.len() > 1
                        && fraction.bytes().skip(1).all(|b| b.is_ascii_digit()));
                fraction_ok.then_some(())?;
                Some((two(second, 60)?, fraction.to_owned()))
            }
        };
        Some(Self {
            hour,
            minute,
            second,
            offset,
        })
    }
}

impl fmt::Display for Time {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02}:{:02}", self.hour, self.minute)?;
        if let Some((second, fraction)) = &self.second {
            write!(f, ":{second:02}{fraction}")?;
        }
        match self.offset {
            None => Ok(()),
            Some(Offset::Utc) => f.write_str(" UTC"),
            Some(Offset::East { hours, minutes }) => write!(f, " UTC+{hours:02}:{minutes:02}"),
            Some(Offset::West { hours, minutes }) => write!(f, " UTC-{hours:02}:{minutes:02}"),
        }
    }
}

/// An ISO 4217 currency of the wallet's table, with its minor units.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Currency {
    /// The code.
    pub code: &'static str,
    /// Its minor units.
    pub minor_units: u8,
}

/// The ISO 4217 minor units of the currencies the wallet accepts.
const MINOR_UNITS: [(&str, u8); 15] = [
    ("EUR", 2),
    ("USD", 2),
    ("GBP", 2),
    ("CHF", 2),
    ("SEK", 2),
    ("NOK", 2),
    ("DKK", 2),
    ("PLN", 2),
    ("CZK", 2),
    ("JPY", 0),
    ("KRW", 0),
    ("BHD", 3),
    ("KWD", 3),
    ("JOD", 3),
    ("TND", 3),
];

impl Currency {
    /// The currency of a code the wallet's table holds.
    #[must_use]
    pub fn parse(code: &str) -> Option<Self> {
        MINOR_UNITS
            .iter()
            .find(|(known, _)| *known == code)
            .map(|&(code, minor_units)| Self { code, minor_units })
    }
}

/// An amount `number CODE`: no sign, no leading zero, exactly the currency's minor units.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Amount {
    /// The whole units, as written.
    pub whole: String,
    /// The minor units, as written.
    pub fraction: String,
    /// The currency.
    pub currency: Currency,
}

impl Amount {
    fn parse(text: &str) -> Result<Self, String> {
        let not_amount = || "not 'number CODE'".to_owned();
        let (number, code) = text.split_once(' ').ok_or_else(not_amount)?;
        let currency = Currency::parse(code).ok_or_else(not_amount)?;
        let digits = usize::from(currency.minor_units);
        let wrong = || format!("the number needs {digits} fractional digits (ISO 4217)");
        let (whole, fraction) = match number.split_once('.') {
            Some((whole, fraction)) if digits > 0 && fraction.len() == digits => (whole, fraction),
            None if digits == 0 => (number, ""),
            _ => return Err(wrong()),
        };
        let whole_ok = whole == "0"
            || (whole.starts_with(|c: char| ('1'..='9').contains(&c))
                && whole.bytes().all(|b| b.is_ascii_digit()));
        if !whole_ok || !fraction.bytes().all(|b| b.is_ascii_digit()) {
            return Err(wrong());
        }
        Ok(Self {
            whole: whole.to_owned(),
            fraction: fraction.to_owned(),
            currency,
        })
    }

    fn text(&self, written: &str, locale: TableLocale, amounts: Amounts) -> String {
        if amounts == Amounts::Written || self.currency.code != "EUR" || locale != TableLocale::En {
            return written.to_owned();
        }
        let digits = self.whole.as_bytes();
        let mut grouped = String::new();
        for (k, digit) in digits.iter().enumerate() {
            if k > 0 && (digits.len() - k).is_multiple_of(3) {
                grouped.push(',');
            }
            grouped.push(char::from(*digit));
        }
        format!("€{grouped}.{}", self.fraction)
    }
}
