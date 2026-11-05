//! PaSO View §3's value types, and a written value of a kind other than an image parsed into its
//! typed form and the [`Text`] the core renders when it is displayed: dates, times, amounts and
//! currencies as typed values, booleans and frequencies as the core module's messages, every
//! other kind as written.

use std::fmt;

use siros_explain::{
    Amount, Currency, Date, DateTime, Decimal, Explain, Fraction, Offset, Second, Text, Time,
};
use siros_openid4vp::json::Node;
use siros_openid4vp::refusal::Quoted;
use siros_openid4vp::rows::{Frequency, HttpsUrl, WalletText};

use crate::markdown::spans;

/// A value kind (PaSO View §3 value types).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValueKind {
    /// An image.
    Image,
    /// A kind other than an image.
    Formatted(FormattedKind),
}

impl ValueKind {
    /// The kind's name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Image => "image",
            Self::Formatted(kind) => kind.as_str(),
        }
    }
}

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
    /// A time of day, with its offset when written.
    Time(Time, Option<Offset>),
    /// A date and a time.
    DateTime(DateTime),
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
            Self::Time(..) => FormattedKind::Time,
            Self::DateTime(_) => FormattedKind::DateTime,
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
#[explain(domain = "paso")]
#[error("{kind} value {written}: {why}")]
pub struct BadValue {
    /// The kind.
    pub kind: &'static str,
    /// The value as written, quoted.
    pub written: String,
    /// What it lacks.
    pub why: String,
}

/// A written value of a kind other than an image, parsed, and its text: a typed value for a date,
/// a time, a date and time, a currency and an amount; the crate module's message for a boolean
/// and a frequency; the text as written for text and a URL, its host in A-label form; the text of
/// `mini_markdown` without its styles, as a text from outside any module holds none.
///
/// # Errors
///
/// [`BadValue`]: the written value does not conform to the kind.
pub fn formatted(kind: FormattedKind, written: Written<'_>) -> Result<(Parsed, Text), BadValue> {
    let bad = |why: &str| BadValue {
        kind: kind.as_str(),
        written: written.to_string(),
        why: why.to_owned(),
    };
    let text = match written {
        Written::Text(text) => text,
        Written::Boolean(value) if kind == FormattedKind::Boolean => {
            let answer = if value {
                WalletText::Yes
            } else {
                WalletText::No
            };
            return Ok((Parsed::Boolean(value), Text::of(&answer)));
        }
        _ if kind == FormattedKind::Boolean => return Err(bad("not a JSON boolean")),
        _ => return Err(bad("not a string")),
    };
    let typed = |parsed: Parsed, value: siros_explain::Value| (parsed, Text::Value(value));
    Ok(match kind {
        FormattedKind::Boolean => return Err(bad("not a JSON boolean")),
        FormattedKind::Text => (Parsed::Text, Text::Raw(text.to_owned())),
        FormattedKind::MiniMarkdown => {
            let plain: String = spans(text).into_iter().map(|span| span.text).collect();
            (Parsed::MiniMarkdown, Text::Raw(plain))
        }
        FormattedKind::Frequency => {
            let frequency = Frequency::parse(text).ok_or_else(|| bad("not a frequency code"))?;
            (Parsed::Frequency(frequency), Text::of(&frequency))
        }
        FormattedKind::Date => {
            let date = date(text).ok_or_else(|| bad("not an ISO 8601 calendar date"))?;
            typed(Parsed::Date(date), siros_explain::Value::Date(date))
        }
        FormattedKind::Time => {
            let (at, offset) = time(text).ok_or_else(|| bad("not an ISO 8601 time"))?;
            typed(
                Parsed::Time(at, offset),
                siros_explain::Value::Time { at, offset },
            )
        }
        FormattedKind::DateTime => {
            let at = date_time(text).ok_or_else(|| bad("not an ISO 8601 date-time"))?;
            typed(Parsed::DateTime(at), siros_explain::Value::DateTime(at))
        }
        FormattedKind::Currency => {
            let currency = Currency::from_code(text)
                .filter(|currency| currency.minor_units().is_some())
                .ok_or_else(|| bad("not an ISO 4217 code of the table"))?;
            typed(
                Parsed::Currency(currency),
                siros_explain::Value::Currency(currency),
            )
        }
        FormattedKind::CurrencyAmount => {
            let amount = amount(text).map_err(|why| bad(&why))?;
            typed(
                Parsed::CurrencyAmount(amount),
                siros_explain::Value::Amount(amount),
            )
        }
        FormattedKind::Url => {
            let url = HttpsUrl::parse(text).map_err(|_| bad("not an https URL"))?;
            let shown = Text::Raw(url.ascii().to_owned());
            (Parsed::Url(url), shown)
        }
    })
}

/// Two ASCII digits up to `max`.
fn two(part: &str, max: u8) -> Option<u8> {
    (part.len() == 2 && part.bytes().all(|b| b.is_ascii_digit()))
        .then(|| part.parse().ok())
        .flatten()
        .filter(|value| *value <= max)
}

/// An extended (`2026-09-02`) or basic (`20260902`) ISO 8601 calendar date from year 1 to 9999.
fn date(text: &str) -> Option<Date> {
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
    let year: u16 = year.parse().ok().filter(|year| (1..=9999).contains(year))?;
    Date::new(year, month.parse().ok()?, day.parse().ok()?)
}

/// An ISO 8601 time `hh:mm[:ss[.f]]` with an optional `Z` or `±hh:mm`, as written: its hour,
/// minute, seconds up to 60 with their fraction, and offset.
struct Clock {
    hour: u8,
    minute: u8,
    second: Option<(u8, Fraction)>,
    offset: Option<Offset>,
}

fn clock(text: &str) -> Option<Clock> {
    let (at, offset) = match text.find(['Z', '+', '-']) {
        Some(split) => (text.get(..split)?, text.get(split..)),
        None => (text, None),
    };
    let offset = match offset {
        None => None,
        Some("Z") => Some(Offset::new(0)?),
        Some(written) => {
            let (hh, mm) = written.get(1..)?.split_once(':')?;
            let minutes = i16::from(two(hh, 23)?) * 60 + i16::from(two(mm, 59)?);
            Some(Offset::new(if written.starts_with('+') {
                minutes
            } else {
                -minutes
            })?)
        }
    };
    let mut parts = at.splitn(3, ':');
    let hour = two(parts.next()?, 23)?;
    let minute = two(parts.next()?, 59)?;
    let second = match parts.next() {
        None => None,
        Some(rest) => {
            let (whole, fraction) = rest.split_at_checked(2)?;
            let fraction = match fraction.strip_prefix('.') {
                None if fraction.is_empty() => Fraction::NONE,
                Some(digits)
                    if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) =>
                {
                    let count = u8::try_from(digits.len())
                        .ok()
                        .filter(|count| *count <= 9)?;
                    let padded = format!("{digits:0<9}");
                    Fraction::new(padded.parse().ok()?, count)?
                }
                _ => return None,
            };
            Some((two(whole, 60)?, fraction))
        }
    };
    Some(Clock {
        hour,
        minute,
        second,
        offset,
    })
}

/// A time of day: its seconds 00 to 59, a leap second having no date to place it.
fn time(text: &str) -> Option<(Time, Option<Offset>)> {
    let Clock {
        hour,
        minute,
        second,
        offset,
    } = clock(text)?;
    let second = match second {
        None => None,
        Some((whole, fraction)) => Some(Second::new(whole, fraction)?),
    };
    Some((Time::new(hour, minute, second)?, offset))
}

/// An ISO 8601 date-time `date T time`: second 60 where RFC 3339 places a leap second.
fn date_time(text: &str) -> Option<DateTime> {
    let (day, at) = text.split_once('T')?;
    let day = date(day)?;
    let Clock {
        hour,
        minute,
        second,
        offset,
    } = clock(at)?;
    match second {
        Some((60, fraction)) => DateTime::leap(day, hour, minute, fraction, offset?),
        Some((whole, fraction)) => Some(DateTime::new(
            day,
            Time::new(hour, minute, Some(Second::new(whole, fraction)?))?,
            offset,
        )),
        None => Some(DateTime::new(day, Time::new(hour, minute, None)?, offset)),
    }
}

/// An amount `number CODE`: no sign, no leading zero, exactly the currency's minor units.
fn amount(text: &str) -> Result<Amount, String> {
    let not_amount = || "not 'number CODE'".to_owned();
    let (number, code) = text.split_once(' ').ok_or_else(not_amount)?;
    let currency = Currency::from_code(code).ok_or_else(not_amount)?;
    let digits = currency.minor_units().ok_or_else(not_amount)?;
    let wrong = || format!("the number needs {digits} fractional digits (ISO 4217)");
    let (whole, fraction) = match number.split_once('.') {
        Some((whole, fraction)) if digits > 0 && fraction.len() == usize::from(digits) => {
            (whole, fraction)
        }
        None if digits == 0 => (number, ""),
        _ => return Err(wrong()),
    };
    let whole_ok = whole == "0"
        || (whole.starts_with(|c: char| ('1'..='9').contains(&c))
            && whole.bytes().all(|b| b.is_ascii_digit()));
    if !whole_ok || !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return Err(wrong());
    }
    let units: i128 = format!("{whole}{fraction}")
        .parse()
        .map_err(|_| "the number exceeds 38 digits".to_owned())?;
    let value = Decimal::new(units, digits).ok_or_else(wrong)?;
    Ok(Amount::new(value, currency))
}
