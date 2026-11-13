//! PaSO View §3's value types, and a written value of a kind other than an image parsed into the
//! value it shows ([`Parsed`]): a date, a time, a date and time, a currency and an amount as
//! siros-syntax's values, a boolean and a frequency as what they state, every other kind as its
//! text. Shown alone, a value resolves through the statement that carries its literal
//! ([`Parsed::shown`]).

use std::borrow::Cow;
use std::fmt;

use siros_explain::Explain;
use siros_i18n::Message;
use siros_openid4vp::json::Node;
use siros_openid4vp::refusal::ReprItem;
use siros_openid4vp::rows::{BooleanText, ClaimText, HttpsUrl};
use siros_syntax::{
    Amount, Currency, Date, DateTime, Decimal, Fraction, Offset, OffsetTime, Second, Time,
};

use crate::frequency::Frequency;

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

impl fmt::Display for FormattedKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
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

impl Written<'_> {
    /// The value as a refusal names it.
    pub(crate) fn named(self) -> ReprItem {
        match self {
            Self::Boolean(value) => ReprItem::repr(&Node::Bool(value)),
            Self::Text(text) => ReprItem::repr(&Node::String(Cow::Borrowed(text))),
            Self::Other(node) => ReprItem::repr(node),
        }
    }
}

/// A written value that does not conform to its kind.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[error("{kind} value {}: {why}", .written.repr_text())]
#[explain(id = "bad_value")]
pub struct BadValue {
    /// The kind.
    pub kind: FormattedKind,
    /// The value.
    pub written: ReprItem,
    /// The rule it breaks.
    #[source]
    pub why: Breach,
}

/// The rule of its kind a written value breaks (View §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, Explain)]
pub enum Breach {
    /// A boolean that is no JSON boolean.
    #[error("not a JSON boolean")]
    #[explain(id = "value.not_boolean")]
    NotBoolean,
    /// A value of a text kind that is no JSON string.
    #[error("not a string")]
    #[explain(id = "value.not_string")]
    NotString,
    /// A frequency outside ISO 20022's codes.
    #[error("not a frequency code")]
    #[explain(id = "value.not_frequency")]
    NotFrequency,
    /// A date outside ISO 8601's calendar dates.
    #[error("not an ISO 8601 calendar date")]
    #[explain(id = "value.not_date")]
    NotDate,
    /// A time outside ISO 8601's times.
    #[error("not an ISO 8601 time")]
    #[explain(id = "value.not_time")]
    NotTime,
    /// A date-time outside ISO 8601's.
    #[error("not an ISO 8601 date-time")]
    #[explain(id = "value.not_date_time")]
    NotDateTime,
    /// A currency outside ISO 4217's table.
    #[error("not an ISO 4217 code of the table")]
    #[explain(id = "value.not_currency")]
    NotCurrency,
    /// An amount that is no number, a space and a code of ISO 4217's table.
    #[error("not 'number CODE'")]
    #[explain(id = "value.not_amount")]
    NotAmount,
    /// An amount whose number is not ISO 4217's form for its currency: digits without a sign or
    /// a leading zero, then exactly its minor units as fractional digits.
    #[error("the number needs {digits} fractional digits (ISO 4217)")]
    #[explain(id = "value.number_form")]
    NumberForm {
        /// The currency's minor units.
        digits: u8,
    },
    /// An amount whose number exceeds an exact decimal's 38 digits.
    #[error("the number exceeds 38 digits")]
    #[explain(id = "value.too_long")]
    TooLong,
    /// A URL that is no https URL.
    #[error("not an https URL")]
    #[explain(id = "value.not_url")]
    NotUrl,
    /// A template value holding every character of the Supplementary Private Use Area-A, one of
    /// which marks a typed value while it is read.
    #[error("holds every character of the Supplementary Private Use Area-A")]
    #[explain(id = "value.no_slot")]
    NoSlot,
}

/// A written value of a kind other than an image, parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed {
    /// A text as shown: a text as written, a `mini_markdown` text without its styles, a URL's
    /// [`HttpsUrl::ascii`].
    Text(String),
    /// A boolean.
    Boolean(bool),
    /// A frequency.
    Frequency(Frequency),
    /// A calendar date.
    Date(Date),
    /// A time of day, with its offset when written.
    Time(OffsetTime),
    /// A date and time.
    DateTime(DateTime),
    /// A currency.
    Currency(Currency),
    /// An amount: its number with exactly its currency's minor digits, and its currency.
    Amount(Amount),
}

impl Parsed {
    /// The statement that shows the value alone, carrying its literal: siros-openid4vp's
    /// [`ClaimText`] for a text, a date and a date and time, [`BooleanText`] for a boolean, the
    /// crate's [`Frequency`] and [`ValueText`] for the other kinds.
    #[must_use]
    pub fn shown(self) -> Box<dyn Message> {
        match self {
            Self::Text(value) => Box::new(ClaimText::Text { value }),
            Self::Boolean(true) => Box::new(BooleanText::Yes),
            Self::Boolean(false) => Box::new(BooleanText::No),
            Self::Frequency(frequency) => Box::new(frequency),
            Self::Date(value) => Box::new(ClaimText::Date { value }),
            Self::Time(value) => Box::new(ValueText::Time { value }),
            Self::DateTime(value) => Box::new(ClaimText::DateTime { value }),
            Self::Currency(code) => Box::new(ValueText::Currency { code }),
            Self::Amount(amount) => Box::new(ValueText::Amount {
                value: amount.value(),
                currency: amount.currency(),
            }),
        }
    }
}

/// A value shown alone whose kind siros-openid4vp's statements lack, carrying it typed: the
/// wallet's formatters give each type its default (`{$value}`), and its wording names another
/// function where it chooses one (`{$value :currency currency=$currency}`).
#[derive(Debug, Clone, PartialEq, Eq, Message)]
pub enum ValueText {
    /// A time of day (`12:30:15+02:00`), unzoned without an offset.
    #[message(id = "value.time")]
    Time {
        /// The time.
        value: OffsetTime,
    },
    /// An ISO 4217 currency (`EUR`).
    #[message(id = "value.currency")]
    Currency {
        /// The code.
        code: Currency,
    },
    /// An amount: its number with exactly its currency's minor digits (`42.50`), and the
    /// currency's code.
    #[message(id = "value.amount")]
    Amount {
        /// The number.
        value: Decimal,
        /// The currency.
        currency: Currency,
    },
}

/// A written value of a kind other than an image, parsed.
///
/// # Errors
///
/// [`BadValue`]: the written value does not conform to the kind.
pub fn formatted(kind: FormattedKind, written: Written<'_>) -> Result<Parsed, BadValue> {
    let bad = |why: Breach| BadValue {
        kind,
        written: written.named(),
        why,
    };
    let text = match written {
        Written::Text(text) => text,
        Written::Boolean(value) if kind == FormattedKind::Boolean => {
            return Ok(Parsed::Boolean(value));
        }
        _ if kind == FormattedKind::Boolean => return Err(bad(Breach::NotBoolean)),
        _ => return Err(bad(Breach::NotString)),
    };
    Ok(match kind {
        FormattedKind::Boolean => return Err(bad(Breach::NotBoolean)),
        FormattedKind::Text => Parsed::Text(text.to_owned()),
        FormattedKind::MiniMarkdown => {
            Parsed::Text(spans(text).into_iter().map(|span| span.text).collect())
        }
        FormattedKind::Frequency => {
            Parsed::Frequency(Frequency::parse(text).ok_or_else(|| bad(Breach::NotFrequency))?)
        }
        FormattedKind::Date => Parsed::Date(date(text).ok_or_else(|| bad(Breach::NotDate))?),
        FormattedKind::Time => Parsed::Time(time(text).ok_or_else(|| bad(Breach::NotTime))?),
        FormattedKind::DateTime => {
            Parsed::DateTime(date_time(text).ok_or_else(|| bad(Breach::NotDateTime))?)
        }
        FormattedKind::Currency => Parsed::Currency(
            Currency::parse(text)
                .ok()
                .filter(|currency| currency.minor_units().is_some())
                .ok_or_else(|| bad(Breach::NotCurrency))?,
        ),
        FormattedKind::CurrencyAmount => Parsed::Amount(amount(text).map_err(bad)?),
        FormattedKind::Url => {
            let url = HttpsUrl::parse(text).map_err(|_| bad(Breach::NotUrl))?;
            Parsed::Text(url.ascii().to_owned())
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
fn time(text: &str) -> Option<OffsetTime> {
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
    Some(OffsetTime::new(Time::new(hour, minute, second)?, offset))
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
fn amount(text: &str) -> Result<Amount, Breach> {
    let not_amount = || Breach::NotAmount;
    let (number, code) = text.split_once(' ').ok_or_else(not_amount)?;
    let currency = Currency::parse(code).map_err(|_| not_amount())?;
    let digits = currency.minor_units().ok_or_else(not_amount)?;
    let wrong = || Breach::NumberForm { digits };
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
        .map_err(|_| Breach::TooLong)?;
    let value = Decimal::new(units, digits).ok_or_else(wrong)?;
    Ok(Amount::new(value, currency))
}
