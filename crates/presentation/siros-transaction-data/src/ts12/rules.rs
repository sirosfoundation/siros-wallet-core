//! The value rules EC TS12 v1.0.1 states in prose (Sections 4.3.1 to 4.3.4), which its schemas
//! leave out.
//!
//! An `[ISO8601]` date or date and time is read in the profile JSON Schema names: RFC 3339
//! `full-date`, `YYYY-MM-DD`, and RFC 3339 `date-time`, with seconds and a UTC offset.

use siros_codec::base64;
use siros_codec::date::Date;
use siros_codec::json::{Json, JsonNumber};

use crate::currency::{CurrencyCode, Fraction};
use crate::ts12::read::{self as json, MemberPath, Ts12PayloadFault};

/// A string of `MIN` to `MAX` characters (JSON Schema `minLength`, `maxLength`).
pub(crate) struct Text<const MIN: usize, const MAX: usize>(String);

impl<const MIN: usize, const MAX: usize> Text<MIN, MAX> {
    /// `value` as a string of `MIN` to `MAX` characters.
    pub(crate) fn parse(value: Json, path: MemberPath) -> Result<Self, Ts12PayloadFault> {
        let text = json::text(value, path)?;
        checked((MIN..=MAX).contains(&text.chars().count()), text, path).map(Self)
    }
}

/// An ISO 8601 date and time as written: RFC 3339 `date-time`.
pub(crate) struct DateTimeText(String);

/// An ISO 8601 date, or date and time, as written.
pub(crate) struct DateOrDateTime(String);

/// A domain name: dot-separated labels of 1 to 63 letters, digits and hyphens, no label
/// starting or ending with a hyphen, at most 253 characters (RFC 1123, Section 2.1).
pub(crate) struct DomainName(String);

/// A resolvable URL: `http` or `https`, with an authority, of visible ASCII characters.
pub(crate) struct WebUrl(String);

/// The URL of an image: a resolvable `http` or `https` URL, or a `data` URL (RFC 2397). The
/// view takes it under the image rules of PaSO View, Section 3.
pub(crate) struct LogoUrl(String);

macro_rules! shown_as_text {
    ($($name:ty),*) => {$(
        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
    )*};
}

shown_as_text!(DateTimeText, DateOrDateTime, DomainName, WebUrl, LogoUrl);

impl<const MIN: usize, const MAX: usize> AsRef<str> for Text<MIN, MAX> {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// An amount of a currency, with the text the verifier wrote (Section 4.3.1, `amount`).
pub(crate) struct Amount(JsonNumber);

impl Amount {
    /// The number.
    pub(crate) fn number(&self) -> &JsonNumber {
        &self.0
    }
}

/// `value` as an ISO 8601 date (RFC 3339 `full-date`).
pub(crate) fn date(value: Json, path: MemberPath) -> Result<Date, Ts12PayloadFault> {
    Date::parse(&json::text(value, path)?).ok_or(Ts12PayloadFault::Invalid(path))
}

/// `value` as an ISO 8601 date and time (RFC 3339 `date-time`).
pub(crate) fn date_time(value: Json, path: MemberPath) -> Result<DateTimeText, Ts12PayloadFault> {
    let text = json::text(value, path)?;
    checked(is_date_time(&text), text, path).map(DateTimeText)
}

/// `value` as an ISO 8601 date, or date and time.
pub(crate) fn date_or_date_time(
    value: Json,
    path: MemberPath,
) -> Result<DateOrDateTime, Ts12PayloadFault> {
    let text = json::text(value, path)?;
    checked(
        Date::parse(&text).is_some() || is_date_time(&text),
        text,
        path,
    )
    .map(DateOrDateTime)
}

/// `value` as a domain name. A QWAC names its domain in a `dNSName`, of these characters only.
pub(crate) fn domain_name(value: Json, path: MemberPath) -> Result<DomainName, Ts12PayloadFault> {
    let text = json::text(value, path)?;
    let label = |label: &str| {
        (1..=63).contains(&label.len())
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    };
    let valid = text.len() <= 253 && text.split('.').all(label);
    checked(valid, text, path).map(DomainName)
}

/// `value` as a resolvable URL.
pub(crate) fn url(value: Json, path: MemberPath) -> Result<WebUrl, Ts12PayloadFault> {
    let text = json::text(value, path)?;
    checked(is_url(&text), text, path).map(WebUrl)
}

/// `value` as a resolvable URL or a `data` URL (RFC 2397).
pub(crate) fn image(value: Json, path: MemberPath) -> Result<LogoUrl, Ts12PayloadFault> {
    let text = json::text(value, path)?;
    checked(is_url(&text) || is_data_url(&text), text, path).map(LogoUrl)
}

/// `value` as an ISO 4217 alphabetic code.
pub(crate) fn currency(value: Json, path: MemberPath) -> Result<CurrencyCode, Ts12PayloadFault> {
    CurrencyCode::of(&json::text(value, path)?).ok_or(Ts12PayloadFault::Invalid(path))
}

/// `value` as an amount of `currency`: an optional minus, the major units, and an optional
/// decimal point with exactly the digits of the minor unit (Section 4.3.1, `amount`). A
/// currency without a minor unit takes no fraction.
pub(crate) fn amount(
    value: Json,
    path: MemberPath,
    currency: CurrencyCode,
) -> Result<Amount, Ts12PayloadFault> {
    let number = json::number(value, path)?;
    let text = number.text();
    if currency.admits(text.strip_prefix('-').unwrap_or(text), Fraction::Optional) {
        Ok(Amount(number))
    } else {
        Err(Ts12PayloadFault::Invalid(path))
    }
}

/// `text` when `valid`.
fn checked(valid: bool, text: String, path: MemberPath) -> Result<String, Ts12PayloadFault> {
    if valid {
        Ok(text)
    } else {
        Err(Ts12PayloadFault::Invalid(path))
    }
}

/// RFC 3339 `date-time`: `full-date "T" hh:mm:ss [.digits] ("Z" / ("+" / "-") hh:mm)`, `T`
/// and `Z` in either case (Section 5.6).
fn is_date_time(text: &str) -> bool {
    let Some((date, rest)) = text.split_at_checked(10) else {
        return false;
    };
    let Some(rest) = rest.strip_prefix(['T', 't']).and_then(clock) else {
        return false;
    };
    let rest = match rest.strip_prefix('.') {
        Some(fraction) => {
            let digits = fraction.bytes().take_while(u8::is_ascii_digit).count();
            if digits == 0 {
                return false;
            }
            fraction.get(digits..).unwrap_or_default()
        }
        None => rest,
    };
    Date::parse(date).is_some() && offset(rest)
}

/// What follows `hh:mm:ss` at the start of `text`. A second of 60 is a leap second (RFC 3339,
/// Section 5.7).
fn clock(text: &str) -> Option<&str> {
    let rest = two(text, 23)?;
    let rest = two(rest.strip_prefix(':')?, 59)?;
    two(rest.strip_prefix(':')?, 60)
}

/// Whether `text` is `Z`, or a sign and `hh:mm`.
fn offset(text: &str) -> bool {
    match text.strip_prefix(['+', '-']) {
        Some(rest) => {
            two(rest, 23)
                .and_then(|rest| rest.strip_prefix(':'))
                .and_then(|rest| two(rest, 59))
                == Some("")
        }
        None => text.eq_ignore_ascii_case("z"),
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

/// `http://` or `https://` (any case), a non-empty authority, visible ASCII only.
fn is_url(text: &str) -> bool {
    let rest = ["https://", "http://"].iter().find_map(|scheme| {
        text.get(..scheme.len())
            .filter(|s| s.eq_ignore_ascii_case(scheme))
            .and_then(|_| text.get(scheme.len()..))
    });
    let authority = rest.and_then(|rest| rest.split(['/', '?', '#']).next());
    authority.is_some_and(|a| !a.is_empty()) && text.bytes().all(|b| b.is_ascii_graphic())
}

/// RFC 2397: `data:` (any case), a media type of `type/subtype` and `attribute=value`
/// parameters, an optional `;base64`, a comma, and the data: base64 after `;base64`, URL
/// characters otherwise.
fn is_data_url(text: &str) -> bool {
    let Some(rest) = text
        .get(..5)
        .filter(|s| s.eq_ignore_ascii_case("data:"))
        .and_then(|_| text.get(5..))
    else {
        return false;
    };
    let Some((header, data)) = rest.split_once(',') else {
        return false;
    };
    let parts: Vec<&str> = header.split(';').collect();
    let (base64, parts) = match parts.split_last() {
        Some((last, rest)) if !rest.is_empty() && last.eq_ignore_ascii_case("base64") => {
            (true, rest)
        }
        _ => (false, parts.as_slice()),
    };
    // RFC 2045, Section 5.1: a token holds no space, control or tspecial.
    let token = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_graphic() && !b"()<>@,;:\\\"/[]?=".contains(&b))
    };
    let media_type = match parts.split_first() {
        Some((media_type, parameters)) => {
            let kind = media_type.is_empty()
                || matches!(media_type.split_once('/'), Some((t, s)) if token(t) && token(s));
            kind && parameters.iter().all(|p| {
                matches!(p.split_once('='), Some((attribute, value)) if token(attribute) && !value.is_empty())
            })
        }
        None => true,
    };
    let data_fits = if base64 {
        base64::decode(data).is_ok()
    } else {
        data.bytes().all(|b| b.is_ascii_graphic())
    };
    media_type && data_fits && header.bytes().all(|b| b.is_ascii_graphic())
}
