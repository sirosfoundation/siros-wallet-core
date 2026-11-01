//! Payload values typed by their value type (PaSO View, Section 3).

use std::fmt;

use siros_codec::date::Date;
use siros_codec::json::{Json, JsonNumber};
use siros_oid4vp::HttpsUrl;

use super::time::{IsoDateTime, IsoTime};
use super::ValueFault;
use crate::currency::{CurrencyCode, Fraction};
use crate::definition::{bidi, BaseType, ValueType};
use crate::image::ImageRef;

/// A payload string: no directional embedding or override, and every isolate terminated (PaSO
/// Proof Metadata, Section 3.3).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PayloadText(String);

impl PayloadText {
    /// The string `text`.
    pub(crate) fn parse(text: String) -> Result<Self, ValueFault> {
        bidi(&text).map_err(ValueFault::Text)?;
        Ok(Self(text))
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A recurrence frequency: an ISO 20022 code (PaSO View, Section 3, `frequency`; EC TS12
/// v1.0.1, Section 4.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Frequency {
    /// `INDA`: several times a day.
    Intraday,
    /// `DAIL`: daily.
    Daily,
    /// `WEEK`: weekly.
    Weekly,
    /// `TOWK`: every two weeks.
    EveryTwoWeeks,
    /// `TWMN`: twice a month.
    TwiceAMonth,
    /// `MNTH`: monthly.
    Monthly,
    /// `TOMN`: every two months.
    EveryTwoMonths,
    /// `QUTR`: quarterly.
    Quarterly,
    /// `FOMN`: every four months.
    EveryFourMonths,
    /// `SEMI`: twice a year.
    TwiceAYear,
    /// `YEAR`: yearly.
    Yearly,
    /// `TYEA`: every two years.
    EveryTwoYears,
}

impl Frequency {
    const ALL: [Self; 12] = [
        Self::Intraday,
        Self::Daily,
        Self::Weekly,
        Self::EveryTwoWeeks,
        Self::TwiceAMonth,
        Self::Monthly,
        Self::EveryTwoMonths,
        Self::Quarterly,
        Self::EveryFourMonths,
        Self::TwiceAYear,
        Self::Yearly,
        Self::EveryTwoYears,
    ];

    /// The ISO 20022 code.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Intraday => "INDA",
            Self::Daily => "DAIL",
            Self::Weekly => "WEEK",
            Self::EveryTwoWeeks => "TOWK",
            Self::TwiceAMonth => "TWMN",
            Self::Monthly => "MNTH",
            Self::EveryTwoMonths => "TOMN",
            Self::Quarterly => "QUTR",
            Self::EveryFourMonths => "FOMN",
            Self::TwiceAYear => "SEMI",
            Self::Yearly => "YEAR",
            Self::EveryTwoYears => "TYEA",
        }
    }

    /// The frequency of the code `code`.
    pub(crate) fn named(code: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|f| f.code() == code)
    }
}

/// An amount and its currency: a decimal number with a decimal point and the digits of the
/// currency's minor unit, a space, and an ISO 4217 alphabetic code (PaSO View, Section 3,
/// `iso_currency_amount`). A currency without a minor unit takes the integer alone.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CurrencyAmount {
    amount: String,
    currency: CurrencyCode,
}

impl CurrencyAmount {
    /// The amount of `text`; `None` for text of another form.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let (amount, code) = text.split_once(' ')?;
        let currency = CurrencyCode::of(code)?;
        currency.admits(amount, Fraction::Required).then(|| Self {
            amount: amount.to_owned(),
            currency,
        })
    }

    /// The decimal number, as the payload writes it.
    #[must_use]
    pub fn amount(&self) -> &str {
        &self.amount
    }

    /// The currency.
    #[must_use]
    pub fn currency(&self) -> CurrencyCode {
        self.currency
    }
}

/// A JSON number, as its writer wrote it: an amount or a count of an EC TS12 v1.0.1 payload.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NumberText(String);

impl NumberText {
    /// The number `number`.
    pub(crate) fn of(number: &JsonNumber) -> Self {
        Self(number.text().to_owned())
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A value that formats as text, and that a template may interpolate (PaSO View, Section 3).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Scalar {
    /// A string without a value type: plain text.
    Text(PayloadText),
    /// `boolean`.
    Boolean(bool),
    /// `frequency`.
    Frequency(Frequency),
    /// `iso_date`.
    Date(Date),
    /// `iso_time`.
    Time(IsoTime),
    /// `iso_date_time`.
    DateTime(IsoDateTime),
    /// `iso_currency`.
    Currency(CurrencyCode),
    /// `iso_currency_amount`.
    CurrencyAmount(CurrencyAmount),
    /// `mini_markdown`.
    MiniMarkdown(PayloadText),
    /// `url`: an `https` URL, shown in full.
    Url(HttpsUrl),
    /// A JSON number of an EC TS12 v1.0.1 payload.
    Number(NumberText),
}

impl Scalar {
    /// The value as the payload writes it: the text a template inserts before the UI formats
    /// it, and that the length rule of a label counts.
    #[must_use]
    pub fn text(&self) -> String {
        match self {
            Self::Text(text) | Self::MiniMarkdown(text) => text.as_str().to_owned(),
            Self::Boolean(b) => b.to_string(),
            Self::Frequency(f) => f.code().to_owned(),
            Self::Date(date) => date.to_string(),
            Self::Time(time) => time.as_str().to_owned(),
            Self::DateTime(time) => time.as_str().to_owned(),
            Self::Currency(code) => code.as_str().to_owned(),
            Self::CurrencyAmount(amount) => {
                format!("{} {}", amount.amount(), amount.currency().as_str())
            }
            Self::Url(url) => url.as_str().to_owned(),
            Self::Number(number) => number.as_str().to_owned(),
        }
    }
}

impl fmt::Display for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text())
    }
}

/// A payload value of a claim with a `display` array, typed by its value type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Typed {
    /// A value that formats as text.
    Scalar(Scalar),
    /// `image`: where to obtain the image.
    Image(ImageRef),
    /// `label_only`: the label is shown alone.
    LabelOnly,
    /// `template:<inner>`: a string whose placeholders are interpolated, then formatted by the
    /// inner type.
    Template(PayloadText, BaseType),
}

/// The value `value` of a claim of value type `value_type`, `None` for plain text. An `image`
/// value takes `integrity`, the string of its `#integrity` sibling.
pub(crate) fn typed(
    value: &Json,
    value_type: Option<ValueType>,
    integrity: Option<&Json>,
) -> Result<Typed, ValueFault> {
    let text = || match value {
        Json::String(text) => PayloadText::parse(text.clone()),
        _ => Err(ValueFault::NotString),
    };
    let base = match value_type {
        None => return Ok(Typed::Scalar(Scalar::Text(text()?))),
        Some(ValueType::Template(inner)) => return Ok(Typed::Template(text()?, inner)),
        Some(ValueType::Plain(base)) => base,
    };
    Ok(match base {
        BaseType::LabelOnly => Typed::LabelOnly,
        BaseType::Image => {
            Typed::Image(ImageRef::parse(text()?.as_str(), integrity).map_err(ValueFault::Image)?)
        }
        BaseType::Boolean => match value {
            Json::Bool(b) => Typed::Scalar(Scalar::Boolean(*b)),
            _ => return Err(ValueFault::Type(base)),
        },
        _ => Typed::Scalar(scalar(text()?, base)?),
    })
}

/// The string `text` as a value of the text-like type `base`.
pub(crate) fn scalar(text: PayloadText, base: BaseType) -> Result<Scalar, ValueFault> {
    let wrong = || ValueFault::Type(base);
    let value = text.as_str();
    Ok(match base {
        BaseType::Frequency => Scalar::Frequency(Frequency::named(value).ok_or_else(wrong)?),
        BaseType::IsoDate => Scalar::Date(Date::parse(value).ok_or_else(wrong)?),
        BaseType::IsoTime => Scalar::Time(IsoTime::parse(value).ok_or_else(wrong)?),
        BaseType::IsoDateTime => Scalar::DateTime(IsoDateTime::parse(value).ok_or_else(wrong)?),
        BaseType::IsoCurrency => Scalar::Currency(CurrencyCode::of(value).ok_or_else(wrong)?),
        BaseType::IsoCurrencyAmount => {
            Scalar::CurrencyAmount(CurrencyAmount::parse(value).ok_or_else(wrong)?)
        }
        BaseType::Url => Scalar::Url(HttpsUrl::parse(value).ok_or_else(wrong)?),
        BaseType::MiniMarkdown => Scalar::MiniMarkdown(text),
        BaseType::Boolean | BaseType::Image | BaseType::LabelOnly => return Err(wrong()),
    })
}
