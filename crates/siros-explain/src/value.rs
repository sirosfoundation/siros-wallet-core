//! Typed values: what a message's arguments and a text hold until the renderer formats them.

use std::borrow::Cow;
use std::cmp::Ordering;
use std::fmt;

use crate::calendar::{Date, DateTime, Offset, Time};
use crate::iso4217::Currency;

/// A typed value. Dates, amounts and currencies stay typed until the renderer formats them in
/// the display locale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// A count: a size, an index, an age.
    Count(Count),
    /// An exact decimal.
    Decimal(Decimal),
    /// An ISO 8601 calendar date.
    Date(Date),
    /// An ISO 8601 time of day, with its UTC offset when written.
    Time {
        /// The time.
        at: Time,
        /// The offset.
        offset: Option<Offset>,
    },
    /// An ISO 8601 date and time, with its UTC offset when written.
    DateTime(DateTime),
    /// An amount in a currency.
    Amount(Amount),
    /// An ISO 4217 currency, shown by the locale's name or symbol for it.
    Currency(Currency),
}

/// A count: a natural number of any length, such as a size, an index, or an age of nym_auth's
/// `age = 1*DIGIT`. A `u64` when it fits, else its decimal digits, so each number has one form.
/// `:integer` formats and selects it from its digits.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Count(Digits);

/// A count's form: a `u64`, or the digits of a count past `u64::MAX`, the first other than `0`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Digits {
    Word(u64),
    Long(Box<str>),
}

impl Count {
    /// The count of a `u64`.
    #[must_use]
    pub const fn of(value: u64) -> Self {
        Self(Digits::Word(value))
    }

    /// The count `1*DIGIT` writes, leading zeros allowed; `None` for another text.
    #[must_use]
    pub fn parse(digits: &str) -> Option<Self> {
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let trimmed = digits.trim_start_matches('0');
        let word = trimmed.bytes().try_fold(0u64, |value, digit| {
            value.checked_mul(10)?.checked_add(u64::from(digit - b'0'))
        });
        Some(Self(
            word.map_or_else(|| Digits::Long(trimmed.into()), Digits::Word),
        ))
    }

    /// The count, when it fits a `u64`.
    #[must_use]
    pub const fn to_u64(&self) -> Option<u64> {
        match &self.0 {
            Digits::Word(value) => Some(*value),
            Digits::Long(_) => None,
        }
    }

    /// Its decimal digits, without leading zeros: `0` for zero.
    #[must_use]
    pub fn digits(&self) -> Cow<'_, str> {
        match &self.0 {
            Digits::Word(value) => Cow::Owned(value.to_string()),
            Digits::Long(digits) => Cow::Borrowed(digits),
        }
    }
}

impl PartialOrd for Count {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Counts compare as integers: a `u64` below a longer count, longer digits above shorter ones.
impl Ord for Count {
    fn cmp(&self, other: &Self) -> Ordering {
        match (&self.0, &other.0) {
            (Digits::Word(a), Digits::Word(b)) => a.cmp(b),
            (Digits::Word(_), Digits::Long(_)) => Ordering::Less,
            (Digits::Long(_), Digits::Word(_)) => Ordering::Greater,
            (Digits::Long(a), Digits::Long(b)) => a.len().cmp(&b.len()).then_with(|| a.cmp(b)),
        }
    }
}

impl fmt::Display for Count {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.digits())
    }
}

/// An exact decimal: `units` × 10^-`scale`, with the scale it was written with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decimal {
    units: i128,
    scale: u8,
}

impl Decimal {
    /// The decimal; `None` beyond 38 fraction digits, which an `i128` cannot hold.
    #[must_use]
    pub const fn new(units: i128, scale: u8) -> Option<Self> {
        if scale > 38 {
            None
        } else {
            Some(Self { units, scale })
        }
    }

    /// The units.
    #[must_use]
    pub const fn units(self) -> i128 {
        self.units
    }

    /// The number of fraction digits.
    #[must_use]
    pub const fn scale(self) -> u8 {
        self.scale
    }
}

/// An amount: an exact decimal in a currency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Amount {
    value: Decimal,
    currency: Currency,
}

impl Amount {
    /// The amount.
    #[must_use]
    pub const fn new(value: Decimal, currency: Currency) -> Self {
        Self { value, currency }
    }

    /// The value.
    #[must_use]
    pub const fn value(self) -> Decimal {
        self.value
    }

    /// The currency.
    #[must_use]
    pub const fn currency(self) -> Currency {
        self.currency
    }
}
