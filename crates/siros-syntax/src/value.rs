//! Counts, exact decimals and amounts.

use std::borrow::Cow;
use std::cmp::Ordering;
use std::fmt;

use crate::iso4217::Currency;
use crate::malformed::{Malformed, Reader, parse};

/// A count: a natural number of any length, such as a size, an index or an age. A `u64` when it
/// fits, else its decimal digits, so each number has one form. Its literal is its digits: `0`, or
/// a digit other than `0` and then digits.
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

    /// The count `text` writes: `0`, or a digit other than `0` and then digits.
    ///
    /// # Errors
    ///
    /// [`Malformed`] for any other text.
    pub fn parse(text: &str) -> Result<Self, Malformed> {
        let mut word = Some(0u64);
        parse(text, "Count", |reader| {
            natural(reader, |digit| {
                word = word.and_then(|value| value.checked_mul(10)?.checked_add(u64::from(digit)));
                true
            })
        })?;
        Ok(Self(
            word.map_or_else(|| Digits::Long(text.into()), Digits::Word),
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

/// Its literal: its digits.
impl fmt::Display for Count {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.digits())
    }
}

/// Reads `0` or a digit other than `0` and then digits, giving `add` each digit; refused at a digit
/// `add` refuses.
fn natural(reader: &mut Reader<'_>, mut add: impl FnMut(u8) -> bool) -> Result<(), Malformed> {
    let at = reader.at();
    let first = reader.digit().ok_or_else(|| reader.here())?;
    if !add(first) {
        return Err(reader.refuse(at));
    }
    if first == 0 {
        return Ok(());
    }
    loop {
        let at = reader.at();
        let Some(digit) = reader.digit() else {
            return Ok(());
        };
        if !add(digit) {
            return Err(reader.refuse(at));
        }
    }
}

/// An exact decimal: `units` × 10^-`scale`, with the scale it was written with. Its literal is
/// `-?(0|[1-9][0-9]*)(\.[0-9]+)?` with `scale` fraction digits, the sign only on a value other
/// than zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decimal {
    units: i128,
    scale: u8,
}

impl Decimal {
    /// The most fraction digits: an `i128` holds 38 decimal digits whatever their value.
    const MAX_SCALE: u8 = 38;

    /// The decimal; `None` beyond 38 fraction digits, which an `i128` cannot hold.
    #[must_use]
    pub const fn new(units: i128, scale: u8) -> Option<Self> {
        if scale > Self::MAX_SCALE {
            None
        } else {
            Some(Self { units, scale })
        }
    }

    /// The decimal `text` writes.
    ///
    /// # Errors
    ///
    /// [`Malformed`] for a text outside the literal form, a negative zero, units beyond an
    /// `i128`, or more than 38 fraction digits.
    pub fn parse(text: &str) -> Result<Self, Malformed> {
        parse(text, "Decimal", Self::read)
    }

    /// The decimal at the reader.
    pub(crate) fn read(reader: &mut Reader<'_>) -> Result<Self, Malformed> {
        let start = reader.at();
        let negative = reader.take(b'-');
        let limit = if negative {
            i128::MIN.unsigned_abs()
        } else {
            i128::MAX.unsigned_abs()
        };
        let mut magnitude = 0u128;
        natural(reader, |digit| shift(&mut magnitude, digit, limit))?;
        let mut scale = 0u8;
        if reader.take(b'.') {
            loop {
                let at = reader.at();
                let Some(digit) = reader.digit() else {
                    break;
                };
                if scale == Self::MAX_SCALE || !shift(&mut magnitude, digit, limit) {
                    return Err(reader.refuse(at));
                }
                scale += 1;
            }
            if scale == 0 {
                return Err(reader.here());
            }
        }
        if negative && magnitude == 0 {
            return Err(reader.refuse(start));
        }
        let units = if negative {
            0i128.checked_sub_unsigned(magnitude)
        } else {
            i128::try_from(magnitude).ok()
        };
        units
            .and_then(|units| Self::new(units, scale))
            .ok_or_else(|| reader.refuse(start))
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

/// `magnitude` × 10 + `digit` into `magnitude`, when it stays within `limit`.
fn shift(magnitude: &mut u128, digit: u8, limit: u128) -> bool {
    let next = magnitude
        .checked_mul(10)
        .and_then(|value| value.checked_add(u128::from(digit)))
        .filter(|value| *value <= limit);
    if let Some(next) = next {
        *magnitude = next;
    }
    next.is_some()
}

/// Its literal: `-1234.50` for `units` -123450 at `scale` 2.
impl fmt::Display for Decimal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let magnitude = self.units.unsigned_abs();
        let place = 10u128
            .checked_pow(u32::from(self.scale))
            .ok_or(fmt::Error)?;
        let whole = magnitude.checked_div(place).ok_or(fmt::Error)?;
        let fraction = magnitude.checked_rem(place).ok_or(fmt::Error)?;
        if self.units < 0 {
            f.write_str("-")?;
        }
        write!(f, "{whole}")?;
        if self.scale > 0 {
            write!(f, ".{fraction:0width$}", width = usize::from(self.scale))?;
        }
        Ok(())
    }
}

/// An amount: an exact decimal in a currency. Its literal is the decimal's, a space, and the
/// currency's code: `42.50 EUR`.
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

    /// The amount `text` writes.
    ///
    /// # Errors
    ///
    /// [`Malformed`] for a text other than a decimal's literal, one space, and an ISO 4217
    /// alphabetic code.
    pub fn parse(text: &str) -> Result<Self, Malformed> {
        parse(text, "Amount", |reader| {
            let value = Decimal::read(reader)?;
            reader.expect(b' ')?;
            let currency = Currency::read(reader)?;
            Ok(Self::new(value, currency))
        })
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

/// Its literal: `42.50 EUR`.
impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.value, self.currency)
    }
}
