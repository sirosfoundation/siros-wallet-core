//! Exact decimals of any length, their rounding at a decimal position, and their fixed-point
//! digits: what the numeric formats compute with.

use std::cmp::Ordering;
use std::num::{NonZeroU32, NonZeroU64};
use std::ops::{Div, Rem};

use crate::digit::{Digit, Numerals};
use crate::mf2::number::NumberLiteral;

/// A rounding mode (MF2's `roundingMode`, after ECMA-402's).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RoundingMode {
    /// Toward positive infinity.
    Ceil,
    /// Toward negative infinity.
    Floor,
    /// Away from zero.
    Expand,
    /// Toward zero.
    Trunc,
    /// To the nearest, a tie toward positive infinity.
    HalfCeil,
    /// To the nearest, a tie toward negative infinity.
    HalfFloor,
    /// To the nearest, a tie away from zero.
    HalfExpand,
    /// To the nearest, a tie toward zero.
    HalfTrunc,
    /// To the nearest, a tie to the even neighbour.
    HalfEven,
}

impl RoundingMode {
    /// Every mode, in the order of their names.
    const ALL: [Self; 9] = [
        Self::Ceil,
        Self::Floor,
        Self::Expand,
        Self::Trunc,
        Self::HalfCeil,
        Self::HalfFloor,
        Self::HalfExpand,
        Self::HalfTrunc,
        Self::HalfEven,
    ];

    /// The mode MF2's option value names.
    pub(crate) fn named(name: &str) -> Option<Self> {
        let names = [
            "ceil",
            "floor",
            "expand",
            "trunc",
            "halfCeil",
            "halfFloor",
            "halfExpand",
            "halfTrunc",
            "halfEven",
        ];
        names
            .iter()
            .zip(Self::ALL)
            .find_map(|(&n, mode)| (n == name).then_some(mode))
    }

    /// Whether a value of this sign, `exact` or not, whose remainder compares to half a unit as
    /// `half`, rounds away from zero; `odd` for an odd quotient.
    fn away(self, negative: bool, exact: bool, half: Ordering, odd: bool) -> bool {
        if exact {
            return false;
        }
        match self {
            Self::Ceil => !negative,
            Self::Floor => negative,
            Self::Expand => true,
            Self::Trunc => false,
            _ => match half {
                Ordering::Less => false,
                Ordering::Greater => true,
                Ordering::Equal => match self {
                    Self::HalfCeil => !negative,
                    Self::HalfFloor => negative,
                    Self::HalfExpand => true,
                    Self::HalfTrunc => false,
                    _ => odd,
                },
            },
        }
    }
}

/// An exact decimal: a sign, its digits, most significant first, without leading or trailing
/// zeros, and the power of ten of its last digit. Zero has no digits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Num {
    negative: bool,
    digits: Vec<Digit>,
    exponent: i64,
}

/// A decimal written out: its sign, its integer digits, one or more, and its fraction digits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Fixed {
    pub(crate) negative: bool,
    pub(crate) int: Vec<Digit>,
    pub(crate) frac: Vec<Digit>,
}

impl Fixed {
    /// Whether every digit is zero.
    pub(crate) fn is_zero(&self) -> bool {
        self.int.iter().chain(&self.frac).all(|&d| d == Digit::Zero)
    }

    /// Whether the fraction digits are all zero.
    pub(crate) fn is_integer(&self) -> bool {
        self.frac.iter().all(|&d| d == Digit::Zero)
    }

    /// The decimal in ASCII digits: `-` below zero, the integer digits, then `.` and the
    /// fraction digits when it has some.
    pub(crate) fn plain(&self) -> String {
        let digits = |digits: &[Digit]| -> String {
            digits.iter().map(|d| Numerals::ASCII.digit(*d)).collect()
        };
        let sign = if self.negative && !self.is_zero() {
            "-"
        } else {
            ""
        };
        let int = digits(&self.int);
        if self.frac.is_empty() {
            format!("{sign}{int}")
        } else {
            format!("{sign}{int}.{}", digits(&self.frac))
        }
    }
}

impl Num {
    /// The decimal of `negative`, `digits` and `exponent`, normalized.
    fn new(negative: bool, digits: Vec<Digit>, mut exponent: i64) -> Self {
        let mut digits: Vec<Digit> = digits
            .into_iter()
            .skip_while(|&d| d == Digit::Zero)
            .collect();
        let zeros = digits
            .iter()
            .rev()
            .take_while(|&&d| d == Digit::Zero)
            .count();
        digits.truncate(digits.len() - zeros);
        exponent += zeros as i64;
        if digits.is_empty() {
            exponent = 0;
        }
        Self {
            negative,
            digits,
            exponent,
        }
    }

    /// The value a `number-literal` writes (MF2 spec/functions/number.md); `None` for another
    /// text or a written digit at a power of ten outside `i16`'s range.
    pub(crate) fn literal(text: &str) -> Option<Self> {
        Given::literal(text).map(|given| given.value)
    }

    /// The power of ten of its most significant digit; `None` for zero.
    pub(crate) fn magnitude(&self) -> Option<i64> {
        (!self.digits.is_empty()).then(|| self.exponent + self.digits.len() as i64 - 1)
    }

    /// Each digit with its power of ten, most significant first.
    fn powers(&self) -> impl Iterator<Item = (i64, Digit)> + '_ {
        let top = self.exponent + self.digits.len() as i64 - 1;
        (self.exponent..=top).rev().zip(self.digits.iter().copied())
    }

    /// The digits of ⌊|value| / 10^`low`⌋, most significant first; none when it is zero.
    fn integer_at(&self, low: i64) -> Vec<Digit> {
        let Some(top) = self.magnitude() else {
            return Vec::new();
        };
        self.digits
            .iter()
            .copied()
            .chain(std::iter::repeat(Digit::Zero))
            .zip((low..=top).rev())
            .map(|(digit, _)| digit)
            .collect()
    }

    /// The value rounded to a multiple of `increment` × 10^`magnitude` by `mode`.
    pub(crate) fn round(&self, magnitude: i64, increment: NonZeroU32, mode: RoundingMode) -> Self {
        if self.digits.is_empty() {
            return self.clone();
        }
        let whole = self.integer_at(magnitude);
        let rest: Vec<Digit> = self
            .powers()
            .filter(|&(power, _)| power < magnitude)
            .map(|(_, digit)| digit)
            .collect();
        let gap = self
            .powers()
            .find(|&(power, _)| power < magnitude)
            .is_some_and(|(power, _)| power + 1 < magnitude);
        let (quotient, remainder) = divide(&whole, increment);
        let half = half_compare(remainder, increment, gap, &rest);
        let exact = remainder == 0 && rest.is_empty();
        let odd = quotient.last().is_some_and(|d| d.value() % 2 == 1);
        let quotient = if mode.away(self.negative, exact, half, odd) {
            add(&quotient, &[Digit::One])
        } else {
            quotient
        };
        Self::new(
            self.negative,
            multiply(&quotient, increment.get()),
            magnitude,
        )
    }

    /// Its digits written out: the integer part, one digit or more, and the fraction down to
    /// 10^`low` and to its last digit, whichever is lower.
    pub(crate) fn fixed(&self, low: i64) -> Fixed {
        let low = low.min(self.exponent).min(0);
        let high = self.magnitude().map_or(0, |top| top.max(0));
        let mut written = self.powers().peekable();
        let (mut int, mut frac) = (Vec::new(), Vec::new());
        for power in (low..=high).rev() {
            let digit = written
                .next_if(|&(at, _)| at == power)
                .map_or(Digit::Zero, |(_, digit)| digit);
            if power < 0 {
                frac.push(digit);
            } else {
                int.push(digit);
            }
        }
        Fixed {
            negative: self.negative,
            int,
            frac,
        }
    }
}

/// A number as its input gives it: its value, and the count of fraction digits it is written
/// with, which its value's last digit never passes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Given {
    value: Num,
    scale: u32,
}

impl Given {
    /// The number a `number-literal` writes (MF2 spec/functions/number.md); `None` for another
    /// text or a written digit at a power of ten outside `i16`'s range.
    pub(crate) fn literal(text: &str) -> Option<Self> {
        let literal = NumberLiteral::parse(text)?;
        let shift = match &literal.exponent {
            None => 0,
            Some((negative, power)) => {
                let power = power.iter().try_fold(0i64, |power, digit| {
                    power.checked_mul(10)?.checked_add(i64::from(digit.value()))
                })?;
                if *negative { -power } else { power }
            }
        };
        let top = shift.checked_add(literal.whole.len() as i64 - 1)?;
        let last = shift.checked_sub(literal.fraction.len() as i64)?;
        // ICU4X's `fixed_decimal` holds a digit's power of ten in an `i16`. A literal past it
        // would write a text of up to its exponent's value in digits.
        let (Ok(_), Ok(last)) = (i16::try_from(top), i16::try_from(last)) else {
            return None;
        };
        let NumberLiteral {
            negative,
            mut whole,
            fraction,
            ..
        } = literal;
        whole.extend(fraction);
        Some(Self {
            value: Num::new(negative, whole, i64::from(last)),
            scale: u32::from(last.min(0).unsigned_abs()),
        })
    }

    /// Its value.
    pub(crate) const fn value(&self) -> &Num {
        &self.value
    }

    /// The count of fraction digits it is written with.
    pub(crate) const fn scale(&self) -> u32 {
        self.scale
    }

    /// The value rounded to an integer by `mode`, written without fraction digits.
    pub(crate) fn integer(&self, mode: RoundingMode) -> Self {
        Self {
            value: self.value.round(0, NonZeroU32::MIN, mode),
            scale: 0,
        }
    }
}

/// How `remainder` + 0.`rest`, in units of 1, compares to half of `increment`; `gap` when a zero
/// stands between the decimal point and `rest`.
fn half_compare(remainder: u64, increment: NonZeroU32, gap: bool, rest: &[Digit]) -> Ordering {
    let twice = remainder * 2;
    let increment = u64::from(increment.get());
    let [first, more @ ..] = rest else {
        return twice.cmp(&increment);
    };
    if twice >= increment {
        Ordering::Greater
    } else if twice + 1 < increment || gap {
        Ordering::Less
    } else if more.is_empty() {
        first.cmp(&Digit::Five)
    } else {
        first.cmp(&Digit::Five).then(Ordering::Greater)
    }
}

/// The sum of two digit strings.
fn add(a: &[Digit], b: &[Digit]) -> Vec<Digit> {
    let mut sum = Vec::with_capacity(a.len().max(b.len()) + 1);
    let mut carry = 0;
    let (mut x, mut y) = (a.iter().rev(), b.iter().rev());
    loop {
        let (p, q) = (x.next(), y.next());
        if p.is_none() && q.is_none() {
            break;
        }
        let total = p.copied().unwrap_or(Digit::Zero).value()
            + q.copied().unwrap_or(Digit::Zero).value()
            + carry;
        sum.push(Digit::last(u128::from(total)));
        carry = total / 10;
    }
    if carry > 0 {
        sum.push(Digit::last(u128::from(carry)));
    }
    sum.reverse();
    sum
}

/// The quotient and remainder of a digit string divided by `divisor`.
fn divide(digits: &[Digit], divisor: NonZeroU32) -> (Vec<Digit>, u64) {
    let divisor = NonZeroU64::from(divisor);
    let mut remainder = 0u64;
    let quotient = digits
        .iter()
        .map(|d| {
            let value = remainder * 10 + u64::from(d.value());
            remainder = Rem::rem(value, divisor);
            Digit::last(u128::from(Div::div(value, divisor)))
        })
        .collect();
    (quotient, remainder)
}

/// A digit string times `factor`.
fn multiply(digits: &[Digit], factor: u32) -> Vec<Digit> {
    let mut product = Vec::with_capacity(digits.len() + 5);
    let mut carry = 0u64;
    for d in digits.iter().rev() {
        let value = u64::from(d.value()) * u64::from(factor) + carry;
        product.push(Digit::last(u128::from(value)));
        carry = value / 10;
    }
    while carry > 0 {
        product.push(Digit::last(u128::from(carry)));
        carry /= 10;
    }
    product.reverse();
    product
}
