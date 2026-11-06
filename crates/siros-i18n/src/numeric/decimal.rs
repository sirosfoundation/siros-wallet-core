//! Exact decimals of any length, their rounding at a decimal position, and their fixed-point
//! digits: what the numeric formats compute with.

use std::cmp::Ordering;
use std::num::{NonZeroU32, NonZeroU64};
use std::ops::{Div, Rem};

use siros_explain::{Count, Decimal};

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
    /// Every mode, in the order of their codes.
    pub(crate) const ALL: [Self; 9] = [
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
    #[cfg(feature = "load")]
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

    /// Its code in a compiled placeholder.
    #[cfg(feature = "load")]
    pub(crate) fn code(self) -> u8 {
        Self::ALL
            .iter()
            .position(|&mode| mode == self)
            .map_or(0, |at| at as u8)
    }

    /// The mode of a code.
    pub(crate) fn of_code(code: u8) -> Option<Self> {
        Self::ALL.get(usize::from(code)).copied()
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
    digits: Vec<u8>,
    exponent: i64,
}

/// A decimal written out: its sign, its integer digits, one or more, and its fraction digits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Fixed {
    pub(crate) negative: bool,
    pub(crate) int: Vec<u8>,
    pub(crate) frac: Vec<u8>,
}

impl Fixed {
    /// Whether every digit is zero.
    pub(crate) fn is_zero(&self) -> bool {
        self.int.iter().chain(&self.frac).all(|&d| d == 0)
    }

    /// Whether the fraction digits are all zero.
    pub(crate) fn is_integer(&self) -> bool {
        self.frac.iter().all(|&d| d == 0)
    }
}

impl Num {
    /// The decimal of `negative`, `digits` and `exponent`, normalized.
    fn new(negative: bool, digits: Vec<u8>, mut exponent: i64) -> Self {
        let mut digits: Vec<u8> = digits.into_iter().skip_while(|&d| d == 0).collect();
        while digits.last() == Some(&0) {
            let _zero = digits.pop();
            exponent += 1;
        }
        if digits.is_empty() {
            exponent = 0;
        }
        Self {
            negative,
            digits,
            exponent,
        }
    }

    /// Zero, of this sign.
    pub(crate) const fn zero(negative: bool) -> Self {
        Self {
            negative,
            digits: Vec::new(),
            exponent: 0,
        }
    }

    /// The value a `number-literal` writes (MF2 spec/functions/number.md); `None` for another
    /// text or an exponent past ±10^9.
    pub(crate) fn literal(text: &str) -> Option<Self> {
        Given::literal(text).map(|given| given.value)
    }

    /// A count's value.
    pub(crate) fn count(count: &Count) -> Self {
        Self::new(false, count.digits().bytes().map(|b| b - b'0').collect(), 0)
    }

    /// A decimal's value.
    pub(crate) fn decimal(decimal: Decimal) -> Self {
        let digits = decimal.units().unsigned_abs().to_string();
        Self::new(
            decimal.units() < 0,
            digits.bytes().map(|b| b - b'0').collect(),
            -i64::from(decimal.scale()),
        )
    }

    /// The value times 10^`power`.
    pub(crate) fn shifted(&self, power: i64) -> Self {
        let mut shifted = self.clone();
        if !shifted.digits.is_empty() {
            shifted.exponent += power;
        }
        shifted
    }

    /// The power of ten of its most significant digit; `None` for zero.
    pub(crate) fn magnitude(&self) -> Option<i64> {
        (!self.digits.is_empty()).then(|| self.exponent + self.digits.len() as i64 - 1)
    }

    /// The value plus the integer `addend`.
    pub(crate) fn plus(&self, addend: i64) -> Self {
        let other = Self::new(
            addend < 0,
            addend
                .unsigned_abs()
                .to_string()
                .bytes()
                .map(|b| b - b'0')
                .collect(),
            0,
        );
        let low = self.exponent.min(other.exponent).min(0);
        let (a, b) = (self.aligned(low), other.aligned(low));
        if self.negative == other.negative || self.digits.is_empty() || other.digits.is_empty() {
            let negative = if self.digits.is_empty() {
                other.negative
            } else {
                self.negative
            };
            return Self::new(negative, add(&a, &b), low);
        }
        match compare(&a, &b) {
            Ordering::Less => Self::new(other.negative, subtract(&b, &a), low),
            Ordering::Equal => Self::zero(false),
            Ordering::Greater => Self::new(self.negative, subtract(&a, &b), low),
        }
    }

    /// The digits of |value| / 10^`low`, an integer when `low` is at most its exponent.
    fn aligned(&self, low: i64) -> Vec<u8> {
        let zeros = usize::try_from(self.exponent - low).unwrap_or(0);
        let mut digits = self.digits.clone();
        digits.resize(digits.len() + zeros, 0);
        digits
    }

    /// The value rounded to a multiple of `increment` × 10^`magnitude` by `mode`.
    pub(crate) fn round(&self, magnitude: i64, increment: u32, mode: RoundingMode) -> Self {
        if self.digits.is_empty() {
            return self.clone();
        }
        let split = self.digits.len() as i64 - (magnitude - self.exponent);
        let (whole, rest): (Vec<u8>, &[u8]) = if split >= self.digits.len() as i64 {
            (self.aligned(magnitude), &[])
        } else if split <= 0 {
            (Vec::new(), &self.digits)
        } else {
            let at = usize::try_from(split).unwrap_or(0);
            let (whole, rest) = self.digits.split_at_checked(at).unwrap_or((&[], &[]));
            (whole.to_vec(), rest)
        };
        let leading = usize::try_from(-split).unwrap_or(0);
        let (quotient, remainder) = divide(&whole, increment);
        let half = half_compare(remainder, increment, leading, rest);
        let exact = remainder == 0 && rest.is_empty();
        let odd = quotient.last().is_some_and(|&d| d % 2 == 1);
        let quotient = if mode.away(self.negative, exact, half, odd) {
            add(&quotient, &[1])
        } else {
            quotient
        };
        Self::new(self.negative, multiply(&quotient, increment), magnitude)
    }

    /// Its digits with `min_fraction` fraction digits or more, the integer part one digit or
    /// more.
    pub(crate) fn fixed(&self, min_fraction: u32) -> Fixed {
        let low = self.exponent.min(-i64::from(min_fraction)).min(0);
        let digits = self.aligned(low);
        let fraction = usize::try_from(-low).unwrap_or(0);
        let int_len = digits.len().saturating_sub(fraction);
        let mut int = digits.get(..int_len).unwrap_or_default().to_vec();
        if int.is_empty() {
            int.push(0);
        }
        let mut frac = vec![0; fraction.saturating_sub(digits.len())];
        frac.extend_from_slice(digits.get(int_len..).unwrap_or_default());
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
    /// text or an exponent past ±10^9.
    pub(crate) fn literal(text: &str) -> Option<Self> {
        let (negative, rest) = match text.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, text),
        };
        let mantissa_end = rest.find(['e', 'E']).unwrap_or(rest.len());
        let (mantissa, exponent) = (rest.get(..mantissa_end)?, rest.get(mantissa_end..)?);
        let (whole, fraction) = match mantissa.split_once('.') {
            Some((whole, fraction)) => (whole, Some(fraction)),
            None => (mantissa, None),
        };
        let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
        if !digits(whole) || (whole.len() > 1 && whole.starts_with('0')) {
            return None;
        }
        if fraction.is_some_and(|f| !digits(f)) {
            return None;
        }
        let shift: i64 = match exponent.get(1..) {
            None => 0,
            Some(power) => {
                let (sign, power) = match power.strip_prefix('-') {
                    Some(power) => (-1, power),
                    None => (1, power.strip_prefix('+').unwrap_or(power)),
                };
                if !digits(power) || power.len() > 9 {
                    return None;
                }
                sign * power.parse::<i64>().ok()?
            }
        };
        let fraction = fraction.unwrap_or_default();
        let all = whole.bytes().chain(fraction.bytes()).map(|b| b - b'0');
        let exponent = shift - fraction.len() as i64;
        Some(Self {
            value: Num::new(negative, all.collect(), exponent),
            scale: u32::try_from((-exponent).max(0)).ok()?,
        })
    }

    /// A count, written without fraction digits.
    pub(crate) fn count(count: &Count) -> Self {
        Self {
            value: Num::count(count),
            scale: 0,
        }
    }

    /// A decimal, written with its scale.
    pub(crate) fn decimal(decimal: Decimal) -> Self {
        Self {
            value: Num::decimal(decimal),
            scale: u32::from(decimal.scale()),
        }
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
            value: self.value.round(0, 1, mode),
            scale: 0,
        }
    }

    /// The value plus the integer `addend`, written with as many fraction digits.
    pub(crate) fn plus(&self, addend: i64) -> Self {
        Self {
            value: self.value.plus(addend),
            scale: self.scale,
        }
    }

    /// The value times 100, written with two fraction digits fewer.
    pub(crate) fn percent(&self) -> Self {
        Self {
            value: self.value.shifted(2),
            scale: self.scale.saturating_sub(2),
        }
    }
}

/// How `remainder` + 0.`zeros``rest`, in units of 1, compares to half of `increment`.
fn half_compare(remainder: u32, increment: u32, zeros: usize, rest: &[u8]) -> Ordering {
    let twice = u64::from(remainder) * 2;
    let increment = u64::from(increment);
    if rest.is_empty() {
        return twice.cmp(&increment);
    }
    if twice >= increment {
        return Ordering::Greater;
    }
    if twice + 1 < increment {
        return Ordering::Less;
    }
    if zeros > 0 {
        return Ordering::Less;
    }
    match rest {
        [5] => Ordering::Equal,
        [first, ..] => first.cmp(&5).then(Ordering::Greater),
        [] => Ordering::Less,
    }
}

/// Compares two digit strings of one length as integers.
fn compare(a: &[u8], b: &[u8]) -> Ordering {
    let trim = |d: &[u8]| -> Vec<u8> { d.iter().copied().skip_while(|&x| x == 0).collect() };
    let (a, b) = (trim(a), trim(b));
    a.len().cmp(&b.len()).then_with(|| a.cmp(&b))
}

/// The sum of two digit strings.
fn add(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut sum = Vec::with_capacity(a.len().max(b.len()) + 1);
    let mut carry = 0;
    let (mut x, mut y) = (a.iter().rev(), b.iter().rev());
    loop {
        let (p, q) = (x.next(), y.next());
        if p.is_none() && q.is_none() {
            break;
        }
        let digit = p.copied().unwrap_or(0) + q.copied().unwrap_or(0) + carry;
        sum.push(digit % 10);
        carry = digit / 10;
    }
    if carry > 0 {
        sum.push(carry);
    }
    sum.reverse();
    sum
}

/// `a` − `b` for `a` ≥ `b`.
fn subtract(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut difference = Vec::with_capacity(a.len());
    let mut borrow = 0i8;
    let mut y = b.iter().rev();
    for &p in a.iter().rev() {
        let mut digit = p as i8 - y.next().copied().unwrap_or(0) as i8 - borrow;
        borrow = i8::from(digit < 0);
        if digit < 0 {
            digit += 10;
        }
        difference.push(digit as u8);
    }
    difference.reverse();
    difference
}

/// The quotient and remainder of a digit string divided by `divisor`, one or more.
fn divide(digits: &[u8], divisor: u32) -> (Vec<u8>, u32) {
    let divisor = NonZeroU64::from(NonZeroU32::new(divisor).unwrap_or(NonZeroU32::MIN));
    let mut remainder = 0u64;
    let quotient = digits
        .iter()
        .map(|&d| {
            let value = remainder * 10 + u64::from(d);
            remainder = Rem::rem(value, divisor);
            Div::div(value, divisor) as u8
        })
        .collect();
    (quotient, remainder as u32)
}

/// A digit string times `factor`.
fn multiply(digits: &[u8], factor: u32) -> Vec<u8> {
    let mut product = Vec::with_capacity(digits.len() + 5);
    let mut carry = 0u64;
    for &d in digits.iter().rev() {
        let value = u64::from(d) * u64::from(factor) + carry;
        product.push((value % 10) as u8);
        carry = value / 10;
    }
    while carry > 0 {
        product.push((carry % 10) as u8);
        carry /= 10;
    }
    product.reverse();
    product
}
