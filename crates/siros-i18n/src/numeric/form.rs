//! A resolved number's steps, rounding and digits.

use std::num::NonZeroU32;

use super::decimal::{Fixed, Given};
use super::pattern::{Pattern, Symbols};
use super::{Form, Fraction, Rounding, Step};
use crate::digit::{Digit, Numerals};

impl Form<'_> {
    /// The operand after the chain's steps.
    pub(super) fn stepped(&self, given: Given) -> Given {
        self.steps.iter().fold(given, |given, step| match *step {
            #[cfg(feature = "number")]
            Step::Integer(mode) => given.integer(mode),
            Step::Add(addend) => given.plus(addend),
        })
    }

    /// The number a call formats: the operand after the chain's steps, times 100 for
    /// `:percent`.
    pub(crate) fn value(&self, given: Given) -> Given {
        let stepped = self.stepped(given);
        if self.percent {
            stepped.percent()
        } else {
            stepped
        }
    }

    /// The number rounded by the digit options; `currency` the currency's fraction digits and
    /// rounding increment.
    pub(crate) fn rounded(&self, given: &Given, currency: (u8, NonZeroU32)) -> Fixed {
        let digits = self.digits;
        let (value, scale) = (given.value(), given.scale());
        let count = |f: Fraction| match f {
            Fraction::Digits(d) => u32::from(d),
            Fraction::Currency => u32::from(currency.0),
            Fraction::Given => scale,
        };
        // An option given beside a default of the operand's scale bounds that default.
        let bounds = |min: Fraction, max: Fraction| match (min, max) {
            (Fraction::Given, Fraction::Digits(max)) => (scale.min(u32::from(max)), u32::from(max)),
            (Fraction::Digits(min), Fraction::Given) => (u32::from(min), scale.max(u32::from(min))),
            (min, max) => (count(min), count(max)),
        };
        let increment = |f: Fraction| match f {
            Fraction::Currency => currency.1,
            Fraction::Digits(_) | Fraction::Given => NonZeroU32::MIN,
        };
        let fixed = |min: Fraction, max: Fraction, inc: NonZeroU32| {
            let inc = if inc == NonZeroU32::MIN {
                increment(max)
            } else {
                inc
            };
            let (min, max) = bounds(min, max);
            let rounded = value.round(-i64::from(max), inc, digits.mode);
            (-i64::from(max), rounded.fixed(-i64::from(min)))
        };
        // Zero's magnitude is 0: ECMA-402 ToRawPrecision (16.5.7), step 2.b.
        let significant = |min: u8, max: u8| {
            let magnitude = value.magnitude().unwrap_or(0);
            let rounded = value.round(magnitude - i64::from(max) + 1, NonZeroU32::MIN, digits.mode);
            let after = rounded.magnitude().unwrap_or(0);
            (
                after - i64::from(max) + 1,
                rounded.fixed(after + 1 - i64::from(min)),
            )
        };
        let mut result = match digits.rounding {
            Rounding::Fraction {
                min,
                max,
                increment,
            } => fixed(min, max, increment).1,
            Rounding::Significant { min, max } => significant(min, max).1,
            Rounding::More {
                fraction,
                significant: s,
            } => {
                let (fm, f) = fixed(fraction.0, fraction.1, NonZeroU32::MIN);
                let (sm, s) = significant(s.0, s.1);
                if sm <= fm { s } else { f }
            }
            Rounding::Less {
                fraction,
                significant: s,
            } => {
                let (fm, f) = fixed(fraction.0, fraction.1, NonZeroU32::MIN);
                let (sm, s) = significant(s.0, s.1);
                if sm <= fm { f } else { s }
            }
        };
        if digits.strip_if_integer && result.is_integer() {
            result.frac.clear();
        }
        let pad = usize::from(digits.min_integer).saturating_sub(result.int.len());
        if pad > 0 {
            let mut int = vec![Digit::Zero; pad];
            int.append(&mut result.int);
            result.int = int;
        }
        result
    }

    /// Writes a rounded number with the pattern; `currency` stands for `¤`.
    pub(crate) fn write(
        &self,
        fixed: &Fixed,
        pattern: &Pattern,
        symbols: &Symbols,
        currency: &str,
        out: &mut String,
    ) {
        let shown = self.sign.shown(fixed);
        pattern.write(fixed, shown, symbols, self.grouping, currency, out);
    }

    /// The number's serialization for exact keys.
    pub(super) fn serial(&self, fixed: &Fixed) -> String {
        if self.integer_keys && fixed.is_integer() {
            let int: String = fixed
                .int
                .iter()
                .map(|d| Numerals::ASCII.digit(*d))
                .collect();
            let int = int.trim_start_matches('0');
            return match (fixed.negative, int.is_empty()) {
                (_, true) => "0".to_owned(),
                (true, false) => format!("-{int}"),
                (false, false) => int.to_owned(),
            };
        }
        fixed.plain()
    }
}
