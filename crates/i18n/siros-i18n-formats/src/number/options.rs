//! MF2's numeric options (spec/functions/number.md, spec/functions/currency.md) over a format's
//! number field: a format's settings give their defaults, a call's options override them. The
//! digit options resolve after ECMA-402's SetNumberFormatDigitOptions, and the number rounds once.

use std::num::NonZeroU32;

use crate::digit::{Digit, Numerals};
use crate::number::decimal::{Fixed, Number, RoundingMode};

/// A numeric option.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Opt {
    Select,
    SignDisplay,
    UseGrouping,
    MinimumIntegerDigits,
    MinimumFractionDigits,
    MaximumFractionDigits,
    FractionDigits,
    MinimumSignificantDigits,
    MaximumSignificantDigits,
    TrailingZeroDisplay,
    RoundingPriority,
    RoundingIncrement,
    RoundingMode,
}

/// The rounding increments `roundingIncrement` takes.
const INCREMENTS: [u16; 15] = [
    1, 2, 5, 10, 20, 25, 50, 100, 200, 250, 500, 1000, 2000, 2500, 5000,
];

/// `digit-size-option = "0" / (("1"-"9") [DIGIT])`.
fn digit_size(text: &str) -> Option<u8> {
    match *text.as_bytes() {
        [units @ b'0'..=b'9'] => Some(units - b'0'),
        [tens @ b'1'..=b'9', units @ b'0'..=b'9'] => Some((tens - b'0') * 10 + (units - b'0')),
        _ => None,
    }
}

/// A digit size from 1 to 21: a count of integer or significant digits.
fn digit_count(text: &str) -> Option<u8> {
    digit_size(text).filter(|n| (1..=21).contains(n))
}

impl Opt {
    const ALL: [Self; 13] = [
        Self::Select,
        Self::SignDisplay,
        Self::UseGrouping,
        Self::MinimumIntegerDigits,
        Self::MinimumFractionDigits,
        Self::MaximumFractionDigits,
        Self::FractionDigits,
        Self::MinimumSignificantDigits,
        Self::MaximumSignificantDigits,
        Self::TrailingZeroDisplay,
        Self::RoundingPriority,
        Self::RoundingIncrement,
        Self::RoundingMode,
    ];

    /// Its name.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Select => "select",
            Self::SignDisplay => "signDisplay",
            Self::UseGrouping => "useGrouping",
            Self::MinimumIntegerDigits => "minimumIntegerDigits",
            Self::MinimumFractionDigits => "minimumFractionDigits",
            Self::MaximumFractionDigits => "maximumFractionDigits",
            Self::FractionDigits => "fractionDigits",
            Self::MinimumSignificantDigits => "minimumSignificantDigits",
            Self::MaximumSignificantDigits => "maximumSignificantDigits",
            Self::TrailingZeroDisplay => "trailingZeroDisplay",
            Self::RoundingPriority => "roundingPriority",
            Self::RoundingIncrement => "roundingIncrement",
            Self::RoundingMode => "roundingMode",
        }
    }

    /// The option `name` names.
    pub(crate) fn named(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|opt| opt.name() == name)
    }

    /// Whether the option takes `text`.
    pub(crate) fn takes(self, text: &str) -> bool {
        match self {
            Self::Select => matches!(text, "plural" | "ordinal" | "exact"),
            Self::SignDisplay => SignDisplay::named(text).is_some(),
            Self::UseGrouping => matches!(text, "auto" | "always" | "never" | "min2"),
            Self::MinimumIntegerDigits
            | Self::MinimumSignificantDigits
            | Self::MaximumSignificantDigits => digit_count(text).is_some(),
            Self::MinimumFractionDigits | Self::MaximumFractionDigits => digit_size(text).is_some(),
            Self::FractionDigits => text == "auto" || digit_size(text).is_some(),
            Self::TrailingZeroDisplay => matches!(text, "auto" | "stripIfInteger"),
            Self::RoundingPriority => matches!(text, "auto" | "morePrecision" | "lessPrecision"),
            Self::RoundingIncrement => text.parse::<u16>().is_ok_and(|n| INCREMENTS.contains(&n)),
            Self::RoundingMode => RoundingMode::named(text).is_some(),
        }
    }
}

/// `signDisplay`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignDisplay {
    Auto,
    Always,
    ExceptZero,
    Negative,
    Never,
}

impl SignDisplay {
    fn named(name: &str) -> Option<Self> {
        Some(match name {
            "auto" => Self::Auto,
            "always" => Self::Always,
            "exceptZero" => Self::ExceptZero,
            "negative" => Self::Negative,
            "never" => Self::Never,
            _ => return None,
        })
    }

    /// The sign a rounded number shows (ECMA-402's `signDisplay`): negative zero shows its
    /// minus under `auto` and `always`.
    pub(crate) fn shown(self, fixed: &Fixed) -> Shown {
        let (negative, zero) = (fixed.negative, fixed.is_zero());
        match self {
            Self::Auto | Self::Always if negative => Shown::Minus,
            Self::Always => Shown::Plus,
            Self::ExceptZero | Self::Negative if zero => Shown::None,
            Self::ExceptZero | Self::Negative if negative => Shown::Minus,
            Self::ExceptZero => Shown::Plus,
            Self::Auto | Self::Negative | Self::Never => Shown::None,
        }
    }
}

/// The sign a number shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Shown {
    None,
    Minus,
    Plus,
}

impl Shown {
    /// The name a guard compares it with.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Minus => "minus",
            Self::Plus => "plus",
        }
    }
}

/// Whether and when the integer digits group: never, or from this many digits in the highest
/// group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Grouping {
    Never,
    From(u8),
}

/// How a selector matches its keys: exact keys, then the cardinal or ordinal category, or
/// exact keys alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Select {
    Plural,
    Ordinal,
    Exact,
}

/// A count of fraction digits: fixed, or those the number is written with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fraction {
    Digits(u8),
    Given,
}

/// How a number rounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rounding {
    /// To fraction digits: `min` to `max`, by multiples of `increment` at the last.
    Fraction {
        min: Fraction,
        max: Fraction,
        increment: NonZeroU32,
    },
    /// To significant digits.
    Significant { min: u8, max: u8 },
    /// Both, the result of the smaller rounding magnitude kept, significant digits on a tie.
    More {
        fraction: (Fraction, Fraction),
        significant: (u8, u8),
    },
    /// Both, the result of the larger rounding magnitude kept, fraction digits on a tie.
    Less {
        fraction: (Fraction, Fraction),
        significant: (u8, u8),
    },
}

/// The digit options of a number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Digits {
    min_integer: u8,
    rounding: Rounding,
    mode: RoundingMode,
    strip_if_integer: bool,
}

/// The numeric options of one resolution: the format's texts, and the call's, which override
/// them. An option's text is checked before it joins either list.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Options<'a> {
    pub(crate) format: &'a [(Opt, &'a str)],
    pub(crate) call: &'a [(Opt, &'a str)],
}

/// The option a resolution refuses, by the rule of its text or its combination.
pub(crate) type Refused = Opt;

fn find<'a>(list: &[(Opt, &'a str)], opt: Opt) -> Option<&'a str> {
    list.iter()
        .find(|(given, _)| *given == opt)
        .map(|(_, text)| *text)
}

impl<'a> Options<'a> {
    /// The option's text: the call's, else the format's.
    pub(crate) fn get(&self, opt: Opt) -> Option<&'a str> {
        find(self.call, opt).or_else(|| find(self.format, opt))
    }

    fn size(&self, opt: Opt, text: Option<&str>) -> Result<Option<u8>, Refused> {
        text.map(|text| digit_size(text).ok_or(opt)).transpose()
    }

    /// `signDisplay`, `auto` when absent.
    pub(crate) fn sign(&self) -> Result<SignDisplay, Refused> {
        match self.get(Opt::SignDisplay) {
            None => Ok(SignDisplay::Auto),
            Some(text) => SignDisplay::named(text).ok_or(Opt::SignDisplay),
        }
    }

    /// `useGrouping` over the locale's minimum grouping digits.
    pub(crate) fn grouping(&self, locale: u8) -> Result<Grouping, Refused> {
        Ok(match self.get(Opt::UseGrouping) {
            None | Some("auto") => Grouping::From(locale),
            Some("always") => Grouping::From(1),
            Some("min2") => Grouping::From(2),
            Some("never") => Grouping::Never,
            Some(_) => return Err(Opt::UseGrouping),
        })
    }

    /// How a selector of this number matches; `None` for a format that sets no `select`.
    pub(crate) fn select(&self) -> Result<Option<Select>, Refused> {
        Ok(match self.get(Opt::Select) {
            None => None,
            Some("plural") => Some(Select::Plural),
            Some("ordinal") => Some(Select::Ordinal),
            Some("exact") => Some(Select::Exact),
            Some(_) => return Err(Opt::Select),
        })
    }

    /// Whether an integer serializes as one for exact keys: no option sets a count of digits.
    pub(crate) fn integer_keys(&self) -> bool {
        [
            Opt::MinimumFractionDigits,
            Opt::MinimumIntegerDigits,
            Opt::MinimumSignificantDigits,
            Opt::MaximumSignificantDigits,
        ]
        .into_iter()
        .all(|opt| self.get(opt).is_none())
    }

    /// `roundingMode`, `halfExpand` when absent.
    fn mode(&self) -> Result<RoundingMode, Refused> {
        match self.get(Opt::RoundingMode) {
            Some(name) => RoundingMode::named(name).ok_or(Opt::RoundingMode),
            None => Ok(RoundingMode::HalfExpand),
        }
    }

    /// The minimum and maximum fraction digits (ECMA-402 SetNumberFormatDigitOptions): the
    /// format's give the defaults, the number's own where it gives none, and the call's
    /// override them; `fractionDigits` sets both.
    fn fraction(&self) -> Result<(Fraction, Fraction), Refused> {
        let default = |opt| {
            Ok::<_, Refused>(
                self.size(opt, find(self.format, opt))?
                    .map_or(Fraction::Given, Fraction::Digits),
            )
        };
        let (default_min, default_max) = (
            default(Opt::MinimumFractionDigits)?,
            default(Opt::MaximumFractionDigits)?,
        );
        match self.get(Opt::FractionDigits) {
            None | Some("auto") => {}
            Some(text) => {
                let digits = digit_size(text).ok_or(Opt::FractionDigits)?;
                return Ok((Fraction::Digits(digits), Fraction::Digits(digits)));
            }
        }
        let (min, max) = (
            self.size(
                Opt::MinimumFractionDigits,
                find(self.call, Opt::MinimumFractionDigits),
            )?,
            self.size(
                Opt::MaximumFractionDigits,
                find(self.call, Opt::MaximumFractionDigits),
            )?,
        );
        Ok(match (min, max) {
            (None, None) => (default_min, default_max),
            (Some(min), None) => (
                Fraction::Digits(min),
                match default_max {
                    Fraction::Digits(max) => Fraction::Digits(max.max(min)),
                    Fraction::Given => Fraction::Given,
                },
            ),
            (None, Some(max)) => (
                match default_min {
                    Fraction::Digits(min) => Fraction::Digits(min.min(max)),
                    Fraction::Given => Fraction::Given,
                },
                Fraction::Digits(max),
            ),
            (Some(min), Some(max)) if min > max => return Err(Opt::MaximumFractionDigits),
            (Some(min), Some(max)) => (Fraction::Digits(min), Fraction::Digits(max)),
        })
    }

    /// The digit options.
    pub(crate) fn digits(&self) -> Result<Digits, Refused> {
        let count = |opt| {
            self.get(opt)
                .map(|text| digit_count(text).ok_or(opt))
                .transpose()
        };
        let min_integer = count(Opt::MinimumIntegerDigits)?.unwrap_or(1);
        let increment = match self.get(Opt::RoundingIncrement) {
            Some(text) => text
                .parse::<u32>()
                .ok()
                .and_then(NonZeroU32::new)
                .ok_or(Opt::RoundingIncrement)?,
            None => NonZeroU32::MIN,
        };
        let (mnsd, mxsd) = (
            count(Opt::MinimumSignificantDigits)?,
            count(Opt::MaximumSignificantDigits)?,
        );
        let has_significant = mnsd.is_some() || mxsd.is_some();
        let significant = (mnsd.unwrap_or(1), mxsd.unwrap_or(21));
        if significant.0 > significant.1 {
            return Err(Opt::MaximumSignificantDigits);
        }
        let fraction = self.fraction()?;
        let rounding = match self.get(Opt::RoundingPriority) {
            None | Some("auto") if has_significant => Rounding::Significant {
                min: significant.0,
                max: significant.1,
            },
            None | Some("auto") => Rounding::Fraction {
                min: fraction.0,
                max: fraction.1,
                increment,
            },
            Some("morePrecision") => Rounding::More {
                fraction,
                significant,
            },
            Some("lessPrecision") => Rounding::Less {
                fraction,
                significant,
            },
            Some(_) => return Err(Opt::RoundingPriority),
        };
        if increment != NonZeroU32::MIN {
            let fraction_only = matches!(rounding, Rounding::Fraction { .. });
            let fixed = fraction.0 == fraction.1 && fraction.0 != Fraction::Given;
            if !fraction_only || !fixed {
                return Err(Opt::RoundingIncrement);
            }
        }
        let strip_if_integer = match self.get(Opt::TrailingZeroDisplay) {
            None | Some("auto") => false,
            Some("stripIfInteger") => true,
            Some(_) => return Err(Opt::TrailingZeroDisplay),
        };
        Ok(Digits {
            min_integer,
            rounding,
            mode: self.mode()?,
            strip_if_integer,
        })
    }
}

impl Digits {
    /// `number` rounded by the options, its integer digits padded to their minimum.
    pub(crate) fn round(&self, number: &Number) -> Fixed {
        let (value, scale) = (number.value(), number.scale());
        let count = |f: Fraction| match f {
            Fraction::Digits(d) => u32::from(d),
            Fraction::Given => scale,
        };
        // An option given beside a default of the number's scale bounds that default.
        let bounds = |min: Fraction, max: Fraction| match (min, max) {
            (Fraction::Given, Fraction::Digits(max)) => (scale.min(u32::from(max)), u32::from(max)),
            (Fraction::Digits(min), Fraction::Given) => (u32::from(min), scale.max(u32::from(min))),
            (min, max) => (count(min), count(max)),
        };
        let fixed = |min: Fraction, max: Fraction, increment: NonZeroU32| {
            let (min, max) = bounds(min, max);
            let rounded = value.round(-i64::from(max), increment, self.mode);
            (-i64::from(max), rounded.fixed(-i64::from(min)))
        };
        // Zero's magnitude is 0: ECMA-402 ToRawPrecision (16.5.7), step 2.b.
        let significant = |min: u8, max: u8| {
            let magnitude = value.magnitude().unwrap_or(0);
            let rounded = value.round(magnitude - i64::from(max) + 1, NonZeroU32::MIN, self.mode);
            let after = rounded.magnitude().unwrap_or(0);
            (
                after - i64::from(max) + 1,
                rounded.fixed(after + 1 - i64::from(min)),
            )
        };
        let mut result = match self.rounding {
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
        if self.strip_if_integer && result.is_integer() {
            result.frac.clear();
        }
        let pad = usize::from(self.min_integer).saturating_sub(result.int.len());
        if pad > 0 {
            let mut int = vec![Digit::Zero; pad];
            int.append(&mut result.int);
            result.int = int;
        }
        result
    }
}

/// The serialization of a rounded number an exact key equals: an integer as one when
/// `integer_keys`, else its digits as rounded.
pub(crate) fn serial(fixed: &Fixed, integer_keys: bool) -> String {
    if integer_keys && fixed.is_integer() {
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

/// Grouping sizes: the group nearest the decimal separator's, and each group's before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Groups {
    pub(crate) primary: u8,
    pub(crate) secondary: u8,
}

impl Groups {
    /// Whether a group separator stands before the digit with `left` digits from it to the end.
    fn boundary(self, left: usize) -> bool {
        let primary = usize::from(self.primary);
        let secondary = usize::from(self.secondary);
        left == primary || (left > primary && (left - primary).is_multiple_of(secondary))
    }
}

/// Writes the integer digits of `fixed`, grouped by `groups` under `grouping` with `separator`.
pub(crate) fn write_int(
    fixed: &Fixed,
    numerals: Numerals,
    groups: Option<(Groups, &str)>,
    grouping: Grouping,
    out: &mut String,
) {
    let len = fixed.int.len();
    let groups = match grouping {
        Grouping::Never => None,
        Grouping::From(minimum) => {
            groups.filter(|(groups, _)| len >= usize::from(groups.primary) + usize::from(minimum))
        }
    };
    for (index, d) in fixed.int.iter().enumerate() {
        if let Some((groups, separator)) = groups
            && index > 0
            && groups.boundary(len - index)
        {
            out.push_str(separator);
        }
        out.push(numerals.digit(*d));
    }
}

/// Writes the fraction digits of `fixed` after `separator`; nothing for a number without any.
pub(crate) fn write_frac(fixed: &Fixed, numerals: Numerals, separator: &str, out: &mut String) {
    if !fixed.frac.is_empty() {
        out.push_str(separator);
        out.extend(fixed.frac.iter().map(|d| numerals.digit(*d)));
    }
}
