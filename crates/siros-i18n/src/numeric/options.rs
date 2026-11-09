//! MF2's numeric options (spec/functions/number.md) resolved along a call chain: each function's
//! operand, the options it inherits from an operand's call and those it discards, the value
//! steps of `:integer` and `:offset`, and the digit options after ECMA-402's
//! SetNumberFormatDigitOptions.

use crate::format::{CallTexts, Function as Called};
use crate::numeric::decimal::RoundingMode;
use crate::numeric::pattern::{Grouping, Pattern};
use crate::numeric::{Digits, Fraction, Rounding, Selection, SignDisplay, Step};

/// Why a chain's options do not resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Refused {
    /// A call of the chain is no numeric function.
    Operand,
    /// An option, by name.
    Option(String),
}

/// A numeric function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Function {
    Number,
    #[cfg(feature = "number")]
    Integer,
    Offset,
    Currency,
    Percent,
}

impl Function {
    /// The numeric function a call names; `None` for another family's.
    pub(crate) const fn of(function: Called) -> Option<Self> {
        match function {
            #[cfg(feature = "number")]
            Called::Number => Some(Self::Number),
            #[cfg(feature = "number")]
            Called::Integer => Some(Self::Integer),
            #[cfg(feature = "offset")]
            Called::Offset => Some(Self::Offset),
            #[cfg(feature = "currency")]
            Called::Currency => Some(Self::Currency),
            #[cfg(feature = "currency")]
            Called::Percent => Some(Self::Percent),
            _ => None,
        }
    }

    /// The options it reads; it ignores others.
    pub(crate) fn reads(self, name: &str) -> bool {
        const DIGITS: [&str; 7] = [
            "signDisplay",
            "useGrouping",
            "minimumSignificantDigits",
            "maximumSignificantDigits",
            "trailingZeroDisplay",
            "roundingPriority",
            "roundingMode",
        ];
        match self {
            Self::Number => {
                DIGITS.contains(&name)
                    || matches!(
                        name,
                        "select"
                            | "minimumIntegerDigits"
                            | "minimumFractionDigits"
                            | "maximumFractionDigits"
                            | "roundingIncrement"
                    )
            }
            #[cfg(feature = "number")]
            Self::Integer => matches!(
                name,
                "select"
                    | "signDisplay"
                    | "useGrouping"
                    | "minimumIntegerDigits"
                    | "maximumSignificantDigits"
            ),
            Self::Offset => matches!(name, "add" | "subtract"),
            Self::Currency => {
                DIGITS.contains(&name)
                    || matches!(
                        name,
                        "currency"
                            | "currencySign"
                            | "currencyDisplay"
                            | "minimumIntegerDigits"
                            | "fractionDigits"
                            | "roundingIncrement"
                    )
            }
            Self::Percent => {
                DIGITS.contains(&name)
                    || matches!(name, "minimumFractionDigits" | "maximumFractionDigits")
            }
        }
    }

    /// Whether it discards this option of its operand's resolved value.
    pub(crate) fn discards(self, name: &str) -> bool {
        match self {
            #[cfg(feature = "number")]
            Self::Integer => matches!(
                name,
                "minimumFractionDigits" | "maximumFractionDigits" | "minimumSignificantDigits"
            ),
            Self::Percent => matches!(
                name,
                "minimumIntegerDigits" | "roundingIncrement" | "select"
            ),
            Self::Number | Self::Offset | Self::Currency => false,
        }
    }
}

/// What a chain of calls starts from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Root {
    /// A number literal of the message, shown with the pattern's fraction digits unless an option
    /// sets them.
    Literal,
    /// An argument's number literal, shown with the fraction digits it is written with unless an
    /// option sets them.
    Argument,
}

/// A call's resolved value: what it starts from, the steps that change the value, its options
/// as resolved, and the function whose formatting applies.
#[derive(Debug, Clone)]
pub(crate) struct Resolved<'a> {
    pub(crate) root: Root,
    pub(crate) steps: Vec<Step>,
    options: Vec<(&'a str, &'a str)>,
    /// Whether an operand set `select`.
    select_inherited: bool,
    /// Whether an operand is a `:currency` value.
    pub(crate) currency_held: bool,
    pub(crate) function: Function,
    pub(crate) formatter: Function,
}

/// `digit-size-option = "0" / (("1"-"9") [DIGIT])`.
fn digit_size(text: &str) -> Option<u8> {
    let valid = matches!(
        text.as_bytes(),
        [b'0'] | [b'1'..=b'9'] | [b'1'..=b'9', b'0'..=b'9']
    );
    valid.then(|| text.parse().ok()).flatten()
}

/// Whether an option's value is one its function takes.
pub(crate) fn valid(name: &str, value: &str) -> bool {
    let size = digit_size(value);
    match name {
        "select" => matches!(value, "plural" | "ordinal" | "exact"),
        "signDisplay" => matches!(
            value,
            "auto" | "always" | "exceptZero" | "negative" | "never"
        ),
        "useGrouping" => matches!(value, "auto" | "always" | "never" | "min2"),
        "minimumIntegerDigits" | "minimumSignificantDigits" | "maximumSignificantDigits" => {
            size.is_some_and(|n| (1..=21).contains(&n))
        }
        "minimumFractionDigits" | "maximumFractionDigits" | "add" | "subtract" => size.is_some(),
        "fractionDigits" => value == "auto" || size.is_some(),
        "trailingZeroDisplay" => matches!(value, "auto" | "stripIfInteger"),
        "roundingPriority" => matches!(value, "auto" | "morePrecision" | "lessPrecision"),
        "roundingIncrement" => value.parse::<u16>().is_ok_and(|n| INCREMENTS.contains(&n)),
        "roundingMode" => RoundingMode::named(value).is_some(),
        #[cfg(feature = "currency")]
        "currency" => crate::numeric::currency::currency(value).is_some(),
        "currencySign" => matches!(value, "standard" | "accounting"),
        "currencyDisplay" => matches!(value, "narrowSymbol" | "symbol" | "name" | "code" | "never"),
        _ => true,
    }
}

/// The rounding increments `roundingIncrement` takes.
const INCREMENTS: [u16; 15] = [
    1, 2, 5, 10, 20, 25, 50, 100, 200, 250, 500, 1000, 2000, 2500, 5000,
];

fn option(refused: &str) -> Refused {
    Refused::Option(refused.to_owned())
}

impl<'a> Resolved<'a> {
    /// The value of a chain of calls, innermost first, on an operand of `root`.
    ///
    /// # Errors
    ///
    /// [`Refused`] for a call of another family, or an option its function refuses.
    pub(crate) fn of(root: Root, calls: &[CallTexts<'a>]) -> Result<Self, Refused> {
        let mut resolved: Option<Self> = None;
        for call in calls {
            let function = Function::of(call.function).ok_or(Refused::Operand)?;
            let mut current = match resolved {
                None => Self {
                    root,
                    steps: Vec::new(),
                    options: Vec::new(),
                    select_inherited: false,
                    currency_held: false,
                    function,
                    formatter: Function::Number,
                },
                Some(earlier) => earlier.operand_of(function)?,
            };
            current.apply(function, call)?;
            resolved = Some(current);
        }
        resolved.ok_or(Refused::Operand)
    }

    /// Applies a call of `function` to the value: its options, then its step.
    fn apply(&mut self, function: Function, call: &CallTexts<'a>) -> Result<(), Refused> {
        self.function = function;
        if function != Function::Offset {
            self.formatter = function;
        }
        for &(name, value) in &call.options {
            if function.reads(name) {
                if !valid(name, value) {
                    return Err(option(name));
                }
                if name == "currency" && self.currency_held {
                    return Err(option(name));
                }
                self.set(name, value);
            }
        }
        if self.select_inherited {
            return Err(option("select"));
        }
        if function == Function::Offset {
            let size = |name| self.get(name).and_then(digit_size).map(i64::from);
            let step = match (size("add"), size("subtract")) {
                (Some(add), None) => add,
                (None, Some(subtract)) => -subtract,
                (Some(_), Some(_)) => return Err(option("subtract")),
                (None, None) => return Err(option("add")),
            };
            self.steps.push(Step::Add(step));
        }
        Ok(())
    }

    fn set(&mut self, name: &'a str, value: &'a str) {
        self.options.retain(|(n, _)| *n != name);
        self.options.push((name, value));
    }

    /// The option `name`, when the formatting function reads it.
    pub(crate) fn get(&self, name: &str) -> Option<&'a str> {
        self.options
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| *v)
    }

    /// The value as the operand of `outer`: `:integer`'s step added, `:offset`'s options dropped
    /// and those `outer` discards. `:offset` adds its step where it is called.
    fn operand_of(mut self, outer: Function) -> Result<Self, Refused> {
        match self.function {
            #[cfg(feature = "number")]
            Function::Integer => {
                let mode = self.mode()?;
                self.steps.push(Step::Integer(mode));
            }
            Function::Currency => self.currency_held = true,
            Function::Number | Function::Offset | Function::Percent => {}
        }
        self.options
            .retain(|(name, _)| *name != "add" && *name != "subtract" && !outer.discards(name));
        self.select_inherited = self.get("select").is_some();
        Ok(self)
    }

    /// `roundingMode`, `halfExpand` when absent.
    pub(crate) fn mode(&self) -> Result<RoundingMode, Refused> {
        match self.read("roundingMode") {
            Some(name) => RoundingMode::named(name).ok_or_else(|| option("roundingMode")),
            None => Ok(RoundingMode::HalfExpand),
        }
    }

    /// The option `name`, when the formatting function reads it.
    fn read(&self, name: &str) -> Option<&'a str> {
        self.get(name).filter(|_| self.formatter.reads(name))
    }

    /// The option `name`, checked, when the formatting function reads it.
    fn checked(&self, name: &str) -> Result<Option<&'a str>, Refused> {
        match self.read(name) {
            Some(value) if !valid(name, value) => Err(option(name)),
            other => Ok(other),
        }
    }

    fn size(&self, name: &str) -> Result<Option<u8>, Refused> {
        Ok(self.checked(name)?.and_then(digit_size))
    }

    /// `signDisplay`.
    pub(crate) fn sign(&self) -> Result<SignDisplay, Refused> {
        let names = ["auto", "always", "exceptZero", "negative", "never"];
        Ok(match self.checked("signDisplay")? {
            None => SignDisplay::Auto,
            Some(value) => names
                .iter()
                .zip(SignDisplay::ALL)
                .find_map(|(&n, sign)| (n == value).then_some(sign))
                .ok_or_else(|| option("signDisplay"))?,
        })
    }

    /// `useGrouping` over the locale's minimum grouping digits.
    pub(crate) fn grouping(&self, locale: u8) -> Result<Grouping, Refused> {
        Ok(match self.checked("useGrouping")? {
            None | Some("auto") => Grouping::From(locale),
            Some("always") => Grouping::From(1),
            Some("min2") => Grouping::From(2),
            Some(_) => Grouping::Never,
        })
    }

    /// How a selector of this value matches; `None` for a value that selects no variant.
    pub(crate) fn selection(&self) -> Result<Option<Selection>, Refused> {
        Ok(match (self.formatter, self.checked("select")?) {
            (Function::Currency, _) => None,
            (Function::Percent, _) | (_, None | Some("plural")) => Some(Selection::Plural),
            (_, Some("ordinal")) => Some(Selection::Ordinal),
            (_, Some(_)) => Some(Selection::Exact),
        })
    }

    /// Whether an integer serializes as one for exact keys.
    pub(crate) fn integer_keys(&self) -> bool {
        [
            "minimumFractionDigits",
            "minimumIntegerDigits",
            "minimumSignificantDigits",
            "maximumSignificantDigits",
        ]
        .iter()
        .all(|name| self.read(name).is_none())
    }

    /// The digit options over a pattern's defaults (ECMA-402 SetNumberFormatDigitOptions).
    pub(crate) fn digits(&self, pattern: &Pattern) -> Result<Digits, Refused> {
        let min_integer = self.size("minimumIntegerDigits")?.unwrap_or(1);
        let increment = match self.checked("roundingIncrement")? {
            Some(text) => text.parse().map_err(|_| option("roundingIncrement"))?,
            None => 1u16,
        };
        let (mnsd, mxsd) = (
            self.size("minimumSignificantDigits")?,
            self.size("maximumSignificantDigits")?,
        );
        let has_sd = mnsd.is_some() || mxsd.is_some();
        let significant = match (mnsd, mxsd) {
            (None, None) => (1, 21),
            (min, max) => {
                let min = min.unwrap_or(1);
                let max = max.unwrap_or(21);
                if min > max {
                    return Err(option("maximumSignificantDigits"));
                }
                (min, max)
            }
        };
        let fraction = self.fraction(pattern)?;
        let rounding = match self.checked("roundingPriority")? {
            None | Some("auto") if has_sd => Rounding::Significant {
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
            Some(_) => Rounding::Less {
                fraction,
                significant,
            },
        };
        if increment != 1 {
            let fraction_only = matches!(rounding, Rounding::Fraction { .. });
            let fixed = fraction.0 == fraction.1 && fraction.0 != Fraction::Given;
            if !fraction_only || !fixed {
                return Err(option("roundingIncrement"));
            }
        }
        Ok(Digits {
            min_integer,
            rounding,
            mode: self.mode()?,
            strip_if_integer: self.checked("trailingZeroDisplay")? == Some("stripIfInteger"),
        })
    }

    /// The minimum and maximum fraction digits. An argument under `:number` defaults to the
    /// digits it is written with, as ICU4X's `DecimalFormatter` shows a `Decimal`; a literal of
    /// the message defaults to the pattern's, as ECMA-402's `Intl.NumberFormat`, which MF2's
    /// conformance suite follows.
    fn fraction(&self, pattern: &Pattern) -> Result<(Fraction, Fraction), Refused> {
        match self.formatter {
            #[cfg(feature = "number")]
            Function::Integer => return Ok((Fraction::Digits(0), Fraction::Digits(0))),
            Function::Currency => {
                return Ok(match self.checked("fractionDigits")? {
                    None | Some("auto") => (Fraction::Currency, Fraction::Currency),
                    Some(text) => {
                        let digits = digit_size(text).ok_or_else(|| option("fractionDigits"))?;
                        (Fraction::Digits(digits), Fraction::Digits(digits))
                    }
                });
            }
            Function::Number | Function::Percent | Function::Offset => {}
        }
        let (min, max) = (
            self.size("minimumFractionDigits")?,
            self.size("maximumFractionDigits")?,
        );
        if self.root == Root::Argument && self.formatter == Function::Number {
            return match (min, max) {
                (Some(min), Some(max)) if min > max => Err(option("maximumFractionDigits")),
                (min, max) => {
                    let given =
                        |digits: Option<u8>| digits.map_or(Fraction::Given, Fraction::Digits);
                    Ok((given(min), given(max)))
                }
            };
        }
        let (default_min, default_max) = (pattern.min_fraction, pattern.max_fraction);
        let (min, max) = match (min, max) {
            (None, None) => (default_min, default_max),
            (Some(min), None) => (min, default_max.max(min)),
            (None, Some(max)) => (default_min.min(max), max),
            (Some(min), Some(max)) if min > max => {
                return Err(option("maximumFractionDigits"));
            }
            (Some(min), Some(max)) => (min, max),
        };
        Ok((Fraction::Digits(min), Fraction::Digits(max)))
    }
}
