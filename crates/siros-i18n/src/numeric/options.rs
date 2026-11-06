//! MF2's numeric options (spec/functions/number.md) resolved along a call chain: each function's
//! operand, the options it inherits from an operand's call and those it discards, the value
//! steps of `:integer` and `:offset`, and the digit options after ECMA-402's
//! SetNumberFormatDigitOptions.

use siros_explain::{ArgKind, Currency};

use crate::error::Refusal;
use crate::format::{Call, Operand};
use crate::numeric::decimal::{Num, RoundingMode};
use crate::numeric::pattern::{Grouping, Pattern};
use crate::numeric::{Digits, Fraction, Rounding, Selection, SignDisplay, Step};

/// A numeric function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Function {
    Number,
    Integer,
    Offset,
    Currency,
    Percent,
}

impl Function {
    pub(crate) fn named(name: &str) -> Option<Self> {
        Some(match name {
            "number" => Self::Number,
            "integer" => Self::Integer,
            "offset" => Self::Offset,
            "currency" => Self::Currency,
            "percent" => Self::Percent,
            _ => return None,
        })
    }

    /// The options it reads; it ignores others.
    fn reads(self, name: &str) -> bool {
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
    fn discards(self, name: &str) -> bool {
        match self {
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
    /// A number literal.
    Literal,
    /// A typed number: a count or a decimal, shown with the fraction digits it is written with
    /// unless an option sets them.
    Number,
    /// A text, read as a `number-literal` when the placeholder renders.
    Text,
    /// An amount in a currency.
    Amount,
    /// A currency alone.
    Currency,
}

/// A call's resolved value: what it starts from, the steps that change the value, its options
/// as resolved, and the function whose formatting applies.
#[derive(Debug, Clone)]
pub(crate) struct Resolved {
    pub(crate) root: Root,
    pub(crate) steps: Vec<Step>,
    options: Vec<(String, String)>,
    /// Whether an operand set `select`.
    select_inherited: bool,
    /// Whether an operand holds a currency: an amount, or a `:currency` value.
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
fn valid(name: &str, value: &str) -> bool {
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
        "currency" => currency(value).is_some(),
        "currencySign" => matches!(value, "standard" | "accounting"),
        "currencyDisplay" => matches!(value, "narrowSymbol" | "symbol" | "name" | "code" | "never"),
        _ => true,
    }
}

/// The rounding increments `roundingIncrement` takes.
const INCREMENTS: [u16; 15] = [
    1, 2, 5, 10, 20, 25, 50, 100, 200, 250, 500, 1000, 2000, 2500, 5000,
];

/// The ISO 4217 currency of a well-formed code, in any case.
pub(crate) fn currency(code: &str) -> Option<Currency> {
    let upper = code.to_ascii_uppercase();
    (upper.len() == 3 && upper.bytes().all(|b| b.is_ascii_uppercase()))
        .then(|| Currency::from_code(&upper))
        .flatten()
}

fn option(refused: &str) -> Refusal {
    Refusal::Option {
        option: refused.to_owned(),
    }
}

impl Resolved {
    /// The call's resolved value.
    pub(crate) fn of(call: &Call<'_>) -> Result<Self, Refusal> {
        let function = Function::named(call.function()).ok_or(Refusal::Operand)?;
        let base = |root| Self {
            root,
            steps: Vec::new(),
            options: Vec::new(),
            select_inherited: false,
            currency_held: root == Root::Amount,
            function,
            formatter: Function::Number,
        };
        let mut resolved = match call.operand() {
            Operand::None => return Err(Refusal::Operand),
            Operand::Literal(text) => {
                if Num::literal(text).is_none() {
                    return Err(Refusal::Operand);
                }
                base(Root::Literal)
            }
            Operand::Argument(ArgKind::Count | ArgKind::Decimal) => base(Root::Number),
            Operand::Argument(ArgKind::Raw | ArgKind::Text) => base(Root::Text),
            Operand::Argument(ArgKind::Amount) => base(Root::Amount),
            Operand::Argument(ArgKind::Currency) => base(Root::Currency),
            Operand::Argument(_) => return Err(Refusal::Operand),
            Operand::Call(inner) => Self::of(inner)?.operand_of(function)?,
        };
        resolved.function = function;
        if function != Function::Offset {
            resolved.formatter = function;
        }
        for entry in call.options().entries() {
            let (name, value) = (*entry.key(), *entry.value());
            if function.reads(name) {
                if !valid(name, value) {
                    return Err(option(name));
                }
                if name == "currency" && resolved.currency_held {
                    return Err(option(name));
                }
                resolved.set(name, value);
            }
        }
        if resolved.select_inherited {
            return Err(option("select"));
        }
        if function == Function::Offset {
            let size = |name| resolved.get(name).and_then(digit_size).map(i64::from);
            let step = match (size("add"), size("subtract")) {
                (Some(add), None) => add,
                (None, Some(subtract)) => -subtract,
                (Some(_), Some(_)) => return Err(option("subtract")),
                (None, None) => return Err(option("add")),
            };
            resolved.steps.push(Step::Add(step));
        }
        Ok(resolved)
    }

    fn set(&mut self, name: &str, value: &str) {
        self.options.retain(|(n, _)| n != name);
        self.options.push((name.to_owned(), value.to_owned()));
    }

    /// The option `name`, when the formatting function reads it.
    pub(crate) fn get(&self, name: &str) -> Option<&str> {
        self.options
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    /// The value as the operand of `outer`: `:integer`'s step added, `:offset`'s options dropped
    /// and those `outer` discards. `:offset` adds its step where it is called.
    fn operand_of(mut self, outer: Function) -> Result<Self, Refusal> {
        match self.function {
            Function::Integer => {
                let mode = self.mode()?;
                self.steps.push(Step::Integer(mode));
            }
            Function::Currency => self.currency_held = true,
            Function::Number | Function::Offset | Function::Percent => {}
        }
        self.options
            .retain(|(name, _)| name != "add" && name != "subtract" && !outer.discards(name));
        self.select_inherited = self.get("select").is_some();
        Ok(self)
    }

    /// `roundingMode`, `halfExpand` when absent.
    pub(crate) fn mode(&self) -> Result<RoundingMode, Refusal> {
        match self.read("roundingMode") {
            Some(name) => RoundingMode::named(name).ok_or_else(|| option("roundingMode")),
            None => Ok(RoundingMode::HalfExpand),
        }
    }

    /// The option `name`, when the formatting function reads it.
    fn read(&self, name: &str) -> Option<&str> {
        self.get(name).filter(|_| self.formatter.reads(name))
    }

    /// The option `name`, checked, when the formatting function reads it.
    fn checked(&self, name: &str) -> Result<Option<&str>, Refusal> {
        match self.read(name) {
            Some(value) if !valid(name, value) => Err(option(name)),
            other => Ok(other),
        }
    }

    fn size(&self, name: &str) -> Result<Option<u8>, Refusal> {
        Ok(self.checked(name)?.and_then(digit_size))
    }

    /// `signDisplay`.
    pub(crate) fn sign(&self) -> Result<SignDisplay, Refusal> {
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
    pub(crate) fn grouping(&self, locale: u8) -> Result<Grouping, Refusal> {
        Ok(match self.checked("useGrouping")? {
            None | Some("auto") => Grouping::From(locale),
            Some("always") => Grouping::From(1),
            Some("min2") => Grouping::From(2),
            Some(_) => Grouping::Never,
        })
    }

    /// How a selector of this value matches.
    pub(crate) fn selection(&self) -> Result<Selection, Refusal> {
        Ok(match (self.formatter, self.checked("select")?) {
            (Function::Currency, _) => Selection::None,
            (Function::Percent, _) | (_, None | Some("plural")) => Selection::Plural,
            (_, Some("ordinal")) => Selection::Ordinal,
            (_, Some(_)) => Selection::Exact,
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
    pub(crate) fn digits(&self, pattern: &Pattern) -> Result<Digits, Refusal> {
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

    /// The minimum and maximum fraction digits. A typed number under `:number` defaults to the
    /// digits it is written with, as ICU4X's `DecimalFormatter` shows a `Decimal`; a literal and
    /// a text default to the pattern's, as ECMA-402's `Intl.NumberFormat`, which MF2's
    /// conformance suite follows.
    fn fraction(&self, pattern: &Pattern) -> Result<(Fraction, Fraction), Refusal> {
        match self.formatter {
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
        if self.root == Root::Number && self.formatter == Function::Number {
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
