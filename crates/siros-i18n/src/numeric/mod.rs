//! What the numeric formats share: MF2's numeric operands and options (spec/functions/number.md),
//! resolved along a call chain when a module loads, and the compiled placeholder that formats and
//! selects a number when it renders. `:number`, `:integer`, `:offset`, `:currency` and `:percent`
//! all compile into it.

#[cfg(feature = "load")]
pub(crate) mod compile;
#[cfg(feature = "currency")]
pub(crate) mod currency;
pub(crate) mod decimal;
#[cfg(feature = "load")]
pub(crate) mod options;
pub(crate) mod pattern;
pub(crate) mod plural;

use crate::bytes::Reader;
#[cfg(feature = "load")]
use crate::bytes::Writer;
use crate::error::RenderError;
use crate::format::{Direction, FormatId, Input, VariantKey, VariantKeys};
use crate::sink::Sink;
use decimal::{Fixed, Given, Num, RoundingMode};
use pattern::{Grouping, Pattern, Shown, Symbols};
use plural::{Category, Operands};

/// A step of a call chain that changes the value: `:integer`'s rounding, `:offset`'s addition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Step {
    Integer(RoundingMode),
    Add(i64),
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
    pub(crate) const ALL: [Self; 5] = [
        Self::Auto,
        Self::Always,
        Self::ExceptZero,
        Self::Negative,
        Self::Never,
    ];

    /// The sign a rounded number shows (ECMA-402's `signDisplay`): negative zero shows its
    /// minus under `auto` and `always`.
    fn shown(self, fixed: &Fixed) -> Shown {
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

/// A count of fraction digits: fixed, the currency's, or those the operand is written with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Fraction {
    Digits(u8),
    Currency,
    Given,
}

/// How a number rounds before it formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rounding {
    /// To fraction digits: `min` to `max`, by multiples of `increment` at the last.
    Fraction {
        min: Fraction,
        max: Fraction,
        increment: u16,
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

/// How a selector matches its keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Selection {
    /// Not a selector.
    None,
    /// Exact keys alone.
    Exact,
    /// Exact keys, then the cardinal plural category.
    Plural,
    /// Exact keys, then the ordinal plural category.
    Ordinal,
}

/// The digit options of a formatted number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Digits {
    pub(crate) min_integer: u8,
    pub(crate) rounding: Rounding,
    pub(crate) mode: RoundingMode,
    pub(crate) strip_if_integer: bool,
}

/// A compiled numeric placeholder, as its render half reads it.
#[derive(Debug)]
pub(crate) struct Form<'a> {
    pub(crate) steps: Vec<Step>,
    pub(crate) sign: SignDisplay,
    pub(crate) grouping: Grouping,
    pub(crate) digits: Digits,
    pub(crate) percent: bool,
    pub(crate) selection: Selection,
    /// Whether an integer serializes as one for exact keys: none of the options that set digit
    /// counts is given.
    pub(crate) integer_keys: bool,
    pub(crate) direction: Direction,
    pub(crate) symbols: Symbols,
    pub(crate) pattern: Pattern,
    /// The cardinal rules, compiled.
    pub(crate) cardinal: Reader<'a>,
    /// The ordinal rules, compiled.
    pub(crate) ordinal: Reader<'a>,
    /// What a currency placeholder adds; the rest of the bytes.
    #[cfg(feature = "currency")]
    pub(crate) rest: Reader<'a>,
}

/// The number a numeric placeholder's input holds, and its currency when it holds one.
pub(crate) struct NumericInput {
    pub(crate) number: Given,
    #[cfg(feature = "currency")]
    pub(crate) currency: Option<siros_explain::Currency>,
}

impl NumericInput {
    /// The number `input` holds.
    pub(crate) fn of(input: &Input<'_>) -> Result<Self, RenderError> {
        use siros_explain::Value;
        let bad = RenderError::Message("bad-operand");
        let number = match input {
            Input::Literal(text) | Input::Text(text) => Given::literal(text).ok_or(bad)?,
            Input::Value(Value::Count(count)) => Given::count(count),
            Input::Value(Value::Decimal(decimal)) => Given::decimal(*decimal),
            Input::Value(Value::Amount(amount)) => Given::decimal(amount.value()),
            Input::None | Input::Value(_) | Input::List { .. } => return Err(bad),
        };
        Ok(Self {
            number,
            #[cfg(feature = "currency")]
            currency: match input {
                Input::Value(Value::Amount(amount)) => Some(amount.currency()),
                _ => None,
            },
        })
    }
}

impl<'a> Form<'a> {
    /// Reads a compiled placeholder of `format`.
    pub(crate) fn read(bytes: &'a [u8], format: FormatId) -> Result<Self, RenderError> {
        let mut reader = Reader::new(bytes, format);
        let steps = (0..reader.count()?)
            .map(|_| match reader.byte()? {
                0 => Ok(Step::Integer(mode(&mut reader)?)),
                1 => Ok(Step::Add(reader.signed()?)),
                _ => Err(reader.malformed()),
            })
            .collect::<Result<_, _>>()?;
        let sign = *SignDisplay::ALL
            .get(usize::from(reader.byte()?))
            .ok_or(reader.malformed())?;
        let grouping = match reader.byte()? {
            0 => Grouping::Never,
            1 => Grouping::From(reader.byte()?),
            _ => return Err(reader.malformed()),
        };
        let min_integer = reader.byte()?;
        let rounding = rounding(&mut reader)?;
        let digits = Digits {
            min_integer,
            rounding,
            mode: mode(&mut reader)?,
            strip_if_integer: reader.flag()?,
        };
        let percent = reader.flag()?;
        let selection = match reader.byte()? {
            0 => Selection::None,
            1 => Selection::Exact,
            2 => Selection::Plural,
            3 => Selection::Ordinal,
            _ => return Err(reader.malformed()),
        };
        let integer_keys = reader.flag()?;
        let direction = match reader.byte()? {
            0 => Direction::Ltr,
            1 => Direction::Rtl,
            2 => Direction::Unknown,
            _ => return Err(reader.malformed()),
        };
        let zero = {
            let mut chars = reader.text()?.chars();
            match (chars.next(), chars.next()) {
                (Some(zero), None) => zero,
                _ => return Err(reader.malformed()),
            }
        };
        let mut symbol = || reader.text().map(str::to_owned);
        let symbols = Symbols {
            zero,
            decimal: symbol()?,
            group: symbol()?,
            minus: symbol()?,
            plus: symbol()?,
            percent: symbol()?,
        };
        let pattern = Pattern::read(&mut reader)?;
        let cardinal = reader.part()?;
        let ordinal = reader.part()?;
        Ok(Self {
            steps,
            sign,
            grouping,
            digits,
            percent,
            selection,
            integer_keys,
            direction,
            symbols,
            pattern,
            cardinal,
            ordinal,
            #[cfg(feature = "currency")]
            rest: reader,
        })
    }

    /// The operand after the chain's steps.
    pub(crate) fn value(&self, given: Given) -> Given {
        let stepped = self.steps.iter().fold(given, |given, step| match *step {
            Step::Integer(mode) => given.integer(mode),
            Step::Add(addend) => given.plus(addend),
        });
        if self.percent {
            stepped.percent()
        } else {
            stepped
        }
    }

    /// The number rounded by the digit options; `currency` the currency's fraction digits and
    /// rounding increment.
    pub(crate) fn rounded(&self, given: &Given, currency: (u8, u16)) -> Fixed {
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
            Fraction::Digits(_) | Fraction::Given => 1,
        };
        let fixed = |min: Fraction, max: Fraction, inc: u16| {
            let inc = if inc == 1 { increment(max) } else { inc };
            let (min, max) = bounds(min, max);
            let rounded = value.round(-i64::from(max), u32::from(inc), digits.mode);
            (-i64::from(max), rounded.fixed(min))
        };
        let significant = |min: u8, max: u8| {
            let magnitude = value.magnitude().unwrap_or(0);
            let rounded = value.round(magnitude - i64::from(max) + 1, 1, digits.mode);
            let after = rounded.magnitude().unwrap_or(0);
            let min_fraction = (i64::from(min) - 1 - after).max(0);
            let min_fraction = u32::try_from(min_fraction).unwrap_or(0);
            (after - i64::from(max) + 1, rounded.fixed(min_fraction))
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
                let (fm, f) = fixed(fraction.0, fraction.1, 1);
                let (sm, s) = significant(s.0, s.1);
                if sm <= fm { s } else { f }
            }
            Rounding::Less {
                fraction,
                significant: s,
            } => {
                let (fm, f) = fixed(fraction.0, fraction.1, 1);
                let (sm, s) = significant(s.0, s.1);
                if sm <= fm { f } else { s }
            }
        };
        if digits.strip_if_integer && result.is_integer() {
            result.frac.clear();
        }
        let pad = usize::from(digits.min_integer).saturating_sub(result.int.len());
        if pad > 0 {
            let mut int = vec![0; pad];
            int.append(&mut result.int);
            result.int = int;
        }
        result
    }

    /// Writes a rounded number with the pattern; `currency` stands for `¤`.
    pub(crate) fn write(&self, fixed: &Fixed, pattern: &Pattern, currency: &str, out: &mut String) {
        let shown = self.sign.shown(fixed);
        pattern.write(fixed, shown, &self.symbols, self.grouping, currency, out);
    }

    /// The keys a rounded number matches, best first.
    pub(crate) fn select<'k>(
        &self,
        fixed: &Fixed,
        keys: VariantKeys<'k>,
    ) -> Result<Vec<VariantKey<'k>>, RenderError> {
        let serial = self.serial(fixed);
        let category = match self.selection {
            Selection::None => return Err(RenderError::Message("bad-selector")),
            Selection::Exact => None,
            Selection::Plural => Some(self.cardinal(fixed)?),
            Selection::Ordinal => Some(plural::category(
                &mut self.ordinal.clone(),
                &Operands::of(fixed),
            )?),
        };
        let mut exact = Vec::new();
        let mut keyword = Vec::new();
        for (key, text) in keys.iter() {
            if Num::literal(text).is_some() {
                if text == serial {
                    exact.push(key);
                }
            } else if let Some(named) = Category::of_keyword(text) {
                if Some(named) == category {
                    keyword.push(key);
                }
            } else {
                return Err(RenderError::Message("bad-variant-key"));
            }
        }
        exact.append(&mut keyword);
        Ok(exact)
    }

    /// The number's serialization for exact keys.
    fn serial(&self, fixed: &Fixed) -> String {
        let digit = |d: &u8| char::from(b'0' + d);
        let int: String = fixed.int.iter().map(digit).collect();
        if self.integer_keys && fixed.is_integer() {
            let int = int.trim_start_matches('0');
            return match (fixed.negative, int.is_empty()) {
                (_, true) => "0".to_owned(),
                (true, false) => format!("-{int}"),
                (false, false) => int.to_owned(),
            };
        }
        let sign = if fixed.negative && !fixed.is_zero() {
            "-"
        } else {
            ""
        };
        let frac: String = fixed.frac.iter().map(digit).collect();
        if frac.is_empty() {
            format!("{sign}{int}")
        } else {
            format!("{sign}{int}.{frac}")
        }
    }

    /// The plural category of a rounded number by the cardinal rules.
    pub(crate) fn cardinal(&self, fixed: &Fixed) -> Result<Category, RenderError> {
        plural::category(&mut self.cardinal.clone(), &Operands::of(fixed))
    }
}

fn mode(reader: &mut Reader<'_>) -> Result<RoundingMode, RenderError> {
    RoundingMode::of_code(reader.byte()?).ok_or(reader.malformed())
}

fn fraction(reader: &mut Reader<'_>) -> Result<Fraction, RenderError> {
    match reader.byte()? {
        255 => Ok(Fraction::Currency),
        254 => Ok(Fraction::Given),
        digits => Ok(Fraction::Digits(digits)),
    }
}

fn rounding(reader: &mut Reader<'_>) -> Result<Rounding, RenderError> {
    Ok(match reader.byte()? {
        0 => Rounding::Fraction {
            min: fraction(reader)?,
            max: fraction(reader)?,
            increment: u16::try_from(reader.number()?).map_err(|_| reader.malformed())?,
        },
        1 => Rounding::Significant {
            min: reader.byte()?,
            max: reader.byte()?,
        },
        kind @ (2 | 3) => {
            let fraction = (fraction(reader)?, fraction(reader)?);
            let significant = (reader.byte()?, reader.byte()?);
            if kind == 2 {
                Rounding::More {
                    fraction,
                    significant,
                }
            } else {
                Rounding::Less {
                    fraction,
                    significant,
                }
            }
        }
        _ => return Err(reader.malformed()),
    })
}

/// Writes the parts of a compiled numeric placeholder that come before its rules and its
/// currency data, in the order [`Form::read`] reads them.
#[cfg(feature = "load")]
pub(crate) struct Head<'p> {
    pub(crate) steps: &'p [Step],
    pub(crate) sign: SignDisplay,
    pub(crate) grouping: Grouping,
    pub(crate) digits: Digits,
    pub(crate) percent: bool,
    pub(crate) selection: Selection,
    pub(crate) integer_keys: bool,
    pub(crate) direction: Direction,
    pub(crate) symbols: &'p Symbols,
    pub(crate) pattern: &'p Pattern,
}

#[cfg(feature = "load")]
impl Head<'_> {
    pub(crate) fn write(&self, writer: &mut Writer) {
        writer.count(self.steps.len());
        for step in self.steps {
            match *step {
                Step::Integer(mode) => {
                    writer.byte(0);
                    writer.byte(mode.code());
                }
                Step::Add(addend) => {
                    writer.byte(1);
                    writer.signed(addend);
                }
            }
        }
        writer.byte(self.sign as u8);
        match self.grouping {
            Grouping::Never => writer.byte(0),
            Grouping::From(minimum) => {
                writer.byte(1);
                writer.byte(minimum);
            }
        }
        writer.byte(self.digits.min_integer);
        let fraction_of = |writer: &mut Writer, f: Fraction| {
            writer.byte(match f {
                Fraction::Digits(d) => d,
                Fraction::Currency => 255,
                Fraction::Given => 254,
            });
        };
        match self.digits.rounding {
            Rounding::Fraction {
                min,
                max,
                increment,
            } => {
                writer.byte(0);
                fraction_of(writer, min);
                fraction_of(writer, max);
                writer.number(u64::from(increment));
            }
            Rounding::Significant { min, max } => {
                writer.byte(1);
                writer.byte(min);
                writer.byte(max);
            }
            Rounding::More {
                fraction,
                significant,
            }
            | Rounding::Less {
                fraction,
                significant,
            } => {
                let more = matches!(self.digits.rounding, Rounding::More { .. });
                writer.byte(if more { 2 } else { 3 });
                fraction_of(writer, fraction.0);
                fraction_of(writer, fraction.1);
                writer.byte(significant.0);
                writer.byte(significant.1);
            }
        }
        writer.byte(self.digits.mode.code());
        writer.flag(self.digits.strip_if_integer);
        writer.flag(self.percent);
        writer.byte(match self.selection {
            Selection::None => 0,
            Selection::Exact => 1,
            Selection::Plural => 2,
            Selection::Ordinal => 3,
        });
        writer.flag(self.integer_keys);
        writer.byte(match self.direction {
            Direction::Ltr => 0,
            Direction::Rtl => 1,
            Direction::Unknown => 2,
        });
        writer.text(self.symbols.zero.encode_utf8(&mut [0; 4]));
        for symbol in [
            &self.symbols.decimal,
            &self.symbols.group,
            &self.symbols.minus,
            &self.symbols.plus,
            &self.symbols.percent,
        ] {
            writer.text(symbol);
        }
        self.pattern.write_to(writer);
    }
}

/// Renders a plain numeric placeholder: `:number`, `:integer`, `:offset`, `:percent`.
pub(crate) fn render(
    format: FormatId,
    compiled: &[u8],
    input: &Input<'_>,
    sink: &mut dyn Sink,
) -> Result<(), RenderError> {
    let form = Form::read(compiled, format)?;
    let number = NumericInput::of(input)?.number;
    let fixed = form.rounded(&form.value(number), (0, 1));
    let mut out = String::new();
    form.write(&fixed, &form.pattern, "", &mut out);
    sink.text(&out);
    Ok(())
}

/// Selects with a plain numeric placeholder.
pub(crate) fn select<'k>(
    format: FormatId,
    compiled: &[u8],
    input: &Input<'_>,
    keys: VariantKeys<'k>,
) -> Result<Vec<VariantKey<'k>>, RenderError> {
    let form = Form::read(compiled, format)?;
    let number = NumericInput::of(input)?.number;
    let fixed = form.rounded(&form.value(number), (0, 1));
    form.select(&fixed, keys)
}

/// The direction a compiled numeric placeholder records.
#[cfg(any(feature = "number", feature = "offset"))]
pub(crate) fn direction(compiled: &[u8], format: FormatId) -> Result<Direction, RenderError> {
    Form::read(compiled, format).map(|form| form.direction)
}
