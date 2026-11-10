//! What the numeric formats share: MF2's numeric operands and options (spec/functions/number.md),
//! resolved along a call chain, and the number they format and select. `:number`, `:integer`,
//! `:offset`, `:currency` and `:percent` share one check at load and one resolution, which
//! resolves the options when a message resolves: a variable may give an option's value.

#[cfg(feature = "currency")]
pub(crate) mod currency;
pub(crate) mod decimal;
mod form;
pub(crate) mod language;
pub(crate) mod options;
pub(crate) mod pattern;
pub(crate) mod plural;

#[cfg(any(feature = "number", feature = "offset"))]
pub(crate) use language::{PLAIN, Plain};

use std::num::NonZeroU32;

use crate::chain::{Call, Chain, Failure, Root, Texts, Value};
use crate::error::Refusal;
use crate::format::Direction;
use crate::scope::Scope;
use decimal::{Fixed, Given, Num, RoundingMode};
use language::Numbers;
use options::{Function, Refused, Resolved};
use pattern::{Grouping, Pattern, Shown};
use plural::{Category, Operands};

/// A step of a call chain that changes the value: `:integer`'s rounding, `:offset`'s addition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Step {
    #[cfg(feature = "number")]
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

/// How a selector matches its keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Selection {
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

/// The language data a numeric call formats with: a section of the context.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Language<'f> {
    /// Numbers and the decimal pattern of `[formats.number]` or `[formats.offset]`.
    #[cfg(any(feature = "number", feature = "offset"))]
    Plain(&'f Plain),
    /// `[formats.currency]`: its numbers, percent pattern and currency data, for `:currency` and
    /// `:percent`.
    #[cfg(feature = "currency")]
    Currency(&'f currency::Parsed),
}

impl<'f> Language<'f> {
    const fn numbers(self) -> &'f Numbers {
        match self {
            #[cfg(any(feature = "number", feature = "offset"))]
            Self::Plain(plain) => &plain.numbers,
            #[cfg(feature = "currency")]
            Self::Currency(section) => &section.numbers,
        }
    }

    /// The direction of a formatted number: its section's module's.
    pub(crate) const fn direction(self) -> Direction {
        self.numbers().direction
    }

    /// The pattern whose digit counts a number takes when no option sets them: the decimal
    /// pattern, or the percent pattern for `:percent`.
    fn pattern(
        self,
        #[cfg_attr(
            not(feature = "currency"),
            expect(
                unused_variables,
                reason = "only the currency section has a percent pattern"
            )
        )]
        formatter: Function,
    ) -> &'f Pattern {
        match self {
            #[cfg(any(feature = "number", feature = "offset"))]
            Self::Plain(plain) => &plain.pattern,
            #[cfg(feature = "currency")]
            Self::Currency(section) if formatter == Function::Percent => &section.percent,
            #[cfg(feature = "currency")]
            Self::Currency(section) => section.standard(),
        }
    }

    /// Whether the language formats a value of `formatter`: a currency section `:currency` and
    /// `:percent` values, a number or offset section the others.
    fn formats(self, formatter: Function) -> bool {
        let currency = matches!(formatter, Function::Currency | Function::Percent);
        match self {
            #[cfg(any(feature = "number", feature = "offset"))]
            Self::Plain(_) => !currency,
            #[cfg(feature = "currency")]
            Self::Currency(_) => currency,
        }
    }

    /// Refuses resolved options its section's data cannot format: a `:currency` value without
    /// a `currency` option.
    fn check(
        self,
        #[cfg_attr(
            not(feature = "currency"),
            expect(unused_variables, reason = "only the currency section refuses options")
        )]
        resolved: &Resolved<'_>,
    ) -> Result<(), Refused> {
        match self {
            #[cfg(any(feature = "number", feature = "offset"))]
            Self::Plain(_) => Ok(()),
            #[cfg(feature = "currency")]
            Self::Currency(section) => section.check(resolved),
        }
    }
}

/// A number's options as one resolution resolved them.
pub(crate) struct Form<'a> {
    steps: Vec<Step>,
    sign: SignDisplay,
    grouping: Grouping,
    digits: Digits,
    percent: bool,
    selection: Option<Selection>,
    /// Whether an integer serializes as one for exact keys: none of the options that set digit
    /// counts is given.
    integer_keys: bool,
    pub(crate) resolved: Resolved<'a>,
}

/// The function that formats a chain's value: its last call's but `:offset`, and `:number` for
/// a chain of `:offset` calls, whose value is the operand's numeric value
/// (spec/functions/number.md, `:offset`'s resolved value). `None` for a chain with a call of
/// another family.
pub(crate) fn formatter(chain: &Chain<'_>) -> Option<Function> {
    let mut formatter = Function::Number;
    for call in chain.calls() {
        match Function::of(call.function)? {
            Function::Offset => {}
            function => formatter = function,
        }
    }
    Some(formatter)
}

/// The kind of a chain's root; a literal must be a number literal.
fn root(chain: &Chain<'_>) -> Result<options::Root, Refusal> {
    match chain.root {
        Root::None => Err(Refusal::Operand),
        Root::Literal(text) => match Given::literal(text) {
            Some(_) => Ok(options::Root::Literal),
            None => Err(Refusal::Operand),
        },
        Root::Argument(_) => Ok(options::Root::Argument),
    }
}

/// A refusal of the chain's options at load.
fn refusal(refused: Refused) -> crate::chain::Refused {
    match refused {
        Refused::Operand => Refusal::Operand.into(),
        Refused::Option(option) => Refusal::Option { option }.into(),
    }
}

/// A refusal of the chain's options at resolution.
fn failure(refused: Refused) -> Failure {
    match refused {
        Refused::Operand => Failure::Operand,
        Refused::Option(option) => Failure::Option(option),
    }
}

/// Checks a chain whose outermost function is numeric, formatted with `language`.
///
/// # Errors
///
/// [`Refusal`] for an operand or an option the functions refuse.
pub(crate) fn check(
    chain: &Chain<'_>,
    language: Language<'_>,
) -> Result<(), crate::chain::Refused> {
    checked(chain, language).map(drop)
}

/// How a chain whose outermost function is numeric, formatted with `language`, selects.
///
/// # Errors
///
/// The refusal of [`check`], and [`Refusal::Selector`] for a `:currency` value, which selects
/// no variant.
pub(crate) fn selection(
    chain: &Chain<'_>,
    language: Language<'_>,
) -> Result<Selection, crate::chain::Refused> {
    checked(chain, language)?.ok_or_else(|| Refusal::Selector.into())
}

/// How the checked chain's value selects; `None` for a value that selects no variant. A chain
/// whose option texts the load fixes resolves them now. Another resolves what they leave fixed:
/// its functions, its operand, a selector's `select`, and the options `:currency` and `:offset`
/// need.
fn checked(
    chain: &Chain<'_>,
    language: Language<'_>,
) -> Result<Option<Selection>, crate::chain::Refused> {
    let root = root(chain)?;
    for call in chain.calls() {
        let function = Function::of(call.function).ok_or(Refusal::Operand)?;
        if let Err(refused) = written_select(function, call) {
            return Err(refusal(refused));
        }
    }
    let formatter = formatter(chain).ok_or(Refusal::Operand)?;
    if !language.formats(formatter) {
        return Err(Refusal::Operand.into());
    }
    match chain.fixed_texts()? {
        Some(texts) => {
            let form = form(root, &texts, language).map_err(refusal)?;
            language.check(&form.resolved).map_err(refusal)?;
            Ok(form.selection)
        }
        None => structure(chain).map_err(refusal),
    }
}

/// What a chain whose options a variable gives leaves fixed, checked as
/// [`Resolved::of`] checks it: each literal option a function reads, `select` written as a
/// literal on the outermost call that reads it, `currency` on one `:currency` call, `add` or
/// `subtract` on each `:offset` call. How the value selects; `None` for a `:currency` value.
fn structure(chain: &Chain<'_>) -> Result<Option<Selection>, Refused> {
    let option = |name: &str| Refused::Option(name.to_owned());
    let mut select: Option<&str> = None;
    let mut currency = false;
    let mut held = false;
    let mut earlier: Option<Function> = None;
    let mut formatter = Function::Number;
    for call in chain.calls() {
        let function = Function::of(call.function).ok_or(Refused::Operand)?;
        if earlier.is_some() && function.discards("select") {
            select = None;
        }
        if select.is_some() {
            return Err(option("select"));
        }
        held |= earlier == Some(Function::Currency);
        for (name, value) in call.options() {
            let Some(rule) = function.rule(name) else {
                continue;
            };
            if name == "currency" {
                if held {
                    return Err(option(name));
                }
                currency = true;
            }
            if value.fixed().is_some_and(|text| !rule.takes(text)) {
                return Err(option(name));
            }
        }
        select = written_select(function, call)?;
        if function == Function::Offset {
            let given = |name: &str| call.option(name).is_some();
            match (given("add"), given("subtract")) {
                (true, true) => return Err(option("subtract")),
                (false, false) => return Err(option("add")),
                (true, false) | (false, true) => {}
            }
        } else {
            formatter = function;
        }
        earlier = Some(function);
    }
    Ok(match (formatter, select) {
        (Function::Currency, _) if !currency => return Err(Refused::Operand),
        (Function::Currency, _) => None,
        (Function::Percent, _) | (_, None | Some("plural")) => Some(Selection::Plural),
        (_, Some("ordinal")) => Some(Selection::Ordinal),
        (_, Some("exact")) => Some(Selection::Exact),
        (_, Some(_)) => return Err(option("select")),
    })
}

/// The `select` a call of `function` writes, when `function` reads it.
///
/// # Errors
///
/// [`Refused::Option`] for a `select` a variable gives: MF2 sets it by a literal alone
/// (spec/functions/number.md, "Number Selection").
fn written_select(function: Function, call: &Call) -> Result<Option<&str>, Refused> {
    if !function.reads("select") {
        return Ok(None);
    }
    match call.option("select") {
        None => Ok(None),
        Some(Value::Literal(text)) => Ok(Some(text)),
        Some(Value::Bound(_) | Value::Variable(_)) => Err(Refused::Option("select".to_owned())),
    }
}

/// Refuses a variant key that is neither a number literal nor a plural keyword.
///
/// # Errors
///
/// [`Refusal::Key`] for such a key.
pub(crate) fn key(key: &str) -> Result<(), Refusal> {
    if Num::literal(key).is_some() || Category::of_keyword(key).is_some() {
        Ok(())
    } else {
        Err(Refusal::Key {
            key: key.to_owned(),
        })
    }
}

/// The options of a chain with its option texts, resolved over a language.
fn form<'t>(
    root: options::Root,
    texts: &'t Texts<'_>,
    language: Language<'_>,
) -> Result<Form<'t>, Refused> {
    let resolved = Resolved::of(root, texts)?;
    let numbers = language.numbers();
    let pattern = language.pattern(resolved.formatter);
    Ok(Form {
        steps: resolved.steps.clone(),
        sign: resolved.sign()?,
        grouping: resolved.grouping(numbers.minimum_grouping)?,
        digits: resolved.digits(pattern)?,
        percent: resolved.formatter == Function::Percent,
        selection: resolved.selection()?,
        integer_keys: resolved.integer_keys(),
        resolved,
    })
}

/// The operand's number and the options resolved over `language`.
fn resolve<'t>(
    chain: &Chain<'_>,
    texts: &'t Texts<'_>,
    scope: &Scope<'_>,
    language: Language<'_>,
) -> Result<(Given, Form<'t>), Failure> {
    let (root, text) = match chain.root {
        Root::None => return Err(Failure::Operand),
        Root::Literal(text) => (options::Root::Literal, text),
        Root::Argument(key) => (options::Root::Argument, scope.argument(key)?),
    };
    let given = Given::literal(text).ok_or(Failure::Operand)?;
    let form = form(root, texts, language).map_err(failure)?;
    Ok((given, form))
}

/// The number formatted.
///
/// # Errors
///
/// [`Failure`] for an operand or option text refused, or an argument not given.
pub(crate) fn format(
    chain: &Chain<'_>,
    texts: &Texts<'_>,
    scope: &Scope<'_>,
    language: Language<'_>,
) -> Result<String, Failure> {
    let (given, form) = resolve(chain, texts, scope, language)?;
    let mut out = String::new();
    match language {
        #[cfg(feature = "currency")]
        Language::Currency(section) if !form.percent => {
            return section.amount(&form, &given);
        }
        language => {
            let fixed = form.rounded(&form.value(given), (0, NonZeroU32::MIN));
            let pattern = language.pattern(form.resolved.formatter);
            form.write(&fixed, pattern, &language.numbers().symbols, "", &mut out);
        }
    }
    Ok(out)
}

/// What a number selects with: its serialization, which an exact key equals, and its plural
/// category, which a keyword names.
#[derive(Debug)]
pub(crate) struct Selected {
    serial: String,
    category: Option<Category>,
}

impl Selected {
    /// The rank of `key` among the keys the number matches: its exact key before its
    /// category's keyword; `None` for a key it does not match.
    pub(crate) fn rank(&self, key: &str) -> Option<usize> {
        if key == self.serial {
            Some(0)
        } else if self.category.is_some() && Category::of_keyword(key) == self.category {
            Some(1)
        } else {
            None
        }
    }
}

/// What the number selects with, by `selection`.
///
/// # Errors
///
/// [`Failure`] as [`format`].
pub(crate) fn selected(
    chain: &Chain<'_>,
    texts: &Texts<'_>,
    scope: &Scope<'_>,
    language: Language<'_>,
    selection: Selection,
) -> Result<Selected, Failure> {
    let (given, form) = resolve(chain, texts, scope, language)?;
    let fixed = form.rounded(&form.value(given), (0, NonZeroU32::MIN));
    let numbers = language.numbers();
    let category = match selection {
        Selection::Exact => None,
        Selection::Plural => Some(numbers.cardinal.category(&Operands::of(&fixed))),
        Selection::Ordinal => Some(numbers.ordinal.category(&Operands::of(&fixed))),
    };
    Ok(Selected {
        serial: form.serial(&fixed),
        category,
    })
}

/// The number as an option's value: the operand after `:integer`'s rounding and `:offset`'s
/// additions, written as a number literal without an exponent.
///
/// # Errors
///
/// [`Failure`] as [`format`].
pub(crate) fn value(
    chain: &Chain<'_>,
    texts: &Texts<'_>,
    scope: &Scope<'_>,
    language: Language<'_>,
) -> Result<String, Failure> {
    let (given, form) = resolve(chain, texts, scope, language)?;
    language.check(&form.resolved).map_err(failure)?;
    let stepped = form.stepped(given);
    #[cfg(feature = "number")]
    let stepped = if form.resolved.function == Function::Integer {
        stepped.integer(form.resolved.mode().map_err(failure)?)
    } else {
        stepped
    };
    Ok(stepped.value().fixed(0).plain())
}
