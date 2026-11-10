//! Currencies: `[formats.currency]`, which holds a language's currency patterns, symbols, names
//! and fraction digits and the percent pattern of `:percent`, and an amount formatted with them
//! (Unicode TR35 Part 3, "Currencies"; CLDR's `alphaNextToNumber` patterns as ICU4X selects them).

use std::hash::Hash;
use std::num::NonZeroU32;

use icu_properties::CodePointMapData;
use icu_properties::props::{GeneralCategory, GeneralCategoryGroup};
use siros_syntax::Currency;

use crate::chain::Failure;
use crate::error::FormatRule;
use crate::format::Options;
use crate::numeric::Form;
use crate::numeric::decimal::{Fixed, Given};
use crate::numeric::language::{Numbers, symbol};
use crate::numeric::options::{Function, Refused, Resolved};
use crate::numeric::pattern::{Affix, Pattern};
use crate::numeric::plural::{Category, Operands};
use crate::seen::repeated;

/// The options `[formats.currency]` takes.
pub(crate) const OPTIONS: [&str; 22] = [
    "zero",
    "decimal",
    "group",
    "minus",
    "plus",
    "grouping",
    "cardinal",
    "ordinal",
    "percent-sign",
    "percent-pattern",
    "pattern",
    "standard",
    "standard-alpha",
    "accounting",
    "accounting-alpha",
    "no-currency",
    "no-currency-accounting",
    "unit-pattern",
    "digits",
    "symbols",
    "narrow",
    "names",
];

/// The ISO 4217 currency of a well-formed code, in any case (MF2's `currency` option).
pub(crate) fn currency(code: &str) -> Option<Currency> {
    Currency::parse(&code.to_ascii_uppercase()).ok()
}

/// `currencyDisplay`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Display {
    Symbol,
    Narrow,
    Name,
    Code,
    Never,
}

impl Display {
    /// The display MF2's option value names.
    fn named(name: &str) -> Option<Self> {
        Some(match name {
            "symbol" => Self::Symbol,
            "narrowSymbol" => Self::Narrow,
            "name" => Self::Name,
            "code" => Self::Code,
            "never" => Self::Never,
            _ => return None,
        })
    }
}

/// A currency's symbol: its text, and whether it starts and ends with a letter.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Symbol {
    currency: Currency,
    text: String,
    starts_letter: bool,
    ends_letter: bool,
}

/// A currency's name for an amount of a plural category.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Name {
    currency: Currency,
    category: Category,
    text: String,
}

/// A currency's fraction digits and rounding increment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Fractions {
    digits: u8,
    increment: NonZeroU32,
}

/// The patterns that place a number and its currency's name, by plural category: `{0}` the
/// number, `{1}` the name. `other` stands for each category without its own.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Units {
    other: String,
    by: Vec<(Category, String)>,
}

/// The currency patterns of a language, by sign style and adjacency.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Patterns {
    standard: Pattern,
    standard_alpha: Pattern,
    accounting: Pattern,
    accounting_alpha: Pattern,
    plain: Pattern,
    plain_accounting: Pattern,
    decimal: Pattern,
}

/// A language's currency data.
#[derive(Debug, Clone)]
struct Data {
    patterns: Patterns,
    symbols: Vec<Symbol>,
    narrow: Vec<Symbol>,
    names: Vec<Name>,
    units: Units,
    default: Fractions,
    fractions: Vec<(Currency, Fractions)>,
}

/// `[formats.currency]`, parsed: its numbers, its percent pattern, and its currency data.
#[derive(Debug, Clone)]
pub(crate) struct Parsed {
    pub(crate) numbers: Numbers,
    pub(crate) percent: Pattern,
    data: Data,
}

/// Whether a character is a letter (General Category L).
fn letter(c: Option<char>) -> bool {
    c.is_some_and(|c| {
        GeneralCategoryGroup::Letter.contains(CodePointMapData::<GeneralCategory>::new().get(c))
    })
}

/// Lines of `<code> <rest>`, each code an ISO 4217 currency.
fn table<T>(text: &str, mut entry: impl FnMut(Currency, &str) -> Option<T>) -> Option<Vec<T>> {
    text.lines()
        .map(|line| {
            let (code, rest) = line.split_once(' ')?;
            entry(Currency::parse(code).ok()?, rest)
        })
        .collect()
}

/// Whether no two items share a key.
fn distinct<T, K: Copy + Hash + Eq>(items: &[T], key: impl Fn(&T) -> K) -> bool {
    repeated(items.iter().map(key)).is_none()
}

fn symbols(text: &str) -> Option<Vec<Symbol>> {
    let symbols = table(text, |currency, rest| {
        (!rest.is_empty()).then(|| Symbol {
            currency,
            text: rest.to_owned(),
            starts_letter: letter(rest.chars().next()),
            ends_letter: letter(rest.chars().next_back()),
        })
    })?;
    distinct(&symbols, |s| s.currency).then_some(symbols)
}

fn names(text: &str) -> Option<Vec<Name>> {
    let names = table(text, |currency, rest| {
        let (keyword, name) = rest.split_once(' ')?;
        let category = Category::of_keyword(keyword)?;
        (!name.is_empty()).then(|| Name {
            currency,
            category,
            text: name.to_owned(),
        })
    })?;
    distinct(&names, |n| (n.currency, n.category)).then_some(names)
}

fn units(text: &str) -> Option<Units> {
    let mut other = None;
    let mut by = Vec::new();
    for line in text.lines() {
        let (keyword, unit) = line.split_once(' ')?;
        if !(unit.contains("{0}") && unit.contains("{1}")) {
            return None;
        }
        match Category::of_keyword(keyword)? {
            Category::Other if other.is_none() => other = Some(unit.to_owned()),
            Category::Other => return None,
            category => by.push((category, unit.to_owned())),
        }
    }
    distinct(&by, |(c, _)| *c).then_some(Units { other: other?, by })
}

fn fractions(text: &str) -> Option<(Fractions, Vec<(Currency, Fractions)>)> {
    let parse = |rest: &str| {
        let mut words = rest.split(' ');
        let digits = words.next()?.parse().ok().filter(|d: &u8| *d <= 20)?;
        let increment = match words.next() {
            Some(word) => word.parse().ok()?,
            None => NonZeroU32::MIN,
        };
        words
            .next()
            .is_none()
            .then_some(Fractions { digits, increment })
    };
    let mut default = None;
    let mut entries = Vec::new();
    for line in text.lines() {
        let (code, rest) = line.split_once(' ')?;
        if code == "default" && default.is_none() {
            default = Some(parse(rest)?);
        } else {
            entries.push((Currency::parse(code).ok()?, parse(rest)?));
        }
    }
    distinct(&entries, |(c, _)| *c).then_some((default?, entries))
}

impl Parsed {
    /// The section's options.
    ///
    /// # Errors
    ///
    /// [`FormatRule`] for an option the section lacks or whose text the grammar refuses.
    pub(crate) fn parse(options: Options<'_>) -> Result<Self, FormatRule> {
        let pattern = |name| options.parse(name, Pattern::parse);
        let (default, fractions) = options.parse("digits", fractions)?;
        Ok(Self {
            numbers: Numbers::parse(options, options.parse("percent-sign", symbol)?)?,
            percent: pattern("percent-pattern")?,
            data: Data {
                patterns: Patterns {
                    standard: pattern("standard")?,
                    standard_alpha: pattern("standard-alpha")?,
                    accounting: pattern("accounting")?,
                    accounting_alpha: pattern("accounting-alpha")?,
                    plain: pattern("no-currency")?,
                    plain_accounting: pattern("no-currency-accounting")?,
                    decimal: pattern("pattern")?,
                },
                symbols: options.parse("symbols", symbols)?,
                narrow: options.parse("narrow", symbols)?,
                names: options.parse("names", names)?,
                units: options.parse("unit-pattern", units)?,
                default,
                fractions,
            },
        })
    }
}

impl Data {
    fn fractions(&self, currency: Currency) -> Fractions {
        self.fractions
            .iter()
            .find(|(c, _)| *c == currency)
            .map_or(self.default, |(_, f)| *f)
    }

    /// The text that stands for `¤`, and whether it starts and ends with a letter: the symbol in
    /// `display`, else the code.
    fn symbol(&self, currency: Currency, display: Display) -> (String, bool, bool) {
        let table = match display {
            Display::Symbol => &self.symbols,
            Display::Narrow => &self.narrow,
            Display::Name | Display::Code | Display::Never => &[][..],
        };
        match table.iter().find(|s| s.currency == currency) {
            Some(symbol) => (
                symbol.text.clone(),
                symbol.starts_letter,
                symbol.ends_letter,
            ),
            None => (currency.to_string(), true, true),
        }
    }

    /// The name of `currency` in `category`, `other`'s when it has none of the category, and its
    /// code when it has no name.
    fn name(&self, currency: Currency, category: Category) -> String {
        let find = |category: Category| {
            self.names
                .iter()
                .find(|n| n.currency == currency && n.category == category)
                .map(|n| n.text.clone())
        };
        find(category)
            .or_else(|| find(Category::Other))
            .unwrap_or_else(|| currency.to_string())
    }
}

impl Parsed {
    /// The standard currency pattern.
    pub(crate) const fn standard(&self) -> &Pattern {
        &self.data.patterns.standard
    }

    /// Refuses a `:currency` value whose call names no currency.
    ///
    /// # Errors
    ///
    /// [`Refused::Operand`] for a `:currency` value without a `currency` option.
    pub(crate) fn check(&self, resolved: &Resolved<'_>) -> Result<(), Refused> {
        if resolved.formatter == Function::Currency && resolved.get("currency").is_none() {
            return Err(Refused::Operand);
        }
        Ok(())
    }

    /// An amount: the number `given` in the currency its call names.
    ///
    /// # Errors
    ///
    /// [`Failure::Option`] for a `currency` or `currencyDisplay` text the function refuses, and
    /// [`Failure::Operand`] for a value whose call names no currency.
    pub(crate) fn amount(&self, form: &Form<'_>, given: &Given) -> Result<String, Failure> {
        let option = |name: &str| Failure::Option(name.to_owned());
        let code = form.resolved.get("currency").ok_or(Failure::Operand)?;
        let currency = currency(code).ok_or_else(|| option("currency"))?;
        let display = match form.resolved.get("currencyDisplay") {
            Some(name) => Display::named(name).ok_or_else(|| option("currencyDisplay"))?,
            None => Display::Symbol,
        };
        let accounting = form.resolved.get("currencySign") == Some("accounting");
        let fractions = self.data.fractions(currency);
        let fixed = form.rounded(
            &form.value(given.clone()),
            (fractions.digits, fractions.increment),
        );
        Ok(self.write(form, &fixed, currency, display, accounting))
    }

    /// An amount rounded, in `display`.
    fn write(
        &self,
        form: &Form<'_>,
        fixed: &Fixed,
        currency: Currency,
        display: Display,
        accounting: bool,
    ) -> String {
        let patterns = &self.data.patterns;
        let symbols = &self.numbers.symbols;
        let mut out = String::new();
        match display {
            Display::Never => {
                let pattern = if accounting {
                    &patterns.plain_accounting
                } else {
                    &patterns.plain
                };
                form.write(fixed, pattern, symbols, "", &mut out);
            }
            Display::Name => {
                let mut number = String::new();
                form.write(fixed, &patterns.decimal, symbols, "", &mut number);
                let category = self.numbers.cardinal.category(&Operands::of(fixed));
                let units = &self.data.units;
                let unit = units
                    .by
                    .iter()
                    .find(|(c, _)| *c == category)
                    .map_or(units.other.as_str(), |(_, unit)| unit.as_str());
                out = unit
                    .replace("{0}", &number)
                    .replace("{1}", &self.data.name(currency, category));
            }
            Display::Symbol | Display::Narrow | Display::Code => {
                let (symbol, starts, ends) = self.data.symbol(currency, display);
                let (before, after) = adjacent(&patterns.standard);
                let alpha = (before && ends) || (after && starts);
                let pattern = match (accounting, alpha) {
                    (false, false) => &patterns.standard,
                    (false, true) => &patterns.standard_alpha,
                    (true, false) => &patterns.accounting,
                    (true, true) => &patterns.accounting_alpha,
                };
                form.write(fixed, pattern, symbols, &symbol, &mut out);
            }
        }
        out
    }
}

/// Where a pattern's currency stands beside its number.
fn adjacent(pattern: &Pattern) -> (bool, bool) {
    let before = pattern.positive.prefix.last() == Some(&Affix::Currency);
    let after = pattern.positive.suffix.first() == Some(&Affix::Currency);
    (before, after)
}
