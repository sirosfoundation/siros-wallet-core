//! Currencies: a language's currency patterns, symbols, names and fraction digits, the part of a
//! compiled `:currency` placeholder they fill, and an amount formatted with them (Unicode TR35
//! Part 3, "Currencies"; CLDR's `alphaNextToNumber` patterns as ICU4X selects them).

use siros_explain::Currency;

use crate::bytes::Reader;
#[cfg(feature = "load")]
use crate::bytes::Writer;
use crate::error::{FormatFailure, RenderError};
use crate::format::Input;
use crate::numeric::decimal::Fixed;
use crate::numeric::pattern::{Affix, Pattern};
use crate::numeric::plural::Category;
use crate::numeric::{Form, NumericInput};

/// `currencyDisplay`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Display {
    Symbol,
    Narrow,
    Name,
    Code,
    Never,
}

impl Display {
    const ALL: [Self; 5] = [
        Self::Symbol,
        Self::Narrow,
        Self::Name,
        Self::Code,
        Self::Never,
    ];

    /// The display MF2's option value names.
    #[cfg(feature = "load")]
    pub(crate) fn named(name: &str) -> Option<Self> {
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
pub(crate) struct Symbol {
    pub(crate) currency: Currency,
    pub(crate) text: String,
    pub(crate) starts_letter: bool,
    pub(crate) ends_letter: bool,
}

/// Which name of a currency: by plural category, or its display name standing alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NameKind {
    Count(Category),
    Display,
}

/// A currency's name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Name {
    pub(crate) currency: Currency,
    pub(crate) kind: NameKind,
    pub(crate) text: String,
}

/// A currency's fraction digits and rounding increment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Fractions {
    pub(crate) digits: u8,
    pub(crate) increment: u16,
}

/// The currency patterns of a language, by sign style and adjacency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Patterns {
    pub(crate) standard: Pattern,
    pub(crate) standard_alpha: Pattern,
    pub(crate) accounting: Pattern,
    pub(crate) accounting_alpha: Pattern,
    pub(crate) plain: Pattern,
    pub(crate) plain_accounting: Pattern,
    pub(crate) decimal: Pattern,
}

/// The currency part of a compiled placeholder.
#[derive(Debug)]
struct Part {
    display: Display,
    accounting: bool,
    fixed: Option<Currency>,
    patterns: Patterns,
    symbols: Vec<Symbol>,
    names: Vec<Name>,
    units: Vec<(Category, String)>,
    default: Fractions,
    fractions: Vec<(Currency, Fractions)>,
}

/// Where a pattern's currency stands beside its number.
fn adjacent(pattern: &Pattern) -> (bool, bool) {
    let before = pattern.positive.prefix.last() == Some(&Affix::Currency);
    let after = pattern.positive.suffix.first() == Some(&Affix::Currency);
    (before, after)
}

fn code_text(currency: Currency) -> String {
    currency.code().iter().map(|&b| char::from(b)).collect()
}

fn read_currency(reader: &mut Reader<'_>) -> Result<Currency, RenderError> {
    let text = reader.text()?;
    Currency::from_code(text).ok_or(reader.malformed())
}

fn read_category(reader: &mut Reader<'_>) -> Result<Category, RenderError> {
    let keyword = reader.text()?;
    Category::of_keyword(keyword).ok_or(reader.malformed())
}

impl Part {
    fn read(reader: &mut Reader<'_>) -> Result<Self, RenderError> {
        let display = *Display::ALL
            .get(usize::from(reader.byte()?))
            .ok_or(reader.malformed())?;
        let accounting = reader.flag()?;
        let fixed = if reader.flag()? {
            Some(read_currency(reader)?)
        } else {
            None
        };
        let patterns = Patterns {
            standard: Pattern::read(reader)?,
            standard_alpha: Pattern::read(reader)?,
            accounting: Pattern::read(reader)?,
            accounting_alpha: Pattern::read(reader)?,
            plain: Pattern::read(reader)?,
            plain_accounting: Pattern::read(reader)?,
            decimal: Pattern::read(reader)?,
        };
        let symbols = (0..reader.count()?)
            .map(|_| {
                let currency = read_currency(reader)?;
                let text = reader.text()?.to_owned();
                let flags = reader.byte()?;
                Ok(Symbol {
                    currency,
                    text,
                    starts_letter: flags & 2 != 0,
                    ends_letter: flags & 1 != 0,
                })
            })
            .collect::<Result<_, RenderError>>()?;
        let names = (0..reader.count()?)
            .map(|_| {
                let currency = read_currency(reader)?;
                let kind = if reader.flag()? {
                    NameKind::Display
                } else {
                    NameKind::Count(read_category(reader)?)
                };
                Ok(Name {
                    currency,
                    kind,
                    text: reader.text()?.to_owned(),
                })
            })
            .collect::<Result<_, RenderError>>()?;
        let units = (0..reader.count()?)
            .map(|_| Ok((read_category(reader)?, reader.text()?.to_owned())))
            .collect::<Result<_, RenderError>>()?;
        let fractions_of = |reader: &mut Reader<'_>| -> Result<Fractions, RenderError> {
            Ok(Fractions {
                digits: reader.byte()?,
                increment: u16::try_from(reader.number()?).map_err(|_| reader.malformed())?,
            })
        };
        let default = fractions_of(reader)?;
        let fractions = (0..reader.count()?)
            .map(|_| Ok((read_currency(reader)?, fractions_of(reader)?)))
            .collect::<Result<_, RenderError>>()?;
        Ok(Self {
            display,
            accounting,
            fixed,
            patterns,
            symbols,
            names,
            units,
            default,
            fractions,
        })
    }

    fn fractions(&self, currency: Currency) -> Fractions {
        self.fractions
            .iter()
            .find(|(c, _)| *c == currency)
            .map_or(self.default, |(_, f)| *f)
    }

    /// The text that stands for `¤`, and whether it starts and ends with a letter.
    fn symbol(&self, currency: Currency) -> (String, bool, bool) {
        let found = self.symbols.iter().find(|s| s.currency == currency);
        match (self.display, found) {
            (Display::Symbol | Display::Narrow, Some(symbol)) => (
                symbol.text.clone(),
                symbol.starts_letter,
                symbol.ends_letter,
            ),
            _ => (code_text(currency), true, true),
        }
    }

    /// The name of `currency` of this kind, `other`'s when it has none of the category.
    fn name(&self, currency: Currency, kind: NameKind) -> String {
        let find = |kind: NameKind| {
            self.names
                .iter()
                .find(|n| n.currency == currency && n.kind == kind)
                .map(|n| n.text.clone())
        };
        find(kind)
            .or_else(|| find(NameKind::Count(Category::Other)))
            .unwrap_or_else(|| code_text(currency))
    }

    /// An amount in `currency`, rounded.
    fn amount(
        &self,
        form: &Form<'_>,
        fixed: &Fixed,
        currency: Currency,
    ) -> Result<String, RenderError> {
        let mut out = String::new();
        match self.display {
            Display::Never => {
                let pattern = if self.accounting {
                    &self.patterns.plain_accounting
                } else {
                    &self.patterns.plain
                };
                form.write(fixed, pattern, "", &mut out);
            }
            Display::Name => {
                let mut number = String::new();
                form.write(fixed, &self.patterns.decimal, "", &mut number);
                let category = form.cardinal(fixed)?;
                let name = self.name(currency, NameKind::Count(category));
                let unit = self
                    .units
                    .iter()
                    .find(|(c, _)| *c == category)
                    .or_else(|| self.units.iter().find(|(c, _)| *c == Category::Other))
                    .map(|(_, unit)| unit.as_str())
                    .ok_or(RenderError::Compiled(crate::currency::ID))?;
                out = unit.replace("{0}", &number).replace("{1}", &name);
            }
            Display::Symbol | Display::Narrow | Display::Code => {
                let (symbol, starts, ends) = self.symbol(currency);
                let (before, after) = adjacent(&self.patterns.standard);
                let alpha = (before && ends) || (after && starts);
                let pattern = match (self.accounting, alpha) {
                    (false, false) => &self.patterns.standard,
                    (false, true) => &self.patterns.standard_alpha,
                    (true, false) => &self.patterns.accounting,
                    (true, true) => &self.patterns.accounting_alpha,
                };
                form.write(fixed, pattern, &symbol, &mut out);
            }
        }
        Ok(out)
    }
}

/// Renders a `:currency` placeholder: an amount, a number in the placeholder's currency, or a
/// currency alone.
pub(crate) fn render(form: &Form<'_>, input: &Input<'_>) -> Result<String, RenderError> {
    let part = Part::read(&mut form.rest.clone())?;
    if let Input::Value(siros_explain::Value::Currency(currency)) = input {
        return Ok(match part.display {
            Display::Name => part.name(*currency, NameKind::Display),
            Display::Never => return Err(RenderError::Message(FormatFailure::BadOperand)),
            Display::Symbol | Display::Narrow | Display::Code => part.symbol(*currency).0,
        });
    }
    let NumericInput { number, currency } = NumericInput::of(input)?;
    let currency = currency
        .or(part.fixed)
        .ok_or(RenderError::Message(FormatFailure::BadOperand))?;
    let fractions = part.fractions(currency);
    let fixed = form.rounded(&form.value(number), (fractions.digits, fractions.increment));
    part.amount(form, &fixed, currency)
}

/// A language's currency data, as the load half writes it into a placeholder.
#[cfg(feature = "load")]
#[derive(Debug, Clone)]
pub(crate) struct Data {
    pub(crate) patterns: Patterns,
    pub(crate) symbols: Vec<Symbol>,
    pub(crate) narrow: Vec<Symbol>,
    pub(crate) names: Vec<Name>,
    pub(crate) units: Vec<(Category, String)>,
    pub(crate) default: Fractions,
    pub(crate) fractions: Vec<(Currency, Fractions)>,
}

#[cfg(feature = "load")]
impl Data {
    /// Writes the currency part of a placeholder in `display`, its tables restricted to `fixed`
    /// when the placeholder names its currency.
    pub(crate) fn write(
        &self,
        display: Display,
        accounting: bool,
        fixed: Option<Currency>,
        writer: &mut Writer,
    ) {
        let kept = |c: &Currency| fixed.is_none_or(|f| f == *c);
        writer.byte(
            Display::ALL
                .iter()
                .position(|&d| d == display)
                .map_or(0, |at| at as u8),
        );
        writer.flag(accounting);
        writer.flag(fixed.is_some());
        if let Some(currency) = fixed {
            writer.text(&code_text(currency));
        }
        for pattern in [
            &self.patterns.standard,
            &self.patterns.standard_alpha,
            &self.patterns.accounting,
            &self.patterns.accounting_alpha,
            &self.patterns.plain,
            &self.patterns.plain_accounting,
            &self.patterns.decimal,
        ] {
            pattern.write_to(writer);
        }
        let symbols: Vec<&Symbol> = match display {
            Display::Symbol => self.symbols.iter().filter(|s| kept(&s.currency)).collect(),
            Display::Narrow => self.narrow.iter().filter(|s| kept(&s.currency)).collect(),
            Display::Name | Display::Code | Display::Never => Vec::new(),
        };
        writer.count(symbols.len());
        for symbol in symbols {
            writer.text(&code_text(symbol.currency));
            writer.text(&symbol.text);
            writer.byte(u8::from(symbol.starts_letter) << 1 | u8::from(symbol.ends_letter));
        }
        let names: Vec<&Name> = if display == Display::Name {
            self.names.iter().filter(|n| kept(&n.currency)).collect()
        } else {
            Vec::new()
        };
        writer.count(names.len());
        for name in names {
            writer.text(&code_text(name.currency));
            match name.kind {
                NameKind::Display => writer.flag(true),
                NameKind::Count(category) => {
                    writer.flag(false);
                    writer.text(category.keyword());
                }
            }
            writer.text(&name.text);
        }
        let units: &[(Category, String)] = if display == Display::Name {
            &self.units
        } else {
            &[]
        };
        writer.count(units.len());
        for (category, unit) in units {
            writer.text(category.keyword());
            writer.text(unit);
        }
        let fractions_to = |writer: &mut Writer, f: Fractions| {
            writer.byte(f.digits);
            writer.number(u64::from(f.increment));
        };
        fractions_to(writer, self.default);
        let fractions: Vec<_> = self.fractions.iter().filter(|(c, _)| kept(c)).collect();
        writer.count(fractions.len());
        for (currency, f) in fractions {
            writer.text(&code_text(*currency));
            fractions_to(writer, *f);
        }
    }
}
