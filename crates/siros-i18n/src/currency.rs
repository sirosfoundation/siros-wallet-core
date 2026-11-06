//! The currency module (spec/functions/number.md): `:currency`, which formats an amount with the
//! language's currency patterns, symbols, names and fraction digits, and `:percent`, which formats
//! and selects a number times 100.

use siros_explain::checked;

use crate::error::{FormatFailure, RenderError};
use crate::format::{Direction, FormatId, FormatRenderer, Input, VariantKey, VariantKeys};
use crate::numeric::{self, Form};
use crate::sink::Sink;

/// The currency module, both halves.
#[derive(Debug)]
pub struct CurrencyFormat;

/// The currency module a build registers.
pub static CURRENCY: CurrencyFormat = CurrencyFormat;

pub(crate) const ID: FormatId = checked!(FormatId, "currency");

/// The first byte of a compiled `:percent` placeholder.
const PERCENT: u8 = 0;
/// The first byte of a compiled `:currency` placeholder.
const AMOUNT: u8 = 1;

/// A compiled placeholder's function, and its numeric form.
fn read(compiled: &[u8]) -> Result<(u8, Form<'_>), RenderError> {
    let (&kind, rest) = compiled.split_first().ok_or(RenderError::Compiled(ID))?;
    Ok((kind, Form::read(rest, ID)?))
}

impl FormatRenderer for CurrencyFormat {
    fn id(&self) -> FormatId {
        ID
    }

    fn direction(&self, compiled: &[u8], _input: &Input<'_>) -> Result<Direction, RenderError> {
        read(compiled).map(|(_, form)| form.direction)
    }

    fn render(
        &self,
        compiled: &[u8],
        input: &Input<'_>,
        sink: &mut dyn Sink,
    ) -> Result<(), RenderError> {
        match read(compiled)? {
            (PERCENT, _) => numeric::render(ID, compiled.get(1..).unwrap_or_default(), input, sink),
            (AMOUNT, form) => {
                sink.text(&numeric::currency::render(&form, input)?);
                Ok(())
            }
            _ => Err(RenderError::Compiled(ID)),
        }
    }

    fn select<'k>(
        &self,
        compiled: &[u8],
        input: &Input<'_>,
        keys: VariantKeys<'k>,
    ) -> Result<Vec<VariantKey<'k>>, RenderError> {
        match read(compiled)? {
            (PERCENT, _) => numeric::select(ID, compiled.get(1..).unwrap_or_default(), input, keys),
            _ => Err(RenderError::Message(FormatFailure::BadSelector)),
        }
    }
}

#[cfg(feature = "load")]
mod load {
    use siros_explain::Currency;
    use unicode_general_category::{GeneralCategory, get_general_category};

    use super::{AMOUNT, CurrencyFormat, ID, PERCENT};
    use crate::bytes::Writer;
    use crate::error::{Refusal, RefusedOption};
    use crate::format::{Call, FormatCompiler, FormatId, LanguageFormats, ParsedFormats};
    use crate::numeric::compile::{Numbers, pattern, symbol, text};
    use crate::numeric::currency::{Data, Display, Fractions, Name, NameKind, Patterns, Symbol};
    use crate::numeric::options::{Resolved, Root, currency};
    use crate::numeric::pattern::Pattern;
    use crate::numeric::plural::Category;

    /// The options the currency module reads.
    const OPTIONS: [&str; 22] = [
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

    /// One language's currency options, parsed.
    struct Parsed {
        numbers: Numbers,
        percent: Pattern,
        data: Data,
    }

    /// Whether a character is a letter (General Category L).
    fn letter(c: Option<char>) -> bool {
        c.map(get_general_category).is_some_and(|category| {
            matches!(
                category,
                GeneralCategory::UppercaseLetter
                    | GeneralCategory::LowercaseLetter
                    | GeneralCategory::TitlecaseLetter
                    | GeneralCategory::ModifierLetter
                    | GeneralCategory::OtherLetter
            )
        })
    }

    /// Lines of `<code> <rest>`, each code an ISO 4217 currency, given once per `key` of the rest.
    fn table<T>(text: &str, mut entry: impl FnMut(Currency, &str) -> Option<T>) -> Option<Vec<T>> {
        text.lines()
            .map(|line| {
                let (code, rest) = line.split_once(' ')?;
                entry(Currency::from_code(code)?, rest)
            })
            .collect()
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
            let (kind, name) = rest.split_once(' ')?;
            let kind = match kind {
                "display" => NameKind::Display,
                keyword => NameKind::Count(Category::of_keyword(keyword)?),
            };
            (!name.is_empty()).then(|| Name {
                currency,
                kind,
                text: name.to_owned(),
            })
        })?;
        distinct(&names, |n| (n.currency, n.kind)).then_some(names)
    }

    fn units(text: &str) -> Option<Vec<(Category, String)>> {
        let units = text
            .lines()
            .map(|line| {
                let (keyword, unit) = line.split_once(' ')?;
                let fits = unit.contains("{0}") && unit.contains("{1}");
                fits.then(|| Category::of_keyword(keyword).map(|c| (c, unit.to_owned())))?
            })
            .collect::<Option<Vec<_>>>()?;
        (distinct(&units, |(c, _)| *c) && units.iter().any(|(c, _)| *c == Category::Other))
            .then_some(units)
    }

    fn fractions(text: &str) -> Option<(Fractions, Vec<(Currency, Fractions)>)> {
        let parse = |rest: &str| {
            let mut words = rest.split(' ');
            let digits = words.next()?.parse().ok().filter(|d: &u8| *d <= 20)?;
            let increment = match words.next() {
                Some(word) => word.parse().ok().filter(|i: &u16| *i > 0)?,
                None => 1,
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
                entries.push((Currency::from_code(code)?, parse(rest)?));
            }
        }
        distinct(&entries, |(c, _)| *c).then_some((default?, entries))
    }

    fn distinct<T, K: PartialEq>(items: &[T], key: impl Fn(&T) -> K) -> bool {
        items.iter().enumerate().all(|(at, item)| {
            items
                .iter()
                .take(at)
                .all(|earlier| key(earlier) != key(item))
        })
    }

    impl FormatCompiler for CurrencyFormat {
        fn id(&self) -> FormatId {
            ID
        }

        fn functions(&self) -> &'static [&'static str] {
            &["currency", "percent"]
        }

        fn options(&self) -> &'static [&'static str] {
            &OPTIONS
        }

        fn parse(
            &self,
            language: &LanguageFormats<'_>,
        ) -> Result<Box<dyn ParsedFormats>, RefusedOption> {
            let percent_sign = text(language, "percent-sign", symbol)?;
            let (default, fractions) = text(language, "digits", fractions)?;
            Ok(Box::new(Parsed {
                numbers: Numbers::parse(language, percent_sign)?,
                percent: text(language, "percent-pattern", pattern)?,
                data: Data {
                    patterns: Patterns {
                        standard: text(language, "standard", pattern)?,
                        standard_alpha: text(language, "standard-alpha", pattern)?,
                        accounting: text(language, "accounting", pattern)?,
                        accounting_alpha: text(language, "accounting-alpha", pattern)?,
                        plain: text(language, "no-currency", pattern)?,
                        plain_accounting: text(language, "no-currency-accounting", pattern)?,
                        decimal: text(language, "pattern", pattern)?,
                    },
                    symbols: text(language, "symbols", symbols)?,
                    narrow: text(language, "narrow", symbols)?,
                    names: text(language, "names", names)?,
                    units: text(language, "unit-pattern", units)?,
                    default,
                    fractions,
                },
            }))
        }
    }

    impl ParsedFormats for Parsed {
        fn compile(&self, call: &Call<'_>) -> Result<Vec<u8>, Refusal> {
            let mut writer = Writer::default();
            if call.function() == "percent" {
                writer.byte(PERCENT);
                let plain = self.numbers.plain(call, &self.percent)?;
                let mut bytes = writer.finish();
                bytes.extend_from_slice(&plain);
                return Ok(bytes);
            }
            writer.byte(AMOUNT);
            let resolved = Resolved::of(call)?;
            let refuse = |option: &str| Refusal::Option {
                option: option.to_owned(),
            };
            let display = match resolved.get("currencyDisplay") {
                Some(name) => Display::named(name).ok_or_else(|| refuse("currencyDisplay"))?,
                None => Display::Symbol,
            };
            let accounting = resolved.get("currencySign") == Some("accounting");
            let fixed = match resolved.get("currency") {
                Some(code) => Some(currency(code).ok_or_else(|| refuse("currency"))?),
                None => None,
            };
            match (resolved.root, fixed) {
                (Root::Literal | Root::Number | Root::Text, None) => return Err(Refusal::Operand),
                (Root::Currency, _) if display == Display::Never => {
                    return Err(refuse("currencyDisplay"));
                }
                _ => {}
            }
            let selects = call.uses().selects();
            self.numbers.write(
                &resolved,
                &self.data.patterns.standard,
                selects,
                &mut writer,
            )?;
            self.data.write(display, accounting, fixed, &mut writer);
            Ok(writer.finish())
        }
    }
}
