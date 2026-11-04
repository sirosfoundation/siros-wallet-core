//! The load half the numeric formats share: a language's number options parsed, and a plain
//! numeric placeholder compiled from them.

use crate::bytes::Writer;
use crate::error::{Refusal, RefusedOption};
use crate::format::{Call, Direction, LanguageFormats};
use crate::numeric::Head;
use crate::numeric::options::{Function, Resolved, Root};
use crate::numeric::pattern::{Pattern, Symbols};
use crate::numeric::plural::Rules;

/// A language's number symbols and plural rules: the options every numeric format defines.
#[derive(Debug, Clone)]
pub(crate) struct Numbers {
    pub(crate) symbols: Symbols,
    pub(crate) minimum_grouping: u8,
    pub(crate) cardinal: Rules,
    pub(crate) ordinal: Rules,
    pub(crate) direction: Direction,
}

/// The option `name`'s text, refused when `accept` refuses it.
pub(crate) fn text<'m, T>(
    language: &LanguageFormats<'m>,
    name: &'static str,
    accept: impl FnOnce(&'m str) -> Option<T>,
) -> Result<T, RefusedOption> {
    let option = language.require(name)?;
    accept(option.text()).ok_or_else(|| option.refuse())
}

/// A symbol: one character or more.
pub(crate) fn symbol(text: &str) -> Option<String> {
    (!text.is_empty()).then(|| text.to_owned())
}

/// A pattern of this engine's grammar.
pub(crate) fn pattern(text: &str) -> Option<Pattern> {
    Pattern::parse(text)
}

impl Numbers {
    /// The options of `language`, `percent` its percent sign.
    pub(crate) fn parse(
        language: &LanguageFormats<'_>,
        percent: String,
    ) -> Result<Self, RefusedOption> {
        let zero = text(language, "zero", |t| {
            let mut chars = t.chars();
            let zero = chars.next()?;
            (chars.next().is_none() && char::from_u32(u32::from(zero) + 9).is_some())
                .then_some(zero)
        })?;
        Ok(Self {
            symbols: Symbols {
                zero,
                decimal: text(language, "decimal", symbol)?,
                group: text(language, "group", symbol)?,
                minus: text(language, "minus", symbol)?,
                plus: text(language, "plus", symbol)?,
                percent,
            },
            minimum_grouping: text(language, "grouping", |t| {
                t.parse().ok().filter(|n| (1..=9).contains(n))
            })?,
            cardinal: text(language, "cardinal", Rules::parse)?,
            ordinal: text(language, "ordinal", Rules::parse)?,
            direction: language.direction(),
        })
    }

    /// The head and rules of a numeric placeholder resolved as `resolved`, formatted with
    /// `pattern`.
    pub(crate) fn write(
        &self,
        resolved: &Resolved,
        pattern: &Pattern,
        selects: bool,
        writer: &mut Writer,
    ) -> Result<(), Refusal> {
        let selection = resolved.selection()?;
        if selects && selection == crate::numeric::Selection::None {
            return Err(Refusal::Selector);
        }
        Head {
            steps: &resolved.steps,
            sign: resolved.sign()?,
            grouping: resolved.grouping(self.minimum_grouping)?,
            digits: resolved.digits(pattern)?,
            percent: resolved.formatter == Function::Percent,
            selection,
            integer_keys: resolved.integer_keys(),
            direction: self.direction,
            symbols: &self.symbols,
            pattern,
        }
        .write(writer);
        writer.part(|part| self.cardinal.write(part));
        writer.part(|part| self.ordinal.write(part));
        Ok(())
    }

    /// A placeholder of `:number`, `:integer`, `:offset` or `:percent`, formatted with `pattern`.
    pub(crate) fn plain(&self, call: &Call<'_>, pattern: &Pattern) -> Result<Vec<u8>, Refusal> {
        let resolved = Resolved::of(call)?;
        if matches!(resolved.root, Root::Amount | Root::Currency)
            || resolved.formatter == Function::Currency
        {
            return Err(Refusal::Operand);
        }
        let mut writer = Writer::default();
        self.write(&resolved, pattern, call.uses().selects(), &mut writer)?;
        Ok(writer.finish())
    }
}

/// A language's options of `:number` and `:offset`: its numbers, and its decimal pattern.
#[cfg(any(feature = "number", feature = "offset"))]
pub(crate) struct Plain {
    numbers: Numbers,
    pattern: Pattern,
}

/// The options `:number` and `:offset` read.
#[cfg(any(feature = "number", feature = "offset"))]
pub(crate) const PLAIN: [&str; 9] = [
    "zero", "decimal", "group", "minus", "plus", "grouping", "cardinal", "ordinal", "pattern",
];

#[cfg(any(feature = "number", feature = "offset"))]
impl Plain {
    /// A language's options.
    pub(crate) fn parse(
        language: &LanguageFormats<'_>,
    ) -> Result<Box<dyn crate::format::ParsedFormats>, RefusedOption> {
        Ok(Box::new(Self {
            numbers: Numbers::parse(language, "%".to_owned())?,
            pattern: text(language, "pattern", pattern)?,
        }))
    }
}

#[cfg(any(feature = "number", feature = "offset"))]
impl crate::format::ParsedFormats for Plain {
    fn compile(&self, call: &Call<'_>) -> Result<Vec<u8>, Refusal> {
        self.numbers.plain(call, &self.pattern)
    }
}
