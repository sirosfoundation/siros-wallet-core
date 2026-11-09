//! The language data the numeric formats share: a language's number symbols, grouping and plural
//! rules, which every numeric section defines, and the `[formats.number]` and `[formats.offset]`
//! sections, which add the decimal pattern.

use crate::error::FormatRule;
use crate::format::{Direction, Options};
#[cfg(any(feature = "number", feature = "offset"))]
use crate::numeric::pattern::Pattern;
use crate::numeric::pattern::Symbols;
use crate::numeric::plural::Rules;

/// A language's number symbols and plural rules: the options every numeric section defines, and
/// the section's module's direction.
#[derive(Debug, Clone)]
pub(crate) struct Numbers {
    pub(crate) symbols: Symbols,
    pub(crate) minimum_grouping: u8,
    pub(crate) cardinal: Rules,
    pub(crate) ordinal: Rules,
    pub(crate) direction: Direction,
}

/// A symbol: one character or more.
pub(crate) fn symbol(text: &str) -> Option<String> {
    (!text.is_empty()).then(|| text.to_owned())
}

/// A digit zero: one character, nine characters after which are digits too.
fn zero(text: &str) -> Option<char> {
    let mut chars = text.chars();
    let zero = chars.next()?;
    (chars.next().is_none() && char::from_u32(u32::from(zero) + 9).is_some()).then_some(zero)
}

impl Numbers {
    /// The options of a section, `percent` its percent sign.
    ///
    /// # Errors
    ///
    /// [`FormatRule`] for an option the section lacks or whose text the grammar refuses.
    pub(crate) fn parse(options: Options<'_>, percent: String) -> Result<Self, FormatRule> {
        Ok(Self {
            symbols: Symbols {
                zero: options.parse("zero", zero)?,
                decimal: options.parse("decimal", symbol)?,
                group: options.parse("group", symbol)?,
                minus: options.parse("minus", symbol)?,
                plus: options.parse("plus", symbol)?,
                percent,
            },
            minimum_grouping: options.parse("grouping", |t| {
                t.parse().ok().filter(|n| (1..=9).contains(n))
            })?,
            cardinal: options.parse("cardinal", Rules::parse)?,
            ordinal: options.parse("ordinal", Rules::parse)?,
            direction: options.direction,
        })
    }
}

/// A language's options of `:number` and `:offset`: its numbers, and its decimal pattern.
#[cfg(any(feature = "number", feature = "offset"))]
#[derive(Debug, Clone)]
pub(crate) struct Plain {
    pub(crate) numbers: Numbers,
    pub(crate) pattern: Pattern,
}

/// The options `[formats.number]` and `[formats.offset]` take.
#[cfg(any(feature = "number", feature = "offset"))]
pub(crate) const PLAIN: [&str; 9] = [
    "zero", "decimal", "group", "minus", "plus", "grouping", "cardinal", "ordinal", "pattern",
];

#[cfg(any(feature = "number", feature = "offset"))]
impl Plain {
    /// A section's options.
    ///
    /// # Errors
    ///
    /// [`FormatRule`] for an option the section lacks or whose text the grammar refuses.
    pub(crate) fn parse(options: Options<'_>) -> Result<Self, FormatRule> {
        Ok(Self {
            numbers: Numbers::parse(options, "%".to_owned())?,
            pattern: options.parse("pattern", Pattern::parse)?,
        })
    }
}
