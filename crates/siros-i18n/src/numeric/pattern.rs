//! CLDR number patterns (Unicode TR35 Part 3, "Number Patterns"): the affixes around a number,
//! its grouping sizes, and its default digit counts.

use crate::bytes::Reader;
#[cfg(feature = "load")]
use crate::bytes::Writer;
use crate::error::RenderError;
use crate::numeric::decimal::Fixed;

/// A part of a prefix or a suffix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Affix {
    /// Literal text.
    Text(String),
    /// `-`: the locale's minus sign.
    Minus,
    /// `+`: the locale's plus sign.
    Plus,
    /// `%`: the locale's percent sign.
    Percent,
    /// `¤`: the currency's symbol, code or name.
    Currency,
}

/// A subpattern's prefix and suffix.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Affixes {
    pub(crate) prefix: Vec<Affix>,
    pub(crate) suffix: Vec<Affix>,
}

impl Affixes {
    fn has(&self, wanted: &Affix) -> bool {
        self.prefix.iter().chain(&self.suffix).any(|a| a == wanted)
    }

    /// The affixes with `-` written as `+`.
    fn plus(&self) -> Self {
        let swap = |parts: &[Affix]| {
            parts
                .iter()
                .map(|a| match a {
                    Affix::Minus => Affix::Plus,
                    other => other.clone(),
                })
                .collect()
        };
        Self {
            prefix: swap(&self.prefix),
            suffix: swap(&self.suffix),
        }
    }
}

/// A number pattern: its positive and its explicit negative subpattern's affixes, its grouping
/// sizes, and its digit counts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Pattern {
    pub(crate) positive: Affixes,
    pub(crate) negative: Option<Affixes>,
    pub(crate) primary: u8,
    pub(crate) secondary: u8,
    pub(crate) min_integer: u8,
    pub(crate) min_fraction: u8,
    pub(crate) max_fraction: u8,
}

/// The sign a number shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Shown {
    None,
    Minus,
    Plus,
}

/// The locale's number symbols.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Symbols {
    /// The digit zero; the digits one to nine follow it.
    pub(crate) zero: char,
    pub(crate) decimal: String,
    pub(crate) group: String,
    pub(crate) minus: String,
    pub(crate) plus: String,
    pub(crate) percent: String,
}

/// Whether and when the integer digits group: never, or from this many digits in the highest
/// group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Grouping {
    Never,
    From(u8),
}

impl Pattern {
    /// Writes `fixed` with the affixes `shown` selects; `currency` stands for `¤`.
    pub(crate) fn write(
        &self,
        fixed: &Fixed,
        shown: Shown,
        symbols: &Symbols,
        grouping: Grouping,
        currency: &str,
        out: &mut String,
    ) {
        let (affixes, sign) = match (shown, &self.negative) {
            (Shown::None, _) => (&self.positive, None),
            (Shown::Minus, Some(negative)) => (negative, None),
            (Shown::Minus, None) => (&self.positive, Some(&symbols.minus)),
            (Shown::Plus, Some(negative)) if negative.has(&Affix::Minus) => {
                return self.plus_with(negative, fixed, symbols, grouping, currency, out);
            }
            (Shown::Plus, _) => (&self.positive, Some(&symbols.plus)),
        };
        if let Some(sign) = sign {
            out.push_str(sign);
        }
        affix(&affixes.prefix, symbols, currency, out);
        self.body(fixed, symbols, grouping, out);
        affix(&affixes.suffix, symbols, currency, out);
    }

    fn plus_with(
        &self,
        negative: &Affixes,
        fixed: &Fixed,
        symbols: &Symbols,
        grouping: Grouping,
        currency: &str,
        out: &mut String,
    ) {
        let plus = negative.plus();
        affix(&plus.prefix, symbols, currency, out);
        self.body(fixed, symbols, grouping, out);
        affix(&plus.suffix, symbols, currency, out);
    }

    /// The digits, grouped, and the fraction after the decimal separator.
    pub(crate) fn body(
        &self,
        fixed: &Fixed,
        symbols: &Symbols,
        grouping: Grouping,
        out: &mut String,
    ) {
        let zero = u32::from(symbols.zero);
        let digit = |d: &u8| char::from_u32(zero + u32::from(*d)).unwrap_or(symbols.zero);
        let len = fixed.int.len();
        let primary = usize::from(self.primary);
        let grouped = match grouping {
            Grouping::Never => false,
            Grouping::From(minimum) => primary > 0 && len >= primary + usize::from(minimum),
        };
        for (index, d) in fixed.int.iter().enumerate() {
            let left = len - index;
            if grouped && index > 0 && self.boundary(left) {
                out.push_str(&symbols.group);
            }
            out.push(digit(d));
        }
        if !fixed.frac.is_empty() {
            out.push_str(&symbols.decimal);
            out.extend(fixed.frac.iter().map(digit));
        }
    }

    /// Whether a group separator stands before the digit with `left` digits from it to the end.
    fn boundary(&self, left: usize) -> bool {
        let (primary, secondary) = (usize::from(self.primary), usize::from(self.secondary));
        left == primary
            || (left > primary && secondary > 0 && (left - primary).is_multiple_of(secondary))
    }

    /// Writes the pattern.
    #[cfg(feature = "load")]
    pub(crate) fn write_to(&self, writer: &mut Writer) {
        affixes_to(&self.positive, writer);
        writer.flag(self.negative.is_some());
        if let Some(negative) = &self.negative {
            affixes_to(negative, writer);
        }
        for size in [
            self.primary,
            self.secondary,
            self.min_integer,
            self.min_fraction,
            self.max_fraction,
        ] {
            writer.byte(size);
        }
    }

    /// Reads a pattern.
    pub(crate) fn read(reader: &mut Reader<'_>) -> Result<Self, RenderError> {
        let positive = affixes_from(reader)?;
        let negative = if reader.flag()? {
            Some(affixes_from(reader)?)
        } else {
            None
        };
        Ok(Self {
            positive,
            negative,
            primary: reader.byte()?,
            secondary: reader.byte()?,
            min_integer: reader.byte()?,
            min_fraction: reader.byte()?,
            max_fraction: reader.byte()?,
        })
    }

    /// The pattern a module writes; `None` for a text outside the grammar this engine formats:
    /// no exponent, no significant-digit pattern, no padding.
    #[cfg(feature = "load")]
    pub(crate) fn parse(text: &str) -> Option<Self> {
        let mut subpatterns = split_unquoted(text, ';');
        let positive = subpatterns.next()?;
        let negative = subpatterns.next();
        if subpatterns.next().is_some() {
            return None;
        }
        let (prefix, body, suffix) = parts(positive)?;
        let mut pattern = numbers(body)?;
        pattern.positive = Affixes { prefix, suffix };
        if let Some(negative) = negative {
            let (prefix, _, suffix) = parts(negative)?;
            pattern.negative = Some(Affixes { prefix, suffix });
        }
        Some(pattern)
    }
}

fn affix(parts: &[Affix], symbols: &Symbols, currency: &str, out: &mut String) {
    for part in parts {
        out.push_str(match part {
            Affix::Text(text) => text,
            Affix::Minus => &symbols.minus,
            Affix::Plus => &symbols.plus,
            Affix::Percent => &symbols.percent,
            Affix::Currency => currency,
        });
    }
}

#[cfg(feature = "load")]
fn affixes_to(affixes: &Affixes, writer: &mut Writer) {
    for parts in [&affixes.prefix, &affixes.suffix] {
        writer.count(parts.len());
        for part in parts {
            match part {
                Affix::Text(text) => {
                    writer.byte(0);
                    writer.text(text);
                }
                Affix::Minus => writer.byte(1),
                Affix::Plus => writer.byte(2),
                Affix::Percent => writer.byte(3),
                Affix::Currency => writer.byte(4),
            }
        }
    }
}

fn affixes_from(reader: &mut Reader<'_>) -> Result<Affixes, RenderError> {
    let mut read = || -> Result<Vec<Affix>, RenderError> {
        (0..reader.count()?)
            .map(|_| {
                Ok(match reader.byte()? {
                    0 => Affix::Text(reader.text()?.to_owned()),
                    1 => Affix::Minus,
                    2 => Affix::Plus,
                    3 => Affix::Percent,
                    4 => Affix::Currency,
                    _ => return Err(reader.malformed()),
                })
            })
            .collect()
    };
    let prefix = read()?;
    let suffix = read()?;
    Ok(Affixes { prefix, suffix })
}

/// The pieces of `text` between unquoted `separator`s.
#[cfg(feature = "load")]
fn split_unquoted(text: &str, separator: char) -> impl Iterator<Item = &str> {
    let mut quoted = false;
    text.split(move |c| {
        if c == '\'' {
            quoted = !quoted;
        }
        c == separator && !quoted
    })
}

/// A subpattern's prefix, its number part, and its suffix.
#[cfg(feature = "load")]
fn parts(text: &str) -> Option<(Vec<Affix>, &str, Vec<Affix>)> {
    let mut quoted = false;
    let mut start = None;
    let mut end = 0;
    for (at, c) in text.char_indices() {
        if c == '\'' {
            quoted = !quoted;
        } else if !quoted && matches!(c, '#' | '0' | ',' | '.') {
            if start.is_some() && end != at {
                return None;
            }
            if start.is_none() {
                start = Some(at);
            }
            end = at + c.len_utf8();
        } else if !quoted && matches!(c, '@' | 'E' | '*') {
            return None;
        }
    }
    let start = start?;
    Some((
        affix_parts(text.get(..start)?)?,
        text.get(start..end)?,
        affix_parts(text.get(end..)?)?,
    ))
}

/// The parts of a prefix or suffix: quoted text literal, `''` an apostrophe.
#[cfg(feature = "load")]
fn affix_parts(text: &str) -> Option<Vec<Affix>> {
    let mut parts: Vec<Affix> = Vec::new();
    let mut literal = String::new();
    let mut chars = text.chars().peekable();
    let mut quoted = false;
    while let Some(c) = chars.next() {
        let special = match c {
            '\'' => {
                if chars.next_if_eq(&'\'').is_some() {
                    literal.push('\'');
                } else {
                    quoted = !quoted;
                }
                continue;
            }
            _ if quoted => None,
            '-' => Some(Affix::Minus),
            '+' => Some(Affix::Plus),
            '%' => Some(Affix::Percent),
            '¤' => Some(Affix::Currency),
            '‰' => return None,
            _ => None,
        };
        match special {
            Some(Affix::Currency)
                if parts.last() == Some(&Affix::Currency) && literal.is_empty() =>
            {
                return None;
            }
            Some(part) => {
                if !literal.is_empty() {
                    parts.push(Affix::Text(std::mem::take(&mut literal)));
                }
                parts.push(part);
            }
            None => literal.push(c),
        }
    }
    if quoted {
        return None;
    }
    if !literal.is_empty() {
        parts.push(Affix::Text(literal));
    }
    Some(parts)
}

/// The number part: grouping sizes from its integer part's `,`, digit counts from its `0` and
/// `#`.
#[cfg(feature = "load")]
fn numbers(body: &str) -> Option<Pattern> {
    let (integer, fraction) = match body.split_once('.') {
        Some((integer, fraction)) => (integer, fraction),
        None => (body, ""),
    };
    if fraction.contains([',', '.']) || integer.is_empty() {
        return None;
    }
    let groups: Vec<&str> = integer.split(',').collect();
    let size = |s: &str| u8::try_from(s.len()).ok();
    let (primary, secondary) = match groups.as_slice() {
        [_] => (0, 0),
        [.., second, last] if groups.len() > 2 => (size(last)?, size(second)?),
        [_, last] => (size(last)?, size(last)?),
        _ => return None,
    };
    if groups.iter().skip(1).any(|g| g.is_empty()) {
        return None;
    }
    let digits: String = groups.concat();
    let zeros_start = digits.find('0').unwrap_or(digits.len());
    if digits.get(zeros_start..)?.contains('#') {
        return None;
    }
    let min_fraction = fraction.chars().take_while(|&c| c == '0').count();
    if fraction.get(min_fraction..)?.contains('0') {
        return None;
    }
    Some(Pattern {
        positive: Affixes::default(),
        negative: None,
        primary,
        secondary,
        min_integer: u8::try_from(digits.len() - zeros_start).ok()?,
        min_fraction: u8::try_from(min_fraction).ok()?,
        max_fraction: u8::try_from(fraction.len()).ok()?,
    })
}
