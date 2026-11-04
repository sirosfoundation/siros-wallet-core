//! CLDR plural rules (Unicode TR35 Part 3, "Language Plural Rules"): parsed from a module's text
//! when it loads, written into a compiled placeholder, and evaluated on a formatted number's
//! operands when it renders.

use std::num::{NonZeroU64, NonZeroU128};
use std::ops::Rem;

use crate::bytes::Reader;
#[cfg(feature = "load")]
use crate::bytes::Writer;
use crate::error::RenderError;
use crate::numeric::decimal::Fixed;

/// A plural category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Category {
    Zero,
    One,
    Two,
    Few,
    Many,
    Other,
}

impl Category {
    const ALL: [Self; 6] = [
        Self::Zero,
        Self::One,
        Self::Two,
        Self::Few,
        Self::Many,
        Self::Other,
    ];

    /// Its keyword.
    pub(crate) const fn keyword(self) -> &'static str {
        match self {
            Self::Zero => "zero",
            Self::One => "one",
            Self::Two => "two",
            Self::Few => "few",
            Self::Many => "many",
            Self::Other => "other",
        }
    }

    /// The category of a keyword.
    pub(crate) fn of_keyword(keyword: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.keyword() == keyword)
    }

    fn of_code(code: u8) -> Option<Self> {
        Self::ALL.get(usize::from(code)).copied()
    }

    #[cfg(feature = "load")]
    fn code(self) -> u8 {
        self as u8
    }
}

/// A plural operand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Operand {
    /// The absolute value.
    N,
    /// The integer digits.
    I,
    /// The count of visible fraction digits.
    V,
    /// The count of visible fraction digits without trailing zeros.
    W,
    /// The visible fraction digits.
    F,
    /// The visible fraction digits without trailing zeros.
    T,
    /// The compact decimal exponent; always 0.
    C,
    /// The same as `C`.
    E,
}

impl Operand {
    const ALL: [Self; 8] = [
        Self::N,
        Self::I,
        Self::V,
        Self::W,
        Self::F,
        Self::T,
        Self::C,
        Self::E,
    ];

    #[cfg(feature = "load")]
    fn named(name: &str) -> Option<Self> {
        let names = ["n", "i", "v", "w", "f", "t", "c", "e"];
        names
            .iter()
            .zip(Self::ALL)
            .find_map(|(&n, operand)| (n == name).then_some(operand))
    }
}

/// An operand's value: the digits of its integer part, without leading zeros, and whether its
/// fraction is nonzero.
struct Value {
    int: Vec<u8>,
    fraction: bool,
}

impl Value {
    fn of(digits: &[u8], fraction: bool) -> Self {
        let int = digits.iter().copied().skip_while(|&d| d == 0).collect();
        Self { int, fraction }
    }

    fn count(count: usize) -> Self {
        Self::of(
            &count
                .to_string()
                .bytes()
                .map(|b| b - b'0')
                .collect::<Vec<_>>(),
            false,
        )
    }

    /// The value's integer part, when it fits a `u64`.
    fn word(&self) -> Option<u64> {
        self.int.iter().try_fold(0u64, |value, &d| {
            value.checked_mul(10)?.checked_add(u64::from(d))
        })
    }

    /// The value modulo `modulus`, its fraction kept.
    fn modulo(&self, modulus: NonZeroU64) -> Self {
        let modulus = NonZeroU128::from(modulus);
        let rest = self.int.iter().fold(0u128, |rest, &d| {
            Rem::rem(rest * 10 + u128::from(d), modulus)
        });
        Self {
            int: rest.to_string().bytes().map(|b| b - b'0').collect(),
            fraction: self.fraction,
        }
    }

    /// Whether it equals an integer of `low..=high`.
    fn among(&self, low: u64, high: u64) -> bool {
        !self.fraction && self.word().is_some_and(|v| (low..=high).contains(&v))
    }

    /// Whether it lies within `low..=high`, fraction included.
    fn within(&self, low: u64, high: u64) -> bool {
        match self.word() {
            Some(v) => v >= low && (v < high || (v == high && !self.fraction)),
            None => false,
        }
    }
}

/// A formatted number's plural operands.
pub(crate) struct Operands<'a> {
    fixed: &'a Fixed,
}

impl<'a> Operands<'a> {
    pub(crate) const fn of(fixed: &'a Fixed) -> Self {
        Self { fixed }
    }

    fn value(&self, operand: Operand) -> Value {
        let frac = &self.fixed.frac;
        let trimmed = frac.len() - frac.iter().rev().take_while(|&&d| d == 0).count();
        let without = frac.get(..trimmed).unwrap_or_default();
        match operand {
            Operand::N => Value::of(&self.fixed.int, !without.is_empty()),
            Operand::I => Value::of(&self.fixed.int, false),
            Operand::V => Value::count(frac.len()),
            Operand::W => Value::count(without.len()),
            Operand::F => Value::of(frac, false),
            Operand::T => Value::of(without, false),
            Operand::C | Operand::E => Value::count(0),
        }
    }
}

/// Reads compiled plural rules and gives a number's category.
pub(crate) fn category(
    reader: &mut Reader<'_>,
    operands: &Operands<'_>,
) -> Result<Category, RenderError> {
    let mut chosen = None;
    for _ in 0..reader.count()? {
        let keyword = Category::of_code(reader.byte()?).ok_or(reader.malformed())?;
        let mut any = false;
        for _ in 0..reader.count()? {
            let mut all = true;
            for _ in 0..reader.count()? {
                all &= relation(reader, operands)?;
            }
            any |= all;
        }
        if any && chosen.is_none() {
            chosen = Some(keyword);
        }
    }
    Ok(chosen.unwrap_or(Category::Other))
}

/// Reads one relation and evaluates it.
fn relation(reader: &mut Reader<'_>, operands: &Operands<'_>) -> Result<bool, RenderError> {
    let head = reader.byte()?;
    let operand = Operand::ALL
        .get(usize::from(head & 0x0f))
        .copied()
        .ok_or(reader.malformed())?;
    let (negated, within) = (head & 0x10 != 0, head & 0x20 != 0);
    let modulus = reader.number()?;
    let mut value = operands.value(operand);
    if let Some(modulus) = NonZeroU64::new(modulus) {
        value = value.modulo(modulus);
    }
    let mut matched = false;
    for _ in 0..reader.count()? {
        let (low, high) = (reader.number()?, reader.number()?);
        matched |= if within {
            value.within(low, high)
        } else {
            value.among(low, high)
        };
    }
    Ok(matched != negated)
}

/// Rules as a module writes them: one `<keyword>: <condition>` per line, samples after `@`
/// ignored.
#[cfg(feature = "load")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Rules {
    rules: Vec<Rule>,
}

#[cfg(feature = "load")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct Rule {
    category: Category,
    condition: Vec<Vec<Relation>>,
}

#[cfg(feature = "load")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct Relation {
    operand: Operand,
    modulus: u64,
    negated: bool,
    within: bool,
    ranges: Vec<(u64, u64)>,
}

#[cfg(feature = "load")]
impl Rules {
    /// The rules a text writes; `None` for a text outside the grammar, a keyword given twice, or
    /// a rule for `other`.
    pub(crate) fn parse(text: &str) -> Option<Self> {
        let mut rules: Vec<Rule> = Vec::new();
        for line in text.lines().filter(|line| !line.trim().is_empty()) {
            let (keyword, condition) = line.split_once(':')?;
            let category = Category::of_keyword(keyword.trim())?;
            if category == Category::Other || rules.iter().any(|r| r.category == category) {
                return None;
            }
            let condition = condition.split('@').next().unwrap_or_default();
            rules.push(Rule {
                category,
                condition: or_condition(condition)?,
            });
        }
        Some(Self { rules })
    }

    /// Writes the rules.
    pub(crate) fn write(&self, writer: &mut Writer) {
        writer.count(self.rules.len());
        for rule in &self.rules {
            writer.byte(rule.category.code());
            writer.count(rule.condition.len());
            for and in &rule.condition {
                writer.count(and.len());
                for relation in and {
                    let head = relation.operand as u8
                        | if relation.negated { 0x10 } else { 0 }
                        | if relation.within { 0x20 } else { 0 };
                    writer.byte(head);
                    writer.number(relation.modulus);
                    writer.count(relation.ranges.len());
                    for &(low, high) in &relation.ranges {
                        writer.number(low);
                        writer.number(high);
                    }
                }
            }
        }
    }
}

/// `condition = and_condition ('or' and_condition)*`.
#[cfg(feature = "load")]
fn or_condition(text: &str) -> Option<Vec<Vec<Relation>>> {
    let words: Vec<&str> = text.split_whitespace().collect();
    if words.is_empty() {
        return None;
    }
    words
        .split(|&w| w == "or")
        .map(|and| and.split(|&w| w == "and").map(relation_of).collect())
        .collect()
}

/// `relation = expr ('is' 'not'? | 'not'? 'in' | 'not'? 'within' | '=' | '!=') range_list`.
#[cfg(feature = "load")]
fn relation_of(words: &[&str]) -> Option<Relation> {
    let (&operand, rest) = words.split_first()?;
    let operand = Operand::named(operand)?;
    let (modulus, rest) = match rest {
        [m, value, rest @ ..] if *m == "mod" || *m == "%" => {
            (value.parse().ok().filter(|&m: &u64| m > 0)?, rest)
        }
        rest => (0, rest),
    };
    if modulus == 0 && rest.first().is_some_and(|&w| w == "mod" || w == "%") {
        return None;
    }
    let (negated, within, rest) = match rest {
        ["is", "not", value] | ["is", value] => {
            let value = value.parse().ok()?;
            return Some(Relation {
                operand,
                modulus,
                negated: rest.len() == 3,
                within: false,
                ranges: vec![(value, value)],
            });
        }
        ["not", "in", rest @ ..] | ["!=", rest @ ..] => (true, false, rest),
        ["in", rest @ ..] | ["=", rest @ ..] => (false, false, rest),
        ["not", "within", rest @ ..] => (true, true, rest),
        ["within", rest @ ..] => (false, true, rest),
        _ => return None,
    };
    let list: String = rest.concat();
    let ranges = list
        .split(',')
        .map(|item| match item.split_once("..") {
            Some((low, high)) => {
                let (low, high) = (low.parse().ok()?, high.parse().ok()?);
                (low <= high).then_some((low, high))
            }
            None => item.parse().ok().map(|v| (v, v)),
        })
        .collect::<Option<Vec<_>>>()?;
    Some(Relation {
        operand,
        modulus,
        negated,
        within,
        ranges,
    })
}
