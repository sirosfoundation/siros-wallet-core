//! The date module's load half: a language's patterns and names parsed, and a placeholder
//! compiled for its function and `length`.

use siros_explain::ArgKind;

use super::{DateFormat, ID};
use crate::bytes::Writer;
use crate::error::{Refusal, RefusedOption};
use crate::format::{
    Call, Direction, FormatCompiler, FormatId, LanguageFormats, Operand, ParsedFormats,
};

/// The options the date module reads.
const OPTIONS: [&str; 22] = [
    "zero",
    "date-short",
    "date-medium",
    "date-long",
    "date-full",
    "time-short",
    "time-medium",
    "time-long",
    "time-full",
    "datetime-short",
    "datetime-medium",
    "datetime-long",
    "datetime-full",
    "months-wide",
    "months-abbreviated",
    "days-wide",
    "days-abbreviated",
    "periods",
    "zone-gmt",
    "zone-hours",
    "year-era",
    "eras",
];

/// A pattern's item, owned.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Item {
    Text(String),
    Field(u8, u8),
}

/// A length: `short`, `medium`, `long` or `full`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Length {
    Short,
    Medium,
    Long,
    Full,
}

impl Length {
    fn named(name: &str) -> Option<Self> {
        Some(match name {
            "short" => Self::Short,
            "medium" => Self::Medium,
            "long" => Self::Long,
            "full" => Self::Full,
            _ => return None,
        })
    }
}

/// Patterns by length.
#[derive(Debug, Clone)]
struct Lengths {
    short: Vec<Item>,
    medium: Vec<Item>,
    long: Vec<Item>,
    full: Vec<Item>,
}

impl Lengths {
    const fn get(&self, length: Length) -> &Vec<Item> {
        match length {
            Length::Short => &self.short,
            Length::Medium => &self.medium,
            Length::Long => &self.long,
            Length::Full => &self.full,
        }
    }
}

/// One language's date options, parsed.
struct Parsed {
    zero: char,
    direction: Direction,
    date: Lengths,
    time: Lengths,
    glue: Lengths,
    months: Vec<String>,
    days: Vec<String>,
    periods: Vec<String>,
    gmt: String,
    hours: [Vec<Item>; 2],
    year_era: Vec<Item>,
    eras: Vec<String>,
}

/// The fields a date or time pattern may hold, each with the widths it takes.
fn field(letter: char, width: usize) -> bool {
    match letter {
        'y' | 'd' | 'h' | 'H' | 'K' | 'k' | 'm' | 's' => width <= 2 || letter == 'y',
        'M' => width <= 4,
        'E' => width <= 4,
        'S' => width <= 9,
        'a' | 'G' => width <= 3,
        'z' => width <= 4,
        'O' => width == 1 || width == 4,
        _ => false,
    }
}

/// A TR35 pattern: letters `A-Za-z` are fields, `'…'` quotes literal text, `''` an apostrophe.
/// `accept` decides each field and its width.
fn items(text: &str, accept: impl Fn(char, usize) -> bool) -> Option<Vec<Item>> {
    let mut items: Vec<Item> = Vec::new();
    let mut literal = String::new();
    let mut chars = text.chars().peekable();
    let mut quoted = false;
    while let Some(c) = chars.next() {
        if c == '\'' {
            if chars.next_if_eq(&'\'').is_some() {
                literal.push('\'');
            } else {
                quoted = !quoted;
            }
        } else if quoted || !c.is_ascii_alphabetic() {
            literal.push(c);
        } else {
            let mut width = 1;
            while chars.next_if_eq(&c).is_some() {
                width += 1;
            }
            if !accept(c, width) {
                return None;
            }
            if !literal.is_empty() {
                items.push(Item::Text(std::mem::take(&mut literal)));
            }
            items.push(Item::Field(
                u8::try_from(c).ok()?,
                u8::try_from(width).ok()?,
            ));
        }
    }
    if quoted {
        return None;
    }
    if !literal.is_empty() {
        items.push(Item::Text(literal));
    }
    Some(items)
}

/// A glue pattern: `{0}` the time, `{1}` the date, each once, the rest literal after TR35's
/// quoting.
fn glue(text: &str) -> Option<Vec<Item>> {
    let marked = text.replace("{0}", "\u{0}").replace("{1}", "\u{1}");
    let (time, date) = (
        marked.matches('\u{0}').count(),
        marked.matches('\u{1}').count(),
    );
    if time != 1 || date != 1 {
        return None;
    }
    let mut result = Vec::new();
    for piece in split_keep(&marked) {
        match piece {
            "\u{0}" => result.push(Item::Field(0, 0)),
            "\u{1}" => result.push(Item::Field(1, 0)),
            text => result.extend(items(text, |_, _| false)?),
        }
    }
    Some(result)
}

/// `text` split into its placeholder marks and the texts between them.
fn split_keep(text: &str) -> Vec<&str> {
    let mut pieces = Vec::new();
    let mut start = 0;
    for (at, c) in text.char_indices() {
        if c == '\u{0}' || c == '\u{1}' {
            if start < at {
                pieces.push(text.get(start..at).unwrap_or_default());
            }
            pieces.push(text.get(at..at + 1).unwrap_or_default());
            start = at + 1;
        }
    }
    if start < text.len() {
        pieces.push(text.get(start..).unwrap_or_default());
    }
    pieces
}

/// Exactly `count` lines, each non-empty.
fn names(text: &str, count: usize) -> Option<Vec<String>> {
    let lines: Vec<String> = text.lines().map(str::to_owned).collect();
    (lines.len() == count && lines.iter().all(|l| !l.is_empty())).then_some(lines)
}

/// A year with its era (CLDR's `Gy` skeleton): one `y` and one `G`, the rest literal.
fn year_era(text: &str) -> Option<Vec<Item>> {
    let items = items(text, |c, w| c == 'y' || (c == 'G' && w <= 3))?;
    let mut fields: Vec<u8> = items
        .iter()
        .filter_map(|i| match i {
            Item::Field(c, _) => Some(*c),
            Item::Text(_) => None,
        })
        .collect();
    fields.sort_unstable();
    (fields == *b"Gy").then_some(items)
}

/// An hour format's positive and negative patterns, `;` between them.
fn hour_format(text: &str) -> Option<[Vec<Item>; 2]> {
    let (positive, negative) = text.split_once(';')?;
    Some([hours(positive)?, hours(negative)?])
}

/// An hour pattern: `H` or `HH`, then optionally a literal and `mm`.
fn hours(text: &str) -> Option<Vec<Item>> {
    let items = items(text, |c, w| (c == 'H' && w <= 2) || (c == 'm' && w == 2))?;
    let fields: Vec<u8> = items
        .iter()
        .filter_map(|i| match i {
            Item::Field(c, _) => Some(*c),
            Item::Text(_) => None,
        })
        .collect();
    matches!(fields.as_slice(), [b'H'] | [b'H', b'm']).then_some(items)
}

fn option<'m, T>(
    language: &LanguageFormats<'m>,
    name: &'static str,
    accept: impl FnOnce(&'m str) -> Option<T>,
) -> Result<T, RefusedOption> {
    let option = language.require(name)?;
    accept(option.text()).ok_or_else(|| option.refuse())
}

fn lengths(language: &LanguageFormats<'_>, prefix: &str) -> Result<Lengths, RefusedOption> {
    let names: [&'static str; 4] = match prefix {
        "date" => ["date-short", "date-medium", "date-long", "date-full"],
        "time" => ["time-short", "time-medium", "time-long", "time-full"],
        _ => [
            "datetime-short",
            "datetime-medium",
            "datetime-long",
            "datetime-full",
        ],
    };
    let parse = |name| {
        if prefix == "datetime" {
            option(language, name, glue)
        } else {
            option(language, name, |t| items(t, field))
        }
    };
    let [short, medium, long, full] = names;
    Ok(Lengths {
        short: parse(short)?,
        medium: parse(medium)?,
        long: parse(long)?,
        full: parse(full)?,
    })
}

impl FormatCompiler for DateFormat {
    fn id(&self) -> FormatId {
        ID
    }

    fn functions(&self) -> &'static [&'static str] {
        &["siros:date", "siros:time", "siros:datetime"]
    }

    fn options(&self) -> &'static [&'static str] {
        &OPTIONS
    }

    fn parse(
        &self,
        language: &LanguageFormats<'_>,
    ) -> Result<Box<dyn ParsedFormats>, RefusedOption> {
        let zero = option(language, "zero", |t| {
            let mut chars = t.chars();
            let zero = chars.next()?;
            (chars.next().is_none() && char::from_u32(u32::from(zero) + 9).is_some())
                .then_some(zero)
        })?;
        let mut months = option(language, "months-wide", |t| names(t, 12))?;
        months.extend(option(language, "months-abbreviated", |t| names(t, 12))?);
        let mut days = option(language, "days-wide", |t| names(t, 7))?;
        days.extend(option(language, "days-abbreviated", |t| names(t, 7))?);
        Ok(Box::new(Parsed {
            zero,
            direction: language.direction(),
            date: lengths(language, "date")?,
            time: lengths(language, "time")?,
            glue: lengths(language, "datetime")?,
            months,
            days,
            periods: option(language, "periods", |t| names(t, 2))?,
            gmt: option(language, "zone-gmt", |t| {
                (t.matches("{0}").count() == 1).then(|| t.to_owned())
            })?,
            hours: option(language, "zone-hours", hour_format)?,
            year_era: option(language, "year-era", year_era)?,
            eras: option(language, "eras", |t| names(t, 2))?,
        }))
    }
}

fn write_items(items: &[Item], writer: &mut Writer) {
    writer.count(items.len());
    for item in items {
        match item {
            Item::Text(text) => {
                writer.byte(0);
                writer.text(text);
            }
            Item::Field(letter, width) => {
                writer.byte(1);
                writer.byte(*letter);
                writer.byte(*width);
            }
        }
    }
}

fn write_texts(texts: &[String], writer: &mut Writer) {
    writer.count(texts.len());
    for text in texts {
        writer.text(text);
    }
}

/// The function a call's operand chain starts from, and the length an earlier call gave.
fn operand<'c>(call: &Call<'c>) -> Result<(Option<ArgKind>, Option<&'c str>), Refusal> {
    match call.operand() {
        Operand::Argument(kind) => Ok((Some(kind), None)),
        Operand::Call(inner) if inner.function().starts_with("siros:") => {
            let (kind, length) = operand(inner)?;
            let own = inner
                .options()
                .entries()
                .iter()
                .find(|e| *e.key() == "length");
            Ok((kind, own.map(|e| *e.value()).or(length)))
        }
        Operand::None | Operand::Literal(_) | Operand::Call(_) => Err(Refusal::Operand),
    }
}

impl ParsedFormats for Parsed {
    fn compile(&self, call: &Call<'_>) -> Result<Vec<u8>, Refusal> {
        let (kind, inherited) = operand(call)?;
        let (code, accepts): (u8, &[ArgKind]) = match call.function() {
            "siros:date" => (0, &[ArgKind::Date, ArgKind::DateTime]),
            "siros:time" => (1, &[ArgKind::Time, ArgKind::DateTime]),
            _ => (2, &[ArgKind::DateTime]),
        };
        if !kind.is_some_and(|kind| accepts.contains(&kind)) {
            return Err(Refusal::Operand);
        }
        if call.uses().selects() {
            return Err(Refusal::Selector);
        }
        let own = call
            .options()
            .entries()
            .iter()
            .find(|e| *e.key() == "length");
        let length = match own.map(|e| *e.value()).or(inherited) {
            Some(name) => Length::named(name).ok_or_else(|| Refusal::Option {
                option: "length".to_owned(),
            })?,
            None => Length::Medium,
        };
        let mut writer = Writer::default();
        writer.byte(code);
        writer.text(self.zero.encode_utf8(&mut [0; 4]));
        writer.byte(match self.direction {
            Direction::Ltr => 0,
            Direction::Rtl => 1,
            Direction::Unknown => 2,
        });
        let (with_date, with_time) = (code != 1, code != 0);
        let empty = Vec::new();
        write_items(
            if with_date {
                self.date.get(length)
            } else {
                &empty
            },
            &mut writer,
        );
        write_items(
            if with_time {
                self.time.get(length)
            } else {
                &empty
            },
            &mut writer,
        );
        let unzoned = match length {
            Length::Long | Length::Full => self.time.get(Length::Medium),
            Length::Short | Length::Medium => self.time.get(length),
        };
        write_items(if with_time { unzoned } else { &empty }, &mut writer);
        write_items(
            if code == 2 {
                self.glue.get(length)
            } else {
                &empty
            },
            &mut writer,
        );
        write_texts(&self.months, &mut writer);
        write_texts(&self.days, &mut writer);
        write_texts(&self.periods, &mut writer);
        writer.text(&self.gmt);
        let [positive, negative] = &self.hours;
        write_items(positive, &mut writer);
        write_items(negative, &mut writer);
        if with_date {
            write_items(&self.year_era, &mut writer);
            write_texts(&self.eras, &mut writer);
        } else {
            write_items(&empty, &mut writer);
            write_texts(&[], &mut writer);
        }
        Ok(writer.finish())
    }
}
