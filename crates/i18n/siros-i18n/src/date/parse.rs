//! `[formats.date]`'s options, parsed: TR35 patterns and name lists.

use super::{EraField, Field, Glue, Hours, Item, Lengths, Names, Parsed, Pattern, fields};
use crate::digit::Numerals;
use crate::error::FormatRule;
use crate::format::Options;

/// A TR35 pattern: letters `A-Za-z` are fields, `'…'` quotes literal text, `''` an apostrophe.
/// `field` reads each field and its width. `None` for a field `field` refuses or wider than 255
/// letters, and for an unclosed quote.
fn items<F>(text: &str, field: impl Fn(char, u8) -> Option<F>) -> Option<Pattern<F>> {
    let mut items = Vec::new();
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
            let mut width: u8 = 1;
            while chars.next_if_eq(&c).is_some() {
                width = width.checked_add(1)?;
            }
            let read = field(c, width)?;
            if !literal.is_empty() {
                items.push(Item::Text(std::mem::take(&mut literal)));
            }
            items.push(Item::Field(read));
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

/// A datetime pattern: `{0}` the time, `{1}` the date, each once, the rest literal after TR35's
/// quoting.
fn glue(text: &str) -> Option<Pattern<Glue>> {
    let mut items = Vec::new();
    let mut rest = text;
    while let Some((before, mark)) = rest.split_once('{') {
        items.extend(self::items(before, |_, _| None::<Glue>)?);
        let (field, after) = match (mark.strip_prefix("0}"), mark.strip_prefix("1}")) {
            (Some(after), _) => (Glue::Time, after),
            (None, Some(after)) => (Glue::Date, after),
            (None, None) => return None,
        };
        items.push(Item::Field(field));
        rest = after;
    }
    items.extend(self::items(rest, |_, _| None::<Glue>)?);
    let count = |wanted: Glue| fields(&items).filter(|field| *field == wanted).count();
    (count(Glue::Time) == 1 && count(Glue::Date) == 1).then_some(items)
}

/// A year with its era (CLDR's `Gy` skeleton): one `y` and one `G`, the rest literal.
fn year_era(text: &str) -> Option<Pattern<EraField>> {
    let items = items(text, |c, width| match (c, width) {
        ('y', _) => Some(EraField::Year(width)),
        ('G', 1..=3) => Some(EraField::Era),
        _ => None,
    })?;
    let years = fields(&items)
        .filter(|f| matches!(f, EraField::Year(_)))
        .count();
    let eras = fields(&items).filter(|f| *f == EraField::Era).count();
    (years == 1 && eras == 1).then_some(items)
}

/// An hour format's positive and negative patterns, `;` between them.
fn hour_format(text: &str) -> Option<[Hours; 2]> {
    let (positive, negative) = text.split_once(';')?;
    Some([hours(positive)?, hours(negative)?])
}

/// The field of an hour pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HourField {
    Hours,
    Minutes,
}

/// An hour pattern: `H` or `HH`, then optionally a literal and `mm`.
fn hours(text: &str) -> Option<Hours> {
    let items = items(text, |c, width| match (c, width) {
        ('H', 1..=2) => Some(HourField::Hours),
        ('m', 2) => Some(HourField::Minutes),
        _ => None,
    })?;
    let mut before = String::new();
    let mut between = None;
    let mut after = String::new();
    let mut read: Vec<HourField> = Vec::new();
    for item in items {
        match item {
            Item::Text(text) if read.is_empty() => before.push_str(&text),
            Item::Text(text) => after.push_str(&text),
            Item::Field(HourField::Hours) if read.is_empty() => read.push(HourField::Hours),
            Item::Field(HourField::Minutes) if read == [HourField::Hours] => {
                between = Some(std::mem::take(&mut after));
                read.push(HourField::Minutes);
            }
            Item::Field(_) => return None,
        }
    }
    (!read.is_empty()).then_some(Hours {
        before,
        minutes: between,
        after,
    })
}

/// The localized GMT format: the text around `{0}`, which stands once.
fn gmt(text: &str) -> Option<(String, String)> {
    let (before, after) = text.split_once("{0}")?;
    (!after.contains("{0}")).then(|| (before.to_owned(), after.to_owned()))
}

impl Parsed {
    /// The section's options.
    ///
    /// # Errors
    ///
    /// [`FormatRule`] for an option the section lacks or whose text the grammar refuses.
    pub(crate) fn parse(options: Options<'_>) -> Result<Self, FormatRule> {
        let pattern = |name, accept: fn(Field) -> bool| {
            options.parse(name, |text| {
                items(text, Field::of).filter(|pattern| fields(pattern).all(accept))
            })
        };
        let date = |name| pattern(name, Field::of_date);
        let zoned = |name| pattern(name, |field| !field.of_date());
        let unzoned = |name| pattern(name, |field| !field.of_date() && !field.zoned());
        let glued = |name| options.parse(name, glue);
        let names = |name, count| options.parse(name, |text| Names::parse(text, count));
        Ok(Self {
            numerals: options.parse("zero", Numerals::parse)?,
            direction: options.direction,
            date: Lengths {
                short: date("date-short")?,
                medium: date("date-medium")?,
                long: date("date-long")?,
                full: date("date-full")?,
            },
            time: Lengths {
                short: unzoned("time-short")?,
                medium: unzoned("time-medium")?,
                long: zoned("time-long")?,
                full: zoned("time-full")?,
            },
            glue: Lengths {
                short: glued("datetime-short")?,
                medium: glued("datetime-medium")?,
                long: glued("datetime-long")?,
                full: glued("datetime-full")?,
            },
            months_wide: names("months-wide", 12)?,
            months_abbreviated: names("months-abbreviated", 12)?,
            days_wide: names("days-wide", 7)?,
            days_abbreviated: names("days-abbreviated", 7)?,
            periods: names("periods", 2)?,
            gmt: options.parse("zone-gmt", gmt)?,
            hours: options.parse("zone-hours", hour_format)?,
            year_era: options.parse("year-era", year_era)?,
            eras: names("eras", 2)?,
        })
    }
}
