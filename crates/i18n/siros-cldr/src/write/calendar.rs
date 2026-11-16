//! The `date`, `time` and `datetime` formats, their patterns chosen as ICU4X 2.4's data
//! generator chooses them (icu_provider_source 2.4.0, `datetime/semantic_skeletons.rs`):
//!
//! - a date is the field set `YMD` at its length, and `YMDE` long at `full`; its fields take the
//!   widths of the Gregorian `dateSkeletons` of the length, and the Gregorian `availableFormats`
//!   give the pattern. A date has three patterns: the year as the length writes it, the full
//!   year, and the full year with its era (`make_packed_skeleton_data`); a year from 1950 to 2049
//!   takes the first, a year before 1000 the third, every other year the second
//!   (icu_datetime 2.4.0, `raw/neo.rs`, `resolve_date_variant`, and icu_calendar's Gregorian
//!   year ambiguity).
//! - a time is the hour, with minutes at `short` and with seconds at the other lengths, from
//!   the generic calendar's `availableFormats`, its hour cycle that of the generic
//!   `timeSkeletons` (`gen_time_components`, `preferred_hour_cycle`).
//! - a date and time joins the date and the time with the Gregorian `dateTimeFormats-atTime`
//!   pattern of the date's length, `long` at `full` (`datetimepattern_convert` in
//!   `datetime/names.rs`).
//! - an offset joins the time by the Gregorian `appendItems` `Timezone` pattern; it writes the
//!   `gmtFormat` around the number's sign, the hours and the minutes after the `units.json`
//!   duration separator (icu_datetime 2.4.0, `format/time_zone.rs`, `LocalizedOffsetFormat`;
//!   icu_provider_source, `time_zones/convert.rs`).

use crate::cldr::{Cldr, CldrError, File};
use crate::skeleton::{self, Chosen, Entry, Field, Item, Skeleton, Symbol};

use super::{CATEGORIES, LENGTHS, Line, Out, guarded, joined, literal, plain, product};

/// One calendar file of the language and the path of its calendar.
struct Doc {
    file: File,
    base: Vec<String>,
}

impl Doc {
    fn read(cldr: &Cldr, calendar: &str) -> Result<Self, CldrError> {
        let file = cldr.main("cldr-dates-full", &format!("ca-{calendar}.json"))?;
        let base = ["main", &cldr.language, "dates", "calendars", calendar]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        Ok(Self { file, base })
    }

    fn at(&self, rest: &[&str]) -> Vec<String> {
        self.base
            .iter()
            .cloned()
            .chain(rest.iter().map(|s| (*s).to_owned()))
            .collect()
    }

    fn text(&self, rest: &[&str]) -> Result<&str, CldrError> {
        let path = self.at(rest);
        let path: Vec<&str> = path.iter().map(String::as_str).collect();
        self.file.text(&path)
    }

    fn object(
        &self,
        rest: &[&str],
    ) -> Result<&serde_json::Map<String, serde_json::Value>, CldrError> {
        let path = self.at(rest);
        let path: Vec<&str> = path.iter().map(String::as_str).collect();
        self.file.object(&path)
    }

    fn refused(&self, rest: &[&str], value: &str) -> CldrError {
        let path = self.at(rest);
        let path: Vec<&str> = path.iter().map(String::as_str).collect();
        self.file.form(&path, value)
    }

    /// The pattern at `rest`, read as ICU4X reads it.
    fn pattern(&self, rest: &[&str]) -> Result<Vec<Item>, CldrError> {
        let text = self.text(rest)?;
        skeleton::pattern(text).map_err(|_| self.refused(rest, text))
    }

    /// The calendar's `availableFormats`, ordered by skeleton (`parse_skeletons` in
    /// `datetime/available_formats.rs`): `-alt-ascii` patterns dropped, `-count-` variants one
    /// skeleton's, and of two keys with one skeleton the later key's.
    fn available(&self) -> Result<Vec<(Skeleton, Entry)>, CldrError> {
        let at = ["dateTimeFormats", "availableFormats"];
        let mut keyed: Vec<(&str, &str, &str)> = Vec::new();
        for (key, value) in self.object(&at)? {
            let key_at = joined(&at, &[key.as_str()]);
            let pattern = value.as_str().ok_or_else(|| self.refused(&key_at, key))?;
            if key.ends_with("-alt-ascii") {
                continue;
            }
            let (skeleton, category) = key.split_once("-count-").unwrap_or((key, "other"));
            if !CATEGORIES.contains(&category) {
                return Err(self.refused(&key_at, category));
            }
            keyed.push((skeleton, category, pattern));
        }
        keyed.sort_unstable();
        let mut skeletons: Vec<(Skeleton, Entry)> = Vec::new();
        let mut rest = keyed.as_slice();
        while let Some((first, _)) = rest.split_first() {
            let count = rest.iter().take_while(|(key, ..)| *key == first.0).count();
            let (group, tail) = rest.split_at_checked(count).unwrap_or((rest, &[]));
            rest = tail;
            let key_at = joined(&at, &[first.0]);
            let mut other = None;
            for (_, category, text) in group {
                let items = skeleton::pattern(text).map_err(|_| self.refused(&key_at, text))?;
                if *category == "other" {
                    other = Some(items);
                }
            }
            let items = other.ok_or_else(|| self.refused(&key_at, first.0))?;
            let Some(fields) =
                skeleton::skeleton(first.0).map_err(|_| self.refused(&key_at, first.0))?
            else {
                continue;
            };
            let entry = Entry {
                items,
                plural: group.len() > 1,
            };
            match skeletons.iter_mut().find(|(known, _)| *known == fields) {
                Some((_, known)) => *known = entry,
                None => skeletons.push((fields, entry)),
            }
        }
        skeletons.sort_by(|(a, _), (b, _)| a.cmp(b));
        Ok(skeletons)
    }

    /// The pattern line of a pattern chosen for the field set at `at`.
    fn line(&self, chosen: &Chosen, at: &[&str]) -> Result<String, CldrError> {
        if chosen.plural {
            return Err(self.refused(at, "a pattern with plural variants"));
        }
        let mut line = String::new();
        for item in &chosen.items {
            match item {
                Item::Text(text) => line.push_str(&literal(text)),
                Item::Field(field) => line.push_str(
                    &placeholder(*field).ok_or_else(|| self.refused(at, &shown(*field)))?,
                ),
                // CLDR 49's German `GyMMMMEd` writes its year as the week-based year `Y`,
                // which ICU4X 2.4 writes as the letter; the line writes the year of the era.
                Item::Unread('Y', width) => line.push_str(
                    &u8::try_from(*width)
                        .ok()
                        .and_then(|width| {
                            placeholder(Field {
                                symbol: Symbol::Year,
                                width,
                            })
                        })
                        .ok_or_else(|| self.refused(at, "Y"))?,
                ),
                Item::Unread(letter, width) => {
                    return Err(self.refused(at, &letter.to_string().repeat(*width)));
                }
            }
        }
        Ok(line)
    }

    /// The `dateFormats` of each length ICU4X reads, refused where CLDR gives a numbering system
    /// to a pattern (`apply_numeric_overrides` in `datetime/names.rs`).
    fn numbering(&self) -> Result<(), CldrError> {
        for length in ["short", "medium", "long"] {
            let at = self.at(&["dateFormats", length]);
            let at: Vec<&str> = at.iter().map(String::as_str).collect();
            let value = self.file.value(&at)?;
            if !value.is_string() {
                return Err(self.file.form(&at, &value.to_string()));
            }
        }
        Ok(())
    }
}

/// The text of a field: its letter, repeated to its width.
fn shown(field: Field) -> String {
    field
        .symbol
        .letter()
        .to_string()
        .repeat(usize::from(field.width))
}

/// The placeholder of a field (TR35 Part 4, "Date Field Symbol Table"); `None` for a field
/// siros-i18n-formats has no field or table for. A year `y` is the year of the era.
fn placeholder(field: Field) -> Option<String> {
    let pad = |name: &str| match field.width {
        1 => Some(format!("{{{name}}}")),
        2 => Some(format!("{{{name}:pad=2}}")),
        _ => None,
    };
    Some(match (field.symbol, field.width) {
        (Symbol::Era, 1..=3) => "{era:table=eras}".to_owned(),
        (Symbol::Year, 1) => "{era-year}".to_owned(),
        (Symbol::Year, 2) => "{era-year:last=2,pad=2}".to_owned(),
        (Symbol::Year, width) => format!("{{era-year:pad={width}}}"),
        (Symbol::Month, 1..=2) => pad("month")?,
        (Symbol::Month, 3) => "{month:table=months.abbreviated}".to_owned(),
        (Symbol::Month, 4) => "{month:table=months.wide}".to_owned(),
        (Symbol::Day, _) => pad("day")?,
        (Symbol::Weekday, 1..=3) => "{weekday:table=days.abbreviated}".to_owned(),
        (Symbol::Weekday, 4) => "{weekday:table=days.wide}".to_owned(),
        (Symbol::AmPm, 1..=3) => "{period:table=periods}".to_owned(),
        (Symbol::Hour12, _) => pad("hour12")?,
        (Symbol::Hour23, _) => pad("hour")?,
        (Symbol::Hour11, _) => pad("hour11")?,
        (Symbol::Minute, _) => pad("minute")?,
        (Symbol::Second, _) => pad("second")?,
        _ => return None,
    })
}

/// Parts of a joining pattern (`{0}`, `{1}`): text, quoted or not, and slots.
enum Part {
    Text(String),
    Slot(char),
}

/// A joining pattern's parts, each of `slots` once (icu_pattern's quoting: `''` an apostrophe,
/// quoted text literal); `None` for another form.
fn parts(text: &str, slots: &[char]) -> Option<Vec<Part>> {
    let mut parts = Vec::new();
    let mut run = String::new();
    let mut quoted = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' if chars.next_if_eq(&'\'').is_some() => run.push('\''),
            '\'' => quoted = !quoted,
            '{' if !quoted => {
                let slot = chars.next()?;
                if chars.next() != Some('}') {
                    return None;
                }
                if !run.is_empty() {
                    parts.push(Part::Text(std::mem::take(&mut run)));
                }
                parts.push(Part::Slot(slot));
            }
            c => run.push(c),
        }
    }
    if !run.is_empty() {
        parts.push(Part::Text(run));
    }
    let once = |slot: &char| {
        parts
            .iter()
            .filter(|part| matches!(part, Part::Slot(s) if s == slot))
            .count()
            == 1
    };
    let known = parts
        .iter()
        .all(|part| !matches!(part, Part::Slot(s) if !slots.contains(s)));
    (!quoted && known && slots.iter().all(once)).then_some(parts)
}

/// The lines of joined parts, each slot's lines in its place.
fn join(parts: &[Part], slot: &dyn Fn(char) -> Vec<Line>) -> Vec<Line> {
    let mut lines = plain(String::new());
    for part in parts {
        let part = match part {
            Part::Text(text) => plain(literal(text)),
            Part::Slot(s) => slot(*s),
        };
        lines = product(&lines, &part);
    }
    lines
}

/// The separator of a duration pattern's runs of `letters` (`strip_separated_padded_characters`
/// in icu_provider_source's `duration/mod.rs`): one text between each run.
fn separator<'a>(pattern: &'a str, letters: &[char]) -> Option<&'a str> {
    let mut rest = pattern;
    let mut found: Option<&str> = None;
    let (last, leading) = letters.split_last()?;
    for (index, letter) in leading.iter().enumerate() {
        rest = rest.trim_start_matches(*letter);
        let next = letters.get(index + 1)?;
        let (between, after) = rest.split_once(*next)?;
        if found.is_some_and(|known| known != between) {
            return None;
        }
        found = Some(between);
        rest = after;
    }
    rest.trim_start_matches(*last)
        .is_empty()
        .then_some(found)
        .flatten()
}

/// The language's calendar names and patterns.
pub(super) struct Calendar {
    gregorian: Doc,
    generic: Doc,
    /// The Gregorian `availableFormats`, for dates.
    dates: Vec<(Skeleton, Entry)>,
    /// The generic calendar's `availableFormats`, for times.
    times: Vec<(Skeleton, Entry)>,
    /// The hour of the language's hour cycle, `h` or `H`.
    hour: Symbol,
    months_wide: Vec<String>,
    months_abbreviated: Vec<String>,
    days_wide: Vec<String>,
    days_abbreviated: Vec<String>,
    periods: Vec<String>,
    eras: Vec<String>,
    /// The `gmtFormat`'s text before the offset and after it.
    gmt: (String, String),
    /// The text between an offset's hours and its minutes.
    separator: String,
}

impl Calendar {
    pub(super) fn read(cldr: &Cldr) -> Result<Self, CldrError> {
        let language = cldr.language.as_str();
        let gregorian = Doc::read(cldr, "gregorian")?;
        let generic = Doc::read(cldr, "generic")?;
        gregorian.numbering()?;
        generic.numbering()?;
        let names = |path: &[&str], keys: &[&str], numbered: &[&str]| {
            keys.iter()
                .zip(numbered)
                .map(|(key, number)| {
                    let full = joined(path, &[key]);
                    Ok(format!("{number} {}", gregorian.text(&full)?))
                })
                .collect::<Result<Vec<String>, CldrError>>()
        };
        let months = [
            "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12",
        ];
        // The weekdays from Monday, numbered as ISO 8601 numbers them.
        let days = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];
        let iso = ["1", "2", "3", "4", "5", "6", "7"];
        let zones = cldr.main("cldr-dates-full", "timeZoneNames.json")?;
        let gmt_at = ["main", language, "dates", "timeZoneNames", "gmtFormat"];
        let gmt = zones.text(&gmt_at)?;
        let (before, after) = gmt
            .split_once("{0}")
            .filter(|(_, after)| !after.contains("{0}"))
            .ok_or_else(|| zones.form(&gmt_at, gmt))?;
        let units = cldr.main("cldr-units-full", "units.json")?;
        let mut separators = Vec::new();
        for (key, letters) in [
            ("hm", &['h', 'm'][..]),
            ("ms", &['m', 's']),
            ("hms", &['h', 'm', 's']),
        ] {
            let unit = format!("durationUnit-type-{key}");
            let at = ["main", language, "units", &unit, "durationUnitPattern"];
            let pattern = units.text(&at)?;
            separators.push(separator(pattern, letters).ok_or_else(|| units.form(&at, pattern))?);
        }
        let separator = match separators.as_slice() {
            [hm, rest @ ..] if rest.iter().all(|other| other == hm) => (*hm).to_owned(),
            _ => return Err(units.form(&["main", language, "units"], &separators.join(" "))),
        };
        Ok(Self {
            dates: gregorian.available()?,
            times: generic.available()?,
            hour: Self::hour(&generic)?,
            months_wide: names(&["months", "format", "wide"], &months, &months)?,
            months_abbreviated: names(&["months", "format", "abbreviated"], &months, &months)?,
            days_wide: names(&["days", "format", "wide"], &days, &iso)?,
            days_abbreviated: names(&["days", "format", "abbreviated"], &days, &iso)?,
            periods: names(
                &["dayPeriods", "format", "abbreviated"],
                &["am", "pm"],
                &["0", "1"],
            )?,
            eras: names(&["eras", "eraAbbr"], &["0", "1"], &["0", "1"])?,
            gmt: (before.to_owned(), after.to_owned()),
            separator,
            gregorian,
            generic,
        })
    }

    /// The hour of the first `timeSkeletons` pattern, from `full`, that has one
    /// (`preferred_hour_cycle`): `h` for a 12-hour cycle, `H` for a 24-hour one.
    fn hour(generic: &Doc) -> Result<Symbol, CldrError> {
        for length in ["full", "long", "medium", "short"] {
            let at = ["timeSkeletons", length];
            for item in generic.pattern(&at)? {
                if let Item::Field(Field { symbol, .. }) = item {
                    match symbol {
                        Symbol::Hour11 | Symbol::Hour12 => return Ok(Symbol::Hour12),
                        Symbol::Hour23 => return Ok(Symbol::Hour23),
                        _ => {}
                    }
                }
            }
        }
        Err(generic.refused(&["timeSkeletons"], "no hour"))
    }

    pub(super) fn tables(&self, out: &mut Out) -> Result<(), CldrError> {
        out.lines("months.wide", &self.months_wide)?;
        out.lines("months.abbreviated", &self.months_abbreviated)?;
        out.lines("days.wide", &self.days_wide)?;
        out.lines("days.abbreviated", &self.days_abbreviated)?;
        out.lines("periods", &self.periods)?;
        out.lines("eras", &self.eras)
    }

    /// The date of `length`: `YMD` at its length, `YMDE` long at `full`.
    fn date(&self, length: &str) -> Result<Vec<Line>, CldrError> {
        let (skeleton_length, weekday) = match length {
            "full" => ("long", true),
            other => (other, false),
        };
        let at = ["dateSkeletons", skeleton_length];
        let (mut era, mut year, mut month, mut day) = (None, None, None, None);
        // The widths `components::Bag::from` and `to_vec_fields` give the date fields of the
        // skeleton (icu_datetime 2.4.0, `provider/fields/components.rs`).
        for item in self.gregorian.pattern(&at)? {
            let Item::Field(field) = item else { continue };
            let width = field.width;
            match field.symbol {
                Symbol::Era => era = Some((Symbol::Era, width.clamp(3, 5))),
                Symbol::Year => year = Some((Symbol::Year, if width == 2 { 2 } else { 1 })),
                Symbol::ExtendedYear | Symbol::CyclicYear | Symbol::RelatedYear => {
                    year = Some((Symbol::Year, 1));
                }
                Symbol::Month | Symbol::StandAloneMonth => {
                    month = Some((Symbol::Month, width.min(5)));
                }
                Symbol::Day => day = Some((Symbol::Day, if width == 2 { 2 } else { 1 })),
                Symbol::DayOfYear | Symbol::WeekdayInMonth | Symbol::ModifiedJulianDay => {
                    day = Some((field.symbol, 1));
                }
                // A numeric stand-alone weekday, a local weekday and milliseconds of the day
                // are `unimplemented!` in ICU4X's `Bag::from`.
                Symbol::LocalWeekday | Symbol::MillisInDay => {
                    return Err(self.gregorian.refused(&at, &shown(field)));
                }
                Symbol::StandAloneWeekday if width <= 2 => {
                    return Err(self.gregorian.refused(&at, &shown(field)));
                }
                // `gen_date_components` takes the weekday from the length, and no time field.
                Symbol::Weekday
                | Symbol::StandAloneWeekday
                | Symbol::AmPm
                | Symbol::NoonMidnight
                | Symbol::FlexiblePeriod
                | Symbol::Hour11
                | Symbol::Hour12
                | Symbol::Hour23
                | Symbol::Minute
                | Symbol::Second
                | Symbol::DecimalSecond(_)
                | Symbol::SpecificZone
                | Symbol::OffsetZone
                | Symbol::GenericZone
                | Symbol::LocationZone
                | Symbol::IsoZone
                | Symbol::IsoZoneWithZ => {}
            }
        }
        let field = |(symbol, width)| Field { symbol, width };
        let (era, year) = (era.map(field), year.map(field));
        let mut fields: Vec<Field> = [month, day].into_iter().flatten().map(field).collect();
        if weekday {
            fields.push(Field {
                symbol: Symbol::Weekday,
                width: 4,
            });
        }
        let with = |extra: &[Field]| {
            let mut all: Vec<Field> = extra.to_vec();
            all.extend(&fields);
            all.sort();
            all
        };
        let requested: Vec<Field> = with(&[era, year].into_iter().flatten().collect::<Vec<_>>());
        let variants = match (era, year) {
            (None, Some(_)) => {
                let full = Field {
                    symbol: Symbol::Year,
                    width: 1,
                };
                let with_era = Field {
                    symbol: Symbol::Era,
                    width: 3,
                };
                Some((with(&[full]), with(&[with_era, full])))
            }
            _ => None,
        };
        let mut standard = skeleton::choose(&self.dates, &requested);
        let Some((full, with_era)) = variants else {
            skeleton::consistent(&mut [&mut standard]);
            return Ok(plain(self.gregorian.line(&standard, &at)?));
        };
        let mut full = skeleton::choose(&self.dates, &full);
        let mut with_era = skeleton::choose(&self.dates, &with_era);
        skeleton::consistent(&mut [&mut standard, &mut full, &mut with_era]);
        let standard = self.gregorian.line(&standard, &at)?;
        let full = self.gregorian.line(&full, &at)?;
        let with_era = self.gregorian.line(&with_era, &at)?;
        let mut lines: Vec<Line> = vec![
            (vec!["year<1000".to_owned()], with_era),
            (
                vec!["year>=1950".to_owned(), "year<2050".to_owned()],
                standard,
            ),
        ];
        lines.retain(|(_, text)| *text != full);
        lines.push((Vec::new(), full));
        Ok(lines)
    }

    /// The time with minutes and the time with seconds, the names each kind loads kept to the
    /// best match's among them and the hour alone.
    fn times(&self) -> Result<(String, String), CldrError> {
        let hour = Field {
            symbol: self.hour,
            width: 1,
        };
        let minute = Field {
            symbol: Symbol::Minute,
            width: 1,
        };
        let second = Field {
            symbol: Symbol::Second,
            width: 1,
        };
        let mut hours = skeleton::choose(&self.times, &[hour]);
        let mut minutes = skeleton::choose(&self.times, &[hour, minute]);
        let mut seconds = skeleton::choose(&self.times, &[hour, minute, second]);
        skeleton::consistent(&mut [&mut hours, &mut minutes, &mut seconds]);
        let at = ["dateTimeFormats", "availableFormats"];
        Ok((
            self.generic.line(&minutes, &at)?,
            self.generic.line(&seconds, &at)?,
        ))
    }

    /// The localized offset: `long` pads its hours and always writes its minutes; the short
    /// offset writes them when they are not zero. `signs` are the number symbols of a positive
    /// and of a negative number.
    fn zone(&self, long: bool, signs: &(String, String)) -> Vec<Line> {
        let (before, after) = (literal(&self.gmt.0), literal(&self.gmt.1));
        let separator = literal(&self.separator);
        let hours = if long {
            "{offset-hours:pad=2}"
        } else {
            "{offset-hours}"
        };
        let mut lines = Vec::new();
        for (test, sign) in [(Some("offset-sign=1"), &signs.1), (None, &signs.0)] {
            let tests: Vec<String> = test.into_iter().map(str::to_owned).collect();
            let head = format!("{before}{}{hours}", literal(sign));
            let minutes = format!("{head}{separator}{{offset-minutes:pad=2}}{after}");
            if long {
                lines.push((tests, minutes));
            } else {
                let mut nonzero = tests.clone();
                nonzero.push("offset-minutes>0".to_owned());
                lines.push((nonzero, minutes));
                lines.push((tests, format!("{head}{after}")));
            }
        }
        lines
    }

    /// The Gregorian joining pattern at `rest` with `slots`.
    fn parts(&self, rest: &[&str], slots: &[char]) -> Result<Vec<Part>, CldrError> {
        let text = self.gregorian.text(rest)?;
        parts(text, slots).ok_or_else(|| self.gregorian.refused(rest, text))
    }

    /// The time at `length`, an offset at `long` and `full` joined to it when the value has one.
    fn time(
        &self,
        length: &str,
        times: &(String, String),
        signs: &(String, String),
    ) -> Result<Vec<Line>, CldrError> {
        let time = match length {
            "short" => &times.0,
            _ => &times.1,
        };
        let zone = match length {
            "long" => self.zone(false, signs),
            "full" => self.zone(true, signs),
            _ => return Ok(plain(time.clone())),
        };
        let append = self.parts(&["dateTimeFormats", "appendItems", "Timezone"], &['0', '1'])?;
        let mut lines = guarded(
            &["offset?"],
            join(&append, &|slot| match slot {
                '0' => plain(time.clone()),
                _ => zone.clone(),
            }),
        );
        lines.extend(plain(time.clone()));
        Ok(lines)
    }

    /// The date and time at `length`: the `atTime` pattern of the date's length, `{0}` the time
    /// and `{1}` the date.
    fn both(
        &self,
        length: &str,
        times: &(String, String),
        signs: &(String, String),
    ) -> Result<Vec<Line>, CldrError> {
        let glue = match length {
            "full" => "long",
            other => other,
        };
        let glue = self.parts(&["dateTimeFormats-atTime", "standard", glue], &['0', '1'])?;
        let date = self.date(length)?;
        let time = self.time(length, times, signs)?;
        Ok(join(&glue, &|slot| match slot {
            '0' => time.clone(),
            _ => date.clone(),
        }))
    }

    pub(super) fn formats(&self, out: &mut Out, signs: &(String, String)) -> Result<(), CldrError> {
        let times = self.times()?;
        for name in ["date", "time", "datetime"] {
            out.section(&format!("formats.{name}"));
            out.setting("of", name)?;
            out.setting("default", "yes")?;
            out.setting("option.length", &LENGTHS.join(" "))?;
            let mut lines = Vec::new();
            for length in LENGTHS {
                let pattern = match name {
                    "date" => self.date(length)?,
                    "time" => self.time(length, &times, signs)?,
                    _ => self.both(length, &times, signs)?,
                };
                let test = format!("length={length}");
                lines.extend(guarded(&[test.as_str()], pattern));
            }
            out.patterns(&lines)?;
        }
        Ok(())
    }
}
