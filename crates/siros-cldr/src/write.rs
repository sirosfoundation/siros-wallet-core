//! The resource the tool writes: its head with the language's locale and direction, and one
//! `[formats.<format>]` section per format module, each option a value of the resource format.

use siros_syntax::Currency;

use crate::cldr::{Cldr, CldrError, File};

/// TR35's plural categories, in its order.
const CATEGORIES: [&str; 6] = ["zero", "one", "two", "few", "many", "other"];

/// The text being written.
struct Out {
    text: String,
}

/// A text's characters escaped for a resource value line: a line's leading and trailing space and
/// tab, and every character outside the format's `content`.
fn escaped(line: &str) -> Result<String, CldrError> {
    if line.contains(['\\', '\n', '\r']) {
        return Err(CldrError::Unwritable {
            text: line.to_owned(),
        });
    }
    let count = line.chars().count();
    let mut out = String::new();
    for (index, c) in line.chars().enumerate() {
        match c {
            ' ' | '\t' if index == 0 || index + 1 == count => {
                out.push('\\');
                out.push(c);
            }
            c if matches!(c, '\u{0}'..='\u{1F}' | '\u{7F}'..='\u{9F}' | '\u{2028}' | '\u{2029}') => {
                out.push_str(&format!("\\u{:04X}", u32::from(c)));
            }
            c => out.push(c),
        }
    }
    Ok(out)
}

impl Out {
    fn line(&mut self, line: &str) {
        self.text.push_str(line);
        self.text.push('\n');
    }

    /// An option of one line.
    fn option(&mut self, name: &str, value: &str) -> Result<(), CldrError> {
        let value = escaped(value)?;
        if value.is_empty() {
            self.line(&format!("{name} ="));
        } else {
            self.line(&format!("{name} = {value}"));
        }
        Ok(())
    }

    /// An option of several lines, each on an indented continuation line.
    fn lines(&mut self, name: &str, lines: &[String]) -> Result<(), CldrError> {
        self.line(&format!("{name} ="));
        for line in lines {
            self.line(&format!("  {}", escaped(line)?));
        }
        Ok(())
    }

    fn section(&mut self, format: &str) {
        self.line("");
        self.line(&format!("[formats.{format}]"));
    }
}

/// The resource of the language's format options.
pub(crate) fn resource(cldr: &Cldr, release: &str) -> Result<String, CldrError> {
    let language = cldr.language.as_str();
    let mut out = Out {
        text: String::new(),
    };
    out.line(&format!(
        "# The format options of {language} from CLDR {release} (unicode-org/cldr-json), written by siros-cldr."
    ));
    out.line(&format!("@locale {language}"));
    let layout = cldr.main("cldr-misc-full", "layout.json")?;
    let order_at = ["main", language, "layout", "orientation", "characterOrder"];
    let order = layout.text(&order_at)?;
    out.line(match order {
        "left-to-right" => "@dir ltr",
        "right-to-left" => "@dir rtl",
        other => return Err(layout.form(&order_at, other)),
    });
    out.line("---");
    let numbers = Numbers::read(cldr)?;
    out.section("number");
    numbers.write(&mut out)?;
    out.option("pattern", &numbers.decimal)?;
    out.section("currency");
    numbers.write(&mut out)?;
    currency(cldr, &numbers, &mut out)?;
    out.section("date");
    date(cldr, &numbers, &mut out)?;
    Ok(out.text)
}

/// The language's number symbols, patterns and plural rules.
struct Numbers {
    language: String,
    system: String,
    zero: String,
    file: File,
    decimal: String,
    cardinal: Vec<String>,
    ordinal: Vec<String>,
}

/// A plural rule set's rules other than `other`, in TR35's category order, samples dropped:
/// `<keyword>: <condition>`. A language's set names the categories it uses.
fn rules(file: &File, at: &[&str]) -> Result<Vec<String>, CldrError> {
    let mut rules = Vec::new();
    for keyword in ["zero", "one", "two", "few", "many"] {
        let key = format!("pluralRule-count-{keyword}");
        let Some(text) = file.optional_text(&joined(at, &[key.as_str()]))? else {
            continue;
        };
        let condition = text
            .split_once('@')
            .map_or(text, |(condition, _samples)| condition)
            .trim();
        rules.push(format!("{keyword}: {condition}"));
    }
    Ok(rules)
}

/// The zero of a numbering system's digits, when they are the ten consecutive characters from
/// it that siros-i18n's `zero` option names.
fn zero(digits: &str) -> Option<char> {
    let zero = digits.chars().next()?;
    let consecutive = (0..10).map(|offset| char::from_u32(u32::from(zero) + offset));
    digits.chars().map(Some).eq(consecutive).then_some(zero)
}

impl Numbers {
    fn read(cldr: &Cldr) -> Result<Self, CldrError> {
        let language = cldr.language.clone();
        let file = cldr.main("cldr-numbers-full", "numbers.json")?;
        let system = file
            .text(&["main", &language, "numbers", "defaultNumberingSystem"])?
            .to_owned();
        let systems = cldr.file("cldr-core/supplemental/numberingSystems.json")?;
        let digits_at = ["supplemental", "numberingSystems", &system, "_digits"];
        let digits = systems.text(&digits_at)?;
        let zero = zero(digits)
            .ok_or_else(|| systems.form(&digits_at, digits))?
            .to_string();
        let decimal = file
            .text(&[
                "main",
                &language,
                "numbers",
                &format!("decimalFormats-numberSystem-{system}"),
                "standard",
            ])?
            .to_owned();
        let plurals = cldr.file("cldr-core/supplemental/plurals.json")?;
        let ordinals = cldr.file("cldr-core/supplemental/ordinals.json")?;
        let cardinal = rules(
            &plurals,
            &["supplemental", "plurals-type-cardinal", &language],
        )?;
        let ordinal = rules(
            &ordinals,
            &["supplemental", "plurals-type-ordinal", &language],
        )?;
        Ok(Self {
            language,
            system,
            zero,
            file,
            decimal,
            cardinal,
            ordinal,
        })
    }

    fn numbers<'a>(&'a self, key: &'a str) -> [&'a str; 4] {
        ["main", &self.language, "numbers", key]
    }

    fn symbol(&self, name: &str) -> Result<&str, CldrError> {
        let key = format!("symbols-numberSystem-{}", self.system);
        let [a, b, c, d] = self.numbers(&key);
        self.file.text(&[a, b, c, d, name])
    }

    fn write(&self, out: &mut Out) -> Result<(), CldrError> {
        out.option("zero", &self.zero)?;
        out.option("decimal", self.symbol("decimal")?)?;
        out.option("group", self.symbol("group")?)?;
        out.option("minus", self.symbol("minusSign")?)?;
        out.option("plus", self.symbol("plusSign")?)?;
        let grouping = self.file.text(&self.numbers("minimumGroupingDigits"))?;
        out.option("grouping", grouping)?;
        out.lines("cardinal", &self.cardinal)?;
        out.lines("ordinal", &self.ordinal)
    }
}

/// Whether ISO 4217's table lists a CLDR currency key.
fn listed(code: &str) -> bool {
    Currency::parse(code).is_ok()
}

fn currency(cldr: &Cldr, numbers: &Numbers, out: &mut Out) -> Result<(), CldrError> {
    let language = numbers.language.as_str();
    out.option("pattern", &numbers.decimal)?;
    let formats_key = format!("currencyFormats-numberSystem-{}", numbers.system);
    let formats_at = numbers.numbers(&formats_key);
    // TR35 Part 3, "Currency Formats": the `alphaNextToNumber` pattern applies when the locale
    // gives one, else the pattern it varies.
    for (name, key, fallback) in [
        ("standard", "standard", None),
        (
            "standard-alpha",
            "standard-alphaNextToNumber",
            Some("standard"),
        ),
        ("accounting", "accounting", None),
        (
            "accounting-alpha",
            "accounting-alphaNextToNumber",
            Some("accounting"),
        ),
        ("no-currency", "standard-noCurrency", None),
        ("no-currency-accounting", "accounting-noCurrency", None),
    ] {
        let at = joined(&formats_at, &[key]);
        let text = match fallback {
            None => numbers.file.text(&at)?,
            Some(fallback) => match numbers.file.optional_text(&at)? {
                Some(text) => text,
                None => numbers.file.text(&joined(&formats_at, &[fallback]))?,
            },
        };
        out.option(name, text)?;
    }
    let mut units = Vec::new();
    for (key, value) in numbers.file.object(&formats_at)? {
        let Some(keyword) = key.strip_prefix("unitPattern-count-") else {
            continue;
        };
        let at = joined(&formats_at, &[key.as_str()]);
        if !CATEGORIES.contains(&keyword) {
            return Err(numbers.file.form(&at, keyword));
        }
        let text = value.as_str().ok_or_else(|| numbers.file.missing(&at))?;
        units.push(format!("{keyword} {text}"));
    }
    out.lines("unit-pattern", &units)?;
    let data = cldr.file("cldr-core/supplemental/currencyData.json")?;
    let fractions_at = ["supplemental", "currencyData", "fractions"];
    let mut default = Vec::new();
    let mut digits = Vec::new();
    for code in data.object(&fractions_at)?.keys() {
        // TR35 Part 3, "Supplemental Currency Data": `digits` defaults to 2, `rounding` to 0.
        let get = |key: &str, absent: &'static str| -> Result<&str, CldrError> {
            let text = data.optional_text(&joined(&fractions_at, &[code.as_str(), key]))?;
            Ok(text.unwrap_or(absent))
        };
        let increment = match get("_rounding", "0")? {
            "0" => String::new(),
            rounding => format!(" {rounding}"),
        };
        let line = format!("{}{increment}", get("_digits", "2")?);
        match code.as_str() {
            "DEFAULT" => default.push(format!("default {line}")),
            code if listed(code) => digits.push(format!("{code} {line}")),
            _ => {}
        }
    }
    default.append(&mut digits);
    out.lines("digits", &default)?;
    let file = cldr.main("cldr-numbers-full", "currencies.json")?;
    let currencies_at = ["main", language, "numbers", "currencies"];
    let (mut symbols, mut narrow, mut names) = (Vec::new(), Vec::new(), Vec::new());
    for code in file.object(&currencies_at)?.keys() {
        if !listed(code) {
            continue;
        }
        let get = |key: &str| file.optional_text(&joined(&currencies_at, &[code.as_str(), key]));
        let symbol = get("symbol")?;
        if let Some(symbol) = symbol.filter(|s| s != code) {
            symbols.push(format!("{code} {symbol}"));
        }
        // TR35 Part 3: the narrow symbol falls back to the symbol, and a currency without one
        // shows its code.
        let narrowed = match get("symbol-alt-narrow")? {
            Some(narrowed) => Some(narrowed),
            None => symbol,
        };
        if let Some(symbol) = narrowed.filter(|s| s != code) {
            narrow.push(format!("{code} {symbol}"));
        }
        // TR35 Part 3: the display name of the count, else of `other`, else without a count,
        // else the code.
        let mut other = false;
        for keyword in CATEGORIES {
            if let Some(name) = get(&format!("displayName-count-{keyword}"))? {
                other |= keyword == "other";
                names.push(format!("{code} {keyword} {name}"));
            }
        }
        if !other && let Some(name) = get("displayName")? {
            names.push(format!("{code} other {name}"));
        }
    }
    out.lines("symbols", &symbols)?;
    out.lines("narrow", &narrow)?;
    out.lines("names", &names)
}

/// `base` then `rest`.
fn joined<'a>(base: &[&'a str], rest: &[&'a str]) -> Vec<&'a str> {
    base.iter().chain(rest).copied().collect()
}

fn date(cldr: &Cldr, numbers: &Numbers, out: &mut Out) -> Result<(), CldrError> {
    let language = numbers.language.as_str();
    let file = cldr.main("cldr-dates-full", "ca-gregorian.json")?;
    let base = ["main", language, "dates", "calendars", "gregorian"];
    let at = |rest: &[&'static str]| joined(&base, rest);
    out.option("zero", &numbers.zero)?;
    for length in ["short", "medium", "long", "full"] {
        out.option(
            &format!("date-{length}"),
            file.text(&at(&["dateFormats", length]))?,
        )?;
    }
    for length in ["short", "medium", "long", "full"] {
        out.option(
            &format!("time-{length}"),
            file.text(&at(&["timeFormats", length]))?,
        )?;
    }
    // TR35 Part 4, "dateTimeFormats": "If there is no atTime pattern, use the standard pattern."
    for length in ["short", "medium", "long", "full"] {
        let glue = match file.optional_text(&at(&["dateTimeFormats-atTime", "standard", length]))? {
            Some(glue) => glue,
            None => file.text(&at(&["dateTimeFormats", length]))?,
        };
        out.option(&format!("datetime-{length}"), glue)?;
    }
    let names = |path: &[&'static str], keys: &[&'static str]| -> Result<Vec<String>, CldrError> {
        keys.iter()
            .map(|key| {
                let mut full = at(path);
                full.push(key);
                file.text(&full).map(str::to_owned)
            })
            .collect()
    };
    let months = [
        "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12",
    ];
    let days = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];
    out.lines(
        "months-wide",
        &names(&["months", "format", "wide"], &months)?,
    )?;
    out.lines(
        "months-abbreviated",
        &names(&["months", "format", "abbreviated"], &months)?,
    )?;
    out.lines("days-wide", &names(&["days", "format", "wide"], &days)?)?;
    out.lines(
        "days-abbreviated",
        &names(&["days", "format", "abbreviated"], &days)?,
    )?;
    out.lines(
        "periods",
        &names(&["dayPeriods", "format", "abbreviated"], &["am", "pm"])?,
    )?;
    let zones = cldr.main("cldr-dates-full", "timeZoneNames.json")?;
    let zone = ["main", language, "dates", "timeZoneNames"];
    let [a, b, c, d] = zone;
    out.option("zone-gmt", zones.text(&[a, b, c, d, "gmtFormat"])?)?;
    out.option("zone-hours", zones.text(&[a, b, c, d, "hourFormat"])?)?;
    out.option(
        "year-era",
        file.text(&at(&["dateTimeFormats", "availableFormats", "Gy"]))?,
    )?;
    out.lines("eras", &names(&["eras", "eraAbbr"], &["0", "1"])?)
}
