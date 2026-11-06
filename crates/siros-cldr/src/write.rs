//! The resource the tool writes: its head with the language's locale and direction, and one
//! `[formats.<format>]` section per format module, each option a value of the resource format.

use siros_explain::Currency;

use crate::cldr::{Cldr, CldrError, File};
use crate::special::{Conjunction, special};

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
    let last = line.chars().count().saturating_sub(1);
    let mut out = String::new();
    for (index, c) in line.chars().enumerate() {
        match c {
            ' ' | '\t' if index == 0 || index == last => {
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
    let order = layout.text(&["main", language, "layout", "orientation", "characterOrder"])?;
    out.line(match order {
        "right-to-left" => "@dir rtl",
        _ => "@dir ltr",
    });
    out.line("---");
    let numbers = Numbers::read(cldr)?;
    out.section("number");
    numbers.write(&mut out)?;
    out.option("pattern", &numbers.decimal)?;
    out.section("offset");
    numbers.write(&mut out)?;
    out.option("pattern", &numbers.decimal)?;
    out.section("currency");
    numbers.write(&mut out)?;
    currency(cldr, &numbers, &mut out)?;
    out.section("date");
    date(cldr, &numbers, &mut out)?;
    out.section("list");
    list(cldr, &mut out)?;
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
/// `<keyword>: <condition>`.
fn rules(file: &File, at: &[&str]) -> Result<Vec<String>, CldrError> {
    let set = file.object(at)?;
    let mut rules = Vec::new();
    for keyword in ["zero", "one", "two", "few", "many"] {
        let Some(value) = set.get(&format!("pluralRule-count-{keyword}")) else {
            continue;
        };
        let text = value.as_str().ok_or_else(|| file.missing(at))?;
        let condition = text.split('@').next().unwrap_or_default().trim();
        rules.push(format!("{keyword}: {condition}"));
    }
    Ok(rules)
}

impl Numbers {
    fn read(cldr: &Cldr) -> Result<Self, CldrError> {
        let language = cldr.language.clone();
        let file = cldr.main("cldr-numbers-full", "numbers.json")?;
        let system = file
            .text(&["main", &language, "numbers", "defaultNumberingSystem"])?
            .to_owned();
        let systems = cldr.file("cldr-core/supplemental/numberingSystems.json")?;
        let digits = systems.text(&["supplemental", "numberingSystems", &system, "_digits"])?;
        let zero = digits.chars().next().map(String::from).unwrap_or_default();
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

/// The ISO 4217 code of a CLDR currency key, when ISO 4217's table lists it.
fn listed(code: &str) -> Option<Currency> {
    Currency::from_code(code)
}

fn currency(cldr: &Cldr, numbers: &Numbers, out: &mut Out) -> Result<(), CldrError> {
    let language = numbers.language.as_str();
    let percent_key = format!("percentFormats-numberSystem-{}", numbers.system);
    out.option("percent-sign", numbers.symbol("percentSign")?)?;
    let [a, b, c, d] = numbers.numbers(&percent_key);
    out.option(
        "percent-pattern",
        numbers.file.text(&[a, b, c, d, "standard"])?,
    )?;
    out.option("pattern", &numbers.decimal)?;
    let formats_key = format!("currencyFormats-numberSystem-{}", numbers.system);
    let formats = numbers.file.object(&numbers.numbers(&formats_key))?;
    let pattern = |key: &str, fallback: &str| -> Result<String, CldrError> {
        formats
            .get(key)
            .or_else(|| formats.get(fallback))
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .ok_or(CldrError::Missing {
                path: "numbers.json".to_owned(),
                at: format!("{formats_key}/{key}"),
            })
    };
    for (name, key, fallback) in [
        ("standard", "standard", "standard"),
        ("standard-alpha", "standard-alphaNextToNumber", "standard"),
        ("accounting", "accounting", "accounting"),
        (
            "accounting-alpha",
            "accounting-alphaNextToNumber",
            "accounting",
        ),
        ("no-currency", "standard-noCurrency", "standard-noCurrency"),
        (
            "no-currency-accounting",
            "accounting-noCurrency",
            "standard-noCurrency",
        ),
    ] {
        out.option(name, &pattern(key, fallback)?)?;
    }
    let units: Vec<String> = formats
        .iter()
        .filter_map(|(key, value)| {
            let keyword = key.strip_prefix("unitPattern-count-")?;
            let category = ["zero", "one", "two", "few", "many", "other"].contains(&keyword);
            category.then(|| value.as_str().map(|v| format!("{keyword} {v}")))?
        })
        .collect();
    out.lines("unit-pattern", &units)?;
    let data = cldr.file("cldr-core/supplemental/currencyData.json")?;
    let fractions = data.object(&["supplemental", "currencyData", "fractions"])?;
    let mut default = Vec::new();
    let mut digits = Vec::new();
    for (code, entry) in fractions {
        let get = |key: &str| entry.get(key).and_then(|v| v.as_str()).unwrap_or("0");
        let increment = match get("_rounding") {
            "0" => String::new(),
            rounding => format!(" {rounding}"),
        };
        let line = format!("{}{increment}", get("_digits"));
        match code.as_str() {
            "DEFAULT" => default.push(format!("default {line}")),
            code if listed(code).is_some() => digits.push(format!("{code} {line}")),
            _ => {}
        }
    }
    default.append(&mut digits);
    out.lines("digits", &default)?;
    let file = cldr.main("cldr-numbers-full", "currencies.json")?;
    let currencies = file.object(&["main", language, "numbers", "currencies"])?;
    let (mut symbols, mut narrow, mut names) = (Vec::new(), Vec::new(), Vec::new());
    for (code, entry) in currencies {
        if listed(code).is_none() {
            continue;
        }
        let get = |key: &str| entry.get(key).and_then(|v| v.as_str());
        if let Some(symbol) = get("symbol").filter(|s| s != code) {
            symbols.push(format!("{code} {symbol}"));
        }
        if let Some(symbol) = get("symbol-alt-narrow")
            .or(get("symbol"))
            .filter(|s| s != code)
        {
            narrow.push(format!("{code} {symbol}"));
        }
        if let Some(display) = get("displayName") {
            names.push(format!("{code} display {display}"));
        }
        for keyword in ["zero", "one", "two", "few", "many", "other"] {
            if let Some(name) = get(&format!("displayName-count-{keyword}")) {
                names.push(format!("{code} {keyword} {name}"));
            }
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
    for length in ["short", "medium", "long", "full"] {
        let glue = file
            .text(&at(&["dateTimeFormats-atTime", "standard", length]))
            .or_else(|_| file.text(&at(&["dateTimeFormats", length])))?;
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

fn list(cldr: &Cldr, out: &mut Out) -> Result<(), CldrError> {
    let language = cldr.language.as_str();
    let file = cldr.main("cldr-misc-full", "listPatterns.json")?;
    for (kind, key, conjunction) in [
        ("and", "listPattern-type-standard", Conjunction::And),
        ("or", "listPattern-type-or", Conjunction::Or),
    ] {
        let at =
            |part: &'static str| -> [&str; 5] { ["main", language, "listPatterns", key, part] };
        for (name, part) in [
            ("start", "start"),
            ("middle", "middle"),
            ("end", "end"),
            ("pair", "2"),
        ] {
            out.option(&format!("{kind}-{name}"), file.text(&at(part))?)?;
        }
        let end = file.text(&at("end"))?;
        match special(language, conjunction, end) {
            Some(case) => out.lines(
                &format!("{kind}-special"),
                &[case.condition, case.pattern.to_owned()],
            )?,
            None => out.option(&format!("{kind}-special"), "")?,
        }
    }
    Ok(())
}
