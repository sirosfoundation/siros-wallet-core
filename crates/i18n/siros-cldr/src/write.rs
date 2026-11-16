//! The resource the tool writes: its head with the language's locale and direction, one
//! `[tables]` section of the language's symbols, plural rules, currency data and calendar names,
//! and the `[formats.<name>]` sections of siros-i18n-formats, `number`, `integer`, `currency`,
//! `date`, `time` and `datetime`. CLDR's number and date patterns become pattern lines here; the
//! guards of a line pick the CLDR pattern a value takes.

use icu_properties::CodePointMapData;
use icu_properties::props::{GeneralCategory, GeneralCategoryGroup};
use siros_syntax::Currency;

use crate::cldr::{Cldr, CldrError, File};

/// TR35's plural categories, in its order.
const CATEGORIES: [&str; 6] = ["zero", "one", "two", "few", "many", "other"];

/// The lengths of the date formats, the default first.
const LENGTHS: [&str; 4] = ["medium", "short", "long", "full"];

/// The text being written.
struct Out {
    text: String,
}

/// A text's characters escaped for a resource value line: a line's leading and trailing space and
/// tab, and every character outside the format's `content`. `pattern` admits the backslashes of
/// a pattern's escapes.
fn escaped(line: &str, pattern: bool) -> Result<String, CldrError> {
    if (!pattern && line.contains('\\')) || line.contains(['\n', '\r']) {
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

/// Literal text in a pattern: its braces and backslashes escaped.
fn literal(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if matches!(c, '{' | '}' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

impl Out {
    fn line(&mut self, line: &str) {
        self.text.push_str(line);
        self.text.push('\n');
    }

    /// A setting of one line.
    fn setting(&mut self, name: &str, value: &str) -> Result<(), CldrError> {
        let value = escaped(value, false)?;
        if value.is_empty() {
            self.line(&format!("{name} ="));
        } else {
            self.line(&format!("{name} = {value}"));
        }
        Ok(())
    }

    /// A setting of several lines, each on an indented continuation line.
    fn lines(&mut self, name: &str, lines: &[String]) -> Result<(), CldrError> {
        self.line(&format!("{name} ="));
        for line in lines {
            self.line(&format!("  {}", escaped(line, false)?));
        }
        Ok(())
    }

    /// The `pattern` setting of `lines`.
    fn patterns(&mut self, lines: &[Line]) -> Result<(), CldrError> {
        self.line("pattern =");
        for (guard, text) in lines {
            let written = if guard.is_empty() && !text.starts_with(['[', ' ', '\t']) {
                text.clone()
            } else {
                format!("[{}] {text}", guard.join(" "))
            };
            self.line(&format!("  {}", escaped(&written, true)?));
        }
        Ok(())
    }

    fn section(&mut self, name: &str) {
        self.line("");
        self.line(&format!("[{name}]"));
    }
}

/// A pattern line: its guard's tests, and its pattern.
type Line = (Vec<String>, String);

/// Each line of `left` followed by each of `right`, in order: a value takes the first line of
/// each part whose guard holds, so the product keeps each part's order.
fn product(left: &[Line], right: &[Line]) -> Vec<Line> {
    let mut lines = Vec::with_capacity(left.len() * right.len());
    for (guard, text) in left {
        for (more, rest) in right {
            let mut tests = guard.clone();
            tests.extend(more.iter().cloned());
            lines.push((tests, format!("{text}{rest}")));
        }
    }
    lines
}

/// One line without a guard.
fn plain(text: String) -> Vec<Line> {
    vec![(Vec::new(), text)]
}

/// Each line with `tests` before its own.
fn guarded(tests: &[&str], lines: Vec<Line>) -> Vec<Line> {
    lines
        .into_iter()
        .map(|(guard, text)| {
            let mut all: Vec<String> = tests.iter().map(|test| (*test).to_owned()).collect();
            all.extend(guard);
            (all, text)
        })
        .collect()
}

/// The resource of the language's formats.
pub(crate) fn resource(cldr: &Cldr, release: &str) -> Result<String, CldrError> {
    let language = cldr.language.as_str();
    let mut out = Out {
        text: String::new(),
    };
    out.line(&format!(
        "# The formats of {language} from CLDR {release} (unicode-org/cldr-json), written by siros-cldr."
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
    let currencies = Currencies::read(cldr, &numbers)?;
    let calendar = Calendar::read(cldr, language)?;
    out.section("tables");
    numbers.tables(&mut out)?;
    currencies.tables(&mut out)?;
    calendar.tables(&mut out)?;
    let decimal = NumberPattern::parse(&numbers.decimal).ok_or_else(|| {
        numbers
            .file
            .form(&["decimalFormats", "standard"], &numbers.decimal)
    })?;
    for (name, extra) in [
        ("number", &[("default", "yes")][..]),
        ("integer", &[("maximumFractionDigits", "0")][..]),
    ] {
        out.section(&format!("formats.{name}"));
        out.setting("of", "number")?;
        for (key, value) in extra {
            out.setting(key, value)?;
        }
        out.setting("select", "plural")?;
        out.patterns(&decimal.lines("")?)?;
    }
    out.section("formats.currency");
    currencies.format(&numbers, &decimal, &mut out)?;
    calendar.formats(&mut out)?;
    Ok(out.text)
}

/// The language's number symbols, decimal pattern and plural rules.
struct Numbers {
    language: String,
    system: String,
    digits: String,
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
        if digits.chars().count() != 10 {
            return Err(systems.form(&digits_at, digits));
        }
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
            digits: digits.to_owned(),
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

    /// The categories of the cardinal rules, `other` last.
    fn categories(&self) -> Vec<&'static str> {
        CATEGORIES
            .into_iter()
            .filter(|category| {
                *category == "other"
                    || self
                        .cardinal
                        .iter()
                        .any(|rule| rule.starts_with(&format!("{category}:")))
            })
            .collect()
    }

    fn tables(&self, out: &mut Out) -> Result<(), CldrError> {
        out.setting("digits", &self.digits)?;
        out.setting("decimal", self.symbol("decimal")?)?;
        out.setting("group", self.symbol("group")?)?;
        out.setting("minus", self.symbol("minusSign")?)?;
        out.setting("plus", self.symbol("plusSign")?)?;
        let grouping = self.file.text(&self.numbers("minimumGroupingDigits"))?;
        out.setting("grouping", grouping)?;
        out.lines("plural.cardinal", &self.cardinal)?;
        out.lines("plural.ordinal", &self.ordinal)
    }
}

/// A part of a number pattern's prefix or suffix.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Affix {
    Text(String),
    Minus,
    Plus,
    Currency,
}

/// A CLDR number pattern (TR35 Part 3, "Number Patterns"): its positive affixes, its explicit
/// negative affixes, and its integer grouping sizes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct NumberPattern {
    positive: (Vec<Affix>, Vec<Affix>),
    negative: Option<(Vec<Affix>, Vec<Affix>)>,
    groups: Option<(usize, usize)>,
}

/// The pieces of `text` between unquoted `separator`s.
fn split_unquoted(text: &str, separator: char) -> impl Iterator<Item = &str> {
    let mut quoted = false;
    text.split(move |c| {
        if c == '\'' {
            quoted = !quoted;
        }
        c == separator && !quoted
    })
}

/// A subpattern's prefix, its number part, and its suffix: the number part is the one run of
/// unquoted `#`, `0`, `,` and `.`.
fn parts(text: &str) -> Option<(Vec<Affix>, String, Vec<Affix>)> {
    let mut quoted = false;
    let mut place = 0;
    let (mut prefix, mut number, mut suffix) = (String::new(), String::new(), String::new());
    for c in text.chars() {
        if c == '\'' {
            quoted = !quoted;
        } else if !quoted && matches!(c, '@' | 'E' | '*') {
            return None;
        }
        let numeric = !quoted && matches!(c, '#' | '0' | ',' | '.');
        place = match (place, numeric) {
            (0 | 1, true) => 1,
            (0, false) => 0,
            (1 | 2, false) => 2,
            _ => return None,
        };
        match place {
            0 => prefix.push(c),
            1 => number.push(c),
            _ => suffix.push(c),
        }
    }
    if place == 0 {
        return None;
    }
    Some((affixes(&prefix)?, number, affixes(&suffix)?))
}

/// The parts of a prefix or suffix: quoted text literal, `''` an apostrophe.
fn affixes(text: &str) -> Option<Vec<Affix>> {
    let mut parts = Vec::new();
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
            '¤' => Some(Affix::Currency),
            '%' | '‰' => return None,
            _ => None,
        };
        match special {
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

impl NumberPattern {
    fn parse(text: &str) -> Option<Self> {
        let mut subpatterns = split_unquoted(text, ';');
        let positive = subpatterns.next()?;
        let negative = subpatterns.next();
        if subpatterns.next().is_some() {
            return None;
        }
        let (prefix, body, suffix) = parts(positive)?;
        let (integer, fraction) = body.split_once('.').unwrap_or((body.as_str(), ""));
        // One integer digit at least, the minimum siros-i18n-formats writes; the fraction's
        // digits come from the format's options.
        let digits: String = integer.chars().filter(|c| *c != ',').collect();
        let optional = fraction.trim_start_matches('0');
        if digits.trim_start_matches('#') != "0"
            || integer.split(',').skip(1).any(str::is_empty)
            || fraction.contains([',', '.'])
            || optional.contains('0')
        {
            return None;
        }
        let groups: Vec<usize> = integer.split(',').map(str::len).collect();
        let groups = match groups.as_slice() {
            [_] => None,
            [.., second, last] if groups.len() > 2 => Some((*last, *second)),
            [_, last] => Some((*last, *last)),
            _ => return None,
        };
        let negative = match negative {
            Some(negative) => {
                let (prefix, _, suffix) = parts(negative)?;
                Some((prefix, suffix))
            }
            None => None,
        };
        Some(Self {
            positive: (prefix, suffix),
            negative,
            groups,
        })
    }

    /// Whether the positive pattern's currency stands before the number and after it.
    fn adjacent(&self) -> (bool, bool) {
        let (prefix, suffix) = &self.positive;
        (
            prefix.last() == Some(&Affix::Currency),
            suffix.first() == Some(&Affix::Currency),
        )
    }

    /// The number's placeholders.
    fn body(&self) -> String {
        match self.groups {
            None => "{int}{frac}".to_owned(),
            Some((primary, secondary)) if primary == secondary => {
                format!("{{int:group={primary}}}{{frac}}")
            }
            Some((primary, secondary)) => {
                format!("{{int:group={primary},second={secondary}}}{{frac}}")
            }
        }
    }

    /// The pattern lines of the number with `currency` standing for `¤`: an explicit negative
    /// subpattern for a number that shows a sign, its `-` the sign; else the positive pattern,
    /// the sign before it.
    fn lines(&self, currency: &str) -> Result<Vec<Line>, CldrError> {
        let write = |(prefix, suffix): &(Vec<Affix>, Vec<Affix>)| {
            let affix = |parts: &[Affix]| {
                parts
                    .iter()
                    .map(|part| match part {
                        Affix::Text(text) => literal(text),
                        Affix::Minus | Affix::Plus => "{sign}".to_owned(),
                        Affix::Currency => currency.to_owned(),
                    })
                    .collect::<String>()
            };
            format!("{}{}{}", affix(prefix), self.body(), affix(suffix))
        };
        let positive = format!("{{sign}}{}", write(&self.positive));
        Ok(match &self.negative {
            None => plain(positive),
            Some(negative) => {
                let signed = negative
                    .0
                    .iter()
                    .chain(&negative.1)
                    .any(|a| *a == Affix::Minus);
                let test = if signed { "!sign=none" } else { "sign=minus" };
                vec![
                    (vec![test.to_owned()], write(negative)),
                    (Vec::new(), positive),
                ]
            }
        })
    }
}

/// Whether a character is a letter (General Category L).
fn letter(c: Option<char>) -> bool {
    c.is_some_and(|c| {
        GeneralCategoryGroup::Letter.contains(CodePointMapData::<GeneralCategory>::new().get(c))
    })
}

/// Whether ISO 4217's table lists a CLDR currency key.
fn listed(code: &str) -> bool {
    Currency::parse(code).is_ok()
}

/// `base` then `rest`.
fn joined<'a>(base: &[&'a str], rest: &[&'a str]) -> Vec<&'a str> {
    base.iter().chain(rest).copied().collect()
}

/// The language's currency patterns, symbols, names and fraction digits.
struct Currencies {
    patterns: [NumberPattern; 6],
    units: Vec<(String, String)>,
    digits: Vec<String>,
    increments: Vec<String>,
    symbols: Vec<(String, String)>,
    narrow: Vec<(String, String)>,
    names: Vec<(String, Vec<String>)>,
}

impl Currencies {
    fn read(cldr: &Cldr, numbers: &Numbers) -> Result<Self, CldrError> {
        let language = numbers.language.as_str();
        let formats_key = format!("currencyFormats-numberSystem-{}", numbers.system);
        let formats_at = numbers.numbers(&formats_key);
        let mut patterns = Vec::new();
        // TR35 Part 3, "Currency Formats": the `alphaNextToNumber` pattern applies when the
        // locale gives one, else the pattern it varies.
        for (key, fallback) in [
            ("standard", None),
            ("standard-alphaNextToNumber", Some("standard")),
            ("accounting", None),
            ("accounting-alphaNextToNumber", Some("accounting")),
            ("standard-noCurrency", None),
            ("accounting-noCurrency", None),
        ] {
            let at = joined(&formats_at, &[key]);
            let text = match fallback {
                None => numbers.file.text(&at)?,
                Some(fallback) => match numbers.file.optional_text(&at)? {
                    Some(text) => text,
                    None => numbers.file.text(&joined(&formats_at, &[fallback]))?,
                },
            };
            patterns.push(NumberPattern::parse(text).ok_or_else(|| numbers.file.form(&at, text))?);
        }
        let patterns: [NumberPattern; 6] = patterns
            .try_into()
            .map_err(|_| numbers.file.missing(&formats_at))?;
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
            if !(text.contains("{0}") && text.contains("{1}")) {
                return Err(numbers.file.form(&at, text));
            }
            units.push((keyword.to_owned(), text.to_owned()));
        }
        let data = cldr.file("cldr-core/supplemental/currencyData.json")?;
        let fractions_at = ["supplemental", "currencyData", "fractions"];
        let (mut digits, mut increments) = (Vec::new(), Vec::new());
        for code in data.object(&fractions_at)?.keys() {
            // TR35 Part 3, "Supplemental Currency Data": `digits` defaults to 2, `rounding` to 0.
            let get = |key: &str, absent: &'static str| -> Result<&str, CldrError> {
                let text = data.optional_text(&joined(&fractions_at, &[code.as_str(), key]))?;
                Ok(text.unwrap_or(absent))
            };
            let key = match code.as_str() {
                "DEFAULT" => "*",
                code if listed(code) => code,
                _ => continue,
            };
            digits.push(format!("{key} {}", get("_digits", "2")?));
            match get("_rounding", "0")? {
                "0" => {}
                rounding => increments.push(format!("{key} {rounding}")),
            }
        }
        digits.sort_by_key(|line| !line.starts_with('*'));
        if !increments.is_empty() && !increments.iter().any(|line| line.starts_with('*')) {
            increments.push("* 1".to_owned());
        }
        increments.sort_by_key(|line| !line.starts_with('*'));
        let file = cldr.main("cldr-numbers-full", "currencies.json")?;
        let currencies_at = ["main", language, "numbers", "currencies"];
        let (mut symbols, mut narrow) = (Vec::new(), Vec::new());
        let mut names: Vec<(String, Vec<String>)> = CATEGORIES
            .iter()
            .map(|category| ((*category).to_owned(), Vec::new()))
            .collect();
        for code in file.object(&currencies_at)?.keys() {
            if !listed(code) {
                continue;
            }
            let get =
                |key: &str| file.optional_text(&joined(&currencies_at, &[code.as_str(), key]));
            let symbol = get("symbol")?;
            if let Some(symbol) = symbol.filter(|s| s != code) {
                symbols.push((code.clone(), symbol.to_owned()));
            }
            // TR35 Part 3: the narrow symbol falls back to the symbol, and a currency without
            // one shows its code.
            let narrowed = match get("symbol-alt-narrow")? {
                Some(narrowed) => Some(narrowed),
                None => symbol,
            };
            if let Some(symbol) = narrowed.filter(|s| s != code) {
                narrow.push((code.clone(), symbol.to_owned()));
            }
            // TR35 Part 3: the display name of the count, else of `other`, else without a
            // count, else the code.
            let mut other = false;
            for (category, list) in &mut names {
                if let Some(name) = get(&format!("displayName-count-{category}"))? {
                    other |= category == "other";
                    list.push(format!("{code} {name}"));
                }
            }
            if !other
                && let Some(name) = get("displayName")?
                && let Some((_, list)) = names.iter_mut().find(|(c, _)| c == "other")
            {
                list.push(format!("{code} {name}"));
            }
        }
        names.retain(|(_, list)| !list.is_empty());
        Ok(Self {
            patterns,
            units,
            digits,
            increments,
            symbols,
            narrow,
            names,
        })
    }

    /// The entries of `symbols` whose symbol stands against the number in the standard
    /// pattern: one that does not start or end, on the number's side, with a letter.
    fn tight(&self, symbols: &[(String, String)]) -> Vec<String> {
        let [standard, ..] = &self.patterns;
        let (before, after) = standard.adjacent();
        symbols
            .iter()
            .filter(|(_, symbol)| {
                let alpha = (before && letter(symbol.chars().next_back()))
                    || (after && letter(symbol.chars().next()));
                !alpha
            })
            .map(|(code, symbol)| format!("{code} {symbol}"))
            .collect()
    }

    fn tables(&self, out: &mut Out) -> Result<(), CldrError> {
        let entries = |list: &[(String, String)]| -> Vec<String> {
            list.iter()
                .map(|(code, text)| format!("{code} {text}"))
                .collect()
        };
        out.lines("currency.digits", &self.digits)?;
        if !self.increments.is_empty() {
            out.lines("currency.increment", &self.increments)?;
        }
        out.lines("currency.symbol", &entries(&self.symbols))?;
        out.lines("currency.symbol.tight", &self.tight(&self.symbols))?;
        out.lines("currency.narrow", &entries(&self.narrow))?;
        out.lines("currency.narrow.tight", &self.tight(&self.narrow))?;
        for (category, list) in &self.names {
            out.lines(&format!("currency.name.{category}"), list)?;
        }
        Ok(())
    }

    /// The name table chain of `category`: its own, then `other`'s.
    fn name(&self, category: &str) -> String {
        let tables: Vec<String> = [category, "other"]
            .iter()
            .filter(|c| self.names.iter().any(|(n, _)| n == *c))
            .map(|c| format!("currency.name.{c}"))
            .collect();
        let mut chain: Vec<String> = Vec::new();
        for table in tables {
            if !chain.contains(&table) {
                chain.push(table);
            }
        }
        if chain.is_empty() {
            "{currency}".to_owned()
        } else {
            format!("{{currency:table={}}}", chain.join("|"))
        }
    }

    fn format(
        &self,
        numbers: &Numbers,
        decimal: &NumberPattern,
        out: &mut Out,
    ) -> Result<(), CldrError> {
        out.setting("of", "amount")?;
        out.setting("default", "yes")?;
        out.setting(
            "option.currencyDisplay",
            "symbol narrowSymbol code name never",
        )?;
        out.setting("option.currencySign", "standard accounting")?;
        let digits = "{currency:table=currency.digits}";
        out.setting("minimumFractionDigits", digits)?;
        out.setting("maximumFractionDigits", digits)?;
        if !self.increments.is_empty() {
            out.setting("roundingIncrement", "{currency:table=currency.increment}")?;
        }
        let [
            standard,
            standard_alpha,
            accounting,
            accounting_alpha,
            plain,
            plain_accounting,
        ] = &self.patterns;
        let mut lines = Vec::new();
        lines.extend(guarded(
            &["currencyDisplay=never", "currencySign=accounting"],
            plain_accounting.lines("")?,
        ));
        lines.extend(guarded(&["currencyDisplay=never"], plain.lines("")?));
        let other = self
            .units
            .iter()
            .find(|(c, _)| c == "other")
            .map(|(_, unit)| unit.as_str())
            .ok_or_else(|| {
                numbers
                    .file
                    .missing(&["currencyFormats", "unitPattern-count-other"])
            })?;
        for category in numbers.categories() {
            let unit = self
                .units
                .iter()
                .find(|(c, _)| c == category)
                .map_or(other, |(_, unit)| unit.as_str());
            let number = decimal.lines("")?;
            let name = self.name(category);
            let mut written = Vec::new();
            let (before, after) = unit
                .split_once("{0}")
                .ok_or_else(|| numbers.file.form(&["currencyFormats", "unitPattern"], unit))?;
            for (guard, text) in number {
                let text = format!("{}{text}{}", literal(before), literal(after))
                    .replace("\\{1\\}", &name);
                written.push((guard, text));
            }
            let tests: Vec<String> = if category == "other" {
                vec!["currencyDisplay=name".to_owned()]
            } else {
                vec![
                    "currencyDisplay=name".to_owned(),
                    format!("plural={category}"),
                ]
            };
            let tests: Vec<&str> = tests.iter().map(String::as_str).collect();
            lines.extend(guarded(&tests, written));
        }
        for (display, table) in [
            ("narrowSymbol", "currency.narrow"),
            ("symbol", "currency.symbol"),
        ] {
            let symbol = format!("{{currency:table={table}}}");
            let display = format!("currencyDisplay={display}");
            let tight = format!("currency@{table}.tight");
            for (sign, tight_pattern, alpha_pattern) in [
                (
                    Some("currencySign=accounting"),
                    accounting,
                    accounting_alpha,
                ),
                (None, standard, standard_alpha),
            ] {
                let mut tests = vec![display.as_str()];
                tests.extend(sign);
                let mut with_tight = tests.clone();
                with_tight.push(&tight);
                lines.extend(guarded(&with_tight, tight_pattern.lines(&symbol)?));
                lines.extend(guarded(&tests, alpha_pattern.lines(&symbol)?));
            }
        }
        lines.extend(guarded(
            &["currencyDisplay=code", "currencySign=accounting"],
            accounting_alpha.lines("{currency}")?,
        ));
        lines.extend(guarded(
            &["currencyDisplay=code"],
            standard_alpha.lines("{currency}")?,
        ));
        out.patterns(&lines)
    }
}

/// A field of a date pattern, by its letter and width (TR35 Part 4, "Date Field Symbol Table"),
/// as the lines that write it.
fn date_field(letter: char, width: usize, era: bool, year_era: &[Line]) -> Option<Vec<Line>> {
    let pad = |name: &str| {
        if width == 2 {
            format!("{{{name}:pad=2}}")
        } else {
            format!("{{{name}}}")
        }
    };
    let one = |text: String| Some(plain(text));
    match (letter, width) {
        ('G', 1..=3) => one("{era:table=eras}".to_owned()),
        // ICU4X's `YearStyle::Auto`: a two-digit year from 1950 to 2049 alone, a year before
        // 1000 with its era, every other year in full.
        ('y', _) => {
            let full = if width > 2 {
                format!("{{year:pad={width}}}")
            } else {
                "{year}".to_owned()
            };
            let mut lines = Vec::new();
            if era {
                let shown = if width > 2 {
                    format!("{{era-year:pad={width}}}")
                } else {
                    "{era-year}".to_owned()
                };
                lines.push((vec!["year<1000".to_owned()], shown));
            } else {
                lines.extend(guarded(&["year<1000"], year_era.to_vec()));
            }
            if width == 2 {
                lines.push((
                    vec!["year>=1950".to_owned(), "year<2050".to_owned()],
                    "{year:last=2,pad=2}".to_owned(),
                ));
            }
            lines.push((Vec::new(), full));
            Some(lines)
        }
        ('M', 3) => one("{month:table=months.abbreviated}".to_owned()),
        ('M', 4) => one("{month:table=months.wide}".to_owned()),
        ('M', 1..=2) => one(pad("month")),
        ('d', 1..=2) => one(pad("day")),
        ('E', 1..=3) => one("{weekday:table=days.abbreviated}".to_owned()),
        ('E', 4) => one("{weekday:table=days.wide}".to_owned()),
        ('h', 1..=2) => one(pad("hour12")),
        ('H', 1..=2) => one(pad("hour")),
        ('K', 1..=2) => one(pad("hour11")),
        ('k', 1..=2) => one(pad("hour24")),
        ('m', 1..=2) => one(pad("minute")),
        ('s', 1..=2) => one(pad("second")),
        ('a', 1..=3) => one("{period:table=periods}".to_owned()),
        _ => None,
    }
}

/// A TR35 pattern's items: literal text, and each field's letter and width.
fn items(text: &str) -> Option<Vec<Result<String, (char, usize)>>> {
    let mut items = Vec::new();
    let mut text_run = String::new();
    let mut chars = text.chars().peekable();
    let mut quoted = false;
    while let Some(c) = chars.next() {
        if c == '\'' {
            if chars.next_if_eq(&'\'').is_some() {
                text_run.push('\'');
            } else {
                quoted = !quoted;
            }
        } else if quoted || !c.is_ascii_alphabetic() {
            text_run.push(c);
        } else {
            let mut width = 1;
            while chars.next_if_eq(&c).is_some() {
                width += 1;
            }
            if !text_run.is_empty() {
                items.push(Ok(std::mem::take(&mut text_run)));
            }
            items.push(Err((c, width)));
        }
    }
    if quoted {
        return None;
    }
    if !text_run.is_empty() {
        items.push(Ok(text_run));
    }
    Some(items)
}

/// The language's calendar patterns and names.
struct Calendar {
    file: File,
    base: Vec<String>,
    months_wide: Vec<String>,
    months_abbreviated: Vec<String>,
    days_wide: Vec<String>,
    days_abbreviated: Vec<String>,
    periods: Vec<String>,
    eras: Vec<String>,
    gmt: (String, String),
    /// The hour formats of a positive offset and of a negative one.
    hours: (String, String),
    year_era: String,
}

impl Calendar {
    fn read(cldr: &Cldr, language: &str) -> Result<Self, CldrError> {
        let file = cldr.main("cldr-dates-full", "ca-gregorian.json")?;
        let base: Vec<String> = ["main", language, "dates", "calendars", "gregorian"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        let at = |rest: &[&str]| -> Vec<String> {
            base.iter()
                .cloned()
                .chain(rest.iter().map(|s| (*s).to_owned()))
                .collect()
        };
        let text = |rest: &[&str]| -> Result<String, CldrError> {
            let path = at(rest);
            let path: Vec<&str> = path.iter().map(String::as_str).collect();
            file.text(&path).map(str::to_owned)
        };
        let names =
            |path: &[&str], keys: &[&str], numbered: &[&str]| -> Result<Vec<String>, CldrError> {
                keys.iter()
                    .zip(numbered)
                    .map(|(key, number)| {
                        let mut full = path.to_vec();
                        full.push(key);
                        Ok(format!("{number} {}", text(&full)?))
                    })
                    .collect()
            };
        let months = [
            "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12",
        ];
        // The weekdays from Monday, numbered as ISO 8601 numbers them.
        let days = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];
        let iso = ["1", "2", "3", "4", "5", "6", "7"];
        let zones = cldr.main("cldr-dates-full", "timeZoneNames.json")?;
        let zone = ["main", language, "dates", "timeZoneNames"];
        let gmt_at = joined(&zone, &["gmtFormat"]);
        let gmt = zones.text(&gmt_at)?;
        let (before, after) = gmt
            .split_once("{0}")
            .filter(|(_, after)| !after.contains("{0}"))
            .ok_or_else(|| zones.form(&gmt_at, gmt))?;
        let hours_at = joined(&zone, &["hourFormat"]);
        let hours = zones.text(&hours_at)?;
        let (positive, negative) = hours
            .split_once(';')
            .ok_or_else(|| zones.form(&hours_at, hours))?;
        Ok(Self {
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
            hours: (positive.to_owned(), negative.to_owned()),
            year_era: text(&["dateTimeFormats", "availableFormats", "Gy"])?,
            file,
            base,
        })
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

    fn optional(&self, rest: &[&str]) -> Result<Option<&str>, CldrError> {
        let path = self.at(rest);
        let path: Vec<&str> = path.iter().map(String::as_str).collect();
        self.file.optional_text(&path)
    }

    fn refused(&self, rest: &[&str], value: &str) -> CldrError {
        let path = self.at(rest);
        let path: Vec<&str> = path.iter().map(String::as_str).collect();
        self.file.form(&path, value)
    }

    fn tables(&self, out: &mut Out) -> Result<(), CldrError> {
        out.lines("months.wide", &self.months_wide)?;
        out.lines("months.abbreviated", &self.months_abbreviated)?;
        out.lines("days.wide", &self.days_wide)?;
        out.lines("days.abbreviated", &self.days_abbreviated)?;
        out.lines("periods", &self.periods)?;
        out.lines("eras", &self.eras)
    }

    /// The year with its era, CLDR's `Gy` pattern, as lines.
    fn year_era(&self) -> Result<Vec<Line>, CldrError> {
        let at = ["dateTimeFormats", "availableFormats", "Gy"];
        let refused = || self.refused(&at, &self.year_era);
        let mut lines = plain(String::new());
        for item in items(&self.year_era).ok_or_else(refused)? {
            let part = match item {
                Ok(text) => plain(literal(&text)),
                Err(('y', width)) => plain(if width > 2 {
                    format!("{{era-year:pad={width}}}")
                } else {
                    "{era-year}".to_owned()
                }),
                Err(('G', 1..=3)) => plain("{era:table=eras}".to_owned()),
                Err(_) => return Err(refused()),
            };
            lines = product(&lines, &part);
        }
        Ok(lines)
    }

    /// The localized GMT format of an offset: `long` pads its hours and always writes its
    /// minutes; the short format writes them when they are not zero.
    fn zone(&self, long: bool) -> Result<Vec<Line>, CldrError> {
        let (before, after) = (literal(&self.gmt.0), literal(&self.gmt.1));
        let mut lines = Vec::new();
        for (sign, hours) in [
            (Some("offset-sign=1"), &self.hours.1),
            (None, &self.hours.0),
        ] {
            let refused = || self.refused(&["hourFormat"], hours);
            // The text up to the hours and after them, and the minutes with the text before
            // them.
            let (mut head, mut minutes, mut tail) = (String::new(), None::<String>, String::new());
            let mut hours_seen = false;
            for item in items(hours).ok_or_else(refused)? {
                match item {
                    Ok(text) if hours_seen => tail.push_str(&literal(&text)),
                    Ok(text) => head.push_str(&literal(&text)),
                    Err(('H', 1..=2)) if !hours_seen => {
                        hours_seen = true;
                        head.push_str(if long {
                            "{offset-hours:pad=2}"
                        } else {
                            "{offset-hours}"
                        });
                    }
                    Err(('m', 2)) if hours_seen && minutes.is_none() => {
                        minutes = Some(format!(
                            "{}{{offset-minutes:pad=2}}",
                            std::mem::take(&mut tail)
                        ));
                    }
                    Err(_) => return Err(refused()),
                }
            }
            if !hours_seen {
                return Err(refused());
            }
            let tests: Vec<String> = sign.into_iter().map(str::to_owned).collect();
            let shown = |minutes: &str| format!("{before}{head}{minutes}{tail}{after}");
            match minutes {
                Some(minutes) if long => lines.push((tests, shown(&minutes))),
                Some(minutes) => {
                    let mut nonzero = tests.clone();
                    nonzero.push("offset-minutes>0".to_owned());
                    lines.push((nonzero, shown(&minutes)));
                    lines.push((tests, shown("")));
                }
                None => lines.push((tests, shown(""))),
            }
        }
        Ok(lines)
    }

    /// The lines of a date or time pattern.
    fn pattern(&self, rest: &[&str]) -> Result<Vec<Line>, CldrError> {
        let text = self.text(rest)?;
        let refused = || self.refused(rest, text);
        let items = items(text).ok_or_else(refused)?;
        let era = items.iter().any(|item| matches!(item, Err(('G', _))));
        let year_era = self.year_era()?;
        let mut lines = plain(String::new());
        for item in items {
            let part = match item {
                Ok(text) => plain(literal(&text)),
                Err(('z', 1..=3) | ('O', 1)) => self.zone(false)?,
                Err(('z' | 'O', 4)) => self.zone(true)?,
                Err((letter, width)) => {
                    date_field(letter, width, era, &year_era).ok_or_else(refused)?
                }
            };
            lines = product(&lines, &part);
        }
        Ok(lines)
    }

    /// The time at `length`: at `long` and `full`, a time without an offset as at `medium`.
    fn time(&self, length: &str) -> Result<Vec<Line>, CldrError> {
        let pattern = self.pattern(&["timeFormats", length])?;
        Ok(match length {
            "long" | "full" => {
                let mut lines = guarded(&["offset?"], pattern);
                lines.extend(self.pattern(&["timeFormats", "medium"])?);
                lines
            }
            _ => pattern,
        })
    }

    /// The date and time at `length`: CLDR's `atTime` pattern, else the standard one
    /// (TR35 Part 4, "dateTimeFormats"), `{0}` the time and `{1}` the date.
    fn both(&self, length: &str) -> Result<Vec<Line>, CldrError> {
        let at_time = ["dateTimeFormats-atTime", "standard", length];
        let (rest, glue): (Vec<&str>, &str) = match self.optional(&at_time)? {
            Some(glue) => (at_time.to_vec(), glue),
            None => (
                vec!["dateTimeFormats", length],
                self.text(&["dateTimeFormats", length])?,
            ),
        };
        let refused = || self.refused(&rest, glue);
        let mut lines = plain(String::new());
        let mut text = glue;
        let (mut times, mut dates) = (0, 0);
        while let Some((before, mark)) = text.split_once('{') {
            lines = product(&lines, &self.literal_run(before).ok_or_else(refused)?);
            let (part, after) = if let Some(after) = mark.strip_prefix("0}") {
                times += 1;
                (self.time(length)?, after)
            } else if let Some(after) = mark.strip_prefix("1}") {
                dates += 1;
                (self.pattern(&["dateFormats", length])?, after)
            } else {
                return Err(refused());
            };
            lines = product(&lines, &part);
            text = after;
        }
        lines = product(&lines, &self.literal_run(text).ok_or_else(refused)?);
        if (times, dates) != (1, 1) {
            return Err(refused());
        }
        Ok(lines)
    }

    /// Text of a pattern without fields: its quoting resolved.
    fn literal_run(&self, text: &str) -> Option<Vec<Line>> {
        let mut out = String::new();
        for item in items(text)? {
            match item {
                Ok(text) => out.push_str(&literal(&text)),
                Err(_) => return None,
            }
        }
        Some(plain(out))
    }

    fn formats(&self, out: &mut Out) -> Result<(), CldrError> {
        for (name, of) in [("date", "date"), ("time", "time"), ("datetime", "datetime")] {
            out.section(&format!("formats.{name}"));
            out.setting("of", of)?;
            out.setting("default", "yes")?;
            out.setting("option.length", &LENGTHS.join(" "))?;
            let mut lines = Vec::new();
            for length in LENGTHS {
                let pattern = match name {
                    "date" => self.pattern(&["dateFormats", length])?,
                    "time" => self.time(length)?,
                    _ => self.both(length)?,
                };
                let test = format!("length={length}");
                lines.extend(guarded(&[test.as_str()], pattern));
            }
            out.patterns(&lines)?;
        }
        Ok(())
    }
}
