//! `[tables]`: the named texts and maps a format's patterns read. A table is its setting's text;
//! a table whose every line is a key, a space and a text is also a map. Some names carry a
//! meaning of their own, checked when the section loads:
//!
//! - `digits`: the ten characters of the digits, zero first;
//! - `minus`, `plus`: the signs `{sign}` writes;
//! - `group`, `decimal`: the separators `{int}` and `{frac}` write unless they name others;
//! - `grouping`: the fewest digits, 1 to 9, the highest group of a grouped integer holds;
//! - `plural.cardinal`, `plural.ordinal`: CLDR plural rules, one `<category>: <condition>` per
//!   line.

use rustc_hash::FxHashMap;
use siros_i18n::{FormatRule, Setting};

use crate::digit::Numerals;
use crate::number::plural::Rules;

/// A table: its text, and its entries when every line is one.
#[derive(Debug)]
pub(crate) struct Table {
    text: Box<str>,
    entries: Option<FxHashMap<Box<str>, Box<str>>>,
}

impl Table {
    fn of(text: &str) -> Self {
        let mut entries = FxHashMap::default();
        let mut map = true;
        for line in text.lines() {
            match line.split_once(' ') {
                Some((key, rest)) if !key.is_empty() && !rest.is_empty() => {
                    map &= entries.insert(key.into(), rest.into()).is_none();
                }
                Some(_) | None => map = false,
            }
        }
        Self {
            text: text.into(),
            entries: map.then_some(entries),
        }
    }

    /// Its text.
    pub(crate) fn text(&self) -> &str {
        &self.text
    }

    /// Whether every line is an entry, with keys that differ.
    pub(crate) const fn is_map(&self) -> bool {
        self.entries.is_some()
    }

    /// The text of the entry `key`, else of the entry `*`; `None` when it has neither.
    pub(crate) fn lookup(&self, key: &str) -> Option<&str> {
        let entries = self.entries.as_ref()?;
        entries
            .get(key)
            .or_else(|| entries.get("*"))
            .map(AsRef::as_ref)
    }

    /// Whether it has the entry `key`.
    pub(crate) fn has(&self, key: &str) -> bool {
        self.entries
            .as_ref()
            .is_some_and(|entries| entries.contains_key(key))
    }
}

/// The tables the context's modules define.
#[derive(Debug, Default)]
pub(crate) struct Tables {
    tables: FxHashMap<Box<str>, Table>,
    numerals: Option<Numerals>,
    grouping: Option<u8>,
    cardinal: Option<Rules>,
    ordinal: Option<Rules>,
}

impl Tables {
    /// Adds a `[tables]` section's tables.
    ///
    /// # Errors
    ///
    /// [`FormatRule::Repeated`] for a table defined before, and [`FormatRule::Text`] for a
    /// table of a meaning its text breaks.
    pub(crate) fn load(&mut self, settings: &[Setting<'_>]) -> Result<(), FormatRule> {
        for setting in settings {
            let key = setting.key;
            let text = || FormatRule::Text {
                key: key.to_owned(),
            };
            match key {
                "digits" => self.numerals = Some(Numerals::parse(setting.text).ok_or_else(text)?),
                "grouping" => {
                    let digits = setting.text.parse().ok().filter(|n| (1..=9).contains(n));
                    self.grouping = Some(digits.ok_or_else(text)?);
                }
                "plural.cardinal" => self.cardinal = Some(Rules::parse(setting.text).ok_or_else(text)?),
                "plural.ordinal" => self.ordinal = Some(Rules::parse(setting.text).ok_or_else(text)?),
                _ => {}
            }
            if self
                .tables
                .insert(key.into(), Table::of(setting.text))
                .is_some()
            {
                return Err(FormatRule::Repeated {
                    key: key.to_owned(),
                });
            }
        }
        Ok(())
    }

    /// The table `name`.
    pub(crate) fn get(&self, name: &str) -> Option<&Table> {
        self.tables.get(name)
    }

    /// The `digits` table's numerals.
    pub(crate) const fn numerals(&self) -> Option<Numerals> {
        self.numerals
    }

    /// The `grouping` table's count.
    pub(crate) const fn grouping(&self) -> Option<u8> {
        self.grouping
    }

    /// The cardinal plural rules.
    pub(crate) const fn cardinal(&self) -> Option<&Rules> {
        self.cardinal.as_ref()
    }

    /// The ordinal plural rules.
    pub(crate) const fn ordinal(&self) -> Option<&Rules> {
        self.ordinal.as_ref()
    }
}
