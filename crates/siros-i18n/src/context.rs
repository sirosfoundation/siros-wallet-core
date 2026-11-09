//! A context: the modules of one locale, which resolve a message's id and arguments into text.

use std::fmt::Write as _;

use rustc_hash::FxHashSet;
use unicode_normalization::UnicodeNormalization;

use crate::compile::{self, Compiled};
#[cfg(feature = "check")]
use crate::error::CheckError;
use crate::error::{LoadError, ResolveError, SyntaxRule};
use crate::format::Formats;
use crate::locale::LocaleTag;
use crate::message::Message;
use crate::mf2;
use crate::resource;
use crate::text::Text;

/// How a context isolates a placeholder's text from the text around it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Bidi {
    /// MF2's Default Bidi Strategy (spec/formatting.md "Handling Bidirectional Text"): a
    /// placeholder stands between U+2066, U+2067 or U+2068 and U+2069 by its value's direction
    /// or its `u:dir`. A left-to-right value in a left-to-right message without `u:dir` stands
    /// alone.
    #[default]
    Default,
    /// Each placeholder's text as formatted.
    None,
}

/// The modules of one locale, each a W3C message resource of MF2 messages, and the format options
/// their `[formats.<format>]` sections define. [`Context::resolve`] resolves a [`Message`]'s id
/// and arguments into a [`Text`].
#[derive(Debug, Clone, Default)]
pub struct Context {
    locale: Option<LocaleTag>,
    bidi: Bidi,
    formats: Formats,
    /// The messages, ascending by id, each id once.
    messages: Vec<Worded>,
}

/// A message under its id.
#[derive(Debug, Clone)]
struct Worded {
    id: String,
    message: Compiled,
}

/// A message's arguments: each key in NFC with its text, ascending by key, each key once.
struct Args(Vec<(String, String)>);

impl Args {
    /// The arguments `message` gives.
    ///
    /// # Errors
    ///
    /// [`ResolveError::Argument`] for a key given twice, or a value whose `Display` fails.
    fn of(message: &dyn Message, id: &str) -> Result<Self, ResolveError> {
        let mut args: Vec<(String, String)> = Vec::new();
        let mut failed: Option<String> = None;
        message.args(&mut |key, value| {
            if failed.is_some() {
                return;
            }
            let key: String = key.nfc().collect();
            let mut text = String::new();
            match write!(text, "{value}") {
                Ok(()) => args.push((key, text)),
                Err(_) => failed = Some(key),
            }
        });
        let refused = |key: String| ResolveError::Argument {
            id: id.to_owned(),
            key,
        };
        if let Some(key) = failed {
            return Err(refused(key));
        }
        args.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));
        let repeated = args.windows(2).find_map(|pair| match pair {
            [(a, _), (b, _)] if a == b => Some(a.clone()),
            _ => None,
        });
        match repeated {
            Some(key) => Err(refused(key)),
            None => Ok(Self(args)),
        }
    }

    /// The text of the argument `key`.
    fn get(&self, key: &str) -> Option<&str> {
        let at = self.0.binary_search_by(|(k, _)| k.as_str().cmp(key)).ok()?;
        self.0.get(at).map(|(_, text)| text.as_str())
    }
}

impl Context {
    /// A context without modules, which isolates placeholders by MF2's Default Bidi Strategy.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The context, isolating placeholders by `bidi`.
    #[must_use]
    pub fn bidi(self, bidi: Bidi) -> Self {
        Self { bidi, ..self }
    }

    /// The context with the resource `source` loaded whole: its `@locale`, which the first
    /// module sets and every later one repeats, its `@dir`, its `[formats.<format>]` sections,
    /// and its messages, each id its section's prefix, a dot and the entry's key. A message's
    /// functions take the options of sections loaded before it or in its own module.
    ///
    /// # Errors
    ///
    /// The [`LoadError`] of the first rule the module breaks: its syntax and MF2's, its
    /// locale, an id or a section the context holds, a format section its format refuses, a
    /// function the build lacks or whose options no module defines, or a call its function
    /// refuses.
    pub fn module(mut self, source: &str) -> Result<Self, LoadError> {
        let resource = resource::parse(source)?;
        match (&resource.locale, &self.locale) {
            (Some(locale), None) => self.locale = Some(locale.clone()),
            (Some(locale), Some(context)) if locale == context => {}
            (locale, context) => {
                return Err(LoadError::Locale {
                    locale: locale.clone(),
                    context: context.clone(),
                });
            }
        }
        for section in &resource.formats {
            self.formats.define(section, resource.direction)?;
        }
        let mut seen: FxHashSet<&str> = FxHashSet::default();
        let mut worded = Vec::with_capacity(resource.messages.len());
        for entry in &resource.messages {
            let id = entry.key.as_str();
            if self.find(id).is_some() || !seen.insert(id) {
                return Err(LoadError::Repeated { id: id.to_owned() });
            }
            let syntax = |rule| LoadError::Syntax {
                line: entry.line,
                rule,
            };
            let message = mf2::parse::parse(&entry.value).map_err(|error| {
                syntax(SyntaxRule::Message {
                    id: id.to_owned(),
                    at: error.0,
                })
            })?;
            mf2::valid::check(id, &message).map_err(syntax)?;
            worded.push(Worded {
                id: id.to_owned(),
                message: compile::compile(
                    id,
                    entry.line,
                    &message,
                    resource.direction,
                    &self.formats,
                )?,
            });
        }
        self.messages.append(&mut worded);
        self.messages.sort_unstable_by(|a, b| a.id.cmp(&b.id));
        Ok(self)
    }

    /// The first module's `@locale`; `None` before the first module.
    #[must_use]
    pub fn locale(&self) -> Option<&LocaleTag> {
        self.locale.as_ref()
    }

    /// The message's id worded by the context's modules, over the message's arguments: each
    /// argument's text is its value's `Display`, its key compared in NFC.
    ///
    /// # Errors
    ///
    /// [`ResolveError`] for an id no module words, an argument given twice or whose `Display`
    /// fails, an argument the wording reads and the message lacks, and a text a function
    /// refuses.
    pub fn resolve(&self, message: &dyn Message) -> Result<Text, ResolveError> {
        let id = message.id();
        let worded = self
            .find(id)
            .ok_or_else(|| ResolveError::Unknown { id: id.to_owned() })?;
        let args = Args::of(message, id)?;
        worded.message.resolve(id, &|key| args.get(key), self.bidi)
    }

    /// The wallet's completeness test: every error and statement the binary links has a
    /// wording that reads only its arguments. It reads the rows the derives register under
    /// `check` (siros-explain's for errors, this crate's for statements).
    ///
    /// # Errors
    ///
    /// The first of [`CheckError::Repeated`] for two rows of one id, [`CheckError::Unworded`]
    /// for a row no module words, and [`CheckError::Unknown`] for a wording that reads an
    /// argument its row lacks, each over the rows in the order of their ids.
    #[cfg(feature = "check")]
    pub fn check(&self) -> Result<(), CheckError> {
        let mut rows: Vec<(&'static str, &'static [&'static str])> = siros_explain::check::rows()
            .map(|row| (row.id, row.keys))
            .chain(crate::check::rows().map(|row| (row.id, row.keys)))
            .collect();
        rows.sort_unstable_by_key(|(id, _)| *id);
        let repeated = rows.windows(2).find_map(|pair| match pair {
            [(a, _), (b, _)] if a == b => Some(*a),
            _ => None,
        });
        if let Some(id) = repeated {
            return Err(CheckError::Repeated { id: id.to_owned() });
        }
        let mut worded = Vec::with_capacity(rows.len());
        for (id, keys) in &rows {
            let found = self.find(id).ok_or_else(|| CheckError::Unworded {
                id: (*id).to_owned(),
            })?;
            worded.push((id, keys, found));
        }
        for (id, keys, found) in worded {
            let reads = found.message.reads();
            if let Some(key) = reads.iter().find(|key| !keys.iter().any(|k| k == *key)) {
                return Err(CheckError::Unknown {
                    id: (*id).to_owned(),
                    key: (*key).to_owned(),
                });
            }
        }
        Ok(())
    }

    /// The message of `id`.
    fn find(&self, id: &str) -> Option<&Worded> {
        let at = self
            .messages
            .binary_search_by(|worded| worded.id.as_str().cmp(id))
            .ok()?;
        self.messages.get(at)
    }
}
