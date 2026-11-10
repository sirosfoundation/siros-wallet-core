//! A context: the modules of one locale, which resolve a message's id and arguments into text.

use rustc_hash::FxHashMap;

use crate::args::Args;
use crate::compile::{self, Compiled};
#[cfg(feature = "check")]
use crate::error::CheckError;
use crate::error::{LoadError, ResolveError};
use crate::format::Formats;
use crate::locale::LocaleTag;
use crate::message::Message;
use crate::mf2;
use crate::normal::Hold;
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
    messages: FxHashMap<Box<str>, Compiled>,
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
    pub fn module(self, source: &str) -> Result<Self, LoadError> {
        self.load(source, Hold::Normal)
    }

    /// The context with `source` loaded as [`Context::module`] loads it, when Unicode
    /// Normalization Form C changes none of its names, variant keys and selector literals. A
    /// build without `nfc` holds each as written, so it loads such a module into the same
    /// messages, which resolve to the same texts. The wallet loads through it the sources it
    /// hands to a matcher built without `nfc`.
    ///
    /// # Errors
    ///
    /// The [`LoadError`] of [`Context::module`], and [`LoadError::Unnormalized`] for the first
    /// message that holds a name, a variant key or a selector literal NFC changes: its first such
    /// name or key in source order, else its selector literal.
    #[cfg(feature = "nfc")]
    pub fn module_in_nfc(self, source: &str) -> Result<Self, LoadError> {
        self.load(source, Hold::Written)
    }

    /// The context with `source` loaded, its names, variant keys and selector literals held by
    /// `hold`.
    fn load(mut self, source: &str, hold: Hold) -> Result<Self, LoadError> {
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
        for section in &resource.sections {
            for entry in &section.entries {
                let id: Box<str> = match &section.name {
                    Some(name) => format!("{name}.{}", entry.key).into(),
                    None => entry.key.as_ref().into(),
                };
                if self.messages.contains_key(&id) {
                    return Err(LoadError::Repeated { id: id.into() });
                }
                let message = mf2::parse::parse(&entry.value, hold)
                    .and_then(|message| {
                        let valid = mf2::valid::Valid::of(&message)?;
                        compile::compile(&valid, resource.direction, &self.formats, hold)
                    })
                    .map_err(|fault| fault.at(&id, entry.line))?;
                self.messages.extend([(id, message)]);
            }
        }
        Ok(self)
    }

    /// The first module's `@locale`; `None` before the first module.
    #[must_use]
    pub fn locale(&self) -> Option<&LocaleTag> {
        self.locale.as_ref()
    }

    /// The message's id worded by the context's modules, over the message's arguments: each
    /// argument's text is its value's `Display`, its key compared in NFC with `nfc` and as given
    /// without it.
    ///
    /// # Errors
    ///
    /// [`ResolveError`] for an id no module words, an argument given twice or whose `Display`
    /// fails, an argument the wording reads and the message lacks, and a text a function
    /// refuses.
    pub fn resolve(&self, message: &dyn Message) -> Result<Text, ResolveError> {
        let id = message.id();
        let unknown = || ResolveError::Unknown { id: id.to_owned() };
        let worded = self.messages.get(id).ok_or_else(unknown)?;
        let args = Args::of(message).map_err(|key| ResolveError::Argument {
            id: id.to_owned(),
            key,
        })?;
        worded.resolve(id, &args, &self.formats, self.bidi)
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
            let found = self.messages.get(*id).ok_or_else(|| CheckError::Unworded {
                id: (*id).to_owned(),
            })?;
            worded.push((id, keys, found));
        }
        for (id, keys, found) in worded {
            if let Some(key) = found
                .reads()
                .into_iter()
                .find(|key| !keys.iter().any(|k| k == key))
            {
                return Err(CheckError::Unknown {
                    id: (*id).to_owned(),
                    key: key.to_owned(),
                });
            }
        }
        Ok(())
    }
}
