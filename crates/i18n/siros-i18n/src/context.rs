//! A context: the modules of one locale, which resolve a message's id and arguments into text.

use crate::args::Args;
use crate::compile;
#[cfg(feature = "check")]
use crate::error::CheckError;
use crate::error::{LoadError, ResolveError};
use crate::format::Formatters;
use crate::formatter::{Formatter, Setting};
use crate::locale::LocaleTag;
use crate::message::Message;
use crate::messages::{Messages, Prefix};
use crate::mf2;
use crate::resource::{self, Section};
use crate::text::Text;

/// How a context isolates a placeholder's text from the text around it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Bidi {
    /// MF2's Default Bidi Strategy (spec/formatting.md "Handling Bidirectional Text"): a
    /// placeholder stands between U+2066, U+2067 or U+2068 and U+2069 by its value's direction.
    /// A left-to-right value in a left-to-right message stands alone.
    #[default]
    Default,
    /// Each placeholder's text as formatted.
    None,
}

/// The formatters and the bidi strategy of a [`Context`] to build.
#[derive(Debug, Default)]
pub struct Builder {
    bidi: Bidi,
    formatters: Formatters,
}

impl Builder {
    /// The builder, its context isolating placeholders by `bidi`.
    #[must_use]
    pub fn bidi(self, bidi: Bidi) -> Self {
        Self { bidi, ..self }
    }

    /// The builder with `formatter` after the formatters given before: a function name or a
    /// type's default an earlier formatter defines stays the earlier one's.
    #[must_use]
    pub fn formatter(mut self, formatter: impl Formatter) -> Self {
        self.formatters.push(Box::new(formatter));
        self
    }

    /// The context, without modules.
    #[must_use]
    pub fn build(self) -> Context {
        Context {
            locale: None,
            bidi: self.bidi,
            formatters: self.formatters,
            messages: Messages::default(),
        }
    }
}

/// The modules of one locale, each a W3C message resource of MF2 messages and of the settings
/// of its formatters, which define the functions beyond `:string` and the one each argument type
/// takes by default. [`Context::resolve`] resolves a [`Message`]'s id and arguments into a
/// [`Text`].
#[derive(Debug, Default)]
pub struct Context {
    locale: Option<LocaleTag>,
    bidi: Bidi,
    formatters: Formatters,
    messages: Messages,
}

impl Context {
    /// A context without modules or formatters, which isolates placeholders by MF2's Default
    /// Bidi Strategy: every argument takes `:string`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The builder of a context with formatters or another bidi strategy.
    #[must_use]
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// The context with the resource `source` loaded whole: its `@locale`, which the first
    /// module sets and every later one repeats, its `@dir`, the sections its formatters read,
    /// and its messages, each id its section's prefix, a dot and the entry's key. A section a
    /// formatter reads gives it its settings before the module's messages compile, so a message
    /// calls the functions of the sections loaded before it or in its own module.
    ///
    /// # Errors
    ///
    /// The [`LoadError`] of the first rule the module breaks: its syntax and MF2's, its
    /// locale, an id the context holds, a section its formatter refuses, a function no
    /// formatter defines, or a call its function refuses.
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
        let mut messages: Vec<&Section<'_>> = Vec::with_capacity(resource.sections.len());
        for section in &resource.sections {
            let Some(name) = section.name.as_deref() else {
                messages.push(section);
                continue;
            };
            let settings: Vec<Setting<'_>> = section
                .entries
                .iter()
                .map(|entry| Setting {
                    key: &entry.key,
                    text: &entry.value,
                })
                .collect();
            let read = self
                .formatters
                .load(name, &settings, resource.direction)
                .map_err(|rule| LoadError::Format {
                    section: name.to_owned(),
                    rule,
                })?;
            if !read {
                messages.push(section);
            }
        }
        for section in messages {
            let (prefix, name) = match &section.name {
                Some(name) => (self.messages.section(name), Some(name)),
                None => (Prefix::NONE, None),
            };
            for entry in &section.entries {
                let id = || match name {
                    Some(name) => format!("{name}.{}", entry.key),
                    None => entry.key.to_string(),
                };
                let slot = self.messages.slot(prefix, &entry.key);
                if slot.is_some() {
                    return Err(LoadError::Repeated { id: id() });
                }
                let message = mf2::parse::parse(&entry.value)
                    .and_then(|message| {
                        let valid = mf2::valid::Valid::of(&message)?;
                        compile::compile(&valid, resource.direction, &self.formatters)
                    })
                    .map_err(|fault| fault.at(&id(), entry.line))?;
                *slot = Some(Box::new(message));
            }
        }
        Ok(self)
    }

    /// The first module's `@locale`; `None` before the first module.
    #[must_use]
    pub fn locale(&self) -> Option<&LocaleTag> {
        self.locale.as_ref()
    }

    /// The message's id worded by the context's modules, over the arguments the wording names,
    /// each asked for by its key as the wording spells it. A call formats its argument by the
    /// function it names; a placeholder, a declaration or a selector that names none, by the
    /// default function of the argument's type, `:string` where no formatter gives one.
    ///
    /// # Errors
    ///
    /// [`ResolveError`] for an id no module words, an argument whose `Display` fails, an
    /// argument the wording reads and the message lacks, a function that takes no value of the
    /// argument's type, a selector or a key its type's default refuses, and a value or an option
    /// text a function refuses.
    pub fn resolve(&self, message: &dyn Message) -> Result<Text, ResolveError> {
        let id = message.id();
        let unknown = || ResolveError::Unknown { id: id.to_owned() };
        let worded = self.messages.find(id).ok_or_else(unknown)?;
        let args = Args::of(message, worded.arguments()).map_err(|key| ResolveError::Argument {
            id: id.to_owned(),
            key: key.to_owned(),
        })?;
        worded.resolve(id, &args, &self.formatters, self.bidi)
    }

    /// The wallet's completeness test: every error and statement the binary links has a wording
    /// that names only its arguments, in its `.input` declarations and in each variable no
    /// declaration binds. It reads the rows the derives register under `check` (siros-explain's
    /// for errors, this crate's for statements).
    ///
    /// # Errors
    ///
    /// The first of [`CheckError::Repeated`] for two rows of one id, [`CheckError::Unworded`]
    /// for a row no module words, and [`CheckError::Unknown`] for a wording that names an
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
            let found = self.messages.find(id).ok_or_else(|| CheckError::Unworded {
                id: (*id).to_owned(),
            })?;
            worded.push((id, keys, found));
        }
        for (id, keys, found) in worded {
            if let Some(key) = found.arguments().find(|key| !keys.iter().any(|k| k == key)) {
                return Err(CheckError::Unknown {
                    id: (*id).to_owned(),
                    key: key.to_owned(),
                });
            }
        }
        Ok(())
    }
}
