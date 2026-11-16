//! The context's rules: each load and resolution refusal names its fixture's rule, an argument
//! takes its type's formatters, MF2's Default Bidi Strategy isolates by the message's and the
//! value's direction, markup styles the spans, an
//! option takes its variable's value, a derived statement gives its named fields, an escaped text
//! resolves to itself, and a language tag takes RFC 5646's case.

#[path = "../support/cldr.rs"]
mod cldr;
mod escape;
mod formatters;
mod locale;
mod options;
mod refusals;
mod statements;
mod text;

use siros_i18n::{Arg, Message};

siros_i18n::scope!("fixture");

/// A message of any id and arguments, each argument's value its text.
pub struct Given {
    pub id: &'static str,
    pub args: Vec<(&'static str, String)>,
}

impl Given {
    /// The message `id` without arguments.
    pub fn bare(id: &'static str) -> Self {
        Self {
            id,
            args: Vec::new(),
        }
    }

    /// The message `id` with one argument.
    pub fn with(id: &'static str, key: &'static str, text: &str) -> Self {
        Self {
            id,
            args: vec![(key, text.to_owned())],
        }
    }
}

impl Message for Given {
    fn id(&self) -> &str {
        self.id
    }

    fn arg(&self, key: &str) -> Option<&dyn Arg> {
        self.args
            .iter()
            .find(|(given, _)| *given == key)
            .map(|(_, text)| text as &dyn Arg)
    }
}

/// A module of `body` in English, left to right.
pub fn english(body: &str) -> String {
    format!("@locale en\n@dir ltr\n---\n{body}\n")
}
