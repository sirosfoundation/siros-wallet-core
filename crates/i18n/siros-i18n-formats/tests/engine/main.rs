//! The formatter's rules: an argument takes its type's formats, an option takes its variable's
//! value, each format rule and call refusal names its fixture's rule, and a formatted value
//! isolates by its format module's direction.

#[path = "../support/cldr.rs"]
mod cldr;
mod formatters;
mod options;
mod refusals;
mod text;

use siros_i18n::{Arg, Message};

/// A message of any id and typed arguments.
pub struct Given {
    pub id: &'static str,
    pub args: Vec<(&'static str, Box<dyn Arg>)>,
}

impl Given {
    /// The message `id` without arguments.
    pub fn new(id: &'static str) -> Self {
        Self {
            id,
            args: Vec::new(),
        }
    }

    /// The message with the argument `key` of `value` too.
    pub fn with(mut self, key: &'static str, value: impl Arg) -> Self {
        self.args.push((key, Box::new(value)));
        self
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
            .map(|(_, value)| value.as_ref())
    }
}

/// A module of `body` in English, left to right.
pub fn english(body: &str) -> String {
    format!("@locale en\n@dir ltr\n---\n{body}\n")
}
