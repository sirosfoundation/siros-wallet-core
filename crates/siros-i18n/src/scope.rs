//! What one resolution of a message reads beside the message.

use std::borrow::Cow;

use rustc_hash::FxHashMap;

use crate::args::Args;
use crate::chain::{Declared, Failure, Value};
use crate::format::Formats;

/// What one resolution of a message reads beside the message: the arguments' texts, the
/// context's format sections, the declared calls, and the value of each variable an option
/// reads.
pub(crate) struct Scope<'m> {
    args: &'m Args<'m>,
    #[cfg_attr(
        not(any(
            feature = "number",
            feature = "currency",
            feature = "offset",
            feature = "date"
        )),
        expect(dead_code, reason = "only the format functions read a section")
    )]
    pub(crate) formats: &'m Formats,
    pub(crate) declared: &'m Declared,
    values: FxHashMap<&'m str, Result<Cow<'m, str>, Failure>>,
}

impl<'m> Scope<'m> {
    /// The resolution over `args` of a message whose declared calls are `declared`, in a
    /// context whose format sections are `formats`.
    pub(crate) fn new(args: &'m Args<'m>, formats: &'m Formats, declared: &'m Declared) -> Self {
        Self {
            args,
            formats,
            declared,
            values: FxHashMap::default(),
        }
    }

    /// Holds the value of the variable `name`, over the values held before it.
    pub(crate) fn hold(&mut self, name: &'m str) {
        let value = crate::format::value(&self.declared.variable(name), self);
        self.values.extend([(name, value)]);
    }

    /// The text of the argument `key`.
    ///
    /// # Errors
    ///
    /// [`Failure::Unresolved`] for an argument the message does not give.
    pub(crate) fn argument(&self, key: &str) -> Result<&'m str, Failure> {
        self.args
            .get(key)
            .ok_or_else(|| Failure::Unresolved(key.to_owned()))
    }

    /// The text of an option's value: a literal as written, a held value, an argument's text.
    ///
    /// # Errors
    ///
    /// The held value's [`Failure`], and [`Failure::Unresolved`] for an argument the message
    /// does not give.
    pub(crate) fn text<'s>(&'s self, given: &'m Value) -> Result<&'s str, Failure> {
        let name = match given {
            Value::Literal(text) | Value::Bound(text) => return Ok(text),
            Value::Variable(name) => &**name,
        };
        match self.values.get(name) {
            Some(value) => value.as_deref().map_err(Failure::clone),
            None => self.argument(name),
        }
    }
}
