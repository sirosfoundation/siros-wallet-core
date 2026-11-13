//! What one resolution of a message reads beside the message.

use std::borrow::Cow;

use rustc_hash::FxHashMap;

use crate::args::Args;
use crate::chain::{Chain, Declared, Failure, Value};
use crate::format::Formats;
use crate::registry::Registry;

/// What one resolution of a message reads beside the message: the arguments' texts and types,
/// the context's format sections and formatters, the declared calls, and the value of each
/// variable an option reads.
pub(crate) struct Scope<'m> {
    args: &'m Args<'m>,
    registry: &'m Registry,
    pub(crate) formats: &'m Formats,
    pub(crate) declared: &'m Declared,
    values: FxHashMap<&'m str, Result<Cow<'m, str>, Failure>>,
}

impl<'m> Scope<'m> {
    /// The resolution over `args` of a message whose declared calls are `declared`, in a
    /// context whose format sections are `formats` and whose formatters are `registry`.
    pub(crate) fn new(
        args: &'m Args<'m>,
        formats: &'m Formats,
        registry: &'m Registry,
        declared: &'m Declared,
    ) -> Self {
        Self {
            args,
            registry,
            formats,
            declared,
            values: FxHashMap::default(),
        }
    }

    /// Holds the value of the variable `name`, over the values held before it.
    pub(crate) fn hold(&mut self, name: &'m str) {
        let value = self
            .typed(self.declared.variable(name))
            .and_then(|chain| crate::format::value(&chain, self));
        self.values.extend([(name, value)]);
    }

    /// The chain over its argument's type: a call the wording leaves unwritten is the type's
    /// default formatter's, and the type takes every call's function.
    ///
    /// # Errors
    ///
    /// [`Failure::Unresolved`] for an argument the message does not give, and
    /// [`Failure::Unformatted`] for a call of a function the type takes no formatter of.
    pub(crate) fn typed(&self, chain: Chain<'m>) -> Result<Chain<'m>, Failure> {
        let Some((key, unwritten)) = chain.argument() else {
            return Ok(chain);
        };
        let of = self
            .args
            .type_of(key)
            .ok_or_else(|| Failure::Unresolved(key.to_owned()))?;
        let chain = if unwritten {
            chain.written(self.registry.default(of).bare())
        } else {
            chain
        };
        let refused = chain
            .calls()
            .map(|call| call.function)
            .find(|function| !self.registry.takes(of, *function));
        match refused {
            Some(function) => Err(Failure::Unformatted(key.to_owned(), function)),
            None => Ok(chain),
        }
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
