//! What one resolution of a message reads beside the message.

use rustc_hash::FxHashMap;
use siros_explain::Arg;

use crate::args::Args;
use crate::chain::{Chain, Declared, Failure, Value};
use crate::format::{Formatters, bare};

/// What one resolution of a message reads beside the message: the arguments, the context's
/// formatters, the declared calls, and the value of each variable an option reads.
pub(crate) struct Scope<'m> {
    args: &'m Args<'m>,
    pub(crate) formatters: &'m Formatters,
    pub(crate) declared: &'m Declared,
    values: FxHashMap<&'m str, Result<&'m str, Failure>>,
}

impl<'m> Scope<'m> {
    /// The resolution over `args` of a message whose declared calls are `declared`, in a
    /// context whose formatters are `formatters`.
    pub(crate) fn new(
        args: &'m Args<'m>,
        formatters: &'m Formatters,
        declared: &'m Declared,
    ) -> Self {
        Self {
            args,
            formatters,
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
    /// default function's, and the type takes the function of the outermost call, which
    /// formats the argument.
    ///
    /// # Errors
    ///
    /// [`Failure::Unresolved`] for an argument the message does not give, and
    /// [`Failure::Unformatted`] for a function the argument's type does not take.
    pub(crate) fn typed(&self, chain: Chain<'m>) -> Result<Chain<'m>, Failure> {
        let Some((key, unwritten)) = chain.argument() else {
            return Ok(chain);
        };
        let of = self
            .args
            .type_of(key)
            .ok_or_else(|| Failure::Unresolved(key.to_owned()))?;
        let chain = if unwritten {
            let function = self.formatters.default(of);
            chain.written(bare(function, self.formatters.name(function)))
        } else {
            chain
        };
        if self.formatters.takes(chain.outer.function, of) {
            Ok(chain)
        } else {
            Err(Failure::Unformatted(
                key.to_owned(),
                chain.outer.name.to_string(),
            ))
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

    /// The value of the argument `key`.
    ///
    /// # Errors
    ///
    /// [`Failure::Unresolved`] for an argument the message does not give.
    pub(crate) fn arg(&self, key: &str) -> Result<&'m dyn Arg, Failure> {
        self.args
            .value(key)
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
            Some(value) => value.clone(),
            None => self.argument(name),
        }
    }
}
