//! Calls and the chains they form. A message holds each call once: a declared call under its
//! variable, a placeholder's with the placeholder. A call's operand names a declared call by its
//! variable, so a [`Chain`], a call with the calls its operand's value applies and what the
//! innermost starts from, is followed through the declarations, by the load to check it and by
//! a resolution to read it.
//!
//! One rule gives a variable its meaning, as an operand and as an option's value: the call
//! declared under its name, else the argument of that key.

use std::borrow::Cow;

use rustc_hash::{FxBuildHasher, FxHashMap};

use crate::error::{Fault, Refusal, ResolveError};
use crate::format::{Function, STRING};
use crate::scope::Scope;

/// What a call applies to.
#[derive(Debug, Clone)]
pub(crate) enum Operand {
    /// No operand: `{:function}`.
    None,
    /// A literal's string value.
    Literal(Box<str>),
    /// The argument of this key, which an `.input` declaration's call applies to.
    Argument(Box<str>),
    /// A variable: the value of the call declared under this name, else the argument of this
    /// key.
    Variable(Box<str>),
}

/// A call on its operand.
#[derive(Debug, Clone)]
pub(crate) struct Link {
    pub(crate) operand: Operand,
    pub(crate) call: Call,
}

/// What a placeholder formats: a call, or a literal or a variable without one, which formats
/// as its declared call does, else with `:string`.
#[derive(Debug, Clone)]
pub(crate) enum Site {
    Call(Link),
    Literal(Box<str>),
    Variable(Box<str>),
}

/// The call of a placeholder without a function.
static STRING_CALL: Call = Call::new(Function::String, Cow::Borrowed(STRING), Vec::new());

/// A message's declared calls, each under its variable. A call's operand names no call declared
/// after it.
#[derive(Debug, Clone)]
pub(crate) struct Declared(FxHashMap<Box<str>, Link>);

impl Declared {
    /// No call, with room for `calls`.
    pub(crate) fn with_capacity(calls: usize) -> Self {
        Self(FxHashMap::with_capacity_and_hasher(calls, FxBuildHasher))
    }

    /// Declares `link` under `name`.
    pub(crate) fn declare(&mut self, name: &str, link: Link) {
        self.0.extend([(name.into(), link)]);
    }

    /// The call declared under `name`.
    pub(crate) fn call(&self, name: &str) -> Option<&Link> {
        self.0.get(name)
    }

    /// The chain of `link`: its call, and the calls of its operand's value through the
    /// declarations.
    pub(crate) fn chain<'m>(&'m self, link: &'m Link) -> Chain<'m> {
        let mut inner = Vec::new();
        let mut operand = &link.operand;
        let root = loop {
            match operand {
                Operand::None => break Root::None,
                Operand::Literal(text) => break Root::Literal(text),
                Operand::Argument(key) => break Root::Argument(key),
                Operand::Variable(name) => match self.call(name) {
                    Some(declared) => {
                        inner.push(&declared.call);
                        operand = &declared.operand;
                    }
                    None => break Root::Argument(name),
                },
            }
        };
        Chain {
            root,
            inner,
            outer: Cow::Borrowed(&link.call),
            unwritten: false,
        }
    }

    /// The chain of the variable `name`: its declared call's, else the argument's, whose call
    /// the wording leaves unwritten: `:string` at the load, the argument type's default
    /// formatter at resolution.
    pub(crate) fn variable<'m>(&'m self, name: &'m str) -> Chain<'m> {
        match self.call(name) {
            Some(link) => self.chain(link),
            None => Chain {
                root: Root::Argument(name),
                inner: Vec::new(),
                outer: Cow::Borrowed(&STRING_CALL),
                unwritten: true,
            },
        }
    }

    /// The chain a placeholder formats.
    pub(crate) fn site<'m>(&'m self, site: &'m Site) -> Chain<'m> {
        match site {
            Site::Call(link) => self.chain(link),
            Site::Variable(name) => self.variable(name),
            Site::Literal(text) => Chain {
                root: Root::Literal(text),
                inner: Vec::new(),
                outer: Cow::Borrowed(&STRING_CALL),
                unwritten: false,
            },
        }
    }
}

/// What a chain of calls starts from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Root<'m> {
    /// No operand: `{:function}`.
    None,
    /// A literal's string value, boxed as the message holds it: a formatter takes it as a
    /// `&dyn Arg`, which `str` cannot be.
    #[expect(clippy::borrowed_box, reason = "a &Box<str> coerces to &dyn Arg; a &str does not")]
    Literal(&'m Box<str>),
    /// The argument of this key.
    Argument(&'m str),
}

/// An option's value (spec/formatting.md, "Option Resolution").
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Value {
    /// The literal written as the value.
    Literal(Box<str>),
    /// The literal a declaration binds to the variable written as the value.
    Bound(Box<str>),
    /// A variable no declaration binds to a literal: at resolution, the value of the declared
    /// call of this name, else the argument of this key.
    Variable(Box<str>),
}

impl Value {
    /// Its text when the load fixes it: a literal's, written or bound.
    pub(crate) fn fixed(&self) -> Option<&str> {
        match self {
            Self::Literal(text) | Self::Bound(text) => Some(text),
            Self::Variable(_) => None,
        }
    }
}

/// An option of a call.
#[derive(Debug, Clone)]
pub(crate) struct Opt {
    pub(crate) name: Box<str>,
    pub(crate) value: Value,
}

/// A call: its function, the function's name as the wording writes it, and its options, each
/// name once, in the order written.
#[derive(Debug, Clone)]
pub(crate) struct Call {
    pub(crate) function: Function,
    pub(crate) name: Cow<'static, str>,
    options: Vec<Opt>,
}

impl Call {
    /// The call of `function`, named `name`, with `options`.
    pub(crate) const fn new(function: Function, name: Cow<'static, str>, options: Vec<Opt>) -> Self {
        Self {
            function,
            name,
            options,
        }
    }

    /// Checks each option with `check`: its name, and its literal's text, `None` where a
    /// variable gives it.
    ///
    /// # Errors
    ///
    /// The first refusal `check` gives.
    pub(crate) fn check_options(
        &self,
        mut check: impl FnMut(&str, Option<&str>) -> Result<(), Refusal>,
    ) -> Result<(), Refusal> {
        self.options
            .iter()
            .try_for_each(|option| check(&option.name, option.value.fixed()))
    }
}

/// A call's chain: what it starts from, the calls its operand's value applies, outermost
/// first, and the call itself, whose function formats, selects or gives the value.
#[derive(Debug)]
pub(crate) struct Chain<'m> {
    pub(crate) root: Root<'m>,
    inner: Vec<&'m Call>,
    pub(crate) outer: Cow<'m, Call>,
    /// An argument's chain whose call the wording does not write.
    unwritten: bool,
}

impl<'m> Chain<'m> {
    /// The argument the chain starts from and whether the wording writes no call on it.
    pub(crate) fn argument(&self) -> Option<(&'m str, bool)> {
        match self.root {
            Root::Argument(key) => Some((key, self.unwritten)),
            Root::None | Root::Literal(_) => None,
        }
    }

    /// The chain with `call` for the call the wording leaves unwritten.
    pub(crate) fn written(self, call: Call) -> Self {
        Self {
            outer: Cow::Owned(call),
            unwritten: false,
            ..self
        }
    }

    /// The calls, innermost first.
    pub(crate) fn calls(&self) -> impl DoubleEndedIterator<Item = &Call> {
        self.inner.iter().rev().copied().chain([&*self.outer])
    }

    /// The options of the outermost call's function along the chain, each name with its text:
    /// a literal as written, a variable's value from `scope` (spec/formatting.md, "Option
    /// Resolution"); an outer call's option over an inner one's.
    ///
    /// # Errors
    ///
    /// [`Failure::Unresolved`] for an argument the message does not give, and
    /// [`Failure::Option`] for a variable whose value fails.
    pub(crate) fn options<'s>(&'s self, scope: &'s Scope<'m>) -> Result<Vec<(&'s str, &'s str)>, Failure> {
        let mut options: Vec<(&str, &str)> = Vec::new();
        for call in self.calls().filter(|call| call.function == self.outer.function) {
            for option in &call.options {
                let text = scope
                    .text(&option.value)
                    .map_err(|failure| failure.under(&option.name))?;
                match options.iter_mut().find(|(name, _)| **name == *option.name) {
                    Some(held) => held.1 = text,
                    None => options.push((&option.name, text)),
                }
            }
        }
        Ok(options)
    }

    /// The resolution error of `failure` in the message `id`, under the outermost call's
    /// function.
    pub(crate) fn error(&self, id: &str, failure: Failure) -> ResolveError {
        let id = id.to_owned();
        let function = self.outer.name.to_string();
        match failure {
            Failure::Operand => ResolveError::Operand { id, function },
            Failure::Option(option) => ResolveError::Option {
                id,
                function,
                option,
            },
            Failure::Unresolved(key) => ResolveError::Unresolved { id, key },
            Failure::Unformatted(key, function) => ResolveError::Unformatted { id, key, function },
            Failure::Selector(function, refusal) => ResolveError::Selector {
                id,
                function,
                refusal,
            },
        }
    }
}

/// Why a call does not format, select or give a value at resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Failure {
    /// The function refuses the operand's text.
    Operand,
    /// The argument of this key takes no function of this name.
    Unformatted(String, String),
    /// The argument type's default function, of this name, refuses the use as a selector or a
    /// variant key.
    Selector(String, Refusal),
    /// The function refuses an option's text, which a variable gives.
    Option(String),
    /// The argument of this key, which the message does not give: the operand's or an
    /// option's.
    Unresolved(String),
}

impl Failure {
    /// The failure of the option `name` whose variable's value failed so: an argument the value
    /// reads stays unresolved, and any other failure refuses the option.
    fn under(self, name: &str) -> Self {
        match self {
            Self::Unresolved(key) => Self::Unresolved(key),
            Self::Operand | Self::Option(_) | Self::Unformatted(..) | Self::Selector(..) => {
                Self::Option(name.to_owned())
            }
        }
    }
}

/// The fault of `refusal` of a chain whose outermost call is `call`.
pub(crate) fn fault(call: &Call, refusal: Refusal) -> Fault {
    Fault::Call(call.name.to_string(), refusal)
}
