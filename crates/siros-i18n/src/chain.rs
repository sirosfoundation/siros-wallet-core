//! Calls and the chains they form. A message holds each call once: a declared call under its
//! variable, a placeholder's with the placeholder. A call's operand names a declared call by its
//! variable, so a [`Chain`], a call with the calls its operand's value applies and what the
//! innermost starts from, is followed through the declarations, by the load to check it and by
//! a resolution to read it.
//!
//! One rule gives a variable its meaning, as an operand and as an option's value: the call
//! declared under its name, else the argument of that key.

use rustc_hash::{FxBuildHasher, FxHashMap};

use crate::error::{Fault, Refusal, ResolveError};
use crate::format::Function;
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
static STRING: Call = Call::new(Function::String, Vec::new());

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
            outer: &link.call,
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
                outer: &STRING,
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
                outer: &STRING,
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
    /// A literal's string value.
    Literal(&'m str),
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
    #[cfg(any(feature = "number", feature = "currency", feature = "date"))]
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

/// A call: its function and its options, each name once, in the order written.
#[derive(Debug, Clone)]
pub(crate) struct Call {
    pub(crate) function: Function,
    options: Vec<Opt>,
}

impl Call {
    /// The call of `function` with `options`.
    pub(crate) const fn new(function: Function, options: Vec<Opt>) -> Self {
        Self { function, options }
    }

    /// Its options, in the order written: each name and its value.
    #[cfg(any(feature = "number", feature = "currency", feature = "date"))]
    pub(crate) fn options(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.options
            .iter()
            .map(|option| (&*option.name, &option.value))
    }

    /// The value of its option `name`.
    #[cfg(any(feature = "number", feature = "currency", feature = "date"))]
    pub(crate) fn option(&self, name: &str) -> Option<&Value> {
        self.options()
            .find(|(given, _)| *given == name)
            .map(|(_, value)| value)
    }
}

/// A call's chain: what it starts from, the calls its operand's value applies, outermost
/// first, and the call itself, whose function formats, selects or gives the value.
#[derive(Debug)]
pub(crate) struct Chain<'m> {
    pub(crate) root: Root<'m>,
    inner: Vec<&'m Call>,
    pub(crate) outer: &'m Call,
    /// An argument's chain whose call the wording does not write.
    unwritten: bool,
}

/// A call's resolved options: its function, and each option with its text, in the order written.
#[derive(Debug)]
pub(crate) struct CallTexts<'s> {
    #[cfg_attr(
        not(any(feature = "number", feature = "currency")),
        expect(
            dead_code,
            reason = "only the numeric functions read a call's function"
        )
    )]
    pub(crate) function: Function,
    #[cfg_attr(
        not(any(feature = "number", feature = "currency", feature = "date")),
        expect(dead_code, reason = "`:string` reads no option")
    )]
    pub(crate) options: Vec<(&'s str, &'s str)>,
}

impl<'s> CallTexts<'s> {
    /// The text of the option `name`.
    #[cfg(feature = "date")]
    pub(crate) fn option(&self, name: &str) -> Option<&'s str> {
        self.options
            .iter()
            .find(|(given, _)| *given == name)
            .map(|(_, text)| *text)
    }
}

/// A chain's resolved options: those of the calls its operand's value applies, innermost first,
/// and its own call's.
#[derive(Debug)]
#[cfg_attr(
    not(any(feature = "number", feature = "currency", feature = "date")),
    expect(dead_code, reason = "`:string` reads no option")
)]
pub(crate) struct Texts<'s> {
    inner: Vec<CallTexts<'s>>,
    outer: CallTexts<'s>,
}

impl<'s> Texts<'s> {
    /// The calls' options, innermost first.
    #[cfg(feature = "date")]
    pub(crate) fn calls(&self) -> impl DoubleEndedIterator<Item = &CallTexts<'s>> {
        self.inner.iter().chain([&self.outer])
    }

    /// The innermost call's options, and those of the calls after it, in order.
    #[cfg(any(feature = "number", feature = "currency"))]
    pub(crate) fn innermost(&self) -> (&CallTexts<'s>, impl Iterator<Item = &CallTexts<'s>>) {
        match self.inner.split_first() {
            Some((first, rest)) => (first, rest.iter().chain(Some(&self.outer))),
            None => (&self.outer, [].iter().chain(None)),
        }
    }
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
    pub(crate) fn written(self, call: &'m Call) -> Self {
        Self {
            outer: call,
            unwritten: false,
            ..self
        }
    }

    /// The calls, innermost first.
    pub(crate) fn calls(&self) -> impl DoubleEndedIterator<Item = &'m Call> {
        self.inner.iter().rev().copied().chain([self.outer])
    }

    /// The function of the innermost call, whose operand is the root.
    pub(crate) fn innermost(&self) -> Function {
        self.inner.last().map_or(self.outer, |call| call).function
    }

    /// The calls' resolved options, each option's text by `text`.
    fn texts_by<'s, E>(
        &self,
        mut text: impl FnMut(&'m Opt) -> Result<&'s str, E>,
    ) -> Result<Texts<'s>, E>
    where
        'm: 's,
    {
        let mut resolved = |call: &'m Call| {
            let options = call
                .options
                .iter()
                .map(|option| Ok((&*option.name, text(option)?)))
                .collect::<Result<_, E>>()?;
            Ok(CallTexts {
                function: call.function,
                options,
            })
        };
        Ok(Texts {
            inner: self
                .inner
                .iter()
                .rev()
                .map(|call| resolved(call))
                .collect::<Result<_, E>>()?,
            outer: resolved(self.outer)?,
        })
    }

    /// The calls' resolved options: a literal as written, a variable's value from `scope`
    /// (spec/formatting.md, "Option Resolution").
    ///
    /// # Errors
    ///
    /// [`Failure::Unresolved`] for an argument the message does not give, and
    /// [`Failure::Option`] for a variable whose value fails.
    pub(crate) fn texts<'s>(&self, scope: &'s Scope<'m>) -> Result<Texts<'s>, Failure> {
        self.texts_by(|option| {
            scope
                .text(&option.value)
                .map_err(|failure| failure.under(&option.name))
        })
    }

    /// The calls' resolved options when the load fixes every option's text; `None` when a
    /// variable gives one.
    #[cfg(any(feature = "number", feature = "currency"))]
    pub(crate) fn fixed_texts(&self) -> Option<Texts<'m>> {
        self.texts_by(|option| option.value.fixed().ok_or(())).ok()
    }

    /// The resolution error of `failure` in the message `id`: an operand's names the innermost
    /// function, an option's the outermost.
    pub(crate) fn error(&self, id: &str, failure: Failure) -> ResolveError {
        let id = id.to_owned();
        match failure {
            Failure::Operand => ResolveError::Operand {
                id,
                function: self.innermost().name().to_owned(),
            },
            Failure::Option(option) => ResolveError::Option {
                id,
                function: self.outer.function.name().to_owned(),
                option,
            },
            Failure::Unresolved(key) => ResolveError::Unresolved { id, key },
            Failure::Unformatted(key, function) => ResolveError::Unformatted {
                id,
                key,
                function: function.name().to_owned(),
            },
            Failure::Selector(function, refusal) => ResolveError::Selector {
                id,
                function: function.name().to_owned(),
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
    /// The argument of this key takes no formatter of the function's name.
    Unformatted(String, Function),
    /// The argument type's default formatter refuses the use as a selector or a variant key.
    Selector(Function, Refusal),
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

/// Why the load refuses a call chain.
#[derive(Debug)]
pub(crate) enum Refused {
    /// The outermost function's options are defined by no module loaded so far.
    #[cfg(any(feature = "number", feature = "currency", feature = "date"))]
    Undefined,
    /// The function refuses the call.
    Call(Refusal),
}

impl From<Refusal> for Refused {
    fn from(refusal: Refusal) -> Self {
        Self::Call(refusal)
    }
}

impl Refused {
    /// The failure at resolution of the refusal of `function`, the default formatter of a
    /// selector's argument type.
    pub(crate) fn failure(self, function: Function) -> Failure {
        match self {
            #[cfg(any(feature = "number", feature = "currency", feature = "date"))]
            Self::Undefined => Failure::Operand,
            Self::Call(refusal) => Failure::Selector(function, refusal),
        }
    }

    /// The fault of the refusal of a chain whose outermost function is `function`.
    pub(crate) fn fault(self, function: Function) -> Fault {
        match self {
            #[cfg(any(feature = "number", feature = "currency", feature = "date"))]
            Self::Undefined => Fault::Undefined(function.name()),
            Self::Call(refusal) => Fault::Call(function.name(), refusal),
        }
    }
}
