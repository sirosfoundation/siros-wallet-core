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
use crate::normal::Unnormalized;
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
        }
    }

    /// The chain of the variable `name`: its declared call's, else `:string` on the argument.
    pub(crate) fn variable<'m>(&'m self, name: &'m str) -> Chain<'m> {
        match self.call(name) {
            Some(link) => self.chain(link),
            None => Chain {
                root: Root::Argument(name),
                inner: Vec::new(),
                outer: &STRING,
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
    #[cfg(any(
        feature = "number",
        feature = "currency",
        feature = "offset",
        feature = "date",
        feature = "conformance"
    ))]
    pub(crate) fn fixed(&self) -> Option<&str> {
        match self {
            Self::Literal(text) | Self::Bound(text) => Some(text),
            Self::Variable(_) => None,
        }
    }
}

/// An option's name: `u:dir` and `u:id` (spec/u-namespace.md), which every function takes, or a
/// function's own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Name {
    Dir,
    Id,
    Of(Box<str>),
}

impl Name {
    /// The name as written.
    fn as_str(&self) -> &str {
        match self {
            Self::Dir => "u:dir",
            Self::Id => "u:id",
            Self::Of(name) => name,
        }
    }
}

/// An option of a call.
#[derive(Debug, Clone)]
pub(crate) struct Opt {
    pub(crate) name: Name,
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

    /// The function's own options, in the order written: each name and its value.
    #[cfg(any(
        feature = "number",
        feature = "currency",
        feature = "offset",
        feature = "date",
        feature = "conformance"
    ))]
    pub(crate) fn options(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.options.iter().filter_map(|option| match &option.name {
            Name::Of(name) => Some((&**name, &option.value)),
            Name::Dir | Name::Id => None,
        })
    }

    /// The value of the function's own option `name`.
    #[cfg(any(
        feature = "number",
        feature = "currency",
        feature = "offset",
        feature = "date"
    ))]
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
}

/// An expression's `u:dir` (spec/u-namespace.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Dir {
    Ltr,
    Rtl,
    Auto,
    Inherit,
}

impl Dir {
    /// The direction a `u:dir` value names; `None` for a value other than `ltr`, `rtl`, `auto`
    /// and `inherit`.
    pub(crate) fn named(value: &str) -> Option<Self> {
        match value {
            "ltr" => Some(Self::Ltr),
            "rtl" => Some(Self::Rtl),
            "auto" => Some(Self::Auto),
            "inherit" => Some(Self::Inherit),
            _ => None,
        }
    }
}

/// A call's resolved options: its function, its `u:dir`, and each option of the function's own
/// with its text, in the order written. `u:id` names a part of a formatted result a text lacks.
#[derive(Debug)]
pub(crate) struct CallTexts<'s> {
    #[cfg_attr(
        not(any(feature = "number", feature = "currency", feature = "offset")),
        expect(
            dead_code,
            reason = "only the numeric functions read a call's function"
        )
    )]
    pub(crate) function: Function,
    dir: Option<Dir>,
    #[cfg_attr(
        not(any(
            feature = "number",
            feature = "currency",
            feature = "offset",
            feature = "date",
            feature = "conformance"
        )),
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
pub(crate) struct Texts<'s> {
    inner: Vec<CallTexts<'s>>,
    outer: CallTexts<'s>,
}

impl<'s> Texts<'s> {
    /// The calls' options, innermost first.
    #[cfg(any(feature = "date", feature = "conformance"))]
    pub(crate) fn calls(&self) -> impl DoubleEndedIterator<Item = &CallTexts<'s>> {
        self.inner.iter().chain([&self.outer])
    }

    /// The innermost call's options, and those of the calls after it, in order.
    #[cfg(any(feature = "number", feature = "currency", feature = "offset"))]
    pub(crate) fn innermost(&self) -> (&CallTexts<'s>, impl Iterator<Item = &CallTexts<'s>>) {
        match self.inner.split_first() {
            Some((first, rest)) => (first, rest.iter().chain(Some(&self.outer))),
            None => (&self.outer, [].iter().chain(None)),
        }
    }

    /// The expression's `u:dir`: the outermost call's that gives one, else `inherit`. A value
    /// keeps its operand's `u:dir`.
    pub(crate) fn dir(&self) -> Dir {
        [&self.outer]
            .into_iter()
            .chain(self.inner.iter().rev())
            .find_map(|call| call.dir)
            .unwrap_or(Dir::Inherit)
    }
}

/// Why the load fixes no texts for a chain's options.
#[cfg(any(
    feature = "number",
    feature = "currency",
    feature = "offset",
    feature = "conformance"
))]
enum Unfixed {
    /// A variable gives an option's value.
    Variable,
    /// A `u:dir` names no direction.
    Misnamed,
}

impl<'m> Chain<'m> {
    /// The calls, innermost first.
    pub(crate) fn calls(&self) -> impl DoubleEndedIterator<Item = &'m Call> {
        self.inner.iter().rev().copied().chain([self.outer])
    }

    /// The function of the innermost call, whose operand is the root.
    fn innermost(&self) -> Function {
        self.inner.last().map_or(self.outer, |call| call).function
    }

    /// The calls' resolved options, each option's text by `text`: `u:dir` parsed, `u:id`
    /// dropped. `misnamed` is the error of a `u:dir` that names no direction.
    fn texts_by<'s, E>(
        &self,
        mut text: impl FnMut(&'m Opt) -> Result<&'s str, E>,
        misnamed: impl Fn() -> E,
    ) -> Result<Texts<'s>, E>
    where
        'm: 's,
    {
        let mut resolved = |call: &'m Call| {
            let mut dir = None;
            let mut options = Vec::with_capacity(call.options.len());
            for option in &call.options {
                let text = text(option)?;
                match &option.name {
                    Name::Dir => dir = Some(Dir::named(text).ok_or_else(&misnamed)?),
                    Name::Id => {}
                    Name::Of(name) => options.push((&**name, text)),
                }
            }
            Ok(CallTexts {
                function: call.function,
                dir,
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
    /// [`Failure::Option`] for a variable whose value fails, or a `u:dir` that names no
    /// direction.
    pub(crate) fn texts<'s>(&self, scope: &'s Scope<'m>) -> Result<Texts<'s>, Failure> {
        self.texts_by(
            |option| {
                scope
                    .text(&option.value)
                    .map_err(|failure| failure.under(option.name.as_str()))
            },
            || Failure::Option(Name::Dir.as_str().to_owned()),
        )
    }

    /// The calls' resolved options when the load fixes every option's text; `None` when a
    /// variable gives one.
    ///
    /// # Errors
    ///
    /// [`Refusal::Option`] for a `u:dir` that names no direction.
    #[cfg(any(
        feature = "number",
        feature = "currency",
        feature = "offset",
        feature = "conformance"
    ))]
    pub(crate) fn fixed_texts(&self) -> Result<Option<Texts<'m>>, Refusal> {
        match self.texts_by(
            |option| option.value.fixed().ok_or(Unfixed::Variable),
            || Unfixed::Misnamed,
        ) {
            Ok(texts) => Ok(Some(texts)),
            Err(Unfixed::Variable) => Ok(None),
            Err(Unfixed::Misnamed) => Err(Refusal::Option {
                option: Name::Dir.as_str().to_owned(),
            }),
        }
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
        }
    }
}

/// How a message uses a call's value at a site that takes its text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Use {
    /// A placeholder formats it.
    Format,
    /// An option takes it as its value.
    Value,
}

/// Why a call does not format, select or give a value at resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Failure {
    /// The function refuses the operand's text.
    Operand,
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
            Self::Operand | Self::Option(_) => Self::Option(name.to_owned()),
        }
    }
}

/// Why the load refuses a call chain.
#[derive(Debug)]
pub(crate) enum Refused {
    /// The outermost function's options are defined by no module loaded so far.
    #[cfg(any(
        feature = "number",
        feature = "currency",
        feature = "offset",
        feature = "date"
    ))]
    Undefined,
    /// The function refuses the call.
    Call(Refusal),
    /// A selector's literal the load's [`Hold`](crate::normal::Hold) refuses.
    Unnormalized(Unnormalized),
}

impl From<Refusal> for Refused {
    fn from(refusal: Refusal) -> Self {
        Self::Call(refusal)
    }
}

impl Refused {
    /// The fault of the refusal of a chain whose outermost function is `function`.
    pub(crate) fn fault(self, function: Function) -> Fault {
        match self {
            #[cfg(any(
                feature = "number",
                feature = "currency",
                feature = "offset",
                feature = "date"
            ))]
            Self::Undefined => Fault::Undefined(function.name()),
            Self::Call(refusal) => Fault::Call(function.name(), refusal),
            Self::Unnormalized(literal) => Fault::Unnormalized(literal.written()),
        }
    }
}
