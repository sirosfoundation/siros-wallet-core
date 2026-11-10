//! A call's chain: what it starts from and the calls applied to it, innermost first. A message
//! holds one chain for each placeholder, each selector and each declared call an option reads;
//! the load builds each from the declarations, so a resolution reads it as it is. A [`Scope`] is
//! what one resolution reads beside the message: the arguments, the context's format sections,
//! and the values of the declared calls.

use std::borrow::Cow;

use crate::args::Args;
use crate::error::{Fault, Refusal, ResolveError};
use crate::format::{Formats, Function};
use crate::normal::Unnormalized;

/// What a chain of calls starts from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Root {
    /// No operand: `{:function}`.
    None,
    /// A literal's string value.
    Literal(Box<str>),
    /// The argument of this key.
    Argument(Box<str>),
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

/// A call's chain: what it starts from, the calls its operand's value applies from the innermost,
/// and the call itself, whose function formats, selects or gives the value.
#[derive(Debug, Clone)]
pub(crate) struct Chain {
    pub(crate) root: Root,
    inner: Vec<Call>,
    pub(crate) outer: Call,
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

impl Chain {
    /// The chain of `call` on `root`.
    pub(crate) const fn new(root: Root, call: Call) -> Self {
        Self {
            root,
            inner: Vec::new(),
            outer: call,
        }
    }

    /// The chain of `call` on this chain's value.
    pub(crate) fn then(mut self, call: Call) -> Self {
        self.inner.push(std::mem::replace(&mut self.outer, call));
        self
    }

    /// The calls, innermost first.
    pub(crate) fn calls(&self) -> impl DoubleEndedIterator<Item = &Call> {
        self.inner.iter().chain([&self.outer])
    }

    /// The function of the innermost call, whose operand is the root.
    fn innermost(&self) -> Function {
        self.inner
            .first()
            .map_or(self.outer.function, |call| call.function)
    }

    /// The variables that give the calls' options a value at resolution.
    #[cfg(feature = "check")]
    pub(crate) fn variables(&self) -> impl Iterator<Item = &str> {
        self.calls()
            .flat_map(|call| &call.options)
            .filter_map(|option| match &option.value {
                Value::Variable(name) => Some(&**name),
                Value::Literal(_) | Value::Bound(_) => None,
            })
    }

    /// The calls' resolved options, each option's text by `text`: `u:dir` parsed, `u:id`
    /// dropped. `misnamed` is the error of a `u:dir` that names no direction.
    fn texts_by<'s, E>(
        &'s self,
        mut text: impl FnMut(&'s Opt) -> Result<&'s str, E>,
        misnamed: impl Fn() -> E,
    ) -> Result<Texts<'s>, E> {
        let mut resolved = |call: &'s Call| {
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
                .map(&mut resolved)
                .collect::<Result<_, E>>()?,
            outer: resolved(&self.outer)?,
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
    pub(crate) fn texts<'s>(&'s self, scope: &'s Scope<'_>) -> Result<Texts<'s>, Failure> {
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
    pub(crate) fn fixed_texts(&self) -> Result<Option<Texts<'_>>, Refusal> {
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

/// What one resolution of a message reads beside the message: the arguments' texts, the
/// context's format sections, and the value of each declared call an option reads, in the order
/// declared.
pub(crate) struct Scope<'m> {
    args: &'m Args,
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
    declared: Vec<(&'m str, Result<Cow<'m, str>, Failure>)>,
}

impl<'m> Scope<'m> {
    /// The resolution over `args` in a context whose format sections are `formats`.
    pub(crate) const fn new(args: &'m Args, formats: &'m Formats) -> Self {
        Self {
            args,
            formats,
            declared: Vec::new(),
        }
    }

    /// Declares the call `chain` under `name`: its value, over the calls declared before it.
    pub(crate) fn declare(&mut self, name: &'m str, chain: &'m Chain) {
        let value = crate::format::value(chain, self);
        self.declared.push((name, value));
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

    /// The text of an option's value: a literal as written, a declared call's value, an
    /// argument's text.
    ///
    /// # Errors
    ///
    /// The declared call's [`Failure`], and [`Failure::Unresolved`] for an argument the message
    /// does not give.
    fn text<'s>(&'s self, given: &'s Value) -> Result<&'s str, Failure> {
        let name = match given {
            Value::Literal(text) | Value::Bound(text) => return Ok(text),
            Value::Variable(name) => &**name,
        };
        match self.declared.iter().find(|(declared, _)| *declared == name) {
            Some((_, value)) => value.as_deref().map_err(Failure::clone),
            None => self.argument(name),
        }
    }
}
