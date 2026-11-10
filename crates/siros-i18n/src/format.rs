//! The build's functions, one family per feature: `:string` always, `:number` and `:integer`
//! (`number`), `:offset` (`offset`), `:currency` and `:percent` (`currency`), `:siros:date`,
//! `:siros:time` and `:siros:datetime` (`date`), and MF2's test functions (`conformance`). A
//! family with options parses its `[formats.<format>]` section. A message's values form a table:
//! literals, arguments, and calls, each on an earlier value. The load checks each call's chain
//! for each use a placeholder, a selector or an option makes of it; a resolution reads the
//! sections and formats, selects or takes the value.

use std::borrow::Cow;

use rustc_hash::{FxHashMap, FxHashSet};

use crate::error::{Defect, FormatRule, LoadError, Refusal, ResolveError};
use crate::normal::{Hold, Unnormalized};
#[cfg(any(
    feature = "number",
    feature = "currency",
    feature = "offset",
    feature = "date"
))]
use crate::resource::Entry;
use crate::resource::FormatSection;

/// A text's directionality: a message's, by its module's `@dir`, and a formatted value's, which
/// MF2's Default Bidi Strategy isolates it by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Direction {
    /// Left to right.
    Ltr,
    /// Right to left.
    Rtl,
    /// Not known.
    Unknown,
}

/// A function the build compiles in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Function {
    String,
    #[cfg(feature = "number")]
    Number,
    #[cfg(feature = "number")]
    Integer,
    #[cfg(feature = "offset")]
    Offset,
    #[cfg(feature = "currency")]
    Currency,
    #[cfg(feature = "currency")]
    Percent,
    #[cfg(feature = "date")]
    Date,
    #[cfg(feature = "date")]
    Time,
    #[cfg(feature = "date")]
    DateTime,
    /// `:test:function`.
    #[cfg(feature = "conformance")]
    Test,
    #[cfg(feature = "conformance")]
    TestSelect,
    #[cfg(feature = "conformance")]
    TestFormat,
}

impl Function {
    /// Every function of the build.
    const ALL: &'static [Self] = &[
        Self::String,
        #[cfg(feature = "number")]
        Self::Number,
        #[cfg(feature = "number")]
        Self::Integer,
        #[cfg(feature = "offset")]
        Self::Offset,
        #[cfg(feature = "currency")]
        Self::Currency,
        #[cfg(feature = "currency")]
        Self::Percent,
        #[cfg(feature = "date")]
        Self::Date,
        #[cfg(feature = "date")]
        Self::Time,
        #[cfg(feature = "date")]
        Self::DateTime,
        #[cfg(feature = "conformance")]
        Self::Test,
        #[cfg(feature = "conformance")]
        Self::TestSelect,
        #[cfg(feature = "conformance")]
        Self::TestFormat,
    ];

    /// The function of this name, without its colon; `None` for a function the build lacks.
    pub(crate) fn named(name: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|function| function.name() == name)
    }

    /// Its name, without its colon.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::String => "string",
            #[cfg(feature = "number")]
            Self::Number => "number",
            #[cfg(feature = "number")]
            Self::Integer => "integer",
            #[cfg(feature = "offset")]
            Self::Offset => "offset",
            #[cfg(feature = "currency")]
            Self::Currency => "currency",
            #[cfg(feature = "currency")]
            Self::Percent => "percent",
            #[cfg(feature = "date")]
            Self::Date => "siros:date",
            #[cfg(feature = "date")]
            Self::Time => "siros:time",
            #[cfg(feature = "date")]
            Self::DateTime => "siros:datetime",
            #[cfg(feature = "conformance")]
            Self::Test => "test:function",
            #[cfg(feature = "conformance")]
            Self::TestSelect => "test:select",
            #[cfg(feature = "conformance")]
            Self::TestFormat => "test:format",
        }
    }

    /// The section that defines its options; `None` for a function that takes none.
    const fn section(self) -> Option<Section> {
        match self {
            Self::String => None,
            #[cfg(feature = "number")]
            Self::Number | Self::Integer => Some(Section::Number),
            #[cfg(feature = "offset")]
            Self::Offset => Some(Section::Offset),
            #[cfg(feature = "currency")]
            Self::Currency | Self::Percent => Some(Section::Currency),
            #[cfg(feature = "date")]
            Self::Date | Self::Time | Self::DateTime => Some(Section::Date),
            #[cfg(feature = "conformance")]
            Self::Test | Self::TestSelect | Self::TestFormat => None,
        }
    }
}

/// A `[formats.<format>]` section's format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Section {
    Number,
    Offset,
    Currency,
    Date,
}

impl Section {
    const ALL: [Self; 4] = [Self::Number, Self::Offset, Self::Currency, Self::Date];

    fn named(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|section| section.name() == name)
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Number => "number",
            Self::Offset => "offset",
            Self::Currency => "currency",
            Self::Date => "date",
        }
    }
}

/// A value of a message: a literal, an argument, or a call of a function on an earlier value. A
/// message holds each declaration's value once, and a variable stands for its index.
#[derive(Debug, Clone)]
pub(crate) enum Value {
    /// A literal's string value.
    Literal(String),
    /// The argument of this key.
    Argument(String),
    /// A call.
    Call(Call),
}

/// A call: its function, the index of its operand's value among the message's earlier values
/// (`None` for `{:function}`), and its options, each name once, in the order written. `u:dir` and
/// `u:id` are among them; [`Chain::texts`] takes them out.
#[derive(Debug, Clone)]
pub(crate) struct Call {
    pub(crate) function: Function,
    pub(crate) operand: Option<usize>,
    pub(crate) options: Vec<(String, OptionValue)>,
}

/// An option's value (spec/formatting.md, "Option Resolution").
#[derive(Debug, Clone)]
pub(crate) enum OptionValue {
    /// A literal written as the value.
    Literal(String),
    /// The variable written as the value: the index of the value it stands for among the
    /// message's earlier values.
    Variable(usize),
}

/// A call of a chain: its function, and its options, each name once, in the order written.
#[derive(Debug)]
pub(crate) struct Link<'m> {
    pub(crate) function: Function,
    pub(crate) options: Vec<(&'m str, Opt<'m>)>,
}

/// An option's value in a chain: a literal written as the value, or the variable written as the
/// value with the index and the value it stands for.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Opt<'m> {
    Literal(&'m str),
    Variable(
        usize,
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
        &'m Value,
    ),
}

impl<'m> Opt<'m> {
    /// Its text when the load fixes it: a literal's, written or bound to the variable; `None` for
    /// a variable that stands for an argument or a call.
    #[cfg(any(
        feature = "number",
        feature = "currency",
        feature = "offset",
        feature = "date",
        feature = "conformance"
    ))]
    pub(crate) fn fixed(self) -> Option<&'m str> {
        match self {
            Self::Literal(text) => Some(text),
            Self::Variable(_, Value::Literal(text)) => Some(text),
            Self::Variable(_, Value::Argument(_) | Value::Call(_)) => None,
        }
    }
}

/// The value at `index`, which the value at `above` reads.
///
/// # Errors
///
/// [`Defect`] for an index at or after `above`, or past the values.
fn earlier(values: &[Value], index: usize, above: usize) -> Result<&Value, Defect> {
    if index >= above {
        return Err(Defect);
    }
    values.get(index).ok_or(Defect)
}

impl<'m> Link<'m> {
    /// The link of `call`, the value at `at` among `values`.
    ///
    /// # Errors
    ///
    /// [`Defect`] for an option's variable that names no earlier value.
    fn of(values: &'m [Value], call: &'m Call, at: usize) -> Result<Self, Defect> {
        let options = call
            .options
            .iter()
            .map(|(name, value)| {
                let value = match value {
                    OptionValue::Literal(text) => Opt::Literal(text),
                    OptionValue::Variable(index) => {
                        Opt::Variable(*index, earlier(values, *index, at)?)
                    }
                };
                Ok((name.as_str(), value))
            })
            .collect::<Result<_, Defect>>()?;
        Ok(Self {
            function: call.function,
            options,
        })
    }
}

/// How a message uses a call's value at one site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Use {
    /// A placeholder formats it.
    Format,
    /// A selector selects on it.
    Select,
    /// An option takes it as its value.
    Value,
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

/// A call's chain: what it starts from, the calls its operand's value applies from the innermost,
/// and the call itself, whose function formats, selects or gives the value.
#[derive(Debug)]
pub(crate) struct Chain<'m> {
    pub(crate) root: Root<'m>,
    inner: Vec<Link<'m>>,
    pub(crate) outer: Link<'m>,
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

    /// The `u:dir` of resolved calls: the outermost call's that gives one, else `inherit`. A
    /// value keeps its operand's `u:dir`.
    pub(crate) fn of(texts: &[CallTexts<'_>]) -> Self {
        texts
            .iter()
            .rev()
            .find_map(|call| call.dir)
            .unwrap_or(Self::Inherit)
    }
}

/// A call's resolved options: its function, its `u:dir`, and each option a function reads with
/// its text, in the order written. `u:id` names a part of a formatted result a text lacks.
#[derive(Debug)]
pub(crate) struct CallTexts<'a> {
    #[cfg_attr(
        not(any(feature = "number", feature = "currency", feature = "offset")),
        expect(
            dead_code,
            reason = "only the numeric functions read a call's function"
        )
    )]
    pub(crate) function: Function,
    pub(crate) dir: Option<Dir>,
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
    pub(crate) options: Vec<(&'a str, Cow<'a, str>)>,
}

impl CallTexts<'_> {
    /// The text of the option `name`.
    #[cfg(feature = "date")]
    pub(crate) fn option(&self, name: &str) -> Option<&str> {
        self.options
            .iter()
            .find(|(given, _)| *given == name)
            .map(|(_, text)| text.as_ref())
    }
}

impl<'m> Chain<'m> {
    /// The chain of the call at `at` among `values`.
    ///
    /// # Errors
    ///
    /// [`Defect`] when `at` names no call, or an operand or an option's variable names no
    /// earlier value.
    pub(crate) fn of(values: &'m [Value], at: usize) -> Result<Self, Defect> {
        let Some(Value::Call(outer)) = values.get(at) else {
            return Err(Defect);
        };
        let mut inner = Vec::new();
        let (mut operand, mut above) = (outer.operand, at);
        let root = loop {
            let Some(index) = operand else {
                break Root::None;
            };
            match earlier(values, index, above)? {
                Value::Literal(text) => break Root::Literal(text),
                Value::Argument(key) => break Root::Argument(key),
                Value::Call(call) => {
                    inner.push(Link::of(values, call, index)?);
                    (operand, above) = (call.operand, index);
                }
            }
        };
        inner.reverse();
        Ok(Self {
            root,
            inner,
            outer: Link::of(values, outer, at)?,
        })
    }

    /// The calls, innermost first.
    pub(crate) fn calls(&self) -> impl DoubleEndedIterator<Item = &Link<'m>> + '_ {
        self.inner.iter().chain(std::iter::once(&self.outer))
    }

    /// The function of the innermost call, whose operand is the root: the outermost call's when
    /// the chain has one call.
    pub(crate) fn innermost(&self) -> Function {
        self.inner
            .first()
            .map_or(self.outer.function, |call| call.function)
    }

    /// The indices of the values the chain's options' variables stand for.
    fn variables(&self) -> impl Iterator<Item = usize> + '_ {
        self.calls().flat_map(|call| {
            call.options.iter().filter_map(|(_, value)| match value {
                Opt::Variable(at, _) => Some(*at),
                Opt::Literal(_) => None,
            })
        })
    }

    /// The calls' resolved options, innermost first, each option's text by `text`: `u:dir`
    /// parsed, `u:id` dropped. `misnamed` is the error of a `u:dir` that names no direction.
    fn texts_by<E>(
        &self,
        mut text: impl FnMut(&'m str, Opt<'m>) -> Result<Cow<'m, str>, E>,
        misnamed: impl Fn(&str) -> E,
    ) -> Result<Vec<CallTexts<'m>>, E> {
        let mut texts = Vec::with_capacity(self.inner.len() + 1);
        for call in self.calls() {
            let mut dir = None;
            let mut options = Vec::with_capacity(call.options.len());
            for &(name, value) in &call.options {
                let resolved = text(name, value)?;
                match name {
                    "u:dir" => dir = Some(Dir::named(&resolved).ok_or_else(|| misnamed(name))?),
                    "u:id" => {}
                    _ => options.push((name, resolved)),
                }
            }
            texts.push(CallTexts {
                function: call.function,
                dir,
                options,
            });
        }
        Ok(texts)
    }

    /// The calls' resolved options, innermost first: a literal as written, a variable's value's
    /// text from `env` (spec/formatting.md, "Option Resolution").
    ///
    /// # Errors
    ///
    /// [`Failure::Unresolved`] for an argument the message does not give, and
    /// [`Failure::Option`] for a variable whose value fails, or a `u:dir` that names no
    /// direction.
    pub(crate) fn texts(&self, env: &mut Env<'_, 'm>) -> Result<Vec<CallTexts<'m>>, Failure> {
        self.texts_by(
            |name, value| match value {
                Opt::Literal(text) => Ok(Cow::Borrowed(text)),
                Opt::Variable(at, _) => env.text(at).map_err(|failure| failure.under(name)),
            },
            |name| Failure::Option(name.to_owned()),
        )
    }

    /// The calls' resolved options when the load fixes every option's text; `None` when a
    /// variable stands for an argument or a call.
    ///
    /// # Errors
    ///
    /// [`Defect`] for a `u:dir` the load fixes that names no direction: the load refuses such
    /// a call when it compiles it.
    #[cfg(any(
        feature = "number",
        feature = "currency",
        feature = "offset",
        feature = "conformance"
    ))]
    pub(crate) fn fixed_texts(&self) -> Result<Option<Vec<CallTexts<'m>>>, Defect> {
        match self.texts_by(
            |_, value| value.fixed().map(Cow::Borrowed).ok_or(Unfixed::Variable),
            |_| Unfixed::Misnamed,
        ) {
            Ok(texts) => Ok(Some(texts)),
            Err(Unfixed::Variable) => Ok(None),
            Err(Unfixed::Misnamed) => Err(Defect),
        }
    }

    /// The resolution error of `failure` in the message `id`: an operand's names the innermost
    /// function, an option's the outermost.
    pub(crate) fn error(&self, id: &str, failure: Failure) -> ResolveError {
        match failure {
            Failure::Operand => ResolveError::Operand {
                id: id.to_owned(),
                function: self.innermost().name().to_owned(),
            },
            Failure::Option(option) => ResolveError::Option {
                id: id.to_owned(),
                function: self.outer.function.name().to_owned(),
                option,
            },
            Failure::Unresolved(key) => ResolveError::Unresolved {
                id: id.to_owned(),
                key,
            },
            Failure::Defect => ResolveError::Defect { id: id.to_owned() },
        }
    }

    /// The call's value as an option's value, its options resolved as at a placeholder: the
    /// operand's text for `:string` and the date functions, the number for the numeric
    /// functions, and the test functions' input.
    fn value(&self, env: &mut Env<'_, 'm>) -> Result<Cow<'m, str>, Failure> {
        #[cfg_attr(
            not(any(
                feature = "number",
                feature = "currency",
                feature = "offset",
                feature = "date",
                feature = "conformance"
            )),
            expect(unused_variables, reason = "`:string` reads no option")
        )]
        let texts = self.texts(env)?;
        match self.outer.function {
            Function::String => crate::string::value(self, env).map(Cow::Borrowed),
            #[cfg(feature = "number")]
            Function::Number | Function::Integer => numeric_value(self, &texts, env),
            #[cfg(feature = "offset")]
            Function::Offset => numeric_value(self, &texts, env),
            #[cfg(feature = "currency")]
            Function::Currency | Function::Percent => numeric_value(self, &texts, env),
            #[cfg(feature = "date")]
            Function::Date | Function::Time | Function::DateTime => {
                crate::date::value(self, &texts, env).map(Cow::Borrowed)
            }
            #[cfg(feature = "conformance")]
            Function::Test | Function::TestSelect | Function::TestFormat => {
                crate::test_functions::value(self, &texts, env).map(Cow::Borrowed)
            }
        }
    }
}

/// The value of a chain whose outermost function is numeric.
#[cfg(any(feature = "number", feature = "currency", feature = "offset"))]
fn numeric_value<'m>(
    chain: &Chain<'m>,
    texts: &[CallTexts<'m>],
    env: &Env<'_, 'm>,
) -> Result<Cow<'m, str>, Failure> {
    let language = language(chain, env.formats).map_err(Failure::missing)?;
    crate::numeric::value(chain, texts, env, language).map(Cow::Owned)
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
    /// A value, a format section or a selection the load holds is missing.
    Defect,
}

impl Failure {
    /// The failure of the option `name` whose variable's value failed so: an argument the value
    /// reads stays unresolved, a defect stays one, and any other failure refuses the option.
    fn under(self, name: &str) -> Self {
        match self {
            Self::Unresolved(key) => Self::Unresolved(key),
            Self::Defect => Self::Defect,
            Self::Operand | Self::Option(_) => Self::Option(name.to_owned()),
        }
    }

    /// The failure of a chain whose section the load found and the resolution lacks, whatever
    /// the refusal: the context holds each section it defines.
    #[cfg(any(feature = "number", feature = "currency", feature = "offset"))]
    fn missing(_: Refused) -> Self {
        Self::Defect
    }
}

impl From<Defect> for Failure {
    fn from(Defect: Defect) -> Self {
        Self::Defect
    }
}

/// Why the compiler refuses a call chain.
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
    /// A selector's literal the load's [`Hold`] refuses.
    Unnormalized(Unnormalized),
    /// A lookup missed what the load holds by construction.
    Defect,
}

impl From<Refusal> for Refused {
    fn from(refusal: Refusal) -> Self {
        Self::Call(refusal)
    }
}

impl From<Defect> for Refused {
    fn from(Defect: Defect) -> Self {
        Self::Defect
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
    /// A variable stands for an argument or a call.
    Variable,
    /// A `u:dir` names no direction.
    Misnamed,
}

/// The arguments' texts, by key.
pub(crate) type Argument<'a> = dyn Fn(&str) -> Option<&'a str> + 'a;

/// What one resolution of a message reads: the arguments' texts, the message's values, the
/// context's format sections, and each value's text as an option's value, once an option reads
/// it.
pub(crate) struct Env<'e, 'm> {
    argument: &'e Argument<'m>,
    values: &'m [Value],
    #[cfg_attr(
        not(any(
            feature = "number",
            feature = "currency",
            feature = "offset",
            feature = "date"
        )),
        expect(dead_code, reason = "only the format functions read a section")
    )]
    formats: &'m Formats,
    texts: FxHashMap<usize, Result<Cow<'m, str>, Failure>>,
}

impl<'e, 'm> Env<'e, 'm> {
    /// The resolution over `argument` of a message whose values are `values`, in a context whose
    /// format sections are `formats`.
    pub(crate) fn new(
        argument: &'e Argument<'m>,
        values: &'m [Value],
        formats: &'m Formats,
    ) -> Self {
        Self {
            argument,
            values,
            formats,
            texts: FxHashMap::default(),
        }
    }

    /// The text of the argument `key`.
    ///
    /// # Errors
    ///
    /// [`Failure::Unresolved`] for an argument the message does not give.
    pub(crate) fn argument(&self, key: &str) -> Result<&'m str, Failure> {
        (self.argument)(key).ok_or_else(|| Failure::Unresolved(key.to_owned()))
    }

    /// The text of the value at `at` as an option's value: a literal as written, an argument's
    /// text, a call's value. A call, and each call its options' variables stand for, which come
    /// before it, is evaluated once, deepest first.
    ///
    /// # Errors
    ///
    /// The value's [`Failure`]; [`Failure::Defect`] for an index that names no value, or a call
    /// whose operand or options name no earlier value.
    fn text(&mut self, at: usize) -> Result<Cow<'m, str>, Failure> {
        let values = self.values;
        let mut pending = vec![(at, false)];
        while let Some((index, ready)) = pending.pop() {
            if self.texts.contains_key(&index) {
                continue;
            }
            let text = match values.get(index).ok_or(Failure::Defect)? {
                Value::Literal(text) => Ok(Cow::Borrowed(text.as_str())),
                Value::Argument(key) => self.argument(key).map(Cow::Borrowed),
                Value::Call(_) => {
                    let chain = Chain::of(values, index)?;
                    if ready {
                        chain.value(self)
                    } else {
                        pending.push((index, true));
                        pending.extend(chain.variables().map(|read| (read, false)));
                        continue;
                    }
                }
            };
            self.texts.extend([(index, text)]);
        }
        match self.texts.get(&at) {
            Some(text) => text.clone(),
            None => Err(Failure::Defect),
        }
    }
}

/// The numeric chain's language: the section of the function that formats its value. `:offset`
/// formats with the function of its operand's call, and with `[formats.offset]` over `:number`,
/// `:integer` or a literal. A call of another family refuses the operand.
#[cfg(any(feature = "number", feature = "currency", feature = "offset"))]
fn language<'f>(
    chain: &Chain<'_>,
    formats: &'f Formats,
) -> Result<crate::numeric::Language<'f>, Refused> {
    #[cfg(any(feature = "number", feature = "currency"))]
    use crate::numeric::options::Function as Numeric;
    let formatter = crate::numeric::formatter(chain).ok_or(Refused::Call(Refusal::Operand))?;
    match (chain.outer.function, formatter) {
        #[cfg(feature = "currency")]
        (_, Numeric::Currency | Numeric::Percent) => Ok(crate::numeric::Language::Currency(
            formats.currency.as_ref().ok_or(Refused::Undefined)?,
        )),
        #[cfg(feature = "offset")]
        (Function::Offset, _) => Ok(crate::numeric::Language::Plain(
            formats.offset.as_ref().ok_or(Refused::Undefined)?,
        )),
        #[cfg(feature = "number")]
        (_, Numeric::Number | Numeric::Integer | Numeric::Offset) => Ok(
            crate::numeric::Language::Plain(formats.number.as_ref().ok_or(Refused::Undefined)?),
        ),
        #[cfg(not(all(feature = "number", feature = "currency")))]
        _ => Err(Refused::Defect),
    }
}

/// Checks the chain for its use at a site, against the sections of the modules loaded so far,
/// a selector's literal held by `hold`.
///
/// # Errors
///
/// [`Refused`] for a section no module defined, a call the function refuses, or a literal
/// `hold` refuses: a function that does not select refuses with [`Refusal::Selector`].
pub(crate) fn check(
    chain: &Chain<'_>,
    at: Use,
    #[cfg_attr(
        not(any(
            feature = "number",
            feature = "currency",
            feature = "offset",
            feature = "date"
        )),
        expect(unused_variables, reason = "only the format functions read a section")
    )]
    formats: &Formats,
    hold: Hold,
) -> Result<(), Refused> {
    match chain.outer.function {
        Function::String => crate::string::check(chain, at, hold),
        #[cfg(feature = "number")]
        Function::Number | Function::Integer => numeric_check(chain, at, formats),
        #[cfg(feature = "offset")]
        Function::Offset => numeric_check(chain, at, formats),
        #[cfg(feature = "currency")]
        Function::Currency | Function::Percent => numeric_check(chain, at, formats),
        #[cfg(feature = "date")]
        Function::Date | Function::Time | Function::DateTime => {
            if formats.date.is_none() {
                return Err(Refused::Undefined);
            }
            Ok(crate::date::check(chain, at)?)
        }
        #[cfg(feature = "conformance")]
        Function::Test | Function::TestSelect | Function::TestFormat => {
            crate::test_functions::check(chain, at)
        }
    }
}

/// Checks a numeric chain for its use.
#[cfg(any(feature = "number", feature = "currency", feature = "offset"))]
fn numeric_check(chain: &Chain<'_>, at: Use, formats: &Formats) -> Result<(), Refused> {
    crate::numeric::check(chain, at, language(chain, formats)?)
}

/// Refuses a key of a selector's column the selection of `function` does not read.
///
/// # Errors
///
/// [`Refusal::Key`] for the first such key.
pub(crate) fn keys(
    function: Function,
    #[cfg_attr(
        not(any(feature = "number", feature = "currency", feature = "offset")),
        expect(unused_variables, reason = "only the numeric selection refuses a key")
    )]
    keys: &[String],
) -> Result<(), Refusal> {
    match function {
        #[cfg(feature = "number")]
        Function::Number | Function::Integer => crate::numeric::keys(keys),
        #[cfg(feature = "offset")]
        Function::Offset => crate::numeric::keys(keys),
        #[cfg(feature = "currency")]
        Function::Currency | Function::Percent => crate::numeric::keys(keys),
        _ => Ok(()),
    }
}

/// The value formatted with its resolved options `texts`, and the formatted text's direction.
///
/// # Errors
///
/// [`Failure`] for an operand or an option text the function refuses, or an argument the
/// message does not give.
pub(crate) fn format<'m>(
    chain: &Chain<'m>,
    #[cfg_attr(
        not(any(
            feature = "number",
            feature = "currency",
            feature = "offset",
            feature = "date",
            feature = "conformance"
        )),
        expect(unused_variables, reason = "`:string` reads no option")
    )]
    texts: &[CallTexts<'m>],
    env: &Env<'_, 'm>,
) -> Result<(String, Direction), Failure> {
    match chain.outer.function {
        Function::String => {
            crate::string::value(chain, env).map(|text| (text.to_owned(), Direction::Unknown))
        }
        #[cfg(feature = "number")]
        Function::Number | Function::Integer => numeric_format(chain, texts, env),
        #[cfg(feature = "offset")]
        Function::Offset => numeric_format(chain, texts, env),
        #[cfg(feature = "currency")]
        Function::Currency | Function::Percent => numeric_format(chain, texts, env),
        #[cfg(feature = "date")]
        Function::Date | Function::Time | Function::DateTime => {
            let section = env.formats.date.as_ref().ok_or(Failure::Defect)?;
            let text = crate::date::format(chain, texts, env, section)?;
            Ok((text, section.direction()))
        }
        #[cfg(feature = "conformance")]
        Function::Test | Function::TestSelect | Function::TestFormat => {
            crate::test_functions::format(chain, texts, env).map(|text| (text, Direction::Unknown))
        }
    }
}

/// A numeric value formatted, and its section's direction.
#[cfg(any(feature = "number", feature = "currency", feature = "offset"))]
fn numeric_format<'m>(
    chain: &Chain<'m>,
    texts: &[CallTexts<'m>],
    env: &Env<'_, 'm>,
) -> Result<(String, Direction), Failure> {
    let language = language(chain, env.formats).map_err(Failure::missing)?;
    let text = crate::numeric::format(chain, texts, env, language)?;
    Ok((text, language.direction()))
}

/// The keys among `keys` the value matches, best first, with its resolved options `texts`.
///
/// # Errors
///
/// [`Failure`] as [`format`].
pub(crate) fn select<'m, 'k>(
    chain: &Chain<'m>,
    #[cfg_attr(
        not(any(
            feature = "number",
            feature = "currency",
            feature = "offset",
            feature = "conformance"
        )),
        expect(unused_variables, reason = "`:string` reads no option")
    )]
    texts: &[CallTexts<'m>],
    env: &Env<'_, 'm>,
    keys: &'k [String],
) -> Result<Vec<&'k str>, Failure> {
    match chain.outer.function {
        Function::String => crate::string::select(chain, env, keys),
        #[cfg(feature = "number")]
        Function::Number | Function::Integer => numeric_select(chain, texts, env, keys),
        #[cfg(feature = "offset")]
        Function::Offset => numeric_select(chain, texts, env, keys),
        #[cfg(feature = "currency")]
        Function::Currency | Function::Percent => numeric_select(chain, texts, env, keys),
        #[cfg(feature = "date")]
        Function::Date | Function::Time | Function::DateTime => Err(Failure::Defect),
        #[cfg(feature = "conformance")]
        Function::Test | Function::TestSelect | Function::TestFormat => {
            crate::test_functions::select(chain, texts, env, keys)
        }
    }
}

/// The keys a numeric value matches.
#[cfg(any(feature = "number", feature = "currency", feature = "offset"))]
fn numeric_select<'m, 'k>(
    chain: &Chain<'m>,
    texts: &[CallTexts<'m>],
    env: &Env<'_, 'm>,
    keys: &'k [String],
) -> Result<Vec<&'k str>, Failure> {
    let language = language(chain, env.formats).map_err(Failure::missing)?;
    crate::numeric::select(chain, texts, env, language, keys)
}

/// A format section's options, each name once, each one its format takes; and the direction of
/// the module that defines it.
#[cfg(any(
    feature = "number",
    feature = "currency",
    feature = "offset",
    feature = "date"
))]
#[derive(Debug, Clone, Copy)]
pub(crate) struct Options<'s> {
    entries: &'s [Entry],
    pub(crate) direction: Direction,
}

#[cfg(any(
    feature = "number",
    feature = "currency",
    feature = "offset",
    feature = "date"
))]
impl<'s> Options<'s> {
    /// The option `name`'s text.
    ///
    /// # Errors
    ///
    /// [`FormatRule::Missing`] when the section lacks it.
    pub(crate) fn text(&self, name: &'static str) -> Result<&'s str, FormatRule> {
        self.entries
            .iter()
            .find(|entry| entry.key == name)
            .map(|entry| entry.value.as_str())
            .ok_or(FormatRule::Missing { option: name })
    }

    /// The option `name`, parsed by `accept`.
    ///
    /// # Errors
    ///
    /// [`FormatRule::Missing`] when the section lacks it, [`FormatRule::Text`] when `accept`
    /// refuses its text.
    pub(crate) fn parse<T>(
        &self,
        name: &'static str,
        accept: impl FnOnce(&'s str) -> Option<T>,
    ) -> Result<T, FormatRule> {
        accept(self.text(name)?).ok_or(FormatRule::Text { option: name })
    }
}

/// The format sections a context defines, each parsed by its family; a section of a format the
/// build lacks is held by name alone.
#[derive(Debug, Clone, Default)]
pub(crate) struct Formats {
    defined: Vec<Section>,
    #[cfg(feature = "number")]
    number: Option<crate::numeric::Plain>,
    #[cfg(feature = "offset")]
    offset: Option<crate::numeric::Plain>,
    #[cfg(feature = "currency")]
    currency: Option<crate::numeric::currency::Parsed>,
    #[cfg(feature = "date")]
    date: Option<crate::date::Parsed>,
}

impl Formats {
    /// Defines a section of a module whose direction is `direction`.
    ///
    /// # Errors
    ///
    /// [`LoadError::Repeated`] for a section the context holds or an option given twice,
    /// [`LoadError::Format`] for a section its format refuses.
    pub(crate) fn define(
        &mut self,
        section: &FormatSection,
        #[cfg_attr(
            not(any(
                feature = "number",
                feature = "currency",
                feature = "offset",
                feature = "date"
            )),
            expect(unused_variables, reason = "a build without formats parses no section")
        )]
        direction: Direction,
    ) -> Result<(), LoadError> {
        let refuse = |rule| LoadError::Format {
            format: section.format.clone(),
            rule,
        };
        let Some(named) = Section::named(&section.format) else {
            return Err(refuse(FormatRule::Unknown));
        };
        if self.defined.contains(&named) {
            return Err(LoadError::Repeated {
                id: format!("formats.{}", section.format),
            });
        }
        let mut given = FxHashSet::default();
        if let Some(entry) = section
            .options
            .iter()
            .find(|entry| !given.insert(entry.key.as_str()))
        {
            return Err(LoadError::Repeated {
                id: format!("formats.{}.{}", section.format, entry.key),
            });
        }
        #[cfg(any(
            feature = "number",
            feature = "currency",
            feature = "offset",
            feature = "date"
        ))]
        self.parse(
            named,
            Options {
                entries: &section.options,
                direction,
            },
        )
        .map_err(refuse)?;
        self.defined.push(named);
        Ok(())
    }

    /// Parses a section of a format the build compiles in; a section of another format stays
    /// unparsed.
    #[cfg(any(
        feature = "number",
        feature = "currency",
        feature = "offset",
        feature = "date"
    ))]
    fn parse(&mut self, section: Section, options: Options<'_>) -> Result<(), FormatRule> {
        match section {
            #[cfg(feature = "number")]
            Section::Number => {
                takes(options, &crate::numeric::PLAIN)?;
                self.number = Some(crate::numeric::Plain::parse(options)?);
            }
            #[cfg(feature = "offset")]
            Section::Offset => {
                takes(options, &crate::numeric::PLAIN)?;
                self.offset = Some(crate::numeric::Plain::parse(options)?);
            }
            #[cfg(feature = "currency")]
            Section::Currency => {
                takes(options, &crate::numeric::currency::OPTIONS)?;
                self.currency = Some(crate::numeric::currency::Parsed::parse(options)?);
            }
            #[cfg(feature = "date")]
            Section::Date => {
                takes(options, &crate::date::OPTIONS)?;
                self.date = Some(crate::date::Parsed::parse(options)?);
            }
            #[cfg(not(all(
                feature = "number",
                feature = "offset",
                feature = "currency",
                feature = "date"
            )))]
            _ => {}
        }
        Ok(())
    }

    /// Whether a module defined the section of `function`'s options; a function that takes none
    /// needs no section.
    pub(crate) fn defines(&self, function: Function) -> bool {
        function
            .section()
            .is_none_or(|section| self.defined.contains(&section))
    }
}

/// Refuses an option the format does not take.
#[cfg(any(
    feature = "number",
    feature = "currency",
    feature = "offset",
    feature = "date"
))]
fn takes(options: Options<'_>, names: &[&str]) -> Result<(), FormatRule> {
    match options
        .entries
        .iter()
        .find(|entry| !names.contains(&entry.key.as_str()))
    {
        Some(entry) => Err(FormatRule::Undefined {
            option: entry.key.clone(),
        }),
        None => Ok(()),
    }
}
