//! A message compiled for a context, and resolved. A compiled message holds each declared call
//! under its variable, and what each placeholder formats and each selector selects on: the load
//! follows each variable to its declaration, so a variable left in the message names a declared
//! call or an argument. The load checks the chain of each placeholder, each selector and each
//! declared call an option reads. Markup opens and closes the styles in nested order.
//!
//! A message resolves lazily: a placeholder formats when the pattern writes it, and a selector
//! selects when the matcher picks a variant (spec/formatting.md "Pattern Selection"). A variable
//! an option reads gives its value once per resolution.

use std::borrow::Cow;

use rustc_hash::{FxBuildHasher, FxHashMap, FxHashSet};

use crate::args::Args;
use crate::chain::{Call, Declared, Dir, Link, Name, Operand, Opt, Site, Use, Value};
use crate::context::Bidi;
use crate::error::{Fault, Refusal, ResolveError};
use crate::format::{Direction, Formats, Function, Selected, Selecting};
use crate::mf2::ast::{self, MarkupKind};
use crate::mf2::valid::{Shape, Valid};
use crate::normal::Hold;
use crate::scope::Scope;
use crate::text::{Style, Text, Writer};

/// A message, compiled: its module's direction, its declared calls, the variables of those its
/// options read, each after those its own value reads, the keys of the arguments it names, and
/// its body.
#[derive(Debug, Clone)]
pub(crate) struct Compiled {
    direction: Direction,
    declared: Declared,
    read: Vec<Box<str>>,
    arguments: Box<[Box<str>]>,
    body: Body,
}

/// A message's body.
#[derive(Debug, Clone)]
enum Body {
    Pattern(Pattern),
    Select(Box<Select>),
}

/// `.match`: its selectors, its variants with a literal key, and the pattern of the variant
/// whose keys are all `*`.
#[derive(Debug, Clone)]
struct Select {
    selectors: Vec<Selector>,
    variants: Vec<Variant>,
    fallback: Pattern,
}

/// A selector: the variable of its declared call, and how the call's function selects.
#[derive(Debug, Clone)]
struct Selector {
    variable: Box<str>,
    selecting: Selecting,
}

/// A variant with a literal key: one key per selector, and its pattern.
#[derive(Debug, Clone)]
struct Variant {
    keys: Vec<Key>,
    pattern: Pattern,
}

/// A variant key.
#[derive(Debug, Clone)]
enum Key {
    Literal(Box<str>),
    CatchAll,
}

/// How well a variant's key matches its selector's value: a literal key by its rank among the
/// keys the value matches, before `*`.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Rank {
    Key(usize),
    CatchAll,
}

impl Variant {
    /// The rank of each key over its selector's value; `None` for a key the value does not
    /// match.
    fn ranks(&self, selected: &[Selected<'_>]) -> impl Iterator<Item = Option<Rank>> {
        self.keys
            .iter()
            .zip(selected)
            .map(|(key, selected)| match key {
                Key::CatchAll => Some(Rank::CatchAll),
                Key::Literal(key) => selected.rank(key).map(Rank::Key),
            })
    }
}

type Pattern = Vec<Part>;

/// A part of a compiled pattern.
#[derive(Debug, Clone)]
enum Part {
    Text(Box<str>),
    Placeholder(Site),
    Open(Style),
    Close(Style),
}

/// What a declared variable stands for where a later expression names it: the literal its
/// declaration binds, or a variable, its own when its declaration binds a call or an argument.
#[derive(Debug, Clone, Copy)]
enum Bound<'a> {
    Literal(&'a str),
    Variable(&'a str),
}

/// The compilation of one message: the context's formats, how the load holds selector literals,
/// what each declared variable stands for, the declared calls, the variables of those options
/// read, and the keys of the arguments the message names.
struct Compiler<'c, 'a> {
    formats: &'c Formats,
    hold: Hold,
    bound: FxHashMap<&'a str, Bound<'a>>,
    declared: Declared,
    reading: FxHashSet<&'a str>,
    read: Vec<Box<str>>,
    arguments: Vec<Box<str>>,
}

/// Compiles a message of a module whose direction is `direction`, each literal a selector
/// compares held by `hold`.
///
/// # Errors
///
/// The [`Fault`] of a function the build lacks, a function whose section no module defined, a
/// call its function refuses, a selector literal `hold` refuses, and markup outside the styles
/// or not nested.
pub(crate) fn compile<'a>(
    message: &Valid<'a, '_>,
    direction: Direction,
    formats: &Formats,
    hold: Hold,
) -> Result<Compiled, Fault> {
    let declarations = message.declarations;
    let calls = declarations
        .iter()
        .filter(|declaration| match declaration {
            ast::Declaration::Input { function, .. } => function.is_some(),
            ast::Declaration::Local { expression, .. } => expression.parts().1.is_some(),
        })
        .count();
    let mut compiler = Compiler {
        formats,
        hold,
        bound: FxHashMap::with_capacity_and_hasher(declarations.len(), FxBuildHasher),
        declared: Declared::with_capacity(calls),
        reading: FxHashSet::default(),
        read: Vec::new(),
        arguments: Vec::new(),
    };
    for declaration in declarations {
        compiler.declare(declaration)?;
    }
    let body = match &message.body {
        Shape::Pattern(pattern) => Body::Pattern(compiler.pattern(pattern)?),
        Shape::Matcher {
            selectors,
            variants,
            fallback,
        } => compiler.matcher(selectors, variants, fallback)?,
    };
    Ok(Compiled {
        direction,
        declared: compiler.declared,
        read: compiler.read,
        arguments: compiler.arguments.into(),
        body,
    })
}

impl<'a> Compiler<'_, 'a> {
    /// Holds `key` as an argument the message names.
    fn argument(&mut self, key: &str) {
        if self.arguments.iter().all(|held| **held != *key) {
            self.arguments.push(key.into());
        }
    }

    /// Holds what a declaration's variable stands for, and its call.
    fn declare(&mut self, declaration: &'a ast::Declaration<'_>) -> Result<(), Fault> {
        let (name, bound) = match declaration {
            ast::Declaration::Input { name, function } => {
                self.argument(name);
                if let Some(function) = function {
                    let link = Link {
                        operand: Operand::Argument(name.as_ref().into()),
                        call: self.call(function)?,
                    };
                    self.declared.declare(name, link);
                }
                (name, Bound::Variable(name))
            }
            ast::Declaration::Local { name, expression } => match expression {
                ast::Expression::Operand {
                    operand,
                    function: None,
                } => (name, self.bound(operand)),
                ast::Expression::Operand {
                    function: Some(function),
                    ..
                }
                | ast::Expression::Function(function) => {
                    let link = Link {
                        operand: self.operand(expression),
                        call: self.call(function)?,
                    };
                    self.declared.declare(name, link);
                    (name, Bound::Variable(name))
                }
            },
        };
        self.bound.extend([(name.as_ref(), bound)]);
        Ok(())
    }

    /// What an operand stands for: a literal; what its variable's declaration binds; or its
    /// variable, which no declaration binds: an argument the message names.
    fn bound(&mut self, operand: &'a ast::Operand<'_>) -> Bound<'a> {
        match operand {
            ast::Operand::Literal(text) => Bound::Literal(text),
            ast::Operand::Variable(name) => match self.bound.get(name.as_ref()).copied() {
                Some(bound) => bound,
                None => {
                    self.argument(name);
                    Bound::Variable(name)
                }
            },
        }
    }

    /// What an expression's call applies to.
    fn operand(&mut self, expression: &'a ast::Expression<'_>) -> Operand {
        match expression {
            ast::Expression::Function(_) => Operand::None,
            ast::Expression::Operand { operand, .. } => match self.bound(operand) {
                Bound::Literal(text) => Operand::Literal(text.into()),
                Bound::Variable(name) => Operand::Variable(name.into()),
            },
        }
    }

    /// The call of `function`.
    fn call(&mut self, function: &'a ast::Function<'_>) -> Result<Call, Fault> {
        let name = function.name.as_ref();
        let called = Function::named(name).ok_or_else(|| Fault::Function(name.to_owned()))?;
        if !self.formats.defines(called) {
            return Err(Fault::Undefined(called.name()));
        }
        let options = function
            .options
            .iter()
            .map(|option| self.option(called, option))
            .collect::<Result<_, _>>()?;
        Ok(Call::new(called, options))
    }

    /// An option of a call of `called`: its value, a literal or a variable, whose declared call
    /// is checked to give a value; and its name, a `u:dir` the load fixes naming a direction.
    fn option(&mut self, called: Function, option: &'a ast::Opt<'_>) -> Result<Opt, Fault> {
        let value = match (&option.value, self.bound(&option.value)) {
            (ast::Operand::Literal(_), Bound::Literal(text)) => Value::Literal(text.into()),
            (_, Bound::Literal(text)) => Value::Bound(text.into()),
            (_, Bound::Variable(name)) => {
                if let Some(link) = self.declared.call(name) {
                    let chain = self.declared.chain(link);
                    crate::format::check(&chain, Use::Value, self.formats)
                        .map_err(|refused| refused.fault(chain.outer.function))?;
                    if self.reading.insert(name) {
                        self.read.push(name.into());
                    }
                }
                Value::Variable(name.into())
            }
        };
        let refuse = || {
            let option = option.name.to_string();
            Fault::Call(called.name(), Refusal::Option { option })
        };
        let name = match option.name.as_ref() {
            "u:dir" => match &value {
                Value::Literal(text) | Value::Bound(text) if Dir::named(text).is_none() => {
                    return Err(refuse());
                }
                Value::Literal(_) | Value::Bound(_) | Value::Variable(_) => Name::Dir,
            },
            "u:id" => Name::Id,
            other if other.starts_with("u:") => return Err(refuse()),
            other => Name::Of(other.into()),
        };
        Ok(Opt { name, value })
    }

    /// What a placeholder formats, its chain checked.
    fn placeholder(&mut self, expression: &'a ast::Expression<'_>) -> Result<Site, Fault> {
        let site = match expression {
            ast::Expression::Operand {
                operand,
                function: None,
            } => match self.bound(operand) {
                Bound::Literal(text) => Site::Literal(text.into()),
                Bound::Variable(name) => Site::Variable(name.into()),
            },
            ast::Expression::Operand {
                function: Some(function),
                ..
            }
            | ast::Expression::Function(function) => Site::Call(Link {
                operand: self.operand(expression),
                call: self.call(function)?,
            }),
        };
        let chain = self.declared.site(&site);
        crate::format::check(&chain, Use::Format, self.formats)
            .map_err(|refused| refused.fault(chain.outer.function))?;
        Ok(site)
    }

    /// The selector of the variable `name`: its declared call, checked to select.
    fn selector(&self, name: &'a str) -> Result<Selector, Fault> {
        let unannotated = || Fault::MissingSelectorAnnotation(name.to_owned());
        let Some(Bound::Variable(variable)) = self.bound.get(name).copied() else {
            return Err(unannotated());
        };
        let chain = self
            .declared
            .call(variable)
            .map(|link| self.declared.chain(link))
            .ok_or_else(unannotated)?;
        let selecting = Selecting::of(&chain, self.formats, self.hold)
            .map_err(|refused| refused.fault(chain.outer.function))?;
        Ok(Selector {
            variable: variable.into(),
            selecting,
        })
    }

    /// A `.match` body: each selector, each variant's keys, which its selector's selection
    /// reads, and each pattern.
    fn matcher(
        &mut self,
        selectors: &'a [Cow<'_, str>],
        variants: &'a [ast::Variant<'_>],
        fallback: &'a ast::Pattern<'_>,
    ) -> Result<Body, Fault> {
        let selectors = selectors
            .iter()
            .map(|name| self.selector(name))
            .collect::<Result<Vec<_>, _>>()?;
        let variants = variants
            .iter()
            .filter(|variant| !variant.catches_all())
            .map(|variant| {
                let keys = selectors
                    .iter()
                    .zip(&variant.keys)
                    .map(|(selector, key)| match key {
                        ast::Key::CatchAll => Ok(Key::CatchAll),
                        ast::Key::Literal(key) => match selector.selecting.reads(key) {
                            Ok(()) => Ok(Key::Literal(key.as_ref().into())),
                            Err(refusal) => {
                                let chain = self.declared.variable(&selector.variable);
                                Err(Fault::Call(chain.outer.function.name(), refusal))
                            }
                        },
                    })
                    .collect::<Result<_, _>>()?;
                let pattern = self.pattern(&variant.pattern)?;
                Ok(Variant { keys, pattern })
            })
            .collect::<Result<_, Fault>>()?;
        Ok(Body::Select(Box::new(Select {
            selectors,
            variants,
            fallback: self.pattern(fallback)?,
        })))
    }

    /// A pattern, its markup checked to open and close each style in nested order, once.
    fn pattern(&mut self, pattern: &'a ast::Pattern<'_>) -> Result<Pattern, Fault> {
        let mut parts = Vec::with_capacity(pattern.len());
        let mut open: Vec<(Style, &str)> = Vec::new();
        for part in pattern {
            parts.push(match part {
                ast::Part::Text(text) => Part::Text(text.as_ref().into()),
                ast::Part::Expression(expression) => {
                    Part::Placeholder(self.placeholder(expression)?)
                }
                ast::Part::Markup(markup) => {
                    let name = markup.name.as_ref();
                    let style = Style::named(name).ok_or_else(|| Fault::Markup(name.to_owned()))?;
                    if !markup.options.is_empty() {
                        return Err(Fault::MarkupOption(name.to_owned()));
                    }
                    match markup.kind {
                        MarkupKind::Open if open.iter().all(|(earlier, _)| *earlier != style) => {
                            open.push((style, name));
                            Part::Open(style)
                        }
                        MarkupKind::Close => match open.pop() {
                            Some((last, _)) if last == style => Part::Close(style),
                            Some(_) | None => return Err(Fault::Nesting(name.to_owned())),
                        },
                        MarkupKind::Open | MarkupKind::Standalone => {
                            return Err(Fault::Nesting(name.to_owned()));
                        }
                    }
                }
            });
        }
        match open.last() {
            Some((_, name)) => Err(Fault::Nesting((*name).to_owned())),
            None => Ok(parts),
        }
    }
}

/// The isolating character a placeholder opens under MF2's Default Bidi Strategy; `None` for a
/// placeholder it does not isolate. `dir` is its `u:dir`, `value` its formatted value's direction
/// and `message` the message's.
fn isolation(bidi: Bidi, dir: Dir, value: Direction, message: Direction) -> Option<&'static str> {
    if bidi == Bidi::None {
        return None;
    }
    let direction = match dir {
        Dir::Ltr => Direction::Ltr,
        Dir::Rtl => Direction::Rtl,
        Dir::Auto => Direction::Unknown,
        Dir::Inherit => value,
    };
    match direction {
        Direction::Ltr if message == Direction::Ltr && dir == Dir::Inherit => None,
        Direction::Ltr => Some("\u{2066}"),
        Direction::Rtl => Some("\u{2067}"),
        Direction::Unknown => Some("\u{2068}"),
    }
}

impl Compiled {
    /// The message `id` resolved over its arguments `args`, with the context's format sections
    /// `formats`.
    ///
    /// # Errors
    ///
    /// [`ResolveError`] for an argument the message does not give, or a text a function
    /// refuses.
    pub(crate) fn resolve(
        &self,
        id: &str,
        args: &Args<'_>,
        formats: &Formats,
        bidi: Bidi,
    ) -> Result<Text, ResolveError> {
        let mut scope = Scope::new(args, formats, &self.declared);
        for variable in &self.read {
            scope.hold(variable);
        }
        let pattern = match &self.body {
            Body::Pattern(pattern) => pattern,
            Body::Select(select) => {
                let selected = select
                    .selectors
                    .iter()
                    .map(|selector| {
                        let chain = self.declared.variable(&selector.variable);
                        chain
                            .texts(&scope)
                            .and_then(|texts| selector.selecting.selected(&chain, &texts, &scope))
                            .map_err(|failure| chain.error(id, failure))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                select
                    .variants
                    .iter()
                    .filter(|variant| variant.ranks(&selected).all(|rank| rank.is_some()))
                    .min_by(|a, b| a.ranks(&selected).cmp(b.ranks(&selected)))
                    .map_or(&select.fallback, |variant| &variant.pattern)
            }
        };
        let mut writer = Writer::default();
        for part in pattern {
            match part {
                Part::Text(text) => writer.text(text),
                Part::Open(style) => writer.open(*style),
                Part::Close(style) => writer.close(*style),
                Part::Placeholder(site) => {
                    let chain = self.declared.site(site);
                    let (text, value, dir) = chain
                        .texts(&scope)
                        .and_then(|texts| {
                            let (text, value) = crate::format::format(&chain, &texts, &scope)?;
                            Ok((text, value, texts.dir()))
                        })
                        .map_err(|failure| chain.error(id, failure))?;
                    match isolation(bidi, dir, value, self.direction) {
                        Some(open) => {
                            writer.text(open);
                            writer.text(&text);
                            writer.text("\u{2069}");
                        }
                        None => writer.text(&text),
                    }
                }
            }
        }
        Ok(writer.finish())
    }

    /// The keys of the arguments the message names: each `.input` declaration's, and each
    /// variable no declaration binds.
    pub(crate) fn arguments(&self) -> impl Iterator<Item = &str> {
        self.arguments.iter().map(|key| &**key)
    }
}
