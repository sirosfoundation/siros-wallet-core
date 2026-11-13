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
use crate::chain::{Call, Chain, Declared, Failure, Link, Operand, Opt, Site, Value};
use crate::context::Bidi;
use crate::error::{Fault, Refusal, ResolveError};
use crate::format::{Direction, Formats, Function, Selected, Selecting};
use crate::mf2::ast::{self, MarkupKind};
use crate::mf2::valid::{Shape, Valid};
use crate::registry::Formatters;
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

/// A selector: its variable, and how its declared call's function selects; `None` for an
/// argument whose call the wording leaves unwritten, which selects by its type's default
/// formatter.
#[derive(Debug, Clone)]
struct Selector {
    variable: Box<str>,
    selecting: Option<Selecting>,
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

/// The compilation of one message: the context's formats, what each declared variable stands
/// for, the declared calls, the variables of those options read, and the keys of the arguments
/// the message names.
struct Compiler<'c, 'a> {
    formats: &'c Formats,
    bound: FxHashMap<&'a str, Bound<'a>>,
    declared: Declared,
    reading: FxHashSet<&'a str>,
    read: Vec<Box<str>>,
    arguments: Vec<Box<str>>,
}

/// Compiles a message of a module whose direction is `direction`.
///
/// # Errors
///
/// The [`Fault`] of a function the build lacks, a function whose section no module defined, a
/// call its function refuses, and markup outside the styles or not nested.
pub(crate) fn compile<'a>(
    message: &Valid<'a, '_>,
    direction: Direction,
    formats: &Formats,
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
    /// is checked to give a value; and its name, outside the `u:` namespace.
    fn option(&mut self, called: Function, option: &'a ast::Opt<'_>) -> Result<Opt, Fault> {
        let value = match (&option.value, self.bound(&option.value)) {
            (ast::Operand::Literal(_), Bound::Literal(text)) => Value::Literal(text.into()),
            (_, Bound::Literal(text)) => Value::Bound(text.into()),
            (_, Bound::Variable(name)) => {
                if let Some(link) = self.declared.call(name) {
                    let chain = self.declared.chain(link);
                    crate::format::check(&chain, self.formats)
                        .map_err(|refused| refused.fault(chain.outer.function))?;
                    if self.reading.insert(name) {
                        self.read.push(name.into());
                    }
                }
                Value::Variable(name.into())
            }
        };
        let name = option.name.as_ref();
        if name.starts_with("u:") {
            let option = name.to_owned();
            return Err(Fault::Call(called.name(), Refusal::Option { option }));
        }
        Ok(Opt {
            name: name.into(),
            value,
        })
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
        crate::format::check(&chain, self.formats)
            .map_err(|refused| refused.fault(chain.outer.function))?;
        Ok(site)
    }

    /// The selector of the variable `name`: its declared call, checked to select, else an
    /// argument. A variable bound to a literal has no function to select by.
    fn selector(&mut self, name: &'a str) -> Result<Selector, Fault> {
        let variable = match self.bound.get(name).copied() {
            Some(Bound::Variable(variable)) => variable,
            Some(Bound::Literal(_)) => {
                return Err(Fault::MissingSelectorAnnotation(name.to_owned()));
            }
            None => {
                self.argument(name);
                name
            }
        };
        let selecting = match self.declared.call(variable) {
            Some(link) => {
                let chain = self.declared.chain(link);
                let selecting = Selecting::of(&chain, self.formats)
                    .map_err(|refused| refused.fault(chain.outer.function))?;
                Some(selecting)
            }
            None => None,
        };
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
                        ast::Key::Literal(key) => match selector
                            .selecting
                            .map_or(Ok(()), |selecting| selecting.reads(key))
                        {
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
/// placeholder it does not isolate. `value` is its formatted value's direction and `message` the
/// message's.
fn isolation(bidi: Bidi, value: Direction, message: Direction) -> Option<&'static str> {
    if bidi == Bidi::None {
        return None;
    }
    match value {
        Direction::Ltr if message == Direction::Ltr => None,
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
        formatters: &Formatters,
        bidi: Bidi,
    ) -> Result<Text, ResolveError> {
        let mut scope = Scope::new(args, formats, formatters, &self.declared);
        for variable in &self.read {
            scope.hold(variable);
        }
        let pattern = match &self.body {
            Body::Pattern(pattern) => pattern,
            Body::Select(select) => {
                let selected = select.selected(&self.declared, &scope, id)?;
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
                    let (text, value) = self.placeholder(site, &scope, id)?;
                    match isolation(bidi, value, self.direction) {
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

    /// The text of the placeholder `site`, and its value's direction.
    ///
    /// # Errors
    ///
    /// [`ResolveError`] as [`Compiled::resolve`].
    fn placeholder<'m>(
        &'m self,
        site: &'m Site,
        scope: &Scope<'m>,
        id: &str,
    ) -> Result<(String, Direction), ResolveError> {
        let chain = scope
            .typed(self.declared.site(site))
            .map_err(|failure| self.declared.site(site).error(id, failure))?;
        chain
            .texts(scope)
            .and_then(|texts| crate::format::format(&chain, &texts, scope))
            .map_err(|failure| chain.error(id, failure))
    }

    /// The keys of the arguments the message names: each `.input` declaration's, and each
    /// variable no declaration binds.
    pub(crate) fn arguments(&self) -> impl Iterator<Item = &str> {
        self.arguments.iter().map(|key| &**key)
    }
}

impl Select {
    /// What each selector's value selects with.
    ///
    /// # Errors
    ///
    /// [`ResolveError`] as [`Compiled::resolve`].
    fn selected<'m>(
        &'m self,
        declared: &'m Declared,
        scope: &Scope<'m>,
        id: &str,
    ) -> Result<Vec<Selected<'m>>, ResolveError> {
        self.selectors
            .iter()
            .enumerate()
            .map(|(column, selector)| {
                let chain = scope
                    .typed(declared.variable(&selector.variable))
                    .map_err(|failure| declared.variable(&selector.variable).error(id, failure))?;
                self.selecting(column, selector, &chain, scope)
                    .and_then(|selecting| {
                        let texts = chain.texts(scope)?;
                        selecting.selected(&chain, &texts, scope)
                    })
                    .map_err(|failure| chain.error(id, failure))
            })
            .collect()
    }

    /// How the selector in `column` selects: by its declared call's function, else by the
    /// default formatter of its argument's type, which reads each key of the column.
    ///
    /// # Errors
    ///
    /// [`Failure::Selector`] for a default formatter that refuses the selector or a key, and
    /// [`Failure::Operand`] for one whose options no module defines.
    fn selecting(
        &self,
        column: usize,
        selector: &Selector,
        chain: &Chain<'_>,
        scope: &Scope<'_>,
    ) -> Result<Selecting, Failure> {
        if let Some(selecting) = selector.selecting {
            return Ok(selecting);
        }
        let function = chain.outer.function;
        let selecting =
            Selecting::of(chain, scope.formats).map_err(|refused| refused.failure(function))?;
        for variant in &self.variants {
            if let Some(Key::Literal(key)) = variant.keys.get(column) {
                selecting
                    .reads(key)
                    .map_err(|refusal| Failure::Selector(function, refusal))?;
            }
        }
        Ok(selecting)
    }
}
