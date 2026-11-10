//! A message compiled for a context, and resolved. A compiled message holds a [`Chain`] for each
//! placeholder and each selector: the load follows each variable to its declaration, so a chain
//! starts from a literal or an argument and names every call applied to it. A variable that
//! gives an option its value at resolution stands for a declared call's value, else for the
//! argument of its name. The load checks each chain for its use. Markup opens and closes the
//! styles in nested order.
//!
//! A message resolves lazily: a placeholder formats when the pattern writes it, and a selector
//! selects when the matcher picks a variant (spec/formatting.md "Pattern Selection"). A declared
//! call an option reads gives its value once per resolution.

use std::borrow::Cow;

use crate::args::Args;
use crate::chain::{Call, Chain, Dir, Name, Opt, Root, Scope, Use, Value};
use crate::context::Bidi;
use crate::error::{Fault, Refusal, ResolveError};
use crate::format::{Direction, Formats, Function, Selected, Selecting};
use crate::mf2::ast::{self, MarkupKind};
use crate::mf2::valid::{Shape, Valid};
use crate::normal::Hold;
use crate::text::{Style, Text, Writer};

/// A message, compiled: its module's direction, the declared calls its options read, and its
/// body.
#[derive(Debug, Clone)]
pub(crate) struct Compiled {
    direction: Direction,
    declared: Vec<Declared>,
    body: Body,
}

/// A declared call whose value an option reads: its variable and its chain.
#[derive(Debug, Clone)]
struct Declared {
    name: Box<str>,
    chain: Chain,
}

/// A message's body.
#[derive(Debug, Clone)]
enum Body {
    Pattern(Pattern),
    /// `.match`: its selectors, its variants with a literal key, and the pattern of the variant
    /// whose keys are all `*`.
    Select {
        selectors: Vec<Selector>,
        variants: Vec<Variant>,
        fallback: Pattern,
    },
}

/// A selector: its chain, and how its function selects.
#[derive(Debug, Clone)]
struct Selector {
    chain: Chain,
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
    /// The chain a placeholder formats.
    Placeholder(Chain),
    Open(Style),
    Close(Style),
}

/// What a declaration binds its variable to.
#[derive(Debug, Clone)]
enum Bound {
    Literal(Box<str>),
    /// The argument of this key.
    Argument(Box<str>),
    Call(Chain),
}

/// A declaration: its variable, what it binds it to, and whether an option reads its call's
/// value.
struct Binding<'a> {
    name: &'a str,
    bound: Bound,
    read: bool,
}

/// The compilation of one message: the context's formats, how the load holds selector literals,
/// and the declarations so far.
struct Compiler<'c, 'a> {
    formats: &'c Formats,
    hold: Hold,
    bindings: Vec<Binding<'a>>,
}

/// Compiles a message of a module whose direction is `direction`, each literal a selector
/// compares held by `hold`.
///
/// # Errors
///
/// The [`Fault`] of a function the build lacks, a function whose section no module defined, a
/// call its function refuses, a selector literal `hold` refuses, and markup outside the styles
/// or not nested.
pub(crate) fn compile(
    message: &Valid<'_, '_>,
    direction: Direction,
    formats: &Formats,
    hold: Hold,
) -> Result<Compiled, Fault> {
    let mut compiler = Compiler {
        formats,
        hold,
        bindings: Vec::with_capacity(message.declarations.len()),
    };
    for declaration in message.declarations {
        let (name, bound) = match declaration {
            ast::Declaration::Input { name, function } => {
                let argument = Bound::Argument(name.as_ref().into());
                let bound = match function {
                    Some(function) => Bound::Call(compiler.call(Some(argument), function)?),
                    None => argument,
                };
                (name, bound)
            }
            ast::Declaration::Local { name, expression } => (name, compiler.bind(expression)?),
        };
        compiler.bindings.push(Binding {
            name,
            bound,
            read: false,
        });
    }
    let body = match &message.body {
        Shape::Pattern(pattern) => Body::Pattern(compiler.pattern(pattern)?),
        Shape::Matcher {
            selectors,
            variants,
            fallback,
        } => compiler.matcher(selectors, variants, fallback)?,
    };
    let declared = compiler
        .bindings
        .into_iter()
        .filter_map(|binding| match binding {
            Binding {
                name,
                bound: Bound::Call(chain),
                read: true,
            } => Some(Declared {
                name: name.into(),
                chain,
            }),
            _ => None,
        })
        .collect();
    Ok(Compiled {
        direction,
        declared,
        body,
    })
}

impl Compiler<'_, '_> {
    /// What an operand stands for: a literal, or what its variable's declaration binds; the
    /// argument of its name for a variable no declaration binds.
    fn operand(&self, operand: &ast::Operand<'_>) -> Bound {
        match operand {
            ast::Operand::Literal(text) => Bound::Literal(text.as_ref().into()),
            ast::Operand::Variable(name) => self
                .bindings
                .iter()
                .find(|binding| binding.name == name)
                .map_or_else(
                    || Bound::Argument(name.as_ref().into()),
                    |binding| binding.bound.clone(),
                ),
        }
    }

    /// What an expression stands for: its operand, or the call of its function on it.
    fn bind(&mut self, expression: &ast::Expression<'_>) -> Result<Bound, Fault> {
        match expression {
            ast::Expression::Operand {
                operand,
                function: None,
            } => Ok(self.operand(operand)),
            ast::Expression::Operand {
                operand,
                function: Some(function),
            } => self
                .call(Some(self.operand(operand)), function)
                .map(Bound::Call),
            ast::Expression::Function(function) => self.call(None, function).map(Bound::Call),
        }
    }

    /// The chain of a call of `function` on `operand`.
    fn call(
        &mut self,
        operand: Option<Bound>,
        function: &ast::Function<'_>,
    ) -> Result<Chain, Fault> {
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
        let call = Call::new(called, options);
        Ok(match operand {
            None => Chain::new(Root::None, call),
            Some(Bound::Literal(text)) => Chain::new(Root::Literal(text), call),
            Some(Bound::Argument(key)) => Chain::new(Root::Argument(key), call),
            Some(Bound::Call(chain)) => chain.then(call),
        })
    }

    /// An option of a call of `called`: its value a literal, written or bound to its variable,
    /// or a variable, whose declared call is checked to give a value; and its name, a `u:dir`
    /// the load fixes naming a direction.
    fn option(&mut self, called: Function, option: &ast::Opt<'_>) -> Result<Opt, Fault> {
        let value = match &option.value {
            ast::Operand::Literal(text) => Value::Literal(text.as_ref().into()),
            ast::Operand::Variable(variable) => {
                let variable = variable.as_ref();
                match self.bindings.iter_mut().find(|b| b.name == variable) {
                    Some(Binding {
                        bound: Bound::Literal(text),
                        ..
                    }) => Value::Bound(text.clone()),
                    Some(Binding {
                        bound: Bound::Argument(key),
                        ..
                    }) => Value::Variable(key.clone()),
                    Some(Binding {
                        bound: Bound::Call(chain),
                        read,
                        ..
                    }) => {
                        crate::format::check(chain, Use::Value, self.formats)
                            .map_err(|refused| refused.fault(chain.outer.function))?;
                        *read = true;
                        Value::Variable(variable.into())
                    }
                    None => Value::Variable(variable.into()),
                }
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

    /// The chain a placeholder formats, checked. A literal or a variable without a function
    /// formats with `:string`.
    fn placeholder(&mut self, expression: &ast::Expression<'_>) -> Result<Chain, Fault> {
        let string = || Call::new(Function::String, Vec::new());
        let chain = match self.bind(expression)? {
            Bound::Call(chain) => chain,
            Bound::Literal(text) => Chain::new(Root::Literal(text), string()),
            Bound::Argument(key) => Chain::new(Root::Argument(key), string()),
        };
        crate::format::check(&chain, Use::Format, self.formats)
            .map_err(|refused| refused.fault(chain.outer.function))?;
        Ok(chain)
    }

    /// The selector of the variable `name`: its declared call's chain, checked to select.
    fn selector(&self, name: &str) -> Result<Selector, Fault> {
        let Some(Binding {
            bound: Bound::Call(chain),
            ..
        }) = self.bindings.iter().find(|binding| binding.name == name)
        else {
            return Err(Fault::MissingSelectorAnnotation(name.to_owned()));
        };
        let selecting = Selecting::of(chain, self.formats, self.hold)
            .map_err(|refused| refused.fault(chain.outer.function))?;
        Ok(Selector {
            chain: chain.clone(),
            selecting,
        })
    }

    /// A `.match` body: each selector, each variant's keys, which its selector's selection
    /// reads, and each pattern.
    fn matcher(
        &mut self,
        selectors: &[Cow<'_, str>],
        variants: &[&ast::Variant<'_>],
        fallback: &ast::Pattern<'_>,
    ) -> Result<Body, Fault> {
        let selectors = selectors
            .iter()
            .map(|name| self.selector(name))
            .collect::<Result<Vec<_>, _>>()?;
        let variants = variants
            .iter()
            .map(|variant| {
                let keys = selectors
                    .iter()
                    .zip(&variant.keys)
                    .map(|(selector, key)| match key {
                        ast::Key::CatchAll => Ok(Key::CatchAll),
                        ast::Key::Literal(key) => match selector.selecting.reads(key) {
                            Ok(()) => Ok(Key::Literal(key.as_ref().into())),
                            Err(refusal) => {
                                Err(Fault::Call(selector.chain.outer.function.name(), refusal))
                            }
                        },
                    })
                    .collect::<Result<_, _>>()?;
                let pattern = self.pattern(&variant.pattern)?;
                Ok(Variant { keys, pattern })
            })
            .collect::<Result<_, Fault>>()?;
        Ok(Body::Select {
            selectors,
            variants,
            fallback: self.pattern(fallback)?,
        })
    }

    /// A pattern, its markup checked to open and close each style in nested order, once.
    fn pattern(&mut self, pattern: &ast::Pattern<'_>) -> Result<Pattern, Fault> {
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
        args: &Args,
        formats: &Formats,
        bidi: Bidi,
    ) -> Result<Text, ResolveError> {
        let mut scope = Scope::new(args, formats);
        for declared in &self.declared {
            scope.declare(&declared.name, &declared.chain);
        }
        let pattern = match &self.body {
            Body::Pattern(pattern) => pattern,
            Body::Select {
                selectors,
                variants,
                fallback,
            } => {
                let selected = selectors
                    .iter()
                    .map(|Selector { chain, selecting }| {
                        chain
                            .texts(&scope)
                            .and_then(|texts| selecting.selected(chain, &texts, &scope))
                            .map_err(|failure| chain.error(id, failure))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                variants
                    .iter()
                    .filter(|variant| variant.ranks(&selected).all(|rank| rank.is_some()))
                    .min_by(|a, b| a.ranks(&selected).cmp(b.ranks(&selected)))
                    .map_or(fallback, |variant| &variant.pattern)
            }
        };
        let mut writer = Writer::default();
        for part in pattern {
            match part {
                Part::Text(text) => writer.text(text),
                Part::Open(style) => writer.open(*style),
                Part::Close(style) => writer.close(*style),
                Part::Placeholder(chain) => {
                    let (text, value, dir) = chain
                        .texts(&scope)
                        .and_then(|texts| {
                            let (text, value) = crate::format::format(chain, &texts, &scope)?;
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

    /// The keys of the arguments the message's placeholders and selectors read, through their
    /// operands and their options' variables, each once, sorted.
    #[cfg(feature = "check")]
    pub(crate) fn reads(&self) -> Vec<&str> {
        fn placeholders(pattern: &Pattern) -> impl Iterator<Item = &Chain> {
            pattern.iter().filter_map(|part| match part {
                Part::Placeholder(chain) => Some(chain),
                Part::Text(_) | Part::Open(_) | Part::Close(_) => None,
            })
        }
        let mut pending: Vec<&Chain> = match &self.body {
            Body::Pattern(pattern) => placeholders(pattern).collect(),
            Body::Select {
                selectors,
                variants,
                fallback,
            } => selectors
                .iter()
                .map(|selector| &selector.chain)
                .chain(variants.iter().flat_map(|v| placeholders(&v.pattern)))
                .chain(placeholders(fallback))
                .collect(),
        };
        let mut followed: Vec<&str> = Vec::new();
        let mut reads: Vec<&str> = Vec::new();
        while let Some(chain) = pending.pop() {
            if let Root::Argument(key) = &chain.root {
                reads.push(key);
            }
            for name in chain.variables() {
                match self.declared.iter().find(|d| &*d.name == name) {
                    Some(_) if followed.contains(&name) => {}
                    Some(declared) => {
                        followed.push(name);
                        pending.push(&declared.chain);
                    }
                    None => reads.push(name),
                }
            }
        }
        reads.sort_unstable();
        reads.dedup();
        reads
    }
}
