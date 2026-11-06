//! A text's evaluation: a query's message found in the package's module that holds it, read from
//! the module's locale entry for the language, its arguments checked against the message's
//! declaration, its variant selected, and its pattern written into a sink.

use std::borrow::Cow;

use siros_explain::{
    AllOf, Amount, ArgKind, Entry, Key, ListKind, ModuleId, ParamName, Presence, Query, Text, Value,
};

use crate::error::{FormatFailure, RenderError};
use crate::form::{
    BareKind, BodyForm, CompiledCall, Dir, KeyRef, MessageForm, ParamForm, PartForm, Root,
    SelectorForm, VariantForm,
};
use crate::format::{Direction, FormatRenderer, Input, VariantKeys};
use crate::package::{ModuleRecord, StoredKind};
use crate::render::{Amounts, Bidi, Renderer};
use crate::screen::ChosenForm;
use crate::sink::{PlainSink, Sink};

/// The modules a rendering drew from, each once, in the order it reached them.
#[derive(Debug, Default)]
pub(crate) struct Trail {
    modules: Vec<ModuleId>,
}

impl Trail {
    fn reach(&mut self, module: ModuleId) {
        if !self.modules.contains(&module) {
            self.modules.push(module);
        }
    }

    /// The modules.
    #[cfg(feature = "load")]
    pub(crate) fn into_modules(self) -> Vec<ModuleId> {
        self.modules
    }
}

/// A crate module's domain.
fn domain(module: &ModuleRecord) -> Option<&str> {
    match module.id.kind() {
        StoredKind::Crate(domain) => Some(domain),
        StoredKind::Main | StoredKind::Defined { .. } => None,
    }
}

/// A message read from its module's locale entry, and the entry's direction.
struct Found {
    message: MessageForm,
    direction: Direction,
}

/// An operand's value, held while a placeholder or a selector reads it.
enum Held<'t> {
    None,
    Literal(&'t str),
    Value(&'t Value),
    Text(Cow<'t, str>),
    List(ListKind, AllOf<String>),
}

impl Held<'_> {
    fn input(&self) -> Input<'_> {
        match self {
            Self::None => Input::None,
            Self::Literal(text) => Input::Literal(text),
            Self::Value(value) => Input::Value(value),
            Self::Text(text) => Input::Text(text),
            Self::List(kind, items) => Input::List { kind: *kind, items },
        }
    }
}

/// A query's arguments, one per parameter of its message, in the declaration's order.
struct Bound<'t> {
    param: &'t ParamForm,
    text: &'t Text,
}

/// Whether a parameter of `param`'s kind takes `text`: a stored text takes any.
fn admits(param: &ParamForm, text: &Text) -> bool {
    let kind = param.kind;
    let given = match text {
        Text::Absent => return param.presence == Presence::Optional,
        Text::Query(_) => ArgKind::Message,
        Text::Value(value) => BareKind::of(value).arg_kind(),
        Text::Name(_) => ArgKind::Name,
        Text::List { .. } => ArgKind::List,
        Text::Raw(_) | Text::Joined(_) => ArgKind::Raw,
    };
    kind == given || kind == ArgKind::Text
}

/// An amount's digits as written, a space, and its ISO 4217 code.
fn written(amount: Amount) -> String {
    let (units, scale) = (amount.value().units(), usize::from(amount.value().scale()));
    let digits = units.unsigned_abs().to_string();
    let padded = format!("{digits:0>width$}", width = scale + 1);
    let split = padded.len() - scale;
    let (whole, fraction) = (
        padded.get(..split).unwrap_or_default(),
        padded.get(split..).unwrap_or_default(),
    );
    let sign = if units < 0 { "-" } else { "" };
    let point = if scale > 0 { "." } else { "" };
    let code: String = amount
        .currency()
        .code()
        .iter()
        .map(|&b| char::from(b))
        .collect();
    format!("{sign}{whole}{point}{fraction} {code}")
}

impl Renderer<'_> {
    /// Writes a text, recording the modules it draws from.
    pub(crate) fn text(
        &self,
        text: &Text,
        sink: &mut dyn Sink,
        trail: &mut Trail,
    ) -> Result<(), RenderError> {
        match text {
            Text::Query(query) => self.query(query, sink, trail),
            Text::Value(value) => self.bare(BareKind::of(value), &Held::Value(value), sink, trail),
            Text::Name(name) => {
                sink.text(name);
                Ok(())
            }
            Text::List { kind, items } => {
                let items = items.try_map(|item| self.plain_text(item, trail))?;
                self.bare(BareKind::List, &Held::List(*kind, items), sink, trail)
            }
            Text::Absent => Err(RenderError::Absent),
            Text::Raw(raw) => {
                sink.text(raw);
                Ok(())
            }
            Text::Joined(items) => items
                .items()
                .iter()
                .try_for_each(|item| self.text(item, sink, trail)),
        }
    }

    /// A text rendered as plain text, to enter another as a string.
    fn plain_text(&self, text: &Text, trail: &mut Trail) -> Result<String, RenderError> {
        let mut sink = PlainSink::default();
        self.text(text, &mut sink, trail)?;
        Ok(sink.finish())
    }

    /// A bare value or list, through the main module's format of its kind.
    fn bare(
        &self,
        kind: BareKind,
        held: &Held<'_>,
        sink: &mut dyn Sink,
        trail: &mut Trail,
    ) -> Result<(), RenderError> {
        if let (Amounts::Written, Held::Value(Value::Amount(amount))) = (self.options.amounts, held)
        {
            sink.text(&written(*amount));
            return Ok(());
        }
        let main = self
            .manifest
            .modules
            .iter()
            .find(|module| *module.id.kind() == StoredKind::Main);
        let main = main.ok_or(RenderError::Bare { kind })?;
        let chosen = self.chosen_of(main, trail)?;
        let call = chosen
            .bare()
            .and_then(|bare| bare.get(kind))
            .ok_or(RenderError::Bare { kind })?;
        self.call(call, held, sink)
    }

    /// The package's module that holds a message of `id`: a crate module whose domain prefixes
    /// the identifier, the longest, else the main module.
    fn holder(&self, id: &str) -> Option<&ModuleRecord> {
        let modules = &self.manifest.modules;
        let holds = |domain: &str| {
            id.strip_prefix(domain)
                .is_some_and(|rest| rest.starts_with('.'))
        };
        let main = || {
            modules
                .iter()
                .find(|module| *module.id.kind() == StoredKind::Main)
        };
        modules
            .iter()
            .filter(|module| domain(module).is_some_and(holds))
            .max_by_key(|module| domain(module).map_or(0, str::len))
            .or_else(main)
    }

    /// The screen's locale entry of the module that holds `key`'s message, which the rendering
    /// then draws from: a package's module by [`Renderer::holder`], a defined module by its
    /// identity, in the package or carried beside it.
    fn holding(&self, key: &Key, trail: &mut Trail) -> Result<&ChosenForm<'_>, RenderError> {
        match key {
            Key::Message(id) => {
                let module = self.holder(id.as_str()).ok_or(RenderError::Unknown)?;
                self.chosen_of(module, trail)
            }
            Key::Defined { module, .. } => {
                let id = ModuleId::Defined(*module);
                if let Some(entry) = self.chosen.entries().iter().find(|e| *e.key() == id) {
                    trail.reach(id);
                    return Ok(entry.value());
                }
                match self.manifest.modules.iter().find(|record| record.id.is(id)) {
                    Some(record) => Err(RenderError::Outside {
                        module: record.id.name(),
                    }),
                    None => Err(RenderError::Unknown),
                }
            }
        }
    }

    /// The screen's locale entry of a package's module, which the rendering then draws from.
    fn chosen_of(
        &self,
        module: &ModuleRecord,
        trail: &mut Trail,
    ) -> Result<&ChosenForm<'_>, RenderError> {
        let entry = self
            .chosen
            .entries()
            .iter()
            .find(|entry| module.id.is(*entry.key()))
            .ok_or_else(|| RenderError::Outside {
                module: module.id.name(),
            })?;
        trail.reach(*entry.key());
        Ok(entry.value())
    }

    /// The message a query names, read from its module's locale entry, and the entry's direction.
    fn find(&self, key: &Key, trail: &mut Trail) -> Result<Found, RenderError> {
        let chosen = self.holding(key, trail)?;
        let id = match key {
            Key::Message(id) => id.as_str(),
            Key::Defined { key, .. } => key.as_str(),
        };
        let message = match chosen {
            ChosenForm::Package { index, .. } => {
                let entry = index.message(id).ok_or(RenderError::Unknown)?;
                self.package.message(&self.manifest, entry)?
            }
            ChosenForm::Carried { locale, .. } => {
                locale.message(id).cloned().ok_or(RenderError::Unknown)?
            }
        };
        Ok(Found {
            message,
            direction: chosen.direction(),
        })
    }

    /// Writes a query's message with its arguments.
    fn query(
        &self,
        query: &Query,
        sink: &mut dyn Sink,
        trail: &mut Trail,
    ) -> Result<(), RenderError> {
        let Found { message, direction } = self.find(query.key(), trail)?;
        let args = query.args();
        if args.len() != message.params.len() {
            return Err(RenderError::Arguments);
        }
        let mut bound = Vec::with_capacity(args.len());
        for param in &message.params {
            let arg = args
                .iter()
                .find(|arg: &&Entry<ParamName, Text>| *arg.key() == param.name);
            match arg {
                Some(arg) if admits(param, arg.value()) => bound.push(Bound {
                    param,
                    text: arg.value(),
                }),
                _ => return Err(RenderError::Arguments),
            }
        }
        let pattern = match &message.body {
            BodyForm::Pattern(pattern) => pattern,
            BodyForm::Select {
                selectors,
                variants,
            } => self.select(&message, selectors, variants, &bound, trail)?,
        };
        for part in pattern {
            match part {
                PartForm::Text(text) => sink.text(text),
                PartForm::Open(style) => sink.open(*style),
                PartForm::Close(style) => sink.close(*style),
                PartForm::Expression(index) => {
                    let expression = message
                        .expressions
                        .get(*index)
                        .ok_or(RenderError::Unknown)?;
                    let held = self.held(&expression.root, &bound, trail)?;
                    let dir = (expression.dir, direction);
                    self.placeholder(&expression.call, dir, &held, sink)?;
                }
            }
        }
        Ok(())
    }

    /// An operand's value: a literal, a typed value, a text, a list's items rendered, or a nested
    /// text rendered as a string.
    fn held<'t>(
        &self,
        root: &'t Root,
        bound: &[Bound<'t>],
        trail: &mut Trail,
    ) -> Result<Held<'t>, RenderError> {
        let index = match root {
            Root::None => return Ok(Held::None),
            Root::Literal(literal) => return Ok(Held::Literal(literal)),
            Root::Argument(index) => *index,
        };
        let Bound { param, text } = bound.get(index).ok_or(RenderError::Arguments)?;
        if matches!(param.kind, ArgKind::Message | ArgKind::Text) {
            return Ok(Held::Text(Cow::Owned(self.plain_text(text, trail)?)));
        }
        Ok(match text {
            Text::Absent => {
                return Err(RenderError::AbsentArgument {
                    argument: param.name.as_str().to_owned(),
                });
            }
            Text::Value(value) => Held::Value(value),
            Text::Name(name) => Held::Text(Cow::Borrowed(name)),
            Text::Raw(raw) => Held::Text(Cow::Borrowed(raw)),
            Text::List { kind, items } => {
                Held::List(*kind, items.try_map(|item| self.plain_text(item, trail))?)
            }
            Text::Query(_) | Text::Joined(_) => {
                Held::Text(Cow::Owned(self.plain_text(text, trail)?))
            }
        })
    }

    fn renderer(&self, call: &CompiledCall) -> Result<&'static dyn FormatRenderer, RenderError> {
        self.formats
            .get(&call.format)
            .ok_or_else(|| RenderError::Format(call.format.clone()))
    }

    /// Writes a value through its compiled call; an amount in `Written` mode as written.
    fn call(
        &self,
        call: &CompiledCall,
        held: &Held<'_>,
        sink: &mut dyn Sink,
    ) -> Result<(), RenderError> {
        if let (Amounts::Written, Held::Value(Value::Amount(amount))) = (self.options.amounts, held)
        {
            sink.text(&written(*amount));
            return Ok(());
        }
        self.renderer(call)?
            .render(&call.bytes, &held.input(), sink)
    }

    /// Writes a placeholder, isolated by the Default Bidi Strategy: `dir` is its `u:dir` and the
    /// message's direction.
    fn placeholder(
        &self,
        call: &CompiledCall,
        dir: (Dir, Direction),
        held: &Held<'_>,
        sink: &mut dyn Sink,
    ) -> Result<(), RenderError> {
        if self.options.bidi == Bidi::None {
            return self.call(call, held, sink);
        }
        let (dir, message) = dir;
        let direction = match dir {
            Dir::Ltr => Direction::Ltr,
            Dir::Rtl => Direction::Rtl,
            Dir::Auto => Direction::Unknown,
            Dir::Inherit => self.renderer(call)?.direction(&call.bytes, &held.input())?,
        };
        let open = match direction {
            Direction::Ltr if message == Direction::Ltr && dir == Dir::Inherit => {
                return self.call(call, held, sink);
            }
            Direction::Ltr => "\u{2066}",
            Direction::Rtl => "\u{2067}",
            Direction::Unknown => "\u{2068}",
        };
        sink.text(open);
        self.call(call, held, sink)?;
        sink.text("\u{2069}");
        Ok(())
    }

    /// The pattern of the best variant (spec/formatting.md "Pattern Selection").
    fn select<'f>(
        &self,
        message: &MessageForm,
        selectors: &[SelectorForm],
        variants: &'f [VariantForm],
        bound: &[Bound<'_>],
        trail: &mut Trail,
    ) -> Result<&'f [PartForm], RenderError> {
        let mut ranks: Vec<Vec<usize>> = Vec::with_capacity(selectors.len());
        for selector in selectors {
            let expression = message
                .expressions
                .get(selector.expression)
                .ok_or(RenderError::Unknown)?;
            let held = self.held(&expression.root, bound, trail)?;
            let renderer = self.renderer(&expression.call)?;
            let matched = renderer.select(
                &expression.call.bytes,
                &held.input(),
                VariantKeys::new(&selector.keys),
            )?;
            ranks.push(matched.iter().map(|key| key.index()).collect());
        }
        let rank = |column: usize, key: usize| {
            ranks
                .get(column)
                .and_then(|keys| keys.iter().position(|&k| k == key))
        };
        let matches = |variant: &VariantForm| {
            variant
                .keys
                .iter()
                .enumerate()
                .all(|(column, key)| match key {
                    KeyRef::CatchAll => true,
                    KeyRef::Key(key) => rank(column, *key).is_some(),
                })
        };
        let better = |candidate: &VariantForm, best: &VariantForm| {
            for (column, (a, b)) in candidate.keys.iter().zip(&best.keys).enumerate() {
                match (a, b) {
                    (KeyRef::CatchAll, KeyRef::CatchAll) => {}
                    (KeyRef::CatchAll, KeyRef::Key(_)) => return false,
                    (KeyRef::Key(_), KeyRef::CatchAll) => return true,
                    (KeyRef::Key(a), KeyRef::Key(b)) if a == b => {}
                    (KeyRef::Key(a), KeyRef::Key(b)) => return rank(column, *a) < rank(column, *b),
                }
            }
            false
        };
        let mut best: Option<&VariantForm> = None;
        for variant in variants.iter().filter(|variant| matches(variant)) {
            best = match best {
                Some(current) if !better(variant, current) => Some(current),
                _ => Some(variant),
            };
        }
        best.map(|variant| variant.pattern.as_slice())
            .ok_or(RenderError::Message(FormatFailure::BadSelector))
    }
}
