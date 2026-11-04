//! The engine's guarantees: each load rule refuses its fixture (I30), rendering is a function of
//! its inputs (I31), `Raw` is shown as written and classed (I32), one language serves a
//! presentation (I33), and a package serializes, reads back and renders the same whatever it
//! holds (I38).

mod language;
mod load_rules;
mod package;
mod raw;
mod render;

use siros_explain::{ArgKind, Domain, Explain, Messages, ModuleId, Value, checked};
use siros_i18n::{
    Amounts, Bidi, BuiltPackage, Call, Compilers, Declaration, Direction, FormatCompiler, FormatId,
    FormatRenderer, Formats, Input, LanguageFormats, LanguagePolicy, LocaleTag, Module,
    ModuleError, OnRenderError, Operand, Package, PackageBuilder, ParsedFormats, Refusal,
    RefusedOption, RenderError, RenderOptions, Renderer, Screen, Sink, VariantKey, VariantKeys,
};

/// The fixture crate's host messages.
#[derive(Debug, thiserror::Error, Explain)]
#[explain(domain = "fixture.host")]
pub(crate) enum Host {
    #[error("hello")]
    Hello,
    #[error("{name} asks")]
    Asks { name: String },
    #[error("{count} items")]
    Counted { count: u64 },
    #[error("because {reason}")]
    Nested { reason: Inner },
    #[error("note {note:?}")]
    Maybe { note: Option<String> },
}

/// A message another message names.
#[derive(Debug, thiserror::Error, Explain)]
#[explain(domain = "fixture.inner")]
pub(crate) enum Inner {
    #[error("inner {code}")]
    Code { code: &'static str },
}

/// The fixture module's identity.
pub(crate) const FIXTURE: ModuleId = ModuleId::Crate(checked!(Domain, "fixture"));

/// The English source of the fixture module, which loads.
pub(crate) const BODY: &str = "\
[host]
hello = Hello
asks = {$name} asks
counted = {$count :number} items
nested = because {$reason}
maybe = note {$note}

[inner]
code = inner {$code}

[formats.number]
digits = 3
";

/// A resource of `body` in `locale`.
pub(crate) fn source(locale: &str, body: &str) -> String {
    format!("@locale {locale}\n---\n{body}")
}

/// The fixture module's declaration.
pub(crate) fn declaration() -> Declaration {
    let mut messages = Host::messages();
    messages.extend(Inner::messages());
    Declaration::new(messages).expect("a declaration")
}

/// The fixture module from `sources`.
pub(crate) fn load(sources: &[&str]) -> Result<Module, ModuleError> {
    let compilers = Compilers::new(&[&PROBE]).expect("compilers");
    Module::load(
        FIXTURE,
        &declaration(),
        sources,
        LanguagePolicy::Any,
        &compilers,
    )
}

/// The options of the tests, with a bidi strategy.
pub(crate) const fn options(bidi: Bidi) -> RenderOptions {
    RenderOptions {
        amounts: Amounts::Formatted,
        bidi,
        on_error: OnRenderError::NoEntry,
    }
}

/// A tag.
pub(crate) fn tag(text: &str) -> LocaleTag {
    LocaleTag::parse(text).expect("a tag")
}

/// The formats of the tests: the probe beside `:string`.
pub(crate) fn formats() -> Formats {
    Formats::new(&[&PROBE]).expect("formats")
}

/// A package of `modules`, every key, in every locale they support.
pub(crate) fn package(modules: &[&Module]) -> BuiltPackage {
    let mut locales: Vec<LocaleTag> = modules
        .iter()
        .flat_map(|module| module.locales().cloned())
        .collect();
    locales.sort();
    locales.dedup();
    let mut builder = PackageBuilder::new(locales).expect("a builder");
    for module in modules {
        builder.module(module, None).expect("a module");
    }
    builder.finish()
}

/// The renderer of `built`'s `modules` in the first tag of `priority`.
pub(crate) fn renderer<'p>(
    built: &'p BuiltPackage,
    modules: &[&Module],
    priority: &[&str],
    formats: &'p Formats,
    bidi: Bidi,
) -> Renderer<'p> {
    let package = Package::read(built.bytes(), built.root()).expect("a package");
    let ids = modules.iter().map(|module| module.id()).collect();
    let screen = Screen::new(&package, ids).expect("a screen");
    let priority: Vec<LocaleTag> = priority.iter().map(|t| tag(t)).collect();
    let located = screen.locale(&priority, &[]).expect("a language");
    located
        .renderer(formats, options(bidi))
        .expect("a renderer")
}

/// A number module for the tests: `:number` over counts, writing their digits; its one option,
/// `digits`, is ASCII digits.
pub(crate) struct Probe;

/// The probe a build registers.
pub(crate) static PROBE: Probe = Probe;

impl FormatCompiler for Probe {
    fn id(&self) -> FormatId {
        checked!(FormatId, "number")
    }

    fn functions(&self) -> &'static [&'static str] {
        &["number"]
    }

    fn options(&self) -> &'static [&'static str] {
        &["digits"]
    }

    fn parse(
        &self,
        language: &LanguageFormats<'_>,
    ) -> Result<Box<dyn ParsedFormats>, RefusedOption> {
        let digits = language
            .option("digits")
            .expect("the loader gives every option");
        let text = digits.text();
        if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
            return Err(digits.refuse());
        }
        Ok(Box::new(Probe))
    }
}

impl ParsedFormats for Probe {
    fn compile(&self, call: &Call<'_>) -> Result<Vec<u8>, Refusal> {
        if !matches!(
            call.operand(),
            Operand::Argument(ArgKind::Count | ArgKind::Decimal)
        ) {
            return Err(Refusal::Operand);
        }
        match call.options().entries().first() {
            Some(option) => Err(Refusal::Option {
                option: (*option.key()).to_owned(),
            }),
            None => Ok(Vec::new()),
        }
    }
}

impl FormatRenderer for Probe {
    fn id(&self) -> FormatId {
        checked!(FormatId, "number")
    }

    fn direction(&self, _compiled: &[u8], _input: &Input<'_>) -> Result<Direction, RenderError> {
        Ok(Direction::Ltr)
    }

    fn render(
        &self,
        _compiled: &[u8],
        input: &Input<'_>,
        sink: &mut dyn Sink,
    ) -> Result<(), RenderError> {
        match input {
            Input::Value(Value::Count(count)) => {
                sink.text(&count.digits());
                Ok(())
            }
            _ => Err(RenderError::Message("bad-operand")),
        }
    }

    fn select<'k>(
        &self,
        _compiled: &[u8],
        _input: &Input<'_>,
        _keys: VariantKeys<'k>,
    ) -> Result<Vec<VariantKey<'k>>, RenderError> {
        Ok(Vec::new())
    }
}
