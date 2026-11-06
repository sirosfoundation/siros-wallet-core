//! A defined module written in its render form with no loader renders as the loader's
//! compilation of the same messages, carried beside a package or held in one; each refusal rule
//! refuses its fixture.

use std::borrow::Cow;

use siros_explain::{
    ArgKind, Count, DefinedKey, DefinedModule, Domain, Entry, Explain, Keyed, Messages, ModuleId,
    ParamKind, Presence, Query, Text, Value, checked,
};
use siros_i18n::{
    Bidi, Body, Compilers, Declaration, DefinedError, DefinedForm, Formats, LanguagePolicy,
    LocaleTag, MainLocale, Module, Package, PackageBuilder, Part, Renderer, Screen, Style, Variant,
};

use crate::{PROBE, formats, options, tag};

/// The oracle's messages: the loader compiles them from MF2.
#[derive(Debug, thiserror::Error, Explain)]
#[explain(domain = "oracle.shown")]
enum Shown {
    #[error("label")]
    Label { name: String },
    #[error("counted")]
    Counted { count: u64 },
    #[error("choice")]
    Choice { e0: &'static str, c1: String },
}

/// The oracle's module.
const ORACLE: ModuleId = ModuleId::Crate(checked!(Domain, "oracle"));

/// The oracle's source in a locale: `pay` and `items` its words.
fn oracle_source(locale: &str, pay: &str, items: &str) -> String {
    format!(
        "@locale {locale}\n@dir ltr\n---\n[shown]\n\
         label = {pay} {{#strong}}{{$name}}{{/strong}}\n\
         counted = {{$count}} {items}\n\
         choice = .input {{$e0 :string}} .match $e0 live {{{{first {{$c1}}}}}} * {{{{last}}}}\n\
         \n[formats.number]\ndigits = 3\n"
    )
}

/// The main module: the probe's options, for bare counts, in each locale.
fn main_module(locales: &[&str]) -> Module {
    let sources: Vec<String> = locales
        .iter()
        .map(|locale| format!("@locale {locale}\n@dir ltr\n---\n[formats.number]\ndigits = 3\n"))
        .collect();
    let sources: Vec<&str> = sources.iter().map(String::as_str).collect();
    Module::load(
        ModuleId::Main,
        &Declaration::new(Vec::new()).expect("empty"),
        &sources,
        LanguagePolicy::Any,
        &Compilers::new(&[&PROBE]).expect("compilers"),
    )
    .expect("a main module")
}

const DEFINED: DefinedModule = DefinedModule::new(checked!(Domain, "probe"), [7; 32]);

fn key(text: &str) -> DefinedKey {
    DefinedKey::parse(text.to_owned()).expect("a key")
}

fn params(entries: &[(&'static str, ArgKind)]) -> Keyed<Cow<'static, str>, ParamKind> {
    Keyed::first_of(entries.iter().map(|(name, kind)| {
        Entry::new(
            Cow::Borrowed(*name),
            ParamKind::new(*kind, Presence::Required),
        )
    }))
}

/// The defined module's declaration: the oracle's keys and arguments.
fn declaration() -> Keyed<DefinedKey, Keyed<Cow<'static, str>, ParamKind>> {
    Keyed::first_of([
        Entry::new(key("label"), params(&[("name", ArgKind::Raw)])),
        Entry::new(key("counted"), params(&[("count", ArgKind::Count)])),
        Entry::new(
            key("choice"),
            params(&[("e0", ArgKind::Name), ("c1", ArgKind::Raw)]),
        ),
    ])
}

/// The defined module's bodies in a locale: the oracle's messages as parts.
fn bodies(pay: &str, items: &str) -> Keyed<DefinedKey, Body> {
    let text = |t: &str| Part::Text(t.to_owned());
    let argument = |name: &'static str| Part::Argument(Cow::Borrowed(name));
    Keyed::first_of([
        Entry::new(
            key("label"),
            Body::Pattern(vec![
                text(&format!("{pay} ")),
                Part::Open(Style::Strong),
                argument("name"),
                Part::Close(Style::Strong),
            ]),
        ),
        Entry::new(
            key("counted"),
            Body::Pattern(vec![argument("count"), text(&format!(" {items}"))]),
        ),
        Entry::new(
            key("choice"),
            Body::Select {
                selectors: vec![Cow::Borrowed("e0")],
                variants: vec![
                    Variant {
                        keys: vec![Some("live")],
                        pattern: vec![text("first "), argument("c1")],
                    },
                    Variant {
                        keys: vec![None],
                        pattern: vec![text("last")],
                    },
                ],
            },
        ),
    ])
}

/// The defined module over the main module's locales.
fn defined(main: &[MainLocale]) -> DefinedForm {
    let mut builder = DefinedForm::builder(DEFINED, LanguagePolicy::Any, declaration());
    for (locale, pay, items) in [("en", "Pay", "items"), ("de", "Zahle", "Dinge")] {
        let tag = tag(locale);
        let main = main.iter().find(|entry| *entry.locale() == tag);
        builder
            .locale(tag, main, &bodies(pay, items))
            .expect("a locale");
    }
    builder.finish()
}

/// Each oracle text with the defined module's text of the same message and arguments.
fn pairs() -> Vec<(Text, Text)> {
    let query = |name: &str, args: Vec<(&'static str, Text)>| {
        let args = args
            .into_iter()
            .map(|(name, text)| Entry::new(Cow::Borrowed(name), text));
        Text::Query(Query::defined(DEFINED, key(name), Keyed::first_of(args)))
    };
    let raw = |text: &str| Text::Raw(text.to_owned());
    vec![
        (
            Text::of(&Shown::Label {
                name: "Ada".to_owned(),
            }),
            query("label", vec![("name", raw("Ada"))]),
        ),
        (
            Text::of(&Shown::Counted { count: 42 }),
            query(
                "counted",
                vec![("count", Text::Value(Value::Count(Count::of(42))))],
            ),
        ),
        (
            Text::of(&Shown::Choice {
                e0: "live",
                c1: "Bo".to_owned(),
            }),
            query(
                "choice",
                vec![("e0", Text::Name("live")), ("c1", raw("Bo"))],
            ),
        ),
        (
            Text::of(&Shown::Choice {
                e0: "dead",
                c1: "Bo".to_owned(),
            }),
            query(
                "choice",
                vec![("e0", Text::Name("dead")), ("c1", raw("Bo"))],
            ),
        ),
    ]
}

/// A screen's renderer in the first tag of `priority`.
fn located<'p>(
    screen: Screen<'p>,
    priority: &[LocaleTag],
    formats: &'p Formats,
    bidi: Bidi,
) -> Renderer<'p> {
    screen
        .locale(priority, &[])
        .expect("a language")
        .renderer(formats, options(bidi))
        .expect("a renderer")
}

#[test]
fn a_defined_form_renders_as_the_loader_compiles_its_messages() {
    let main = main_module(&["en", "de"]);
    let oracle = Module::load(
        ORACLE,
        &Declaration::new(Shown::messages()).expect("a declaration"),
        &[
            &oracle_source("en", "Pay", "items"),
            &oracle_source("de", "Zahle", "Dinge"),
        ],
        LanguagePolicy::Any,
        &Compilers::new(&[&PROBE]).expect("compilers"),
    )
    .expect("the oracle loads");
    let locales = vec![tag("de"), tag("en")];
    let mut builder = PackageBuilder::new(locales.clone()).expect("a builder");
    builder.module(&main, None).expect("main");
    builder.module(&oracle, None).expect("the oracle");
    let without = builder.finish();
    let without = Package::read(without.bytes(), without.root()).expect("a package");
    let main_locales = without.main_locales().expect("the main locales");
    assert_eq!(
        Some(&main_locales),
        main.main_locales().as_ref(),
        "the package's main entries are the loaded main module's"
    );
    let form = defined(&main_locales);
    let mut builder = PackageBuilder::new(locales).expect("a builder");
    builder.module(&main, None).expect("main");
    builder.defined(&form).expect("the defined module");
    let with = builder.finish();
    let with = Package::read(with.bytes(), with.root()).expect("a package");
    let formats = formats();
    let carried = [form];
    for locale in ["en", "de"] {
        for bidi in [Bidi::Default, Bidi::None] {
            let priority = [tag(locale)];
            let render = |screen| located(screen, &priority, &formats, bidi);
            let oracle =
                render(Screen::new(&without, vec![ModuleId::Main, ORACLE]).expect("a screen"));
            let defined = ModuleId::Defined(DEFINED);
            let held = render(Screen::new(&with, vec![ModuleId::Main, defined]).expect("held"));
            let beside = render(
                Screen::carrying(&without, vec![ModuleId::Main, defined], &carried)
                    .expect("carried"),
            );
            for (expected, text) in pairs() {
                let expected = oracle.formatted(&expected).expect("the oracle renders");
                assert_eq!(held.formatted(&text).expect("held"), expected, "{text:?}");
                assert_eq!(
                    beside.formatted(&text).expect("beside"),
                    expected,
                    "{text:?}"
                );
            }
            assert_eq!(held.inputs(), beside.inputs(), "one digest in both places");
        }
    }
}

#[test]
fn each_refusal_rule_refuses_its_fixture() {
    let main = main_module(&["en"]).main_locales().expect("a main module");
    let en = main.first();
    let text = |t: &str| Part::Text(t.to_owned());
    let one = |name: &str, body: Body| Keyed::first_of([Entry::new(key(name), body)]);
    let only = |name: &str, kind: ArgKind| {
        DefinedForm::builder(
            DEFINED,
            LanguagePolicy::Any,
            Keyed::first_of([Entry::new(key(name), params(&[("a", kind)]))]),
        )
    };
    let select = |keys: Vec<Vec<Option<&'static str>>>| Body::Select {
        selectors: vec![Cow::Borrowed("a")],
        variants: keys
            .into_iter()
            .map(|keys| Variant {
                keys,
                pattern: vec![text("x")],
            })
            .collect(),
    };
    let cases: Vec<(&str, Result<(), DefinedError>, DefinedError)> = vec![
        (
            "a locale twice",
            {
                let mut builder = only("k", ArgKind::Raw);
                let body = one("k", Body::Pattern(vec![text("x")]));
                builder.locale(tag("en"), en, &body).expect("first");
                builder.locale(tag("en"), en, &body)
            },
            DefinedError::Locale(tag("en")),
        ),
        (
            "a key missing",
            only("k", ArgKind::Raw).locale(tag("en"), en, &Keyed::empty()),
            DefinedError::Missing {
                key: "k".to_owned(),
                locale: tag("en"),
            },
        ),
        (
            "a key undeclared",
            only("k", ArgKind::Raw).locale(
                tag("en"),
                en,
                &Keyed::first_of([
                    Entry::new(key("k"), Body::Pattern(vec![])),
                    Entry::new(key("other"), Body::Pattern(vec![])),
                ]),
            ),
            DefinedError::Undeclared {
                key: "other".to_owned(),
                locale: tag("en"),
            },
        ),
        (
            "an undeclared argument",
            only("k", ArgKind::Raw).locale(
                tag("en"),
                en,
                &one("k", Body::Pattern(vec![Part::Argument(Cow::Borrowed("b"))])),
            ),
            DefinedError::Argument {
                key: "k".to_owned(),
                argument: "b".to_owned(),
            },
        ),
        (
            "a typed argument without a main format",
            only("k", ArgKind::Count).locale(
                tag("fr"),
                None,
                &one("k", Body::Pattern(vec![Part::Argument(Cow::Borrowed("a"))])),
            ),
            DefinedError::Format {
                key: "k".to_owned(),
                locale: tag("fr"),
                argument: "a".to_owned(),
            },
        ),
        (
            "a selector over a count",
            only("k", ArgKind::Count).locale(tag("en"), en, &one("k", select(vec![vec![None]]))),
            DefinedError::Selector {
                key: "k".to_owned(),
                argument: "a".to_owned(),
            },
        ),
        (
            "no fallback variant",
            only("k", ArgKind::Name).locale(
                tag("en"),
                en,
                &one("k", select(vec![vec![Some("live")]])),
            ),
            DefinedError::Variants("k".to_owned()),
        ),
        (
            "markup closed unopened",
            only("k", ArgKind::Raw).locale(
                tag("en"),
                en,
                &one("k", Body::Pattern(vec![Part::Close(Style::Strong)])),
            ),
            DefinedError::Markup("k".to_owned()),
        ),
    ];
    for (case, result, expected) in cases {
        assert_eq!(result, Err(expected), "{case}");
    }
}
