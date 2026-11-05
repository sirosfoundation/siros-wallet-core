//! A rendering is a function of its text and its inputs, which the renderer reports; a text's
//! arguments are those its message declares, each of its declared kind; an absent argument,
//! an absent text and a module outside the screen are refused.

use std::borrow::Cow;

use siros_explain::{
    Amount, Count, Currency, Decimal, DefinedKey, DefinedModule, Domain, Entry, Keyed, ModuleId,
    Query, Text, Value, checked,
};
use siros_i18n::{
    Amounts, BareKind, Bidi, Compilers, LanguagePolicy, Module, Package, RENDERER, RenderError,
    RenderOptions, Screen, Style,
};

use crate::{
    BODY, Host, Inner, PROBE, declaration, formats, load, options, package, renderer, source, tag,
};

#[test]
fn the_digest_is_the_sha256_of_the_sources() {
    // sha256sum over the source's length as a big-endian u64 and its bytes (GNU coreutils 9.4).
    let text = "@locale en\n---\n[host]\nasks = {$name} asks for your {#strong}age{/strong}\n";
    let expected = "a9ded22a5185f931e3f652ad799601d363d29de6b64f938bd9a51c8d553fde1b";
    let declaration = siros_i18n::Declaration::new(vec![siros_explain::Message::new(
        checked!(siros_explain::MessageId, "example.host.asks"),
        None,
        siros_explain::names!("name"),
        [siros_explain::ParamKind::of::<String>()],
    )])
    .expect("a declaration");
    let id = ModuleId::Crate(checked!(Domain, "example"));
    let compilers = Compilers::new(&[]).expect("compilers");
    let module =
        Module::load(id, &declaration, &[text], LanguagePolicy::Any, &compilers).expect("a module");
    let hex: String = module.digest().iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, expected);
}

#[test]
fn equal_inputs_render_equal_bytes_and_each_input_counts() {
    let english = source("en", BODY);
    let (first, second) = (
        load(&[&english]).expect("a module"),
        load(&[&english]).expect("a module"),
    );
    let formats = formats();
    let (built_first, built_second) = (package(&[&first]), package(&[&second]));
    let (a, b) = (
        renderer(&built_first, &[&first], &["en"], &formats, Bidi::Default),
        renderer(&built_second, &[&second], &["en"], &formats, Bidi::Default),
    );
    assert_eq!(a.inputs(), b.inputs());
    assert_eq!(a.inputs().renderer(), RENDERER);
    assert_eq!(
        a.inputs().modules().get(&crate::FIXTURE),
        Some(&first.digest())
    );
    let texts = [
        Text::of(&Host::Asks {
            name: "Ada".to_owned(),
        }),
        Text::of(&Host::Counted { count: 3 }),
        Text::of(&Host::Nested {
            reason: Inner::Code { code: "x1" },
        }),
    ];
    assert_eq!(
        a.render(&texts).expect("texts"),
        b.render(&texts).expect("texts")
    );
    let altered = load(&[&source("en", &BODY.replace("Hello", "Hallo"))]).expect("a module");
    let built_altered = package(&[&altered]);
    assert_ne!(
        renderer(
            &built_altered,
            &[&altered],
            &["en"],
            &formats,
            Bidi::Default
        )
        .inputs(),
        a.inputs()
    );
    assert_ne!(
        renderer(&built_first, &[&first], &["en"], &formats, Bidi::None).inputs(),
        a.inputs()
    );
}

#[test]
fn a_nested_query_enters_as_a_string() {
    let english = source("en", BODY);
    let module = load(&[&english]).expect("a module");
    let formats = formats();
    let built = package(&[&module]);
    let renderer = renderer(&built, &[&module], &["en"], &formats, Bidi::Default);
    let text = Text::of(&Host::Nested {
        reason: Inner::Code { code: "x1" },
    });
    // The Default Bidi Strategy (spec/formatting.md): U+2068 and U+2069 around each placeholder
    // of unknown direction, U+2066 around a left-to-right one.
    assert_eq!(
        renderer.plain(&text).expect("a text"),
        "because \u{2068}inner \u{2068}x1\u{2069}\u{2069}"
    );
    let count = Text::of(&Host::Counted { count: 3 });
    assert_eq!(
        renderer.plain(&count).expect("a text"),
        "\u{2066}3\u{2069} items"
    );
}

#[test]
fn formatted_text_has_one_form() {
    let body = BODY.replace(
        "hello = Hello",
        "hello = {#strong}a{/strong}{#strong}b{/strong}{#emphasis}{/emphasis}c{#strong}{#underline}d{/underline}{/strong}",
    );
    let module = load(&[&source("en", &body)]).expect("a module");
    let formats = formats();
    let built = package(&[&module]);
    let renderer = renderer(&built, &[&module], &["en"], &formats, Bidi::None);
    let formatted = renderer.formatted(&Text::of(&Host::Hello)).expect("a text");
    let spans: Vec<(&str, &[Style])> = formatted
        .spans()
        .iter()
        .map(|span| (span.text(), span.styles()))
        .collect();
    let expected: [(&str, &[Style]); 3] = [
        ("ab", &[Style::Strong]),
        ("c", &[]),
        ("d", &[Style::Strong, Style::Underline]),
    ];
    assert_eq!(spans, expected);
    assert_eq!(
        renderer.plain(&Text::of(&Host::Hello)).expect("a text"),
        formatted.plain()
    );
}

#[test]
fn arguments_follow_their_declaration() {
    let english = source("en", BODY);
    let defined = DefinedModule::new(checked!(Domain, "fixture"), [7; 32]);
    let compilers = Compilers::new(&[&PROBE]).expect("compilers");
    let module = Module::load(
        ModuleId::Defined(defined),
        &declaration(),
        &[&english
            .replace("[host]", "[fixture.host]")
            .replace("[inner]", "[fixture.inner]")],
        LanguagePolicy::Any,
        &compilers,
    )
    .expect("a module");
    let formats = formats();
    let built = package(&[&module]);
    let renderer = renderer(&built, &[&module], &["en"], &formats, Bidi::None);
    let query = |args: Vec<(&'static str, Text)>| {
        let args = args
            .into_iter()
            .map(|(name, text)| Entry::new(Cow::Borrowed(name), text))
            .collect();
        let key = DefinedKey::parse("fixture.host.asks".to_owned()).expect("a key");
        Text::Query(Query::defined(
            defined,
            key,
            Keyed::new(args).expect("distinct"),
        ))
    };
    assert_eq!(
        renderer
            .plain(&query(vec![("name", Text::Raw("Ada".to_owned()))]))
            .expect("a text"),
        "Ada asks"
    );
    let count = Text::Value(Value::Count(Count::of(1)));
    for args in [
        vec![("name", count)],
        vec![],
        vec![
            ("name", Text::Raw("Ada".to_owned())),
            ("extra", Text::Absent),
        ],
    ] {
        assert_eq!(
            renderer.plain(&query(args)).expect_err("refused"),
            RenderError::Arguments
        );
    }
    let crate_module = load(&[&english]).expect("a module");
    let built_crate = package(&[&crate_module]);
    let crate_renderer = crate::renderer(
        &built_crate,
        &[&crate_module],
        &["en"],
        &formats,
        Bidi::None,
    );
    let absent = Text::of(&Host::Maybe { note: None });
    assert_eq!(
        crate_renderer.plain(&absent).expect_err("refused"),
        RenderError::AbsentArgument {
            argument: "note".to_owned()
        }
    );
    let given = Text::of(&Host::Maybe {
        note: Some("kept".to_owned()),
    });
    assert_eq!(crate_renderer.plain(&given).expect("a text"), "note kept");
    assert_eq!(
        renderer.plain(&Text::Absent).expect_err("refused"),
        RenderError::Absent
    );
    let unknown = Text::of(&Host::Hello);
    assert_eq!(
        renderer.plain(&unknown).expect_err("refused"),
        RenderError::Unknown
    );
}

#[test]
fn bare_values_take_the_main_module_and_amounts_their_mode() {
    let main = Module::load(
        ModuleId::Main,
        &siros_i18n::Declaration::new(Vec::new()).expect("empty"),
        &["@locale en\n---\n[formats.number]\ndigits = 3\n"],
        LanguagePolicy::Any,
        &Compilers::new(&[&PROBE]).expect("compilers"),
    )
    .expect("a main module");
    let crate_module = load(&[&source("en", BODY)]).expect("a module");
    let formats = formats();
    let count = Text::Value(Value::Count(Count::of(42)));
    let built_main = package(&[&main]);
    let with_main = renderer(&built_main, &[&main], &["en"], &formats, Bidi::Default);
    assert_eq!(with_main.plain(&count).expect("a text"), "42");
    let built_crate = package(&[&crate_module]);
    let without = renderer(
        &built_crate,
        &[&crate_module],
        &["en"],
        &formats,
        Bidi::Default,
    );
    assert_eq!(
        without.plain(&count).expect_err("refused"),
        RenderError::Bare {
            kind: BareKind::Count
        }
    );
    let currency = |code: &str| Currency::from_code(code).expect("ISO 4217");
    let amount = |units, scale, code| {
        Text::Value(Value::Amount(Amount::new(
            Decimal::new(units, scale).expect("a decimal"),
            currency(code),
        )))
    };
    let package_main = Package::read(built_main.bytes(), built_main.root()).expect("a package");
    let screen = Screen::new(&package_main, vec![ModuleId::Main]).expect("a screen");
    let written = RenderOptions {
        amounts: Amounts::Written,
        ..options(Bidi::Default)
    };
    let located = screen.locale(&[tag("en")], &[]).expect("en");
    let renderer = located.renderer(&formats, written).expect("a renderer");
    for (text, expected) in [
        (amount(-1250, 2, "EUR"), "-12.50 EUR"),
        (amount(5, 3, "BHD"), "0.005 BHD"),
        (amount(1200, 0, "JPY"), "1200 JPY"),
    ] {
        assert_eq!(renderer.plain(&text).expect("an amount"), expected);
    }
    assert_eq!(
        with_main.plain(&amount(1, 0, "EUR")).expect_err("refused"),
        RenderError::Bare {
            kind: BareKind::Amount
        }
    );
}

#[test]
fn a_build_registers_each_format_once_and_every_compiled_one() {
    assert_eq!(
        siros_i18n::Formats::new(&[&PROBE, &PROBE]).err(),
        Some(RenderError::Registered("number"))
    );
    let module = load(&[&source("en", BODY)]).expect("a module");
    let built = package(&[&module]);
    let package = Package::read(built.bytes(), built.root()).expect("a package");
    let screen = Screen::new(&package, vec![crate::FIXTURE]).expect("a screen");
    let located = screen.locale(&[tag("en")], &[]).expect("en");
    let without = siros_i18n::Formats::new(&[]).expect("formats");
    assert_eq!(
        located.renderer(&without, options(Bidi::None)).err(),
        Some(RenderError::Format("number".to_owned()))
    );
}
