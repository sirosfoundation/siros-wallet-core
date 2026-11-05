//! One fixture per load rule, each refused for its rule and no other.

use std::borrow::Cow;

use siros_explain::{
    ArgKind, DefinedKey, Domain, Entry, Keyed, Message, MessageId, ModuleId, ParamKind, Presence,
    checked, names,
};
use siros_i18n::{
    Compilers, Declaration, LanguagePolicy, Module, ModuleError, Refusal, ResourceRule, Validity,
};

use crate::{BODY, PROBE, declaration, load, source};

/// The fixture module from the English source with `from` replaced by `to`.
fn altered(from: &str, to: &str) -> Result<Module, ModuleError> {
    assert!(BODY.contains(from), "the fixture holds {from:?}");
    load(&[&source("en", &BODY.replacen(from, to, 1))])
}

/// The rule a refusal names, for the fixtures that refuse a source's resource format.
fn resource(text: &str) -> ResourceRule {
    match load(&[text]) {
        Err(ModuleError::Resource { rule, .. }) => rule,
        other => panic!("{text:?} gave {other:?}"),
    }
}

#[test]
fn the_fixture_loads() {
    let english = source("en", BODY);
    let german = source("de", &BODY.replace("Hello", "Hallo"));
    let module = load(&[&english, &german]).expect("the fixture loads");
    assert_eq!(
        module
            .locales()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["en", "de"]
    );
}

#[test]
fn each_resource_rule_refuses_its_fixture() {
    let entry = format!("hello = x\n{}", source("en", BODY));
    let cases = [
        (
            source("en", &format!("  stray\n{BODY}")),
            ResourceRule::Line,
        ),
        (
            source("en", &BODY.replace("= Hello", "= Hel\\qlo")),
            ResourceRule::Escape,
        ),
        ("@locale en\n".to_owned(), ResourceRule::Frontmatter),
        (
            format!("{}---\n", source("en", BODY)),
            ResourceRule::Frontmatter,
        ),
        (entry, ResourceRule::Order),
        (
            format!("@author someone\n{}", source("en", BODY)),
            ResourceRule::Metadata {
                name: "author".to_owned(),
            },
        ),
        (format!("---\n{BODY}"), ResourceRule::NoLocale),
        (
            source("e_n", BODY),
            ResourceRule::Tag {
                tag: "e_n".to_owned(),
            },
        ),
        (
            format!("@dir up\n{}", source("en", BODY)),
            ResourceRule::Direction {
                direction: "up".to_owned(),
            },
        ),
    ];
    for (text, rule) in cases {
        assert_eq!(resource(&text), rule, "{text:?}");
    }
}

#[test]
fn each_module_rule_refuses_its_fixture() {
    let en = || "en".to_owned();
    let key = |key: &str| key.to_owned();
    let english = source("en", BODY);
    let other = ModuleId::Crate(checked!(Domain, "other"));
    let compilers = Compilers::new(&[&PROBE]).expect("compilers");
    let cases: Vec<(Result<Module, ModuleError>, ModuleError)> = vec![
        (load(&[&english, &english]), ModuleError::Locale(en())),
        (
            Module::load(
                other,
                &declaration(),
                &[&english],
                LanguagePolicy::Any,
                &compilers,
            ),
            ModuleError::Outside("fixture.host.asks".to_owned()),
        ),
        (
            altered("hello = Hello", "hello = Hello\nhello = Hi"),
            ModuleError::Repeated {
                key: key("host.hello"),
                locale: en(),
            },
        ),
        (
            altered("hello = Hello\n", ""),
            ModuleError::Missing {
                key: key("host.hello"),
                locale: en(),
            },
        ),
        (
            altered("hello = Hello", "hello = Hello\nbye = Bye"),
            ModuleError::Undeclared {
                key: key("host.bye"),
                locale: en(),
            },
        ),
        (
            altered("= Hello", "= {Hello"),
            ModuleError::Syntax {
                key: key("host.hello"),
                locale: en(),
                at: 6,
            },
        ),
        (
            altered("= Hello", "= .local $a = {a} .local $a = {b} {{x}}"),
            ModuleError::Invalid {
                key: key("host.hello"),
                locale: en(),
                rule: Validity::DuplicateDeclaration {
                    variable: "a".to_owned(),
                },
            },
        ),
        (
            altered("= Hello", "= {$nobody}"),
            ModuleError::Argument {
                key: key("host.hello"),
                locale: en(),
                argument: "nobody".to_owned(),
            },
        ),
        (
            altered("= Hello", "= {|x| :nothing}"),
            ModuleError::Function {
                key: key("host.hello"),
                locale: en(),
                function: "nothing".to_owned(),
            },
        ),
        (
            altered("{$name} asks", "{$name :number} asks"),
            ModuleError::Kind {
                key: key("host.asks"),
                locale: en(),
                call: "$name :number".to_owned(),
                refusal: Refusal::Operand,
            },
        ),
        (
            altered("{$count :number}", "{$count :number style=percent}"),
            ModuleError::Kind {
                key: key("host.counted"),
                locale: en(),
                call: "$count :number".to_owned(),
                refusal: Refusal::Option {
                    option: "style".to_owned(),
                },
            },
        ),
        (
            altered("= Hello", "= {#bold}Hello{/bold}"),
            ModuleError::Markup {
                key: key("host.hello"),
                locale: en(),
                markup: "bold".to_owned(),
            },
        ),
        (
            altered("= Hello", "= {#strong a=b}Hello{/strong}"),
            ModuleError::MarkupOption {
                key: key("host.hello"),
                locale: en(),
                markup: "strong".to_owned(),
            },
        ),
        (
            altered("= Hello", "= {#strong}Hello"),
            ModuleError::Nesting {
                key: key("host.hello"),
                locale: en(),
                markup: "strong".to_owned(),
            },
        ),
        (
            altered(
                "[formats.number]",
                "[formats.string]\nx = y\n\n[formats.number]",
            ),
            ModuleError::Format {
                format: "string".to_owned(),
                locale: en(),
            },
        ),
        (
            altered("digits = 3", "digits = 3\ngroup = ,"),
            ModuleError::UnknownOption {
                format: "number".to_owned(),
                option: "group".to_owned(),
                locale: en(),
            },
        ),
        (
            altered("digits = 3\n", ""),
            ModuleError::Option {
                format: "number",
                option: "digits",
                locale: en(),
            },
        ),
        (
            altered("digits = 3", "digits = three"),
            ModuleError::OptionText {
                format: "number",
                option: "digits",
                locale: en(),
                text: "three".to_owned(),
            },
        ),
    ];
    for (loaded, expected) in cases {
        assert_eq!(loaded.expect_err("refused"), expected);
    }
}

#[test]
fn declarations_and_registrations_refuse_their_fixtures() {
    let id = checked!(MessageId, "fixture.host.hello");
    let twice = vec![
        Message::new(id, Some("a"), names!(), []),
        Message::new(id, Some("b"), names!(), []),
    ];
    assert_eq!(
        Declaration::new(twice).expect_err("refused"),
        ModuleError::Declaration("fixture.host.hello".to_owned())
    );
    let same = vec![
        Message::new(id, Some("a"), names!(), []),
        Message::new(id, Some("a"), names!(), []),
    ];
    assert_eq!(
        Declaration::new(same).expect("counted once").ids().count(),
        1
    );
    // A converter's argument name is one or more tokens, as a type's `Names` are.
    let key = DefinedKey::parse("label".to_owned()).expect("a key");
    let param = |name: &'static str| {
        let kind = ParamKind::new(ArgKind::Raw, Presence::Required);
        Keyed::new(vec![Entry::new(Cow::Borrowed(name), kind)]).expect("one name")
    };
    assert_eq!(
        Declaration::defined(
            Keyed::new(vec![Entry::new(key.clone(), param("1x"))]).expect("one key")
        )
        .expect_err("refused"),
        ModuleError::ParameterName {
            key: "label".to_owned(),
            name: "1x".to_owned(),
        }
    );
    assert!(
        Declaration::defined(Keyed::new(vec![Entry::new(key, param("c1"))]).expect("one key"))
            .is_ok()
    );
    assert!(matches!(
        Compilers::new(&[&PROBE, &PROBE]),
        Err(ModuleError::Compiler("number"))
    ));
}
