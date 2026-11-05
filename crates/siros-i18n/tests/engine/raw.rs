//! I32: `Raw` is the last resort. A raw text is shown as written, and every argument of kind
//! `Raw` among the crate's messages is classed.

use siros_explain::{ArgKind, Message, Messages, Text};
use siros_i18n::{
    Bidi, InvalidTag, ModuleError, NoLanguage, PackageError, Refusal, RefusedOption, RenderError,
    ResourceRule, Validity,
};

use crate::{BODY, Host, formats, load, package, renderer, source};

#[test]
fn a_raw_text_is_shown_as_written() {
    let module = load(&[&source("en", BODY)]).expect("a module");
    let formats = formats();
    let built = package(&[&module]);
    let renderer = renderer(&built, &[&module], &["en"], &formats, Bidi::Default);
    // MF2 syntax, a backslash, a bidi isolate and a text outside NFC: none of them is read.
    let written = "{$x} \\ {#strong}|\u{2068}D\u{323}\u{307}";
    let alone = renderer
        .formatted(&Text::Raw(written.to_owned()))
        .expect("a text");
    assert_eq!(alone.spans().len(), 1);
    assert_eq!(
        (alone.spans()[0].text(), alone.spans()[0].styles()),
        (written, &[][..])
    );
    let argument = renderer
        .plain(&Text::of(&Host::Asks {
            name: written.to_owned(),
        }))
        .expect("a text");
    assert_eq!(argument, format!("\u{2068}{written}\u{2069} asks"));
}

/// Why an argument is `Raw`, by section 4.14's classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    /// A received value without a type: text quoted from a module's source or a received
    /// identity, which the refusal names as written.
    Received,
}

/// Each `Raw` argument of the crate's messages, by message and argument, and its class.
const CLASSED: &[(&str, &str, Class)] = &[
    ("i18n.module.locale", "locale", Class::Received),
    ("i18n.module.outside", "message", Class::Received),
    ("i18n.module.declaration", "message", Class::Received),
    ("i18n.module.parameter_name", "key", Class::Received),
    ("i18n.module.parameter_name", "name", Class::Received),
    ("i18n.module.repeated", "key", Class::Received),
    ("i18n.module.repeated", "locale", Class::Received),
    ("i18n.module.missing", "key", Class::Received),
    ("i18n.module.missing", "locale", Class::Received),
    ("i18n.module.undeclared", "key", Class::Received),
    ("i18n.module.undeclared", "locale", Class::Received),
    ("i18n.module.syntax", "key", Class::Received),
    ("i18n.module.syntax", "locale", Class::Received),
    ("i18n.module.invalid", "key", Class::Received),
    ("i18n.module.invalid", "locale", Class::Received),
    ("i18n.module.argument", "key", Class::Received),
    ("i18n.module.argument", "locale", Class::Received),
    ("i18n.module.argument", "argument", Class::Received),
    ("i18n.module.function", "key", Class::Received),
    ("i18n.module.function", "locale", Class::Received),
    ("i18n.module.function", "function", Class::Received),
    ("i18n.module.kind", "key", Class::Received),
    ("i18n.module.kind", "locale", Class::Received),
    ("i18n.module.kind", "call", Class::Received),
    ("i18n.module.bare", "locale", Class::Received),
    ("i18n.module.markup", "key", Class::Received),
    ("i18n.module.markup", "locale", Class::Received),
    ("i18n.module.markup", "markup", Class::Received),
    ("i18n.module.markup_option", "key", Class::Received),
    ("i18n.module.markup_option", "locale", Class::Received),
    ("i18n.module.markup_option", "markup", Class::Received),
    ("i18n.module.nesting", "key", Class::Received),
    ("i18n.module.nesting", "locale", Class::Received),
    ("i18n.module.nesting", "markup", Class::Received),
    ("i18n.module.format", "format", Class::Received),
    ("i18n.module.format", "locale", Class::Received),
    ("i18n.module.unknown_option", "format", Class::Received),
    ("i18n.module.unknown_option", "option", Class::Received),
    ("i18n.module.unknown_option", "locale", Class::Received),
    ("i18n.module.option", "locale", Class::Received),
    ("i18n.module.option_text", "locale", Class::Received),
    ("i18n.module.option_text", "text", Class::Received),
    ("i18n.resource.metadata", "name", Class::Received),
    ("i18n.resource.tag", "tag", Class::Received),
    ("i18n.resource.direction", "direction", Class::Received),
    (
        "i18n.validity.missing_selector_annotation",
        "variable",
        Class::Received,
    ),
    (
        "i18n.validity.duplicate_declaration",
        "variable",
        Class::Received,
    ),
    (
        "i18n.validity.duplicate_option_name",
        "option",
        Class::Received,
    ),
    ("i18n.refusal.option", "option", Class::Received),
    ("i18n.render.absent_argument", "argument", Class::Received),
    ("i18n.render.outside", "module", Class::Received),
    ("i18n.render.format", "format", Class::Received),
    ("i18n.language.not_understood", "module", Class::Received),
    ("i18n.language.selected", "module", Class::Received),
    ("i18n.language.selected", "locale", Class::Received),
    ("i18n.package.module", "module", Class::Received),
    ("i18n.package.repeated_locale", "locale", Class::Received),
    ("i18n.package.repeated_module", "module", Class::Received),
    ("i18n.package.repeated_key", "module", Class::Received),
    ("i18n.package.repeated_key", "key", Class::Received),
    ("i18n.package.key", "module", Class::Received),
    ("i18n.package.key", "key", Class::Received),
    (
        "i18n.package.repeated_credential",
        "credential",
        Class::Received,
    ),
    (
        "i18n.package.repeated_transaction",
        "transaction",
        Class::Received,
    ),
    ("i18n.locale.invalid_tag", "tag", Class::Received),
];

#[test]
fn every_raw_argument_is_classed() {
    let groups: [Vec<Message>; 9] = [
        ModuleError::messages(),
        ResourceRule::messages(),
        Validity::messages(),
        Refusal::messages(),
        RefusedOption::messages(),
        RenderError::messages(),
        NoLanguage::messages(),
        PackageError::messages(),
        InvalidTag::messages(),
    ];
    let mut raw = Vec::new();
    for message in groups.iter().flatten() {
        for param in message.params() {
            if param.kind().kind() == ArgKind::Raw {
                raw.push((message.id().as_str(), param.name().as_str()));
            }
        }
    }
    let unclassed: Vec<_> = raw
        .iter()
        .filter(|(id, name)| !CLASSED.iter().any(|(i, n, _)| i == id && n == name))
        .collect();
    assert!(
        unclassed.is_empty(),
        "unclassed Raw arguments: {unclassed:?}"
    );
    let stale: Vec<_> = CLASSED
        .iter()
        .filter(|(i, n, _)| !raw.contains(&(*i, *n)))
        .collect();
    assert!(
        stale.is_empty(),
        "classed arguments that are no Raw argument: {stale:?}"
    );
}
