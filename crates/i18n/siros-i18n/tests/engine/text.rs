//! A resolved text: its placeholders isolated by MF2's Default Bidi Strategy, and its spans
//! styled by its markup.

use siros_i18n::{Bidi, Context, Span, Style, Styles};

use crate::Given;

/// MF2's Default Bidi Strategy (spec/formatting.md, "Handling Bidirectional Text"): a value of
/// unknown direction, as `:string`'s are, stands between U+2068 and U+2069 in a message of any
/// direction, and alone under `Bidi::None`.
#[test]
fn placeholders_isolate_by_the_default_bidi_strategy() {
    let context = |dir: &str, bidi: Bidi| {
        Context::builder()
            .bidi(bidi)
            .build()
            .module(&format!("@locale en\n{dir}---\nstring = {{$x}}\n"))
            .expect("the module loads")
    };
    let cases = [
        (context("@dir ltr\n", Bidi::Default), "\u{2068}5\u{2069}"),
        (context("@dir rtl\n", Bidi::Default), "\u{2068}5\u{2069}"),
        (context("", Bidi::Default), "\u{2068}5\u{2069}"),
        (context("@dir rtl\n", Bidi::None), "5"),
    ];
    for (context, expected) in cases {
        let text = context
            .resolve(&Given::with("string", "x", "5"))
            .expect("a text");
        assert_eq!(text.to_string(), expected);
    }
}

/// Markup opens and closes a style; adjacent text of one style set is one span, and a text
/// without characters is none.
#[test]
fn markup_styles_the_spans() {
    let body = "styled = {#strong}a{/strong}{#strong}b{/strong}{#emphasis}{/emphasis}c\
                {#strong}{#underline}d{/underline}{/strong}";
    let context = Context::new()
        .module(&format!("@locale en\n---\n{body}\n"))
        .expect("the module loads");
    let text = context.resolve(&Given::bare("styled")).expect("a text");
    let span = |text: &str, styles: &[Style]| Span {
        text: text.to_owned(),
        styles: styles
            .iter()
            .fold(Styles::empty(), |set, &style| set.with(style)),
    };
    assert_eq!(
        text.spans(),
        [
            span("ab", &[Style::Strong]),
            span("c", &[]),
            span("d", &[Style::Strong, Style::Underline]),
        ]
    );
    assert_eq!(text.to_string(), "abcd");
}
