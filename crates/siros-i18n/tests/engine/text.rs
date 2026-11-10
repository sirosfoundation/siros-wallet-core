//! A resolved text: its placeholders isolated by MF2's Default Bidi Strategy, and its spans
//! styled by its markup.

use siros_i18n::{Bidi, Context, Span, Style, Styles};

use crate::{Given, cldr};

/// MF2's Default Bidi Strategy (spec/formatting.md, "Handling Bidirectional Text"): a value of
/// left-to-right direction stands alone in a left-to-right message without `u:dir`, and between
/// U+2066 and U+2069 otherwise; a right-to-left value between U+2067 and U+2069; a value of
/// unknown direction between U+2068 and U+2069. `:string`'s values are of unknown direction,
/// `u:dir` sets a value's, and English numbers are left to right.
#[test]
fn placeholders_isolate_by_the_default_bidi_strategy() {
    let body = "\
number = {$x :number}
number_ltr = {$x :number u:dir=ltr}
string = {$x}
string_ltr = {$x :string u:dir=ltr}
string_rtl = {$x :string u:dir=rtl}
string_auto = {$x :string u:dir=auto}";
    let formats = cldr::formats("en").expect("the en fixture");
    let context = |dir: &str, bidi: Bidi| {
        Context::new()
            .bidi(bidi)
            .module(&formats)
            .and_then(|context| context.module(&format!("@locale en\n{dir}---\n{body}\n")))
            .expect("the modules load")
    };
    let ltr = context("@dir ltr\n", Bidi::Default);
    let rtl = context("@dir rtl\n", Bidi::Default);
    let unknown = context("", Bidi::Default);
    let none = context("@dir rtl\n", Bidi::None);
    let cases = [
        (&ltr, "number", "5"),
        (&ltr, "number_ltr", "\u{2066}5\u{2069}"),
        (&ltr, "string", "\u{2068}5\u{2069}"),
        (&ltr, "string_ltr", "\u{2066}5\u{2069}"),
        (&ltr, "string_rtl", "\u{2067}5\u{2069}"),
        (&ltr, "string_auto", "\u{2068}5\u{2069}"),
        (&rtl, "number", "\u{2066}5\u{2069}"),
        (&rtl, "string_ltr", "\u{2066}5\u{2069}"),
        (&rtl, "string_rtl", "\u{2067}5\u{2069}"),
        (&unknown, "number", "\u{2066}5\u{2069}"),
        (&none, "number", "5"),
        (&none, "string_rtl", "5"),
    ];
    for (context, id, expected) in cases {
        let text = context.resolve(&Given::with(id, "x", "5")).expect("a text");
        assert_eq!(text.to_string(), expected, "{id}");
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
