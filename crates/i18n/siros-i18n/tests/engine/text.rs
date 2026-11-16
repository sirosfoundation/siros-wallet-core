//! A resolved text: its placeholders isolated by MF2's Default Bidi Strategy, and its spans
//! styled by its markup.

use siros_i18n::{Bidi, Context, Span, Style, Styles};

use crate::{Given, cldr};

/// MF2's Default Bidi Strategy (spec/formatting.md, "Handling Bidirectional Text"): a value of
/// left-to-right direction stands alone in a left-to-right message, and between U+2066 and
/// U+2069 otherwise; a right-to-left value between U+2067 and U+2069; a value of unknown
/// direction between U+2068 and U+2069. `:string`'s values are of unknown direction, and a
/// number takes the direction of its format section's module: English left to right, Hebrew
/// right to left.
#[test]
fn placeholders_isolate_by_the_default_bidi_strategy() {
    let body = "\
number = {$x :number}
string = {$x}";
    let context = |language: &str, dir: &str, bidi: Bidi| {
        let formats = cldr::formats(language).expect("the fixture");
        Context::new()
            .formatters(cldr::strings())
            .bidi(bidi)
            .module(&formats)
            .and_then(|context| context.module(&format!("@locale {language}\n{dir}---\n{body}\n")))
            .expect("the modules load")
    };
    let ltr = context("en", "@dir ltr\n", Bidi::Default);
    let rtl = context("en", "@dir rtl\n", Bidi::Default);
    let unknown = context("en", "", Bidi::Default);
    let hebrew_in_ltr = context("he", "@dir ltr\n", Bidi::Default);
    let hebrew = context("he", "@dir rtl\n", Bidi::Default);
    let none = context("he", "@dir ltr\n", Bidi::None);
    let cases = [
        (&ltr, "number", "5"),
        (&ltr, "string", "\u{2068}5\u{2069}"),
        (&rtl, "number", "\u{2066}5\u{2069}"),
        (&rtl, "string", "\u{2068}5\u{2069}"),
        (&unknown, "number", "\u{2066}5\u{2069}"),
        (&hebrew_in_ltr, "number", "\u{2067}5\u{2069}"),
        (&hebrew, "number", "\u{2067}5\u{2069}"),
        (&none, "number", "5"),
        (&none, "string", "5"),
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
