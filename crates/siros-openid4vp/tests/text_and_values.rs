//! The text rules against their standards' own data: RFC 4647 §3.4's Lookup examples,
//! CommonMark 0.31.2's emphasis examples (`data/commonmark-0.31.2-spec.json`, spec.commonmark.org
//! 0.31.2, SHA-256 d431b29d97b6f73e69d547109cf5081578fac931e72afe95639ebe766c1b2a20), and the
//! value kinds of PaSO View §3 formatted as its examples show them.

use serde_json::Value as Json;
use siros_openid4vp::ids::LocaleTag;
use siros_openid4vp::rows::{
    Amounts, Choice, Date, Env, EnvError, FormattedKind, HttpsUrl, Label, Parsed, Shown,
    TableLocale, Value, Written,
};
use siros_openid4vp::text::{Span, Style, commonmark_html, lookup, lookup_chain, spans};

fn tag(text: &'static str) -> LocaleTag<'static> {
    LocaleTag::parse(text).expect("tag")
}

fn styled(parts: &[(&str, Style)]) -> Vec<Span> {
    parts
        .iter()
        .map(|(text, style)| Span {
            text: (*text).to_owned(),
            style: *style,
        })
        .collect()
}

const EM: Style = Style::EM;
const STRONG: Style = Style::STRONG;
const PLAIN: Style = Style::PLAIN;
const UNDERLINE: Style = Style::UNDERLINE;

#[test]
fn rfc_4647_lookup_follows_the_sections_examples() {
    assert_eq!(
        lookup_chain("zh-Hant-CN-x-private1-private2"),
        [
            "zh-Hant-CN-x-private1-private2",
            "zh-Hant-CN-x-private1",
            "zh-Hant-CN",
            "zh-Hant",
            "zh"
        ]
    );
    // §3.4: de-ch finds de or de-CH, never de-CH-1996.
    let range = tag("de-ch");
    assert_eq!(lookup(&range, &["de-CH-1996", "de"]), Some(&"de"));
    assert_eq!(lookup(&range, &["de-CH", "de"]), Some(&"de-CH"));
    assert_eq!(lookup(&range, &["de-CH-1996"]), None);
    assert!(
        LocaleTag::parse("*").is_err(),
        "a priority list holds concrete tags"
    );
}

#[test]
fn commonmark_emphasis_examples_render_as_the_specification_states() {
    let spec: Json =
        serde_json::from_str(include_str!("data/commonmark-0.31.2-spec.json")).expect("spec");
    let chosen: Vec<&Json> = spec
        .as_array()
        .expect("examples")
        .iter()
        .filter(|e| e["section"] == "Emphasis and strong emphasis")
        .filter(|e| {
            let markdown = e["markdown"].as_str().expect("markdown");
            !markdown.contains(['`', '[', ']', '<', '>', '\\', '&', '!'])
                && markdown.matches('\n').count() == 1
        })
        .collect();
    let failures: Vec<String> = chosen
        .iter()
        .filter_map(|e| {
            let markdown = e["markdown"].as_str().expect("markdown");
            let got = commonmark_html(markdown.trim_end_matches('\n'));
            (got != e["html"].as_str().expect("html"))
                .then(|| format!("example {}: {markdown:?} gave {got:?}", e["example"]))
        })
        .collect();
    assert_eq!(chosen.len(), 108, "the inline-only examples of the section");
    assert_eq!(failures, Vec::<String>::new());
    // The section's examples where emphasis nests, which a span carries as one style, and where
    // an escape, raw HTML, a code span or an autolink takes precedence over emphasis, which
    // mini_markdown keeps as written.
    let flattened: [(u64, &[(&str, Style)]); 13] = [
        (408, &[("foo bar", EM)]),
        (467, &[("foo", Style::EM.with(Style::STRONG))]),
        (437, &[("foo ", PLAIN), ("\\*", EM)]),
        (440, &[("foo ", PLAIN), ("\\*", STRONG)]),
        (449, &[("foo ", PLAIN), ("\\_", EM)]),
        (452, &[("foo ", PLAIN), ("\\_", STRONG)]),
        (475, &[(r#"*<img src="foo" title="*"/>"#, PLAIN)]),
        (476, &[(r#"**<a href="**">"#, PLAIN)]),
        (477, &[(r#"__<a href="__">"#, PLAIN)]),
        (478, &[("a `*`", EM)]),
        (479, &[("a `_`", EM)]),
        (480, &[("**a<https://foo.bar/?q=**>", PLAIN)]),
        (481, &[("__a<https://foo.bar/?q=__>", PLAIN)]),
    ];
    let examples = spec.as_array().expect("examples");
    for (number, want) in flattened {
        let example = examples
            .iter()
            .find(|e| e["example"] == number)
            .expect("example");
        let markdown = example["markdown"].as_str().expect("markdown");
        assert_eq!(
            spans(markdown.trim_end_matches('\n')),
            styled(want),
            "example {number}"
        );
    }
    let [strong_em] = spans("***foo***").try_into().expect("one span");
    assert!(strong_em.style.has(EM) && strong_em.style.has(STRONG));
    assert!(!strong_em.style.has(UNDERLINE));
}

#[test]
fn mini_markdown_keeps_every_other_construct_literal() {
    // <u> underlines; escapes, code spans and raw HTML take precedence and stay literal;
    // emphasis does not pair across lines.
    assert_eq!(
        spans("- a **b** <u>c</u> `*d*` \\*e* <a href='*'>*f*</a>"),
        styled(&[
            ("- a ", PLAIN),
            ("b", STRONG),
            (" ", PLAIN),
            ("c", UNDERLINE),
            (" `*d*` \\*e* <a href='*'>", PLAIN),
            ("f", EM),
            ("</a>", PLAIN)
        ])
    );
    assert_eq!(spans("*a\nb*"), styled(&[("*a\nb*", PLAIN)]));
    // CommonMark §6.1: a backtick run closes only on a run of its length; unclosed, it stays
    // literal, as an unpaired <u> or </u> does. §6.5-6.6: a delimiter inside an autolink or a
    // tag is text. A `<` that starts neither, such as one before a digit, leaves its delimiters
    // free to pair.
    let cases: [(&str, &[(&str, Style)]); 14] = [
        ("a `b *c*", &[("a `b ", PLAIN), ("c", EM)]),
        ("`a``b *c*", &[("`a``b ", PLAIN), ("c", EM)]),
        ("``a`b *c*`", &[("``a`b *c*`", PLAIN)]),
        ("``a`b`` *c*", &[("``a`b`` ", PLAIN), ("c", EM)]),
        ("a <u>b", &[("a <u>b", PLAIN)]),
        ("a </u>b", &[("a </u>b", PLAIN)]),
        ("`", &[("`", PLAIN)]),
        ("*a <b c=*>", &[("*a <b c=*>", PLAIN)]),
        ("x <br/>*b*", &[("x <br/>", PLAIN), ("b", EM)]),
        ("*x <https://a.b/*>", &[("*x <https://a.b/*>", PLAIN)]),
        ("*x <a*b>", &[("x <a", EM), ("b>", PLAIN)]),
        ("*x <a/*>", &[("x <a/", EM), (">", PLAIN)]),
        ("*x <ab*c>", &[("x <ab", EM), ("c>", PLAIN)]),
        ("*a <1*", &[("a <1", EM)]),
    ];
    for (text, want) in cases {
        assert_eq!(spans(text), styled(want), "{text}");
    }
    // §6.6: CommonMark passes <u> and </u> through as raw HTML.
    assert_eq!(
        commonmark_html("*a <u>b</u>*"),
        "<p><em>a <u>b</u></em></p>\n"
    );
    assert_eq!(
        Label::text("a **b**").spans(),
        styled(&[("a **b**", PLAIN)])
    );
    assert_eq!(
        Label::mini_markdown("a **b**").spans(),
        styled(&[("a ", PLAIN), ("b", STRONG)])
    );
}

fn text_of(
    kind: FormattedKind,
    written: Written<'_>,
    locale: TableLocale,
    amounts: Amounts,
) -> Option<String> {
    Value::format(kind, written, locale, amounts)
        .ok()
        .and_then(|value| value.text().map(str::to_owned))
}

#[test]
fn value_kinds_parse_and_format_from_the_wallets_table() {
    use FormattedKind as K;
    use Written::{Boolean as B, Text as T};
    let other = siros_openid4vp::json::Node::parse("3").expect("number");
    let table: [(K, Written<'_>, Option<&str>); 31] = [
        (K::Boolean, B(true), Some("Yes")),
        (K::Boolean, T("true"), None),
        (K::Date, B(true), None),
        (K::Frequency, T("MNTH"), Some("monthly")),
        (K::Frequency, T("MONTHLY"), None),
        (K::Date, T("2026-09-02"), Some("2 Sep 2026")),
        (K::Date, T("20260902"), Some("2 Sep 2026")),
        (K::Date, T("2026-02-30"), None),
        (K::Time, T("10:15:30Z"), Some("10:15:30 UTC")),
        (K::Time, T("25:00"), None),
        (K::Time, T("10:00+24:00"), None),
        (K::Time, T("10"), None),
        (
            K::DateTime,
            T("2026-06-02T10:15:30+02:00"),
            Some("2 Jun 2026, 10:15:30 UTC+02:00"),
        ),
        (K::DateTime, T("2026-06-02 10:15"), None),
        (K::Currency, T("EUR"), Some("EUR")),
        (K::Currency, T("EURO"), None),
        (
            K::CurrencyAmount,
            T("1234567.50 EUR"),
            Some("€1,234,567.50"),
        ),
        (K::CurrencyAmount, T("123456.00 EUR"), Some("€123,456.00")),
        (K::CurrencyAmount, T("0.50 EUR"), Some("€0.50")),
        (K::CurrencyAmount, T("100 JPY"), Some("100 JPY")),
        (K::CurrencyAmount, T("EUR 45.00"), None),
        (K::CurrencyAmount, T("49.9 EUR"), None),
        (K::CurrencyAmount, T("49 EUR"), None),
        (K::CurrencyAmount, T("012.00 EUR"), None),
        (K::CurrencyAmount, T("100. JPY"), None),
        (K::MiniMarkdown, T("*a*"), Some("*a*")),
        (K::MiniMarkdown, Written::Other(&other), None),
        (K::Text, T("plain"), Some("plain")),
        (
            K::Url,
            T("https://bücher.example/x?q=1"),
            Some("https://xn--bcher-kva.example/x?q=1"),
        ),
        (
            K::Url,
            T("https://shop.example/a"),
            Some("https://shop.example/a"),
        ),
        (K::Url, T("http://shop.example"), None),
    ];
    for (kind, written, want) in table {
        assert_eq!(
            text_of(kind, written, TableLocale::En, Amounts::Formatted).as_deref(),
            want,
            "{kind:?} {written}"
        );
    }
    // German dates, booleans and frequencies from the table; amounts as written; raw amounts kept.
    let de = TableLocale::of(&tag("de-CH")).expect("de-CH selects de");
    assert_eq!(
        text_of(K::Date, T("2026-09-02"), de, Amounts::Formatted).as_deref(),
        Some("02.09.2026")
    );
    assert_eq!(
        text_of(K::Boolean, B(false), TableLocale::De, Amounts::Formatted).as_deref(),
        Some("Nein")
    );
    assert_eq!(
        text_of(K::Frequency, T("MNTH"), TableLocale::De, Amounts::Formatted).as_deref(),
        Some("monatlich")
    );
    assert_eq!(
        text_of(
            K::CurrencyAmount,
            T("1.50 EUR"),
            TableLocale::De,
            Amounts::Formatted
        )
        .as_deref(),
        Some("1.50 EUR")
    );
    assert_eq!(
        text_of(
            K::CurrencyAmount,
            T("1.50 EUR"),
            TableLocale::En,
            Amounts::Raw
        )
        .as_deref(),
        Some("1.50 EUR")
    );
}

#[test]
fn a_value_keeps_its_parsed_form() {
    let date = Value::format(
        FormattedKind::Date,
        Written::Text("2026-09-02"),
        TableLocale::En,
        Amounts::Formatted,
    )
    .expect("date");
    assert!(matches!(
        date,
        Value::Formatted {
            parsed: Parsed::Date(Date {
                year: 2026,
                month: 9,
                day: 2
            }),
            ..
        }
    ));
    let monthly = Value::format(
        FormattedKind::Frequency,
        Written::Text("MNTH"),
        TableLocale::En,
        Amounts::Formatted,
    )
    .expect("frequency");
    assert!(
        matches!(monthly, Value::Formatted { parsed: Parsed::Frequency(f), .. } if f.code() == "MNTH")
    );
    let amount = Value::format(
        FormattedKind::CurrencyAmount,
        Written::Text("2.00 EUR"),
        TableLocale::En,
        Amounts::Formatted,
    )
    .expect("amount");
    assert!(
        matches!(amount, Value::Formatted { parsed: Parsed::CurrencyAmount(ref a), .. } if a.currency.code == "EUR")
    );
    let marked = Value::format(
        FormattedKind::MiniMarkdown,
        Written::Text("*c*"),
        TableLocale::En,
        Amounts::Formatted,
    )
    .expect("text");
    assert_eq!(marked.spans(), Some(styled(&[("c", EM)])));
    let plain = Value::format(
        FormattedKind::Text,
        Written::Text("x"),
        TableLocale::En,
        Amounts::Formatted,
    )
    .expect("text");
    assert_eq!(plain.spans(), None);
}

#[test]
fn a_configuration_that_cannot_exist_is_refused() {
    let none: [LocaleTag<'static>; 0] = [];
    assert_eq!(
        Env::new(none, Vec::new(), Amounts::Formatted, Choice::First),
        Err(EnvError::NoLocale)
    );
    assert_eq!(
        Env::new([tag("fr")], Vec::new(), Amounts::Formatted, Choice::First),
        Err(EnvError::NotInTable("fr".to_owned())),
        "a locale the wallet's table lacks"
    );
}

#[test]
fn calendar_dates_times_and_urls_follow_iso_8601_and_uts_46() {
    use FormattedKind as K;
    use Written::Text as T;
    let cases: [(K, &str, Option<&str>); 19] = [
        (K::Date, "2026-01-31", Some("31 Jan 2026")),
        (K::Date, "2023-02-28", Some("28 Feb 2023")),
        (K::Date, "2026-09/02", None),
        (K::Date, "2026-+1-02", None),
        (K::Date, "2026-13-01", None),
        (K::Date, "2024-02-29", Some("29 Feb 2024")),
        (K::Date, "2023-02-29", None),
        (K::Date, "1900-02-29", None),
        (K::Date, "2000-02-29", Some("29 Feb 2000")),
        (K::Date, "2026-04-31", None),
        (K::Date, "0000-01-01", None),
        (K::Time, "23:59:60.5-05:30", Some("23:59:60.5 UTC-05:30")),
        (K::Time, "07:05", Some("07:05")),
        (K::Time, "7:05", None),
        (K::Time, "10:15:30.", None),
        (
            K::Url,
            "https://user@bücher.example:8443/x",
            Some("https://user@xn--bcher-kva.example:8443/x"),
        ),
        (
            K::Url,
            "https://Ü@bücher.example/",
            Some("https://Ü@xn--bcher-kva.example/"),
        ),
        (K::Url, "https://shop.example/a b", None),
        (K::Url, "https://", None),
    ];
    for (kind, written, want) in cases {
        assert_eq!(
            text_of(kind, T(written), TableLocale::En, Amounts::Formatted).as_deref(),
            want,
            "{kind:?} {written}"
        );
    }
}

/// A host beyond ASCII without an A-label form is shown as written and never fetched: UTS #46
/// refuses a label that starts with a combining mark (U+0301), and maps U+FF5B, U+FF5C, U+FF02 and
/// U+FF40 to `{`, `|`, `"` and a backtick, which RFC 3987's `ireg-name` refuses.
#[test]
fn hosts_without_an_a_label_form_are_unreachable() {
    for written in [
        "https://\u{301}x.example/l.png",
        "https://a\u{ff5b}b.example/",
        "https://a\u{ff5c}b.example/",
        "https://a\u{ff02}b.example/",
        "https://a\u{ff40}b.example/",
    ] {
        let shown = HttpsUrl::shown(written);
        assert!(
            matches!(&shown, Ok(Shown::Unreachable(url)) if url.written() == written),
            "{written}: {shown:?}"
        );
    }
}

/// A CPython 3.12 writer, applied to the value `json.loads` reads from a text.
#[derive(Debug, Clone, Copy)]
enum Writer {
    /// `json.dumps(value, ensure_ascii=False)`.
    Dumps,
    /// `json.dumps(value)`.
    Ascii,
    /// `json.dumps(value, separators=(",", ":"), ensure_ascii=False)`.
    Compact,
    /// `repr(value)`.
    Repr,
    /// `repr(float(value))`; none when `float` refuses the integer.
    Float,
}

impl Writer {
    fn write(self, text: &str) -> Option<String> {
        use siros_openid4vp::json::{Node, Number};
        let node = Node::parse(text).expect("json");
        match self {
            Self::Dumps => Some(node.python_text().to_string()),
            Self::Ascii => Some(node.python_ascii().to_string()),
            Self::Compact => Some(
                siros_openid4vp::plugins::JsonText::parse(text)
                    .expect("json")
                    .as_str()
                    .to_owned(),
            ),
            Self::Repr => Some(node.python_repr().to_string()),
            Self::Float => {
                let Node::Number(number) = node else {
                    panic!("{text} is no number")
                };
                // repr writes an infinite double inf or -inf; of_double writes the finite ones.
                number.to_double().map(|double| {
                    Number::of_double(double).map_or_else(
                        || if double > 0.0 { "inf" } else { "-inf" }.to_owned(),
                        |written| written.text().to_owned(),
                    )
                })
            }
        }
    }
}

#[test]
fn json_values_are_written_as_pythons_json_dumps_writes_them() {
    use Writer::{Ascii, Compact, Dumps, Float, Repr};
    // An integer beyond the double range.
    let beyond = format!("1{}", "0".repeat(400));
    let cases: [(Writer, &str, Option<&str>); 24] = [
        (
            Dumps,
            r#"[1, 2.5, true, null, {"a": "é", "b": [1e20, 1E-5, 0.0001, 1e16, 1e15, -0.0, 100.0]}]"#,
            Some(
                r#"[1, 2.5, true, null, {"a": "é", "b": [1e+20, 1e-05, 0.0001, 1e+16, 1000000000000000.0, -0.0, 100.0]}]"#,
            ),
        ),
        (
            Dumps,
            r#""tab\tquote\"back\\slash\u0001""#,
            Some(r#""tab\tquote\"back\\slash\u0001""#),
        ),
        (Dumps, "-0", Some("0")),
        (Dumps, r#""a b\u001f é""#, Some(r#""a b\u001f é""#)),
        (Dumps, "1e400", Some("Infinity")),
        (Dumps, "-1e400", Some("-Infinity")),
        (
            Dumps,
            "123456789012345678901234567890",
            Some("123456789012345678901234567890"),
        ),
        (Dumps, "1.5e300", Some("1.5e+300")),
        (Dumps, r#""\r\b\f""#, Some(r#""\r\b\f""#)),
        (
            Ascii,
            r#"{"é": ["\u2028", "😀", "a"], "n": 1.5}"#,
            Some(r#"{"\u00e9": ["\u2028", "\ud83d\ude00", "a"], "n": 1.5}"#),
        ),
        (
            Compact,
            r#"{"a": [1, 2.5, null, true, "é"], "b": {"c": 1e20}}"#,
            Some(r#"{"a":[1,2.5,null,true,"é"],"b":{"c":1e+20}}"#),
        ),
        (
            Repr,
            "[null, true, false, 1, -0, 2.5, 1e400, -1e400, 1e16]",
            Some("[None, True, False, 1, 0, 2.5, inf, -inf, 1e+16]"),
        ),
        (
            Repr,
            r#"{"k": "v", "it's": "say \"hi\""}"#,
            Some(r#"{'k': 'v', "it's": 'say "hi"'}"#),
        ),
        (Repr, r#""a'b""#, Some(r#""a'b""#)),
        (Repr, r#""a'b\"c""#, Some(r#"'a\'b"c'"#)),
        (
            Repr,
            r#""\\ \t \n \r \u0001 \u007f \u0085""#,
            Some(r#"'\\ \t \n \r \x01 \x7f \x85'"#),
        ),
        (
            Repr,
            r#""é \u00a0 \u00ad \u0378 \u2028 \ufeff \ue000 \udb40\udc01""#,
            Some(r#"'é \xa0 \xad \u0378 \u2028 \ufeff \ue000 \U000e0001'"#),
        ),
        (Float, "3", Some("3.0")),
        (Float, "-0", Some("0.0")),
        (Float, "0.1", Some("0.1")),
        (Float, "2.5e-7", Some("2.5e-07")),
        (
            Float,
            "123456789012345678901234567890",
            Some("1.2345678901234568e+29"),
        ),
        (Float, "1e400", Some("inf")),
        (Float, &beyond, None),
    ];
    for (writer, text, want) in cases {
        assert_eq!(writer.write(text).as_deref(), want, "{writer:?} {text}");
    }
    // An integer the wallet writes equals the one json.loads reads, past the doubles' precision.
    use siros_openid4vp::json::Node;
    assert_eq!(
        Node::integer(i128::MIN),
        Node::parse("-170141183460469231731687303715884105728").expect("json")
    );
    // RFC 8259: the value kinds, and an object's members in text order.
    assert_eq!(Node::parse("true"), Ok(Node::Bool(true)));
    assert_eq!(Node::parse("null"), Ok(Node::Null));
    let object = Node::parse(r#"{"b": 1, "a": 2}"#).expect("object");
    assert_eq!(
        object
            .as_object()
            .expect("object")
            .names()
            .collect::<Vec<_>>(),
        ["b", "a"]
    );
}
