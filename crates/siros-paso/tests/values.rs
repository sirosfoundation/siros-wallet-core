//! PaSO View §3's text rules against their standards' own data: CommonMark 0.31.2's emphasis
//! examples (`data/commonmark-0.31.2-spec.json`, spec.commonmark.org 0.31.2, SHA-256
//! d431b29d97b6f73e69d547109cf5081578fac931e72afe95639ebe766c1b2a20), and the value kinds parsed
//! into the typed values ISO 8601 and ISO 4217 write.

use serde_json::Value as Json;
use siros_explain::{
    Amount, Currency, Date, DateTime, Decimal, Fraction, Offset, Second, Text, Time, Value as Typed,
};
use siros_openid4vp::rows::WalletText;
use siros_paso::frequency::Frequency;
use siros_paso::markdown::{Span, Style, commonmark_html, spans};
use siros_paso::value::{FormattedKind, Parsed, Written, formatted};

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
}

fn text_of(kind: FormattedKind, written: Written<'_>) -> Option<Text> {
    formatted(kind, written).ok().map(|(_, text)| text)
}

fn date(year: u16, month: u8, day: u8) -> Text {
    Text::Value(Typed::Date(Date::new(year, month, day).expect("a date")))
}

fn amount(units: i128, scale: u8, code: &str) -> Text {
    let currency = Currency::from_code(code).expect("an ISO 4217 code");
    let value = Decimal::new(units, scale).expect("a decimal");
    Text::Value(Typed::Amount(Amount::new(value, currency)))
}

fn time(hour: u8, minute: u8, second: Option<(u8, u32, u8)>) -> Time {
    let second = second.map(|(whole, nanos, digits)| {
        Second::new(whole, Fraction::new(nanos, digits).expect("a fraction")).expect("a second")
    });
    Time::new(hour, minute, second).expect("a time")
}

fn offset(minutes: i16) -> Offset {
    Offset::new(minutes).expect("an offset")
}

/// What a value of a kind shows: a text its source fixes, or a refusal.
enum Want {
    Is(Text),
    Refused,
}

/// PaSO View §3's value kinds: each conforming value parses into the typed value ISO 8601 and
/// ISO 4217 write, the frequency ISO 20022's code names, the boolean answer, or the text as
/// written (UTS #46's A-labels for a URL's host); each other is refused.
#[test]
fn value_kinds_parse_as_paso_view_section_3_states() {
    use FormattedKind as K;
    use Want::{Is, Refused};
    use Written::{Boolean as B, Text as T};
    let other = siros_openid4vp::json::Node::parse("3").expect("number");
    let raw = |text: &str| Is(Text::Raw(text.to_owned()));
    let table: [(K, Written<'_>, Want); 31] = [
        (K::Boolean, B(true), Is(Text::of(&WalletText::Yes))),
        (K::Boolean, T("true"), Refused),
        (K::Date, B(true), Refused),
        (K::Frequency, T("MNTH"), Is(Text::of(&Frequency::Monthly))),
        (K::Frequency, T("MONTHLY"), Refused),
        (K::Date, T("2026-09-02"), Is(date(2026, 9, 2))),
        (K::Date, T("20260902"), Is(date(2026, 9, 2))),
        (K::Date, T("2026-02-30"), Refused),
        (
            K::Time,
            T("10:15:30Z"),
            Is(Text::Value(Typed::Time {
                at: time(10, 15, Some((30, 0, 0))),
                offset: Some(offset(0)),
            })),
        ),
        (K::Time, T("25:00"), Refused),
        (K::Time, T("10:00+24:00"), Refused),
        (K::Time, T("10"), Refused),
        (
            K::DateTime,
            T("2026-06-02T10:15:30+02:00"),
            Is(Text::Value(Typed::DateTime(DateTime::new(
                Date::new(2026, 6, 2).expect("a date"),
                time(10, 15, Some((30, 0, 0))),
                Some(offset(120)),
            )))),
        ),
        (K::DateTime, T("2026-06-02 10:15"), Refused),
        (
            K::Currency,
            T("EUR"),
            Is(Text::Value(Typed::Currency(
                Currency::from_code("EUR").expect("EUR"),
            ))),
        ),
        (K::Currency, T("EURO"), Refused),
        (
            K::CurrencyAmount,
            T("1234567.50 EUR"),
            Is(amount(123_456_750, 2, "EUR")),
        ),
        (
            K::CurrencyAmount,
            T("123456.00 EUR"),
            Is(amount(12_345_600, 2, "EUR")),
        ),
        (K::CurrencyAmount, T("0.50 EUR"), Is(amount(50, 2, "EUR"))),
        (K::CurrencyAmount, T("100 JPY"), Is(amount(100, 0, "JPY"))),
        (K::CurrencyAmount, T("EUR 45.00"), Refused),
        (K::CurrencyAmount, T("49.9 EUR"), Refused),
        (K::CurrencyAmount, T("49 EUR"), Refused),
        (K::CurrencyAmount, T("012.00 EUR"), Refused),
        (K::CurrencyAmount, T("100. JPY"), Refused),
        (K::MiniMarkdown, T("*a*"), raw("a")),
        (K::MiniMarkdown, Written::Other(&other), Refused),
        (K::Text, T("plain"), raw("plain")),
        (
            K::Url,
            T("https://bücher.example/x?q=1"),
            raw("https://xn--bcher-kva.example/x?q=1"),
        ),
        (
            K::Url,
            T("https://shop.example/a"),
            raw("https://shop.example/a"),
        ),
        (K::Url, T("http://shop.example"), Refused),
    ];
    for (kind, written, want) in table {
        let got = text_of(kind, written);
        match want {
            Is(text) => assert_eq!(got, Some(text), "{kind:?} {written}"),
            Refused => assert_eq!(got, None, "{kind:?} {written}"),
        }
    }
}

#[test]
fn a_value_keeps_its_parsed_form() {
    let parsed = |kind, written: &str| formatted(kind, Written::Text(written)).expect("parses").0;
    assert!(matches!(
        parsed(FormattedKind::Date, "2026-09-02"),
        Parsed::Date(d) if (d.year(), d.month(), d.day()) == (2026, 9, 2)
    ));
    assert!(
        matches!(parsed(FormattedKind::Frequency, "MNTH"), Parsed::Frequency(f) if f.code() == "MNTH")
    );
    assert!(
        matches!(parsed(FormattedKind::CurrencyAmount, "2.00 EUR"), Parsed::CurrencyAmount(a) if a.currency().code() == *b"EUR")
    );
}

/// ISO 8601's calendar and clock, RFC 3339 §5.7's leap second at 23:59:60 UTC on a month's last
/// day, and UTS #46's A-labels.
#[test]
fn calendar_dates_times_and_urls_follow_iso_8601_and_uts_46() {
    use FormattedKind as K;
    use Written::Text as T;
    let day = |year, month, day| date(year, month, day);
    let cases: [(K, &str, Option<Text>); 22] = [
        (K::Date, "2026-01-31", Some(day(2026, 1, 31))),
        (K::Date, "2023-02-28", Some(day(2023, 2, 28))),
        (K::Date, "2026-09/02", None),
        (K::Date, "2026-+1-02", None),
        (K::Date, "2026-13-01", None),
        (K::Date, "2024-02-29", Some(day(2024, 2, 29))),
        (K::Date, "2023-02-29", None),
        (K::Date, "1900-02-29", None),
        (K::Date, "2000-02-29", Some(day(2000, 2, 29))),
        (K::Date, "2026-04-31", None),
        (K::Date, "0000-01-01", None),
        // A leap second needs the date that places it.
        (K::Time, "23:59:60.5-05:30", None),
        (
            K::Time,
            "07:05",
            Some(Text::Value(Typed::Time {
                at: time(7, 5, None),
                offset: None,
            })),
        ),
        (K::Time, "7:05", None),
        (K::Time, "10:15:30.", None),
        (
            K::DateTime,
            "2016-12-31T23:59:60.5Z",
            Some(Text::Value(Typed::DateTime(
                DateTime::leap(
                    Date::new(2016, 12, 31).expect("a date"),
                    23,
                    59,
                    Fraction::new(500_000_000, 1).expect("a fraction"),
                    offset(0),
                )
                .expect("RFC 3339 Appendix D's leap second"),
            ))),
        ),
        (K::DateTime, "2016-12-30T23:59:60Z", None),
        (K::DateTime, "2016-12-31T23:59:60", None),
        (
            K::Url,
            "https://user@bücher.example:8443/x",
            Some(Text::Raw(
                "https://user@xn--bcher-kva.example:8443/x".to_owned(),
            )),
        ),
        (
            K::Url,
            "https://Ü@bücher.example/",
            Some(Text::Raw("https://Ü@xn--bcher-kva.example/".to_owned())),
        ),
        (K::Url, "https://shop.example/a b", None),
        (K::Url, "https://", None),
    ];
    for (kind, written, want) in cases {
        assert_eq!(text_of(kind, T(written)), want, "{kind:?} {written}");
    }
}
