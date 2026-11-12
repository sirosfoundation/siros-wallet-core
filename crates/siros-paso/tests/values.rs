//! PaSO View §3's text rules against their standards' own data: CommonMark 0.31.2's emphasis
//! examples (`data/commonmark-0.31.2-spec.json`, spec.commonmark.org 0.31.2, SHA-256
//! d431b29d97b6f73e69d547109cf5081578fac931e72afe95639ebe766c1b2a20), the value kinds parsed
//! into the typed values ISO 8601 and ISO 4217 write, and the statement that shows each value
//! alone with its literal.

use serde_json::Value as Json;
use siros_paso::frequency::Frequency;
use siros_paso::markdown::{Span, Style, commonmark_html, spans};
use siros_paso::value::{Breach, FormattedKind, Parsed, Written, formatted};
use siros_syntax::{
    Amount, Currency, Date, DateTime, Decimal, Fraction, Offset, OffsetTime, Second, Time,
};

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
    assert!(!chosen.is_empty());
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

/// A value parsed, or the rule it breaks.
fn shown(kind: FormattedKind, written: Written<'_>) -> Result<Parsed, Breach> {
    formatted(kind, written).map_err(|bad| bad.why)
}

fn date(year: u16, month: u8, day: u8) -> Parsed {
    Parsed::Date(Date::new(year, month, day).expect("a date"))
}

fn currency(code: &str) -> Currency {
    Currency::parse(code).expect("an ISO 4217 code")
}

fn amount(units: i128, scale: u8, code: &str) -> Parsed {
    let value = Decimal::new(units, scale).expect("a decimal");
    Parsed::Amount(Amount::new(value, currency(code)))
}

fn text(text: &str) -> Parsed {
    Parsed::Text(text.to_owned())
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

/// What a value of a kind parses to, or a refusal for the rule it breaks.
enum Want {
    Is(Parsed),
    Refused(Breach),
}

/// PaSO View §3's value kinds: each conforming value parses into the typed value ISO 8601 and
/// ISO 4217 write, the frequency ISO 20022's code names, the boolean answer, or the text as
/// written (a URL's host in RFC 3492's Punycode); each other is refused.
#[test]
fn value_kinds_parse_as_paso_view_section_3_states() {
    use FormattedKind as K;
    use Want::{Is, Refused};
    use Written::{Boolean as B, Text as T};
    let other = siros_openid4vp::json::Node::parse("3").expect("number");
    let raw = |written: &str| Is(text(written));
    let table: [(K, Written<'_>, Want); 31] = [
        (K::Boolean, B(true), Is(Parsed::Boolean(true))),
        (K::Boolean, T("true"), Refused(Breach::NotBoolean)),
        (K::Date, B(true), Refused(Breach::NotString)),
        (
            K::Frequency,
            T("MNTH"),
            Is(Parsed::Frequency(Frequency::Monthly)),
        ),
        (K::Frequency, T("MONTHLY"), Refused(Breach::NotFrequency)),
        (K::Date, T("2026-09-02"), Is(date(2026, 9, 2))),
        (K::Date, T("20260902"), Is(date(2026, 9, 2))),
        (K::Date, T("2026-02-30"), Refused(Breach::NotDate)),
        (
            K::Time,
            T("10:15:30Z"),
            Is(Parsed::Time(OffsetTime::new(
                time(10, 15, Some((30, 0, 0))),
                Some(offset(0)),
            ))),
        ),
        (K::Time, T("25:00"), Refused(Breach::NotTime)),
        (K::Time, T("10:00+24:00"), Refused(Breach::NotTime)),
        (K::Time, T("10"), Refused(Breach::NotTime)),
        (
            K::DateTime,
            T("2026-06-02T10:15:30+02:00"),
            Is(Parsed::DateTime(DateTime::new(
                Date::new(2026, 6, 2).expect("a date"),
                time(10, 15, Some((30, 0, 0))),
                Some(offset(120)),
            ))),
        ),
        (
            K::DateTime,
            T("2026-06-02 10:15"),
            Refused(Breach::NotDateTime),
        ),
        (K::Currency, T("EUR"), Is(Parsed::Currency(currency("EUR")))),
        (K::Currency, T("EURO"), Refused(Breach::NotCurrency)),
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
        (
            K::CurrencyAmount,
            T("EUR 45.00"),
            Refused(Breach::NotAmount),
        ),
        (
            K::CurrencyAmount,
            T("49.9 EUR"),
            Refused(Breach::NumberForm { digits: 2 }),
        ),
        (
            K::CurrencyAmount,
            T("49 EUR"),
            Refused(Breach::NumberForm { digits: 2 }),
        ),
        (
            K::CurrencyAmount,
            T("012.00 EUR"),
            Refused(Breach::NumberForm { digits: 2 }),
        ),
        (
            K::CurrencyAmount,
            T("100. JPY"),
            Refused(Breach::NumberForm { digits: 0 }),
        ),
        (K::MiniMarkdown, T("*a*"), raw("a")),
        (
            K::MiniMarkdown,
            Written::Other(&other),
            Refused(Breach::NotString),
        ),
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
        (K::Url, T("http://shop.example"), Refused(Breach::NotUrl)),
    ];
    for (kind, written, want) in table {
        let got = shown(kind, written);
        match want {
            Is(text) => assert_eq!(got, Ok(text), "{kind:?} {written:?}"),
            Refused(breach) => assert_eq!(got, Err(breach), "{kind:?} {written:?}"),
        }
    }
}

/// ISO 8601's calendar and clock, RFC 3339 §5.7's leap second at 23:59:60 UTC on a month's last
/// day (IERS Bulletin C 52 placed one at the end of 2016-12-31), and RFC 3492's Punycode.
#[test]
fn calendar_dates_times_and_urls_follow_iso_8601_and_rfc_3492() {
    use FormattedKind as K;
    use Written::Text as T;
    let day = |year, month, day| date(year, month, day);
    let cases: [(K, &str, Result<Parsed, Breach>); 22] = [
        (K::Date, "2026-01-31", Ok(day(2026, 1, 31))),
        (K::Date, "2023-02-28", Ok(day(2023, 2, 28))),
        (K::Date, "2026-09/02", Err(Breach::NotDate)),
        (K::Date, "2026-+1-02", Err(Breach::NotDate)),
        (K::Date, "2026-13-01", Err(Breach::NotDate)),
        (K::Date, "2024-02-29", Ok(day(2024, 2, 29))),
        (K::Date, "2023-02-29", Err(Breach::NotDate)),
        (K::Date, "1900-02-29", Err(Breach::NotDate)),
        (K::Date, "2000-02-29", Ok(day(2000, 2, 29))),
        (K::Date, "2026-04-31", Err(Breach::NotDate)),
        (K::Date, "0000-01-01", Err(Breach::NotDate)),
        // A leap second needs the date that places it.
        (K::Time, "23:59:60.5-05:30", Err(Breach::NotTime)),
        (
            K::Time,
            "07:05",
            Ok(Parsed::Time(OffsetTime::new(time(7, 5, None), None))),
        ),
        (K::Time, "7:05", Err(Breach::NotTime)),
        (K::Time, "10:15:30.", Err(Breach::NotTime)),
        (
            K::DateTime,
            "2016-12-31T23:59:60.5Z",
            Ok(Parsed::DateTime(
                DateTime::leap(
                    Date::new(2016, 12, 31).expect("a date"),
                    23,
                    59,
                    Fraction::new(500_000_000, 1).expect("a fraction"),
                    offset(0),
                )
                .expect("IERS Bulletin C 52's leap second"),
            )),
        ),
        (
            K::DateTime,
            "2016-12-30T23:59:60Z",
            Err(Breach::NotDateTime),
        ),
        (K::DateTime, "2016-12-31T23:59:60", Err(Breach::NotDateTime)),
        (
            K::Url,
            "https://user@bücher.example:8443/x",
            Ok(text("https://user@xn--bcher-kva.example:8443/x")),
        ),
        (
            K::Url,
            "https://Ü@bücher.example/",
            Ok(text("https://Ü@xn--bcher-kva.example/")),
        ),
        (K::Url, "https://shop.example/a b", Err(Breach::NotUrl)),
        (K::Url, "https://", Err(Breach::NotUrl)),
    ];
    for (kind, written, want) in cases {
        assert_eq!(shown(kind, T(written)), want, "{kind:?} {written:?}");
    }
}

/// A value shown alone resolves through a statement carrying its literal (ISO 8601's extended
/// form, ISO 4217's code, an amount's number with its currency's minor digits): siros-openid4vp's
/// statement where one has the kind, else PaSO's.
#[test]
fn a_value_shown_alone_is_a_statement_of_its_literal() {
    use FormattedKind as K;
    use Written::{Boolean as B, Text as T};
    /// A value, the statement's id and its arguments.
    type Case<'a> = (K, Written<'a>, &'a str, &'a [(&'a str, &'a str)]);
    let table: [Case<'_>; 9] = [
        (K::Boolean, B(false), "openid4vp.wallet.no", &[]),
        (K::Frequency, T("QUTR"), "paso.frequency.qutr", &[]),
        (
            K::Date,
            T("20260902"),
            "openid4vp.wallet.date",
            &[("value", "2026-09-02")],
        ),
        (
            K::Time,
            T("07:05"),
            "paso.value.time",
            &[("value", "07:05")],
        ),
        (
            K::DateTime,
            T("2026-06-02T10:15:30+02:00"),
            "openid4vp.wallet.date_time",
            &[("value", "2026-06-02T10:15:30+02:00")],
        ),
        (
            K::Currency,
            T("JPY"),
            "paso.value.currency",
            &[("code", "JPY")],
        ),
        (
            K::CurrencyAmount,
            T("42.50 EUR"),
            "paso.value.amount",
            &[("value", "42.50"), ("currency", "EUR")],
        ),
        (
            K::MiniMarkdown,
            T("**a**"),
            "openid4vp.wallet.text",
            &[("value", "a")],
        ),
        (
            K::Text,
            T("{0}"),
            "openid4vp.wallet.text",
            &[("value", "{0}")],
        ),
    ];
    for (kind, written, id, want) in table {
        let statement = formatted(kind, written).expect("conforms").shown();
        let args: Vec<(&str, Option<String>)> = want
            .iter()
            .map(|(key, _)| (*key, statement.arg(key).map(ToString::to_string)))
            .collect();
        let want: Vec<(&str, Option<String>)> = want
            .iter()
            .map(|(key, value)| (*key, Some((*value).to_owned())))
            .collect();
        assert_eq!((statement.id(), args), (id, want), "{kind:?} {written:?}");
    }
}
