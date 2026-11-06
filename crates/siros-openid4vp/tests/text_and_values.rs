//! The text rules against their standards' own data: RFC 4647 §3.3.1's basic filtering and the
//! owner's rule over a priority list, the wallet's configuration, UTS #46's hosts without an
//! A-label form, and the JSON texts CPython writes.

use siros_openid4vp::ids::LocaleTag;
use siros_openid4vp::rows::{Choice, Env, EnvError, HttpsUrl, Shown};
use siros_openid4vp::text::{DisplayText, TextError, lookup};
use siros_testkit::fixtures::OPTIONS;

fn tag(text: &'static str) -> LocaleTag {
    LocaleTag::parse(text).expect("tag")
}

/// I33's known answers: RFC 4647 §3.3.1 basic filtering, the equal tag first, else the first tag
/// extending the range; the owner's rule: "en should match enUS or enGB", "but not the other way
/// around". §3.3.1's own example: `de-de` matches `de-DE-1996`, and neither `de-Deva` nor
/// `de-Latn-DE`; tags compare case-insensitively (§2). A text outside §2.1's grammar is no tag.
#[test]
fn a_range_matches_an_equal_tag_else_the_first_extending_it() {
    let cases: [(&str, &[&str], Option<&str>); 11] = [
        ("en", &["en-GB"], Some("en-GB")),
        ("en", &["en-US", "en-GB"], Some("en-US")),
        ("en", &["en-GB", "en"], Some("en")),
        ("en-US", &["en"], None),
        ("en-US", &["en-GB"], None),
        ("en-GB", &["en"], None),
        ("de-de", &["de-DE-1996"], Some("de-DE-1996")),
        ("de-de", &["de-Deva", "de-Latn-DE"], None),
        ("en", &["eng"], None),
        ("EN-gb", &["en-GB"], Some("en-GB")),
        ("en", &["en-"], None),
    ];
    for (range, tags, want) in cases {
        assert_eq!(
            lookup(&tag(range), tags).copied(),
            want,
            "{range} over {tags:?}"
        );
    }
}

#[test]
fn a_configuration_that_cannot_exist_is_refused() {
    assert_eq!(
        Env::new(Vec::new(), Vec::new(), OPTIONS, Vec::new(), Choice::First),
        Err(EnvError::NoLocale)
    );
}

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

/// RFC 8259 §6's numbers keep their JSON text in what a message or a template names, where a
/// double would show another value; a rule's text keeps Python's `repr` of `json.loads("1e400")`,
/// and a value the request left out is an absent argument.
#[test]
fn a_named_value_keeps_its_numbers_as_written() {
    use siros_explain::IntoArg;
    use siros_openid4vp::json::Node;
    use siros_openid4vp::refusal::{ReprItem, ReprOption};
    for (text, spaced, compact) in [
        ("1e400", "1e400", "1e400"),
        ("1e-400", "1e-400", "1e-400"),
        ("1.50", "1.50", "1.50"),
        (r#""a b""#, "a b", "a b"),
        (r#"[1E+2, "x"]"#, r#"[1E+2, "x"]"#, r#"[1E+2,"x"]"#),
        (r#"{"n": -0.0}"#, r#"{"n": -0.0}"#, r#"{"n":-0.0}"#),
    ] {
        let node = Node::parse(text).expect("json");
        assert_eq!(node.written_text(), spaced, "{text}");
        assert_eq!(node.written_compact(), compact, "{text}");
    }
    let beyond = Node::parse("1e400").expect("json");
    let item = ReprItem::repr(&beyond);
    assert_eq!(item.to_string(), "inf");
    assert_eq!(IntoArg::arg(&item), "1e400");
    assert_eq!(IntoArg::arg(&ReprOption::of(Some(&beyond))), Some("1e400"));
    let absent = ReprOption::of(None);
    assert_eq!(absent.to_string(), "None");
    assert_eq!(IntoArg::arg(&absent), None);
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
    // An object's members in text order.
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

/// The display text rule: the characters Unicode's General Category table places in Cc, Cf, Zl,
/// Zp, Co and Cn, and each kind's length: 500 for a label, 2000 for a value, 100 for a template
/// and 600 for a card's line.
#[test]
fn unsafe_or_over_long_text_is_refused() {
    type Kind = fn(&str) -> Result<DisplayText, TextError>;
    let label: Kind = DisplayText::label;
    let value: Kind = DisplayText::value;
    let long = |n: usize, c: char| c.to_string().repeat(n);
    let table: Vec<(&str, String, Kind, Option<TextError>)> = vec![
        ("letters and spaces", "Given Name".into(), label, None),
        (
            "a label of white space alone",
            " \u{3000}".into(),
            label,
            Some(TextError::Empty),
        ),
        ("a value of white space alone", " ".into(), value, None),
        (
            "non-ASCII letters",
            "Straße 7, Zürich, 名前".into(),
            label,
            None,
        ),
        ("a no-break space", "a\u{a0}b".into(), label, None),
        ("an emoji", "\u{1f600}".into(), label, None),
        (
            "a line feed (Cc)",
            "line\nbreak".into(),
            label,
            Some(TextError::Unsafe),
        ),
        ("a tab (Cc)", "a\tb".into(), value, Some(TextError::Unsafe)),
        ("DEL (Cc)", "\u{7f}".into(), label, Some(TextError::Unsafe)),
        (
            "a C1 control (Cc)",
            "\u{85}".into(),
            label,
            Some(TextError::Unsafe),
        ),
        (
            "a right-to-left override (Cf)",
            "\u{202e}gpj.exe".into(),
            label,
            Some(TextError::Unsafe),
        ),
        (
            "a left-to-right isolate (Cf)",
            "\u{2066}x\u{2069}".into(),
            value,
            Some(TextError::Unsafe),
        ),
        (
            "a left-to-right mark (Cf)",
            "a\u{200e}".into(),
            label,
            Some(TextError::Unsafe),
        ),
        (
            "an Arabic letter mark (Cf)",
            "\u{61c}".into(),
            label,
            Some(TextError::Unsafe),
        ),
        (
            "a zero-width space (Cf)",
            "a\u{200b}b".into(),
            label,
            Some(TextError::Unsafe),
        ),
        (
            "a byte order mark (Cf)",
            "\u{feff}".into(),
            label,
            Some(TextError::Unsafe),
        ),
        (
            "a tag character (Cf)",
            "\u{e0041}".into(),
            label,
            Some(TextError::Unsafe),
        ),
        (
            "a line separator (Zl)",
            "\u{2028}".into(),
            label,
            Some(TextError::Unsafe),
        ),
        (
            "a paragraph separator (Zp)",
            "\u{2029}".into(),
            label,
            Some(TextError::Unsafe),
        ),
        (
            "a private-use character (Co)",
            "\u{e000}".into(),
            label,
            Some(TextError::Unsafe),
        ),
        (
            "a supplementary private-use character (Co)",
            "\u{f0000}".into(),
            label,
            Some(TextError::Unsafe),
        ),
        (
            "an unassigned code point (Cn)",
            "\u{378}".into(),
            label,
            Some(TextError::Unsafe),
        ),
        (
            "a noncharacter (Cn)",
            "\u{fffe}".into(),
            label,
            Some(TextError::Unsafe),
        ),
        ("a label at its limit", long(500, 'a'), label, None),
        ("a label counts characters", long(500, 'é'), label, None),
        (
            "a label over its limit",
            long(501, 'a'),
            label,
            Some(TextError::TooLong),
        ),
        ("a value at its limit", long(2_000, 'a'), value, None),
        (
            "a value over its limit",
            long(2_001, 'a'),
            value,
            Some(TextError::TooLong),
        ),
        (
            "a card line over its limit",
            long(601, 'a'),
            DisplayText::card,
            Some(TextError::TooLong),
        ),
        (
            "a template over its limit",
            long(101, 'a'),
            DisplayText::template,
            Some(TextError::TooLong),
        ),
    ];
    for (case, text, kind, expected) in table {
        match expected {
            None => assert_eq!(kind(&text).expect(case).as_str(), text, "{case}"),
            Some(error) => assert_eq!(kind(&text), Err(error), "{case}"),
        }
    }
}
