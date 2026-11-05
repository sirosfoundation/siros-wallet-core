//! The text rules against their standards' own data: RFC 4647 §3.3.1's basic filtering and the
//! owner's rule over a priority list, the wallet's configuration, UTS #46's hosts without an
//! A-label form, and the JSON texts CPython writes.

use siros_openid4vp::ids::LocaleTag;
use siros_openid4vp::rows::{Choice, Env, EnvError, HttpsUrl, Shown};
use siros_openid4vp::text::lookup;
use siros_testkit::fixtures::OPTIONS;

fn tag(text: &'static str) -> LocaleTag {
    LocaleTag::parse(text).expect("tag")
}

/// I33's known answers: RFC 4647 §3.3.1 basic filtering, the equal tag first, else the first tag
/// extending the range; the owner's rule: "en should match enUS or enGB", "but not the other way
/// around".
#[test]
fn a_range_matches_an_equal_tag_else_the_first_extending_it() {
    let cases: [(&str, &[&str], Option<&str>); 6] = [
        ("en", &["en-GB"], Some("en-GB")),
        ("en", &["en-US", "en-GB"], Some("en-US")),
        ("en", &["en-GB", "en"], Some("en")),
        ("en-US", &["en"], None),
        ("en-US", &["en-GB"], None),
        ("en-GB", &["en"], None),
    ];
    for (range, tags, want) in cases {
        assert_eq!(
            lookup(&tag(range), tags).copied(),
            want,
            "{range} over {tags:?}"
        );
    }
    assert!(
        LocaleTag::parse("*").is_err(),
        "a priority list holds concrete tags"
    );
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
