//! `MediaType::parse` against RFC 9110: §8.3.1's four equivalent examples and the forms §5.6
//! admits, then one text per rule it refuses.

use siros_openid4vp::effects::{MediaType, NotMediaType};

#[test]
fn rfc_9110_media_types_parse_with_their_essence() {
    // §8.3.1: "The following examples are all equivalent".
    for text in [
        r#"text/html;charset=utf-8"#,
        r#"Text/HTML;Charset="utf-8""#,
        r#"text/html; charset="utf-8""#,
        r#"text/html;charset=UTF-8"#,
    ] {
        let media = MediaType::parse(text).expect(text);
        assert_eq!((media.essence(), media.as_str()), ("text/html", text));
    }
    // §5.6.6: OWS around ";", an empty parameter; §5.6.4: a quoted-pair, obs-text; §5.6.2: tchar.
    for (text, essence) in [
        ("image/PNG", "image/png"),
        ("image/svg+xml", "image/svg+xml"),
        (
            "application/vnd.a!#$%&'*^_`|~-1",
            "application/vnd.a!#$%&'*^_`|~-1",
        ),
        ("text/plain ;\tq=1", "text/plain"),
        ("text/plain;", "text/plain"),
        ("text/plain;;q=1", "text/plain"),
        (r#"text/plain;t="a \"b\" \\ c""#, "text/plain"),
        ("text/plain;t=\"é\"", "text/plain"),
    ] {
        let media = MediaType::parse(text).expect(text);
        assert_eq!(media.essence(), essence, "{text}");
    }
}

#[test]
fn each_rule_of_rfc_9110_refuses_its_own_break() {
    let text = |text: &str| text.to_owned();
    for refused in [
        NotMediaType::Type {
            text: text(""),
            at: 0,
        },
        NotMediaType::Type {
            text: text("/png"),
            at: 0,
        },
        NotMediaType::Slash {
            text: text("image"),
            at: 5,
        },
        NotMediaType::Subtype {
            text: text("image/"),
            at: 6,
        },
        // A token holds no space; a parameter starts with its name.
        NotMediaType::Separator {
            text: text("image/png x"),
            at: 10,
        },
        NotMediaType::Separator {
            text: text("text/plain;q=a b"),
            at: 15,
        },
        NotMediaType::Separator {
            text: text("text/plain;=1"),
            at: 11,
        },
        NotMediaType::Equals {
            text: text("text/plain;q"),
            at: 12,
        },
        NotMediaType::ParameterValue {
            text: text("text/plain;q="),
            at: 13,
        },
        // An unclosed quoted-string; a quoted-pair escaping a control character.
        NotMediaType::QuotedString {
            text: text("text/plain;q=\"a"),
            at: 15,
        },
        NotMediaType::QuotedString {
            text: text("text/plain;q=\"\\\u{1}\""),
            at: 15,
        },
    ] {
        let given = match &refused {
            NotMediaType::Type { text, .. }
            | NotMediaType::Slash { text, .. }
            | NotMediaType::Subtype { text, .. }
            | NotMediaType::Separator { text, .. }
            | NotMediaType::Equals { text, .. }
            | NotMediaType::ParameterValue { text, .. }
            | NotMediaType::QuotedString { text, .. } => text.clone(),
        };
        assert_eq!(MediaType::parse(&given), Err(refused));
    }
}
