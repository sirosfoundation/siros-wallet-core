//! The display text rule, as one table of refusals and the text it accepts.

use siros_display::{DisplayText, LabelText};

#[test]
fn unsafe_or_over_long_text_is_refused() {
    let label = |text: &str| LabelText::new(text).map(|t| t.as_str().to_owned());
    let value = |text: &str| DisplayText::value(text).map(|t| t.as_str().to_owned());
    let long = |n: usize, c: char| c.to_string().repeat(n);
    // (case, text, kind, the error code; `None` when the text is shown as given)
    type Kind = fn(&str) -> Result<String, siros_display::TextError>;
    let table: &[(&str, String, Kind, Option<&str>)] = &[
        ("letters and spaces", "Given Name".into(), label, None),
        (
            "a label of white space alone",
            " \u{3000}".into(),
            label,
            Some("text_empty"),
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
            Some("text_unsafe"),
        ),
        ("a tab (Cc)", "a\tb".into(), value, Some("text_unsafe")),
        ("DEL (Cc)", "\u{7f}".into(), label, Some("text_unsafe")),
        (
            "a C1 control (Cc)",
            "\u{85}".into(),
            label,
            Some("text_unsafe"),
        ),
        (
            "a right-to-left override (Cf)",
            "\u{202e}gpj.exe".into(),
            label,
            Some("text_unsafe"),
        ),
        (
            "a left-to-right isolate (Cf)",
            "\u{2066}x\u{2069}".into(),
            value,
            Some("text_unsafe"),
        ),
        (
            "a left-to-right mark (Cf)",
            "a\u{200e}".into(),
            label,
            Some("text_unsafe"),
        ),
        (
            "an Arabic letter mark (Cf)",
            "\u{61c}".into(),
            label,
            Some("text_unsafe"),
        ),
        (
            "a zero-width space (Cf)",
            "a\u{200b}b".into(),
            label,
            Some("text_unsafe"),
        ),
        (
            "a byte order mark (Cf)",
            "\u{feff}".into(),
            label,
            Some("text_unsafe"),
        ),
        (
            "a tag character (Cf)",
            "\u{e0041}".into(),
            label,
            Some("text_unsafe"),
        ),
        (
            "a line separator (Zl)",
            "\u{2028}".into(),
            label,
            Some("text_unsafe"),
        ),
        (
            "a paragraph separator (Zp)",
            "\u{2029}".into(),
            label,
            Some("text_unsafe"),
        ),
        (
            "a private-use character (Co)",
            "\u{e000}".into(),
            label,
            Some("text_unsafe"),
        ),
        (
            "a supplementary private-use character (Co)",
            "\u{f0000}".into(),
            label,
            Some("text_unsafe"),
        ),
        (
            "an unassigned code point (Cn)",
            "\u{378}".into(),
            label,
            Some("text_unsafe"),
        ),
        (
            "a noncharacter (Cn)",
            "\u{fffe}".into(),
            label,
            Some("text_unsafe"),
        ),
        ("a label at its limit", long(500, 'a'), label, None),
        ("a label counts characters", long(500, 'é'), label, None),
        (
            "a label over its limit",
            long(501, 'a'),
            label,
            Some("text_too_long"),
        ),
        ("a value at its limit", long(2_000, 'a'), value, None),
        (
            "a value over its limit",
            long(2_001, 'a'),
            value,
            Some("text_too_long"),
        ),
    ];
    for (case, text, kind, expected) in table {
        let got = kind(text);
        match expected {
            None => assert_eq!(got.as_deref(), Ok(text.as_str()), "{case}"),
            Some(code) => assert_eq!(got.map_err(|e| e.code()), Err(*code), "{case}"),
        }
    }
}

/// Display text refuses exactly the characters of the general categories Cc, Cf, Zl, Zp, Co and
/// Cn, as `unicode-general-category` gives them, for every `char`.
#[test]
fn the_refused_characters_are_those_of_the_unsafe_categories() {
    use unicode_general_category::{get_general_category, GeneralCategory};

    let differing: Vec<char> = (0..=u32::from(char::MAX))
        .filter_map(char::from_u32)
        .filter(|&c| {
            let category = matches!(
                get_general_category(c),
                GeneralCategory::Control
                    | GeneralCategory::Format
                    | GeneralCategory::LineSeparator
                    | GeneralCategory::ParagraphSeparator
                    | GeneralCategory::PrivateUse
                    | GeneralCategory::Unassigned
            );
            let refused = DisplayText::value(c.encode_utf8(&mut [0; 4])).is_err();
            category != refused
        })
        .collect();
    assert!(differing.is_empty(), "{differing:?}");
}
