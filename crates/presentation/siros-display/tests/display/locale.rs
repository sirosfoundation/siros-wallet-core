//! D2: the locale function, as one table of RFC 4647 Lookup (Section 3.4) and the default entry of
//! PaSO View, Section 4.

use siros_display::{lookup, Locale, Localized};

struct Entry(Option<Locale>);

impl Localized for Entry {
    fn locale(&self) -> Option<&Locale> {
        self.0.as_ref()
    }
}

fn locale(tag: &str) -> Locale {
    Locale::parse(tag).unwrap_or_else(|e| panic!("{tag}: {e}"))
}

/// A case, the wallet's language, the entry locales, and the index of the entry the function
/// takes.
type Row<'a> = (&'a str, &'a str, &'a [Option<&'a str>], Option<usize>);

#[test]
fn lookup_truncates_the_language_then_takes_the_default_entry() {
    let table: &[Row<'_>] = &[
        // RFC 4647, Section 3.4: the truncations of "zh-Hant-CN-x-private1-private2".
        (
            "the range whole",
            "zh-Hant-CN-x-private1-private2",
            &[Some("zh-Hant-CN-x-private1-private2"), Some("zh")],
            Some(0),
        ),
        (
            "the range without its last subtag",
            "zh-Hant-CN-x-private1-private2",
            &[Some("zh"), Some("zh-Hant-CN-x-private1")],
            Some(1),
        ),
        (
            "an extension truncated",
            "de-DE-u-co-phonebk",
            &[Some("de-DE"), Some("de-DE-u-co")],
            Some(1),
        ),
        (
            "the primary language subtag last",
            "zh-Hant-CN-x-private1-private2",
            &[Some("en"), Some("zh")],
            Some(1),
        ),
        // RFC 4647, Section 3.4: "de-ch" produces "de" or "de-CH", never "de-CH-1996".
        (
            "a longer tag never matches",
            "de-CH",
            &[Some("de-CH-1996")],
            None,
        ),
        (
            "a truncation matches",
            "de-CH",
            &[Some("de-CH-1996"), Some("de")],
            Some(1),
        ),
        (
            "a shorter range matches no region",
            "de",
            &[Some("de-DE")],
            None,
        ),
        (
            "tags compare without case",
            "EN-us",
            &[Some("de"), Some("en-US")],
            Some(1),
        ),
        // PaSO View, Section 4: no match takes the entry without a locale.
        (
            "the default entry without a match",
            "fr",
            &[Some("en"), None],
            Some(1),
        ),
        (
            "a match before the default entry",
            "en-GB",
            &[None, Some("en")],
            Some(1),
        ),
        (
            "no match and no default entry",
            "ja",
            &[Some("en"), Some("de")],
            None,
        ),
        ("no entry", "en", &[], None),
        (
            "a grandfathered tag",
            "i-klingon",
            &[Some("en"), Some("i-klingon")],
            Some(1),
        ),
        (
            "a private-use tag",
            "x-siros",
            &[Some("en"), Some("x-siros")],
            Some(1),
        ),
    ];
    for (case, language, entries, expected) in table {
        let entries: Vec<Entry> = entries.iter().map(|tag| Entry(tag.map(locale))).collect();
        let taken = lookup(&locale(language), &entries)
            .and_then(|entry| entries.iter().position(|e| std::ptr::eq(e, entry)));
        assert_eq!(taken, *expected, "{case}");
    }
}
