//! `LocaleTag` against RFC 5646 §2.1.1's case: tags from RFC 5646, and tags whose case that
//! section's rule gives by hand.

use siros_i18n::LocaleTag;

/// Each tag as written, then in RFC 5646 §2.1.1's case.
const CASES: [(&str, &str); 16] = [
    // §2.1.1's examples.
    ("mn-Cyrl-MN", "mn-Cyrl-MN"),
    ("MN-cYRL-mn", "mn-Cyrl-MN"),
    ("mN-cYrL-Mn", "mn-Cyrl-MN"),
    ("en-CA-x-ca", "en-CA-x-ca"),
    ("sgn-BE-FR", "sgn-BE-FR"),
    ("az-Latn-x-latn", "az-Latn-x-latn"),
    // Appendix A's examples.
    ("az-Arab-x-AZE-derbend", "az-Arab-x-aze-derbend"),
    ("zh-CN-a-myext-x-private", "zh-CN-a-myext-x-private"),
    ("qaa-Qaaa-QM-x-southern", "qaa-Qaaa-QM-x-southern"),
    // RFC 5646's examples with a leading singleton: Appendix A's `x-whatever` and its invalid
    // `a-DE`, which RFC 4647's ranges admit, and §2.2.8's `i-enochian` and `i-klingon`.
    ("x-whatever", "x-whatever"),
    ("a-DE", "a-de"),
    ("i-enochian", "i-enochian"),
    ("i-klingon", "i-klingon"),
    // A leading singleton before a two-letter and a four-letter subtag, by §2.1.1's rule.
    ("x-ab", "x-ab"),
    ("x-abcd", "x-abcd"),
    ("X-AB-CD", "x-ab-cd"),
];

#[test]
fn each_tag_takes_rfc_5646_case() {
    let wrong: Vec<String> = CASES
        .iter()
        .filter_map(|&(written, cased)| match LocaleTag::parse(written) {
            Ok(tag) if tag.as_str() == cased => None,
            Ok(tag) => Some(format!("{written} -> {tag} (RFC 5646: {cased})")),
            Err(error) => Some(format!("{written} refused: {error}")),
        })
        .collect();
    assert!(wrong.is_empty(), "{wrong:#?}");
}
