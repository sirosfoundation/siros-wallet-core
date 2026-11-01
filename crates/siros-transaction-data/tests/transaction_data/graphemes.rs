//! The grapheme cluster count against `unicode-segmentation`, for every `char` in the contexts
//! that set each rule of UAX #29 apart.

use siros_transaction_data::grapheme_clusters;
use unicode_segmentation::UnicodeSegmentation;

/// Texts around a character `{}`: a letter, CR and LF, a combining mark, Hangul jamo and
/// syllables, regional indicators, an emoji sequence, and Indic conjuncts.
const CONTEXTS: [(&str, &str); 22] = [
    ("a", ""),
    ("", "a"),
    ("\r", ""),
    ("", "\n"),
    ("", "\u{301}"),
    ("\u{1100}", ""),
    ("", "\u{1100}"),
    ("\u{1160}", ""),
    ("", "\u{1160}"),
    ("\u{11a8}", ""),
    ("", "\u{11a8}"),
    ("\u{ac00}", ""),
    ("\u{ac01}", ""),
    ("", "\u{ac00}"),
    ("\u{1f1e6}", ""),
    ("\u{1f1e6}\u{1f1e6}", "\u{1f1e6}"),
    ("", "\u{200d}\u{1f600}"),
    ("\u{1f600}", "\u{200d}\u{1f600}"),
    ("", "\u{94d}\u{915}"),
    ("\u{915}", "\u{915}"),
    ("\u{915}\u{94d}", "\u{915}"),
    ("\u{915}\u{94d}\u{915}", "\u{94d}\u{200d}\u{915}"),
];

#[test]
#[ignore = "every char in 22 contexts: run once per round"]
fn the_cluster_count_is_that_of_uax_29() {
    let differing: Vec<String> = (0..=u32::from(char::MAX))
        .filter_map(char::from_u32)
        .flat_map(|c| CONTEXTS.map(|(before, after)| format!("{before}{c}{after}")))
        .filter(|text| grapheme_clusters(text) != text.graphemes(true).count())
        .take(20)
        .collect();
    assert!(differing.is_empty(), "{differing:?}");
}
