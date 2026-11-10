//! A field's text: a label needs a visible character, one neither White_Space (UCD PropList.txt)
//! nor Default_Ignorable_Code_Point (UCD DerivedCoreProperties.txt); a cut keeps whole extended
//! grapheme clusters (UAX #29) and closes the directional initiators it leaves open (UAX #9)
//! before its ellipsis.

use siros_credman::{Extent, FIELD_MAX, FieldName, FieldText, NoName};
use siros_openid4vp::text::{DisplayText, TextError};

/// The visible rule, as a field's name and a metadata label read a text: the text, the name it
/// gives, and the label's refusal.
#[test]
fn a_label_needs_a_visible_character() {
    let table: [(&str, Result<&str, &NoName>, Option<TextError>); 12] = [
        // White_Space.
        (" ", Err(&NoName), Some(TextError::Empty)),
        ("\u{a0}", Err(&NoName), Some(TextError::Empty)),
        // Default_Ignorable_Code_Point: of Cf, Lo and Mn.
        ("\u{200b}", Err(&NoName), Some(TextError::Unsafe)),
        ("\u{2068}", Err(&NoName), Some(TextError::Unsafe)),
        ("\u{3164}", Err(&NoName), Some(TextError::Empty)),
        ("\u{115f}", Err(&NoName), Some(TextError::Empty)),
        ("\u{fe0f}", Err(&NoName), Some(TextError::Empty)),
        ("\u{2068} \u{2069}", Err(&NoName), Some(TextError::Unsafe)),
        // Visible: a letter, a Prepended_Concatenation_Mark (Cf), a letter inside an isolate.
        ("A", Ok("A"), None),
        ("\u{600}", Ok("\u{600}"), Some(TextError::Unsafe)),
        (
            "\u{2068}A\u{2069}",
            Ok("\u{2068}A\u{2069}"),
            Some(TextError::Unsafe),
        ),
        // A name starts at its first character other than white space.
        (" \u{3000}A", Ok("A"), None),
    ];
    for (text, name, label) in table {
        let named = FieldName::fit(text);
        assert_eq!(named.as_ref().map(FieldName::as_str), name, "{text:?}");
        assert_eq!(DisplayText::label(text).err(), label, "{text:?}");
    }
}

/// The cut, by hand from UAX #29 and UAX #9: the text, the field's text, and its extent.
#[test]
fn a_cut_keeps_clusters_whole_and_closes_what_it_leaves_open() {
    const FSI: &str = "\u{2068}";
    const PDI: &str = "\u{2069}";
    const RLE: &str = "\u{202b}";
    const PDF: &str = "\u{202c}";
    const END: &str = "\u{2026}";
    let a = |n: usize| "a".repeat(n);
    let b = |n: usize| "b".repeat(n);
    let cut = Extent::Clipped;
    let table = [
        ("80 characters", a(80), a(80), Extent::Whole),
        ("81 characters", a(81), format!("{}{END}", a(79)), cut),
        (
            "e and a combining acute",
            format!("{}e\u{301}zz", a(78)),
            format!("{}{END}", a(78)),
            cut,
        ),
        (
            "a regional indicator pair",
            format!("{}\u{1f1e9}\u{1f1ea}zz", a(78)),
            format!("{}{END}", a(78)),
            cut,
        ),
        (
            "a ZWJ sequence",
            format!("{}\u{1f468}\u{200d}\u{1f469}\u{200d}\u{1f467}zz", a(76)),
            format!("{}{END}", a(76)),
            cut,
        ),
        (
            "inside FSI and PDI",
            format!("{FSI}{}{PDI}", b(80)),
            format!("{FSI}{}{PDI}{END}", b(77)),
            cut,
        ),
        (
            "inside RLE and PDF",
            format!("{RLE}{}{PDF}", b(80)),
            format!("{RLE}{}{PDF}{END}", b(77)),
            cut,
        ),
        (
            "the innermost closed first",
            format!("{RLE}{FSI}{}", b(80)),
            format!("{RLE}{FSI}{}{PDI}{PDF}{END}", b(75)),
            cut,
        ),
        (
            "X6a: a PDI closes the embedding inside its isolate",
            format!("{FSI}{RLE}x{PDI}{}", b(80)),
            format!("{FSI}{RLE}x{PDI}{}{END}", b(75)),
            cut,
        ),
        (
            "X7: a PDF matches embeddings alone",
            format!("{FSI}{PDF}{}", b(80)),
            format!("{FSI}{PDF}{}{PDI}{END}", b(76)),
            cut,
        ),
        (
            "X8: a paragraph separator closes every initiator",
            format!("{FSI}x\n{}", b(80)),
            format!("{FSI}x\n{}{END}", b(76)),
            cut,
        ),
        (
            "the longest cut that fits",
            format!("{FSI}{RLE}{}{PDI}{}", b(76), b(10)),
            format!("{FSI}{RLE}{}{PDI}{END}", b(76)),
            cut,
        ),
        (
            "GB9b: a last Prepend joins the ellipsis",
            format!("{}\u{600}\nzz", a(78)),
            format!("{}{END}", a(78)),
            cut,
        ),
    ];
    for (case, text, want, extent) in table {
        let field = FieldText::fit(&text);
        assert_eq!(
            (field.as_str(), field.extent()),
            (want.as_str(), extent),
            "{case}"
        );
        assert!(field.as_str().chars().count() <= FIELD_MAX, "{case}");
    }
}
