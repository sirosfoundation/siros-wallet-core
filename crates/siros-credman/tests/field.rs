//! A field's text: a label needs a visible character, one neither White_Space (UCD PropList.txt)
//! nor Default_Ignorable_Code_Point (UCD DerivedCoreProperties.txt); a cut keeps whole extended
//! grapheme clusters (UAX #29) and closes the directional initiators it leaves open (UAX #9)
//! before its ellipsis.

use siros_credman::{Extent, FIELD_MAX, FieldName, FieldText, NoName};
use siros_openid4vp::text::{DisplayText, TextError};
use unicode_segmentation::UnicodeSegmentation;

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
            "GB12, GB13: a cut between two flags",
            format!("{}\u{1f1e9}\u{1f1ea}\u{1f1eb}\u{1f1f7}zz", a(77)),
            format!("{}\u{1f1e9}\u{1f1ea}{END}", a(77)),
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

/// The characters of a field's longest cut.
const LONGEST: usize = FIELD_MAX - 1;

/// What a field's cut does to a text placed so that one of its positions ends the longest cut.
struct Probe {
    /// The characters the cut keeps of the text and of the letters before it.
    kept: usize,
    /// unicode-segmentation reports a boundary where the cut falls.
    boundary: bool,
    /// unicode-segmentation reports a boundary at the position.
    allowed: bool,
}

/// A field's cut of `text` after `LONGEST - at` letters and before two more, which puts the
/// position `at` of `text` where the longest cut ends.
fn probe(text: &[char], at: usize) -> Probe {
    let mut probed = "a".repeat(LONGEST - at);
    probed.extend(text);
    probed.push_str("zz");
    let field = FieldText::fit(&probed);
    let kept = field
        .as_str()
        .strip_suffix('\u{2026}')
        .expect("a cut text ends in an ellipsis");
    assert!(probed.starts_with(kept), "{probed:?}");
    let position = probed
        .char_indices()
        .nth(LONGEST)
        .map(|(offset, _)| offset)
        .expect("the text holds the position");
    Probe {
        kept: kept.chars().count(),
        boundary: boundary(&probed, kept.len()),
        allowed: boundary(&probed, position),
    }
}

/// Whether unicode-segmentation reports an extended grapheme cluster boundary at `offset`.
fn boundary(text: &str, offset: usize) -> bool {
    text.grapheme_indices(true)
        .any(|(start, _)| start == offset)
}

/// Every cut a field makes falls on a boundary unicode-segmentation (Unicode 17.0.0) reports.
/// Inside a line of GraphemeBreakTest.txt, each cut also falls on a boundary the line marks
/// (Unicode 18.0.0, the rules the cut implements). Between the `exact` characters below (letters,
/// digits, punctuation, emoji, controls, Hangul, regional indicators), a cut falls at every
/// boundary unicode-segmentation reports.
///
/// The texts: every line of `data/GraphemeBreakTest-18.0.0.txt`
/// (<https://www.unicode.org/Public/18.0.0/ucd/auxiliary/GraphemeBreakTest.txt>, SHA-256
/// b0cf047ee94485bbdc846de2b902f5f8a815f6b674f9d04223cddadd91c9df31), each character below
/// alone and each pair of them. A probe puts a position of a text where a field's longest cut
/// ends. A line's marks hold inside it: before and after it stand letters, which change no
/// boundary inside.
#[test]
fn a_cut_falls_on_a_cluster_boundary() {
    // Each line: its characters, and whether each position from its start to its end is a
    // boundary.
    let lines: Vec<(Vec<char>, Vec<bool>)> = include_str!("data/GraphemeBreakTest-18.0.0.txt")
        .lines()
        .filter_map(|line| line.split('#').next())
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let mut chars = Vec::new();
            let mut breaks = Vec::new();
            for token in line.split_whitespace() {
                match token {
                    "÷" => breaks.push(true),
                    "×" => breaks.push(false),
                    code => chars.push(
                        u32::from_str_radix(code, 16)
                            .ok()
                            .and_then(char::from_u32)
                            .expect("a code point"),
                    ),
                }
            }
            assert_eq!(breaks.len(), chars.len() + 1, "{line}");
            (chars, breaks)
        })
        .collect();
    let mut cuts = 0;
    let mut marked = 0;
    for (line, breaks) in &lines {
        for at in 0..=line.len() {
            let probe = probe(line, at);
            assert!(probe.boundary, "{line:?} at {at}");
            cuts += 1;
            let inside = (probe.kept + at)
                .checked_sub(LONGEST)
                .filter(|index| (1..line.len()).contains(index));
            if let Some(index) = inside {
                assert_eq!(breaks.get(index), Some(&true), "{line:?} at {at}");
                marked += 1;
            }
        }
    }
    let exact = [
        // Letters, digits, punctuation and space of several scripts; Extended_Pictographic; an
        // unassigned code point.
        'a',
        'Z',
        '0',
        ' ',
        '.',
        'é',
        'Ж',
        'Ω',
        'א',
        'ا',
        'ก',
        '一',
        'あ',
        '©',
        '\u{1F600}',
        '\u{378}',
        // Controls (GB4, GB5), CR and LF (GB3).
        '\0',
        '\u{85}',
        '\u{AD}',
        '\u{2028}',
        '\u{2060}',
        '\r',
        '\n',
        // Hangul (GB6, GB7, GB8): the ends of the ranges of L, V and T, Kirat Rai's V, the first
        // and last LV and LVT syllables.
        '\u{1100}',
        '\u{115F}',
        '\u{A960}',
        '\u{A97C}',
        '\u{1160}',
        '\u{11A7}',
        '\u{D7B0}',
        '\u{D7C6}',
        '\u{16D63}',
        '\u{16D67}',
        '\u{16D6A}',
        '\u{11A8}',
        '\u{11FF}',
        '\u{D7CB}',
        '\u{D7FB}',
        '\u{AC00}',
        '\u{AC1C}',
        '\u{D788}',
        '\u{AC01}',
        '\u{AC1B}',
        '\u{D7A3}',
        // Regional indicators (GB12, GB13).
        '\u{1F1E6}',
        '\u{1F1FF}',
        // Indic_Conjunct_Break Consonant characters and a danda of their blocks (GB9c).
        '\u{915}',
        '\u{995}',
        '\u{964}',
        '\u{1000}',
        '\u{1780}',
        '\u{A989}',
        '\u{11B0A}',
        '\u{11DF1}',
        '\u{11F04}',
    ];
    let joining = [
        // Mn, Me and Mc (GB9, GB9a): Extend, Indic_Conjunct_Break Extend and Linker, SpacingMark,
        // and an Mc of Grapheme_Cluster_Break Other.
        '\u{300}',
        '\u{308}',
        '\u{93C}',
        '\u{94D}',
        '\u{1039}',
        '\u{17D2}',
        '\u{20DD}',
        '\u{488}',
        '\u{903}',
        '\u{9BE}',
        '\u{102B}',
        '\u{1B44}',
        '\u{A9C0}',
        '\u{1D165}',
        // Extend, ZWJ and SpacingMark outside Mn, Me and Mc (GB9, GB9a, GB11).
        '\u{E33}',
        '\u{EB3}',
        '\u{200C}',
        '\u{200D}',
        '\u{FF9E}',
        '\u{FF9F}',
        '\u{1F3FB}',
        '\u{1F3FF}',
        '\u{E0020}',
        '\u{E007F}',
        // Prepend (GB9b): the ends of its ranges.
        '\u{600}',
        '\u{605}',
        '\u{6DD}',
        '\u{70F}',
        '\u{890}',
        '\u{891}',
        '\u{8E2}',
        '\u{D4E}',
        '\u{110BD}',
        '\u{110CD}',
        '\u{111C2}',
        '\u{111C3}',
        '\u{113D1}',
        '\u{1193F}',
        '\u{11941}',
        '\u{11A84}',
        '\u{11A89}',
        '\u{11D46}',
        '\u{11F02}',
        // Indic_Conjunct_Break Linker characters of category Lo (GB9c).
        '\u{1CF5}',
        '\u{1CF6}',
        '\u{11A3A}',
    ];
    let characters: Vec<(char, bool)> = exact
        .iter()
        .map(|c| (*c, true))
        .chain(joining.iter().map(|c| (*c, false)))
        .collect();
    // Each character alone, after a letter and before one; each pair, between its characters.
    let mut probes: Vec<(Vec<char>, usize, bool)> = Vec::new();
    for (first, exact_first) in &characters {
        probes.push((vec![*first], 0, *exact_first));
        probes.push((vec![*first], 1, *exact_first));
        for (second, exact_second) in &characters {
            probes.push((vec![*first, *second], 1, *exact_first && *exact_second));
        }
    }
    let mut exactly = 0;
    for (text, at, exact) in &probes {
        let probe = probe(text, *at);
        assert!(probe.boundary, "{text:?} at {at}");
        if *exact {
            assert_eq!(probe.kept == LONGEST, probe.allowed, "{text:?} at {at}");
            exactly += 1;
        }
        cuts += 1;
    }
    println!(
        "{cuts} cuts checked: {} lines of GraphemeBreakTest-18.0.0.txt, {marked} of their cuts \
         inside a line; {} characters alone and in pairs, {exactly} of their cuts equal to the \
         oracle",
        lines.len(),
        characters.len(),
    );
}
