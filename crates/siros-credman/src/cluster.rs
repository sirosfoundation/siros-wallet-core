//! Where a field's cut may fall: a sufficient condition for an extended grapheme cluster boundary
//! of UAX #29 revision 49 (Unicode 18.0.0, the version of icu_properties' data). Each cut it
//! allows falls on a boundary. Next to a mark, after a Prepend character and after a ZWJ, it may
//! refuse a boundary.
//!
//! General_Category comes from icu_properties. The lists come from the UCD 18.0.0 files
//! auxiliary/GraphemeBreakProperty.txt (Prepend; L, V, T, LV and LVT; Regional_Indicator; the
//! Extend, ZWJ and SpacingMark characters outside Mn, Me and Mc), emoji/emoji-data.txt
//! (Emoji_Modifier, which GraphemeBreakProperty.txt lists as Extend) and DerivedCoreProperties.txt
//! (Indic_Conjunct_Break), with the blocks of Blocks.txt.

use icu_properties::CodePointMapData;
use icu_properties::props::GeneralCategory;

/// The cluster boundaries of a text, read one character at a time.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Clusters {
    /// The class of the last character read; `None` before the first.
    last: Option<Class>,
}

impl Clusters {
    /// `true` when a cut between the text read and `next` falls on a cluster boundary, `false`
    /// when a rule may join them; then reads `next`.
    pub(crate) fn cut_before(&mut self, next: char) -> bool {
        let mut class = Class::of(next);
        if let (Class::Regional { odd }, Some(Class::Regional { odd: true })) =
            (&mut class, self.last)
        {
            *odd = false;
        }
        // GB1: a text starts with a boundary.
        let boundary = self.last.is_none_or(|last| !last.joins(class));
        self.last = Some(class);
        boundary
    }
}

/// What the rules read of a character.
#[derive(Debug, Clone, Copy)]
enum Class {
    /// U+000D CARRIAGE RETURN.
    Cr,
    /// U+000A LINE FEED.
    Lf,
    /// Hangul_Syllable_Type L.
    L,
    /// Hangul_Syllable_Type V, and the Kirat Rai vowel signs GraphemeBreakProperty.txt lists as V.
    V,
    /// Hangul_Syllable_Type T.
    T,
    /// Hangul_Syllable_Type LV.
    Lv,
    /// Hangul_Syllable_Type LVT.
    Lvt,
    /// A regional indicator; `odd` when it ends a run of regional indicators of odd length.
    Regional { odd: bool },
    /// Grapheme_Cluster_Break Prepend.
    Prepend,
    /// U+200D ZERO WIDTH JOINER.
    Zwj,
    /// Mn, Me or Mc, or an Extend or SpacingMark character of another category. Every
    /// Indic_Conjunct_Break Linker and Extend character but those of [`Class::Linker`] and the ZWJ
    /// is one.
    Mark,
    /// An Indic_Conjunct_Break Linker of category Lo.
    Linker,
    /// A character of a block that holds Indic_Conjunct_Break Consonant characters.
    Indic,
    /// Any other character.
    Other,
}

impl Class {
    fn of(c: char) -> Self {
        match c {
            '\r' => Self::Cr,
            '\n' => Self::Lf,
            '\u{200D}' => Self::Zwj,
            '\u{1100}'..='\u{115F}' | '\u{A960}'..='\u{A97C}' => Self::L,
            '\u{1160}'..='\u{11A7}'
            | '\u{D7B0}'..='\u{D7C6}'
            | '\u{16D63}'
            | '\u{16D67}'..='\u{16D6A}' => Self::V,
            '\u{11A8}'..='\u{11FF}' | '\u{D7CB}'..='\u{D7FB}' => Self::T,
            // A syllable's index modulo 28 numbers its trailing jamo, 0 for none: LV.
            '\u{AC00}'..='\u{D7A3}' if (u32::from(c) - 0xAC00) % 28 == 0 => Self::Lv,
            '\u{AC00}'..='\u{D7A3}' => Self::Lvt,
            '\u{1F1E6}'..='\u{1F1FF}' => Self::Regional { odd: true },
            '\u{0600}'..='\u{0605}'
            | '\u{06DD}'
            | '\u{070F}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08E2}'
            | '\u{0D4E}'
            | '\u{110BD}'
            | '\u{110CD}'
            | '\u{111C2}'..='\u{111C3}'
            | '\u{113D1}'
            | '\u{1193F}'
            | '\u{11941}'
            | '\u{11A84}'..='\u{11A89}'
            | '\u{11D46}'
            | '\u{11F02}' => Self::Prepend,
            '\u{1CF5}'..='\u{1CF6}' | '\u{11A3A}' => Self::Linker,
            // Extend: ZWNJ, the halfwidth katakana sound marks, the emoji modifiers and the tags;
            // SpacingMark: the Thai and Lao vowel signs AM.
            '\u{0E33}'
            | '\u{0EB3}'
            | '\u{200C}'
            | '\u{FF9E}'..='\u{FF9F}'
            | '\u{1F3FB}'..='\u{1F3FF}'
            | '\u{E0020}'..='\u{E007F}' => Self::Mark,
            _ => match CodePointMapData::<GeneralCategory>::new().get(c) {
                GeneralCategory::NonspacingMark
                | GeneralCategory::EnclosingMark
                | GeneralCategory::SpacingMark => Self::Mark,
                _ if indic(c) => Self::Indic,
                _ => Self::Other,
            },
        }
    }

    /// Whether a UAX #29 rule may keep `self` and the `next` character in one cluster. GB9c and
    /// GB11 read `self` alone, which joins more pairs than the rules join.
    const fn joins(self, next: Self) -> bool {
        matches!(
            (self, next),
            // GB3
            (Self::Cr, Self::Lf)
                // GB6, GB7, GB8
                | (Self::L, Self::L | Self::V | Self::Lv | Self::Lvt)
                | (Self::Lv | Self::V, Self::V | Self::T)
                | (Self::Lvt | Self::T, Self::T)
                // GB9, GB9a
                | (_, Self::Mark | Self::Zwj)
                // GB9b; GB11 and GB9c after a ZWJ. GB9b also keeps an ellipsis after the cut
                // from joining a last Prepend character.
                | (Self::Prepend | Self::Zwj, _)
                // GB9c: \p{InCB=Linker} \p{InCB=Extend}* × \p{InCB=Consonant}
                | (Self::Mark | Self::Linker, Self::Indic)
                // GB12, GB13
                | (Self::Regional { odd: true }, Self::Regional { .. })
        )
    }
}

/// Whether `c` lies in a block that holds Indic_Conjunct_Break Consonant characters: Devanagari,
/// Bengali, Gujarati, Oriya, Telugu, Malayalam, Myanmar, Khmer, Tai Tham, Balinese, Sundanese,
/// Javanese, Myanmar Extended-B, Myanmar Extended-A, Meetei Mayek Extensions, Meetei Mayek,
/// Kharoshthi, Chakma, Tulu-Tigalari, Dives Akuru, Zanabazar Square, Soyombo, Devanagari
/// Extended-A, Bengali Supplement and Kawi.
const fn indic(c: char) -> bool {
    matches!(
        c,
        '\u{0900}'..='\u{097F}'
            | '\u{0980}'..='\u{09FF}'
            | '\u{0A80}'..='\u{0AFF}'
            | '\u{0B00}'..='\u{0B7F}'
            | '\u{0C00}'..='\u{0C7F}'
            | '\u{0D00}'..='\u{0D7F}'
            | '\u{1000}'..='\u{109F}'
            | '\u{1780}'..='\u{17FF}'
            | '\u{1A20}'..='\u{1AAF}'
            | '\u{1B00}'..='\u{1BBF}'
            | '\u{A980}'..='\u{A9FF}'
            | '\u{AA60}'..='\u{AA7F}'
            | '\u{AAE0}'..='\u{AAFF}'
            | '\u{ABC0}'..='\u{ABFF}'
            | '\u{10A00}'..='\u{10A5F}'
            | '\u{11100}'..='\u{1114F}'
            | '\u{11380}'..='\u{113FF}'
            | '\u{11900}'..='\u{1195F}'
            | '\u{11A00}'..='\u{11AAF}'
            | '\u{11B00}'..='\u{11B5F}'
            | '\u{11DF0}'..='\u{11DFF}'
            | '\u{11F00}'..='\u{11F5F}'
    )
}
