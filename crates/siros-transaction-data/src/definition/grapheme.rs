//! Extended grapheme clusters (UAX #29, Unicode 16.0), counted in one pass over a text.

mod runs;

use runs::RUNS;

/// The first Hangul syllable, and how many there are.
const HANGUL_FIRST: u32 = 0xAC00;
const HANGUL_SYLLABLES: u32 = 11_172;

/// The grapheme break property of a character, with its Indic conjunct break where GB9c reads
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Property {
    Other,
    Cr,
    Lf,
    Control,
    /// Extend, InCB=None.
    Extend,
    /// Extend, InCB=Extend.
    ExtendLinked,
    /// Extend, InCB=Linker.
    Linker,
    /// ZWJ, which is InCB=Extend.
    Zwj,
    RegionalIndicator,
    Prepend,
    SpacingMark,
    L,
    V,
    T,
    Lv,
    Lvt,
    /// Extended_Pictographic.
    Pictographic,
    /// Other, InCB=Consonant.
    Consonant,
}

/// A run of characters of one property: its first code point, in three bytes.
pub(super) struct Run {
    start: [u8; 3],
    property: Property,
}

impl Run {
    const fn new(start: u32, property: Property) -> Self {
        let [_, high, middle, low] = start.to_be_bytes();
        Self {
            start: [high, middle, low],
            property,
        }
    }

    fn start(&self) -> u32 {
        let [high, middle, low] = self.start;
        u32::from_be_bytes([0, high, middle, low])
    }
}

impl Property {
    fn of(c: char) -> Self {
        let code = u32::from(c);
        if let Some(syllable) = code
            .checked_sub(HANGUL_FIRST)
            .filter(|&syllable| syllable < HANGUL_SYLLABLES)
        {
            // The 28 syllables of one leading consonant: an LV syllable, then its LVT syllables.
            return if syllable % 28 == 0 {
                Self::Lv
            } else {
                Self::Lvt
            };
        }
        let after = RUNS.partition_point(|run| run.start() <= code);
        after
            .checked_sub(1)
            .and_then(|at| RUNS.get(at))
            .map_or(Self::Control, |run| run.property)
    }

    /// Extend, of any Indic conjunct break.
    fn extends(self) -> bool {
        matches!(self, Self::Extend | Self::ExtendLinked | Self::Linker)
    }
}

/// Of GB11: how the text ends.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Emoji {
    Other,
    /// Extended_Pictographic Extend*.
    Pictographic,
    /// Extended_Pictographic Extend* ZWJ.
    Joined,
}

/// Of GB12 and GB13: the number of regional indicators the text ends in.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Parity {
    Even,
    Odd,
}

/// Of GB9c: how the text ends.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Conjunct {
    Other,
    /// InCB=Consonant InCB=Extend*.
    Consonant,
    /// InCB=Consonant [InCB=Extend InCB=Linker]*, with a Linker.
    Linked,
}

/// What the rules read of a text so far.
#[derive(Clone, Copy)]
struct Context {
    last: Property,
    emoji: Emoji,
    regional: Parity,
    conjunct: Conjunct,
}

impl Context {
    /// The context of a text that ends in `previous`, then `next`.
    fn then(previous: Option<Self>, next: Property) -> Self {
        let (emoji, regional, conjunct) = previous
            .map_or((Emoji::Other, Parity::Even, Conjunct::Other), |context| {
                (context.emoji, context.regional, context.conjunct)
            });
        Self {
            last: next,
            emoji: match (emoji, next) {
                (_, Property::Pictographic) => Emoji::Pictographic,
                (Emoji::Pictographic, next) if next.extends() => Emoji::Pictographic,
                (Emoji::Pictographic, Property::Zwj) => Emoji::Joined,
                _ => Emoji::Other,
            },
            regional: match (regional, next) {
                (Parity::Even, Property::RegionalIndicator) => Parity::Odd,
                _ => Parity::Even,
            },
            conjunct: match (conjunct, next) {
                (_, Property::Consonant) => Conjunct::Consonant,
                (Conjunct::Consonant | Conjunct::Linked, Property::Linker) => Conjunct::Linked,
                (conjunct, Property::ExtendLinked | Property::Zwj) => conjunct,
                _ => Conjunct::Other,
            },
        }
    }

    /// Whether a cluster boundary lies between the text and `next`.
    fn breaks_before(self, next: Property) -> bool {
        use Property as P;
        match (self.last, next) {
            (P::Cr, P::Lf) => false,
            (P::Control | P::Cr | P::Lf, _) | (_, P::Control | P::Cr | P::Lf) => true,
            (P::L, P::L | P::V | P::Lv | P::Lvt)
            | (P::Lv | P::V, P::V | P::T)
            | (P::Lvt | P::T, P::T)
            | (_, P::Zwj | P::SpacingMark)
            | (P::Prepend, _) => false,
            (_, next) if next.extends() => false,
            (_, P::Consonant) => self.conjunct != Conjunct::Linked,
            (P::Zwj, P::Pictographic) => self.emoji != Emoji::Joined,
            (P::RegionalIndicator, P::RegionalIndicator) => self.regional == Parity::Even,
            _ => true,
        }
    }
}

/// The number of extended grapheme clusters of `text`: the unit of PaSO's label limits.
#[must_use]
pub fn clusters(text: &str) -> usize {
    text.chars()
        .map(Property::of)
        .fold((0, None::<Context>), |(clusters, context), next| {
            let boundary = context.is_none_or(|context| context.breaks_before(next));
            (
                clusters + usize::from(boundary),
                Some(Context::then(context, next)),
            )
        })
        .0
}
