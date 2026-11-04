//! Proof Metadata §3.3: what every label meets, and the directional rule payload strings meet
//! too.

use siros_explain::Explain;
use unicode_segmentation::UnicodeSegmentation;

/// A string that breaks the directional rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "paso.directional")]
pub enum Directional {
    /// U+202A to U+202E: an embedding or override.
    #[error("directional embedding or override U+{:04X}", u32::from(*.0))]
    Embedding(#[explain(skip)] char),
    /// An isolate U+2066 to U+2068 without a later U+2069.
    #[error("a directional isolate is not terminated by U+2069")]
    UnterminatedIsolate,
}

impl Directional {
    /// The violation of the directional rule in a string: no embedding or override, each
    /// isolate closed by a later U+2069. A U+2069 without an open isolate passes.
    #[must_use]
    pub fn find(text: &str) -> Option<Self> {
        let mut open = 0usize;
        for c in text.chars() {
            match c {
                '\u{202A}'..='\u{202E}' => return Some(Self::Embedding(c)),
                '\u{2066}'..='\u{2068}' => open += 1,
                '\u{2069}' => open = open.saturating_sub(1),
                _ => {}
            }
        }
        (open > 0).then_some(Self::UnterminatedIsolate)
    }
}

/// Where a label shows, which sets its maximum length in grapheme clusters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LabelSlot {
    /// A claim `display` entry's `name`: 60.
    ClaimName,
    /// `transaction_title`: 100.
    Title,
    /// `affirmative_action_label`: 40.
    Affirmative,
    /// `denial_action_label`: 40.
    Denial,
    /// `security_hint`: 160.
    Hint,
}

impl LabelSlot {
    /// The maximum length in extended grapheme clusters.
    #[must_use]
    pub const fn max(self) -> usize {
        match self {
            Self::ClaimName => 60,
            Self::Title => 100,
            Self::Affirmative | Self::Denial => 40,
            Self::Hint => 160,
        }
    }
}

/// A label that breaks Proof Metadata §3.3.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "paso.label")]
pub enum LabelViolation {
    /// A C0 (U+0000 to U+001F) or C1 (U+0080 to U+009F) control character.
    #[error("control character U+{:04X}", u32::from(*.0))]
    Control(#[explain(skip)] char),
    /// The directional rule.
    #[error(transparent)]
    Directional(#[from] Directional),
    /// More extended grapheme clusters than the slot allows.
    #[error("{clusters} grapheme clusters, more than {max}")]
    TooLong {
        /// The clusters.
        clusters: usize,
        /// The slot's maximum.
        max: usize,
    },
}

/// A label's text that meets Proof Metadata §3.3 for its slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LabelText<'t>(&'t str);

impl<'t> LabelText<'t> {
    /// The text when it meets the rules for the slot: no control character, the directional
    /// rule, at most the slot's length in extended grapheme clusters.
    pub fn parse(text: &'t str, slot: LabelSlot) -> Result<Self, LabelViolation> {
        if let Some(control) = text
            .chars()
            .find(|c| matches!(u32::from(*c), 0..0x20 | 0x80..0xA0))
        {
            return Err(LabelViolation::Control(control));
        }
        if let Some(directional) = Directional::find(text) {
            return Err(directional.into());
        }
        let clusters = text.graphemes(true).count();
        if clusters > slot.max() {
            return Err(LabelViolation::TooLong {
                clusters,
                max: slot.max(),
            });
        }
        Ok(Self(text))
    }

    /// The text.
    #[must_use]
    pub const fn as_str(self) -> &'t str {
        self.0
    }
}

impl LabelText<'static> {
    /// A label of the wallet's own table: the tests hold each to the rules for its slot.
    pub(crate) const fn wallet(text: &'static str) -> Self {
        Self(text)
    }
}
