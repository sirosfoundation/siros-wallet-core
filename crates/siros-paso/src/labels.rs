//! Proof Metadata §3.3: what every label meets as written, and the directional rule payload
//! strings meet too. Every label also shows a visible character ([`DisplayText::visible`]), which
//! Credential Manager requires of a field's name (android-credman-sys ABI.md §5,
//! `field_display_name`).

use std::num::NonZeroUsize;

use siros_explain::Explain;
use siros_openid4vp::text::DisplayText;
use unicode_segmentation::UnicodeSegmentation;

use crate::markdown::spans;

/// A string that breaks the directional rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, Explain)]
pub enum Directional {
    /// U+202A to U+202E: an embedding or override.
    #[error("directional embedding or override U+{:04X}", u32::from(*.0))]
    #[explain(id = "directional.embedding")]
    Embedding(#[explain(skip)] char),
    /// An isolate U+2066 to U+2068 without a later U+2069.
    #[error("a directional isolate is not terminated by U+2069")]
    #[explain(id = "directional.unterminated_isolate")]
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

/// Where a label shows, which [`LabelLimits`] gives its maximum length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LabelSlot {
    /// A claim `display` entry's `name`.
    ClaimName,
    /// `transaction_title`.
    Title,
    /// `affirmative_action_label`.
    Affirmative,
    /// `denial_action_label`.
    Denial,
    /// `security_hint`.
    Hint,
}

/// A label limit the code fixes, one or more, as a [`NonZeroUsize`]: zero fails the build.
#[macro_export]
macro_rules! label_limit {
    ($limit:literal) => {
        const {
            match ::std::num::NonZeroUsize::new($limit) {
                ::core::option::Option::Some(limit) => limit,
                #[allow(
                    clippy::panic,
                    reason = "a panic in a constant fails the build (E0080)"
                )]
                ::core::option::Option::None => ::core::panic!("a label limit is one or more"),
            }
        }
    };
}

/// A profile's maximum label lengths in extended grapheme clusters, each one or more.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LabelLimits {
    /// A claim `display` entry's `name`.
    pub claim_name: NonZeroUsize,
    /// `transaction_title`.
    pub title: NonZeroUsize,
    /// `affirmative_action_label`.
    pub affirmative: NonZeroUsize,
    /// `denial_action_label`.
    pub denial: NonZeroUsize,
    /// `security_hint`.
    pub hint: NonZeroUsize,
}

impl LabelLimits {
    /// Proof Metadata §3.3.
    pub const PASO: Self = Self {
        claim_name: label_limit!(60),
        title: label_limit!(100),
        affirmative: label_limit!(40),
        denial: label_limit!(40),
        hint: label_limit!(160),
    };

    /// The limit of a slot.
    #[must_use]
    pub const fn of(self, slot: LabelSlot) -> NonZeroUsize {
        match slot {
            LabelSlot::ClaimName => self.claim_name,
            LabelSlot::Title => self.title,
            LabelSlot::Affirmative => self.affirmative,
            LabelSlot::Denial => self.denial,
            LabelSlot::Hint => self.hint,
        }
    }
}

/// A label that breaks Proof Metadata §3.3, or that shows no visible character.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
pub enum LabelViolation {
    /// A C0 (U+0000 to U+001F) or C1 (U+0080 to U+009F) control character.
    #[error("control character U+{:04X}", u32::from(*.0))]
    #[explain(id = "label.control")]
    Control(#[explain(skip)] char),
    /// The directional rule.
    #[error(transparent)]
    Directional(#[from] Directional),
    /// More extended grapheme clusters than the limit allows.
    #[error("{clusters} grapheme clusters, more than {max}")]
    #[explain(id = "label.too_long")]
    TooLong {
        /// The clusters.
        clusters: usize,
        /// The limit.
        max: usize,
    },
    /// No character the label shows is visible ([`DisplayText::visible`]).
    #[error("the label shows no visible character")]
    #[explain(id = "label.invisible")]
    Invisible,
}

/// A label's text that meets Proof Metadata §3.3 under its limit as written and shows a visible
/// character.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LabelText<'t>(&'t str);

impl<'t> LabelText<'t> {
    /// A plain label's text when it meets the rules: no control character, the directional rule,
    /// at most `limit` extended grapheme clusters, and a visible character.
    ///
    /// # Errors
    ///
    /// [`LabelViolation`]: the first rule the text breaks, in that order.
    pub fn parse(text: &'t str, limit: NonZeroUsize) -> Result<Self, LabelViolation> {
        as_written(text, limit)?;
        shows(text.chars())?;
        Ok(Self(text))
    }

    /// A `mini_markdown` label's text when it meets the rules: as written, no control character,
    /// the directional rule and at most `limit` extended grapheme clusters; and a visible
    /// character in the text of its spans ([`spans`]), its markup left out.
    ///
    /// # Errors
    ///
    /// [`LabelViolation`]: the first rule the text breaks, in that order.
    pub fn markdown(text: &'t str, limit: NonZeroUsize) -> Result<Self, LabelViolation> {
        as_written(text, limit)?;
        shows(spans(text).iter().flat_map(|span| span.text.chars()))?;
        Ok(Self(text))
    }

    /// The text.
    #[must_use]
    pub const fn as_str(self) -> &'t str {
        self.0
    }
}

/// Proof Metadata §3.3 on a label as written: no C0 (U+0000 to U+001F) or C1 (U+0080 to U+009F)
/// control character, the directional rule, at most `limit` extended grapheme clusters.
///
/// # Errors
///
/// [`LabelViolation`]: the first rule the text breaks, in that order.
pub(crate) fn as_written(text: &str, limit: NonZeroUsize) -> Result<(), LabelViolation> {
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
    if clusters > limit.get() {
        return Err(LabelViolation::TooLong {
            clusters,
            max: limit.get(),
        });
    }
    Ok(())
}

/// The visible-character rule over the characters a label shows.
///
/// # Errors
///
/// [`LabelViolation::Invisible`]: no character of `shown` is visible ([`DisplayText::visible`]).
fn shows(shown: impl IntoIterator<Item = char>) -> Result<(), LabelViolation> {
    if shown.into_iter().any(DisplayText::visible) {
        Ok(())
    } else {
        Err(LabelViolation::Invisible)
    }
}
