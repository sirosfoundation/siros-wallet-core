//! Text that is safe to show: the characters it may hold, the visible character a label needs, and
//! the length of each kind of text a credential's metadata writes.

use icu_properties::props::{DefaultIgnorableCodePoint, GeneralCategory};
use icu_properties::{CodePointMapData, CodePointSetData};
use siros_explain::Explain;

/// The most characters of a label, a name, a title or a hint.
pub const LABEL_MAX: usize = 500;

/// The most characters of a value or a description.
pub const VALUE_MAX: usize = 2_000;

/// The most characters of an issuer template's text around the issuer's name.
pub const TEMPLATE_MAX: usize = 100;

/// The most characters of a card's title or issuer line: a label within an issuer template.
pub const CARD_TEXT_MAX: usize = LABEL_MAX + TEMPLATE_MAX;

/// Text that holds no character of the Unicode General Categories Cc (control), Cf (format: the
/// bidi embeddings, overrides and isolates, the bidi marks and the zero-width characters), Zl and
/// Zp (line and paragraph separators), Co (private use) and Cn (unassigned). Unsafe or over-long
/// text is refused whole. The claims kit reads a credential's metadata texts through it; the
/// values of a credential's claims show as written.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DisplayText(String);

impl DisplayText {
    /// A label, a name, a title or a hint: at most [`LABEL_MAX`] characters, one of them visible
    /// ([`DisplayText::visible`]).
    ///
    /// # Errors
    ///
    /// [`TextError`]: the rule `text` breaks.
    pub fn label(text: &str) -> Result<Self, TextError> {
        Self::non_blank(text, LABEL_MAX)
    }

    /// A card's title or issuer line: at most [`CARD_TEXT_MAX`] characters, one of them visible
    /// ([`DisplayText::visible`]).
    ///
    /// # Errors
    ///
    /// [`TextError`]: the rule `text` breaks.
    pub fn card(text: &str) -> Result<Self, TextError> {
        Self::non_blank(text, CARD_TEXT_MAX)
    }

    /// A value or a description: at most [`VALUE_MAX`] characters.
    ///
    /// # Errors
    ///
    /// [`TextError`]: the rule `text` breaks.
    pub fn value(text: &str) -> Result<Self, TextError> {
        Self::of(text, VALUE_MAX)
    }

    /// An issuer template's text around the issuer's name: at most [`TEMPLATE_MAX`] characters.
    ///
    /// # Errors
    ///
    /// [`TextError`]: the rule `text` breaks.
    pub fn template(text: &str) -> Result<Self, TextError> {
        Self::of(text, TEMPLATE_MAX)
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The text, owned.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }

    /// Whether `c` shows: it is neither White_Space (UCD PropList.txt) nor
    /// Default_Ignorable_Code_Point (UCD DerivedCoreProperties.txt).
    #[must_use]
    pub fn visible(c: char) -> bool {
        !c.is_whitespace() && !CodePointSetData::new::<DefaultIgnorableCodePoint>().contains(c)
    }

    fn non_blank(text: &str, max: usize) -> Result<Self, TextError> {
        let text = Self::of(text, max)?;
        if !text.0.chars().any(Self::visible) {
            return Err(TextError::Empty);
        }
        Ok(text)
    }

    fn of(text: &str, max: usize) -> Result<Self, TextError> {
        if text.chars().any(unsafe_to_show) {
            return Err(TextError::Unsafe);
        }
        if text.chars().count() > max {
            return Err(TextError::TooLong);
        }
        Ok(Self(text.to_owned()))
    }
}

fn unsafe_to_show(c: char) -> bool {
    matches!(
        CodePointMapData::<GeneralCategory>::new().get(c),
        GeneralCategory::Control
            | GeneralCategory::Format
            | GeneralCategory::LineSeparator
            | GeneralCategory::ParagraphSeparator
            | GeneralCategory::PrivateUse
            | GeneralCategory::Unassigned
    )
}

/// Why text is refused for display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error, Explain)]
pub enum TextError {
    /// The text holds a control, format, separator, private-use or unassigned character.
    #[error("the text holds a control, format, separator, private-use or unassigned character")]
    #[explain(id = "text.unsafe")]
    Unsafe,
    /// The text has more characters than its kind allows.
    #[error("the text has more characters than its kind allows")]
    #[explain(id = "text.too_long")]
    TooLong,
    /// A label's, a title's or an issuer line's text holds no visible character
    /// ([`DisplayText::visible`]).
    #[error("the text holds no visible character")]
    #[explain(id = "text.empty")]
    Empty,
}
