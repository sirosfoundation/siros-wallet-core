//! Display text: the only text the core puts on a screen.

use std::cmp::Ordering;
use std::fmt;

mod unsafe_ranges;

use unsafe_ranges::UNSAFE;

/// The most characters of a label, a name, a title or a hint. EC TS12 v1.0.1, Section 3.3.3
/// allows 250.
pub const LABEL_MAX: usize = 500;

/// The most characters of a value. The TS12 mandate text holds at most 1000.
pub const VALUE_MAX: usize = 2_000;

/// The most characters of an issuer template's text around the issuer's name.
pub const TEMPLATE_MAX: usize = 100;

/// The most characters of a card's title or issuer line: a label within an issuer template.
pub const CARD_TEXT_MAX: usize = LABEL_MAX + TEMPLATE_MAX;

/// A label, a name, a title or a hint: display text of at most [`LABEL_MAX`] characters, one of
/// them other than white space. The host refuses a blank field name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LabelText(DisplayText);

impl LabelText {
    /// The label `text`.
    ///
    /// # Errors
    ///
    /// [`TextError::Empty`] for white space alone; the rule of [`DisplayText`] it breaks.
    pub fn new(text: &str) -> Result<Self, TextError> {
        DisplayText::non_blank(text, LABEL_MAX).map(Self)
    }

    /// The text.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// The label as display text.
    pub fn text(&self) -> &DisplayText {
        &self.0
    }
}

impl From<LabelText> for DisplayText {
    fn from(label: LabelText) -> Self {
        label.0
    }
}

/// A card's title or issuer line: display text of at most [`CARD_TEXT_MAX`] characters, one of
/// them other than white space.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CardText(DisplayText);

impl CardText {
    /// The line `text`.
    ///
    /// # Errors
    ///
    /// [`TextError::Empty`] for white space alone; the rule of [`DisplayText`] it breaks.
    pub fn new(text: &str) -> Result<Self, TextError> {
        DisplayText::non_blank(text, CARD_TEXT_MAX).map(Self)
    }

    /// The line of the label `label`.
    pub fn of(label: &LabelText) -> Self {
        Self(label.0.clone())
    }

    /// The text.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// An issuer line around the issuer's name: text with [`IssuerTemplate::PLACEHOLDER`] once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerTemplate {
    before: DisplayText,
    after: DisplayText,
}

/// Why text is no issuer template.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum TemplateError {
    /// The text has no `{issuer}`, or has it twice.
    Placeholder,
    /// The text around `{issuer}` breaks a rule of display text, or has more than
    /// [`TEMPLATE_MAX`] characters.
    Text(#[source] TextError),
}

impl TemplateError {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Placeholder => "template_placeholder",
            Self::Text(error) => error.code(),
        }
    }
}

impl IssuerTemplate {
    /// Where the issuer's name goes.
    pub const PLACEHOLDER: &'static str = "{issuer}";

    /// The template `text`.
    ///
    /// # Errors
    ///
    /// [`TemplateError`]: `{issuer}` absent or repeated, or the text around it unsafe or longer
    /// than [`TEMPLATE_MAX`] characters.
    pub fn parse(text: &str) -> Result<Self, TemplateError> {
        let (before, after) = text
            .split_once(Self::PLACEHOLDER)
            .ok_or(TemplateError::Placeholder)?;
        if after.contains(Self::PLACEHOLDER) {
            return Err(TemplateError::Placeholder);
        }
        let part = |text| DisplayText::new(text, TEMPLATE_MAX).map_err(TemplateError::Text);
        let (before, after) = (part(before)?, part(after)?);
        if before.as_str().chars().count() + after.as_str().chars().count() > TEMPLATE_MAX {
            return Err(TemplateError::Text(TextError::TooLong));
        }
        Ok(Self { before, after })
    }

    /// The line of the issuer named `name`: safe text, with a character other than white space
    /// in the name, of at most [`LABEL_MAX`] and [`TEMPLATE_MAX`] characters, which make
    /// [`CARD_TEXT_MAX`].
    pub fn line(&self, name: &LabelText) -> CardText {
        let (before, after) = (self.before.as_str(), self.after.as_str());
        CardText(DisplayText(format!("{before}{}{after}", name.as_str())))
    }
}

/// Text that is safe to show.
///
/// It holds no character of the Unicode general categories Cc (control), Cf (format: the bidi
/// embeddings, overrides and isolates, the bidi marks and the zero-width characters), Zl and Zp
/// (line and paragraph separators), Co (private use) and Cn (unassigned, as of Unicode 16.0).
/// Spaces are safe. Unsafe or over-long text is refused whole: the user sees exactly the text
/// that the other party acts on.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DisplayText(String);

impl DisplayText {
    /// A value: at most [`VALUE_MAX`] characters.
    ///
    /// # Errors
    ///
    /// [`TextError`]: the rule `text` breaks.
    pub fn value(text: &str) -> Result<Self, TextError> {
        Self::new(text, VALUE_MAX)
    }

    /// Text of at most `max` characters, one of them other than white space.
    fn non_blank(text: &str, max: usize) -> Result<Self, TextError> {
        let text = Self::new(text, max)?;
        if text.0.chars().all(char::is_whitespace) {
            return Err(TextError::Empty);
        }
        Ok(text)
    }

    /// Text of at most `max` characters.
    fn new(text: &str, max: usize) -> Result<Self, TextError> {
        if text.chars().any(unsafe_to_show) {
            return Err(TextError::Unsafe);
        }
        if text.chars().count() > max {
            return Err(TextError::TooLong);
        }
        Ok(Self(text.to_owned()))
    }

    /// The text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DisplayText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Whether `c` is of the categories Cc, Cf, Zl, Zp, Co or Cn.
fn unsafe_to_show(c: char) -> bool {
    let code = u32::from(c);
    UNSAFE
        .binary_search_by(|&(first, last)| {
            if last < code {
                Ordering::Less
            } else if first > code {
                Ordering::Greater
            } else {
                Ordering::Equal
            }
        })
        .is_ok()
}

/// Why text is refused for display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}", self.code())]
pub enum TextError {
    /// The text holds a control, format, separator, private-use or unassigned character.
    Unsafe,
    /// The text has more characters than its kind allows.
    TooLong,
    /// The text of a label, a card's title or an issuer line is white space alone.
    Empty,
}

impl TextError {
    /// A stable identifier.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unsafe => "text_unsafe",
            Self::TooLong => "text_too_long",
            Self::Empty => "text_empty",
        }
    }
}
