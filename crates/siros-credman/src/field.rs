//! A row as Credential Manager's field: its label and value as one short line of plain text, and
//! whether a text was cut to fit, which A9 reads.

use siros_explain::Explain;
use siros_openid4vp::rows::{Row, Value};

/// The most characters of a field's label or value the matcher writes: a picker row holds one short
/// line. The bound is siros-credman's own; Credential Manager's ABI states no length for a field
/// (android-credman-sys ABI.md §5).
pub const FIELD_MAX: usize = 80;

/// Whether a field's text holds what it shows whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Extent {
    /// The text is whole.
    Whole,
    /// The text is cut to fit, or stands for a value a line of text cannot show.
    Clipped,
}

/// The text of a field: at most [`FIELD_MAX`] characters, and its extent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldText {
    text: String,
    extent: Extent,
}

/// The label of a field: a [`FieldText`] with a character other than white space, which
/// Credential Manager requires of a field's name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldName(FieldText);

/// A row whose label is white space alone: no field can name it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(id = "field.no_name")]
#[error("a row's label is white space alone")]
pub struct NoName;

/// A field of an entry: its label, and its value when the row has one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    name: FieldName,
    value: Option<FieldText>,
}

impl FieldText {
    /// `text`, cut to [`FIELD_MAX`] characters and ending in an ellipsis when longer.
    #[must_use]
    pub fn fit(text: &str) -> Self {
        if text.chars().count() <= FIELD_MAX {
            return Self {
                text: text.to_owned(),
                extent: Extent::Whole,
            };
        }
        let mut text: String = text.chars().take(FIELD_MAX - 1).collect();
        text.push('\u{2026}');
        Self {
            text,
            extent: Extent::Clipped,
        }
    }

    /// `text` standing for a value a line of text cannot show whole.
    #[must_use]
    pub fn partial(text: &str) -> Self {
        Self {
            extent: Extent::Clipped,
            ..Self::fit(text)
        }
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The extent.
    #[must_use]
    pub const fn extent(&self) -> Extent {
        self.extent
    }
}

impl FieldName {
    /// `text` from its first character other than white space, cut to [`FIELD_MAX`]
    /// characters.
    ///
    /// # Errors
    ///
    /// [`NoName`] for white space alone.
    pub fn fit(text: &str) -> Result<Self, NoName> {
        match text.trim_start() {
            "" => Err(NoName),
            text => Ok(Self(FieldText::fit(text))),
        }
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// The extent.
    #[must_use]
    pub const fn extent(&self) -> Extent {
        self.0.extent()
    }
}

impl Field {
    /// The field of a row, its label's and its value's texts plain, their styles dropped:
    /// Credential Manager draws plain text. A full-text row shows its label alone; an image shows
    /// clipped, as a field holds text alone.
    ///
    /// # Errors
    ///
    /// [`NoName`]: the label is white space alone.
    pub fn of(row: &Row) -> Result<Self, NoName> {
        let name = FieldName::fit(&row.label.to_string())?;
        let value = match &row.value {
            None => None,
            Some(Value::Image(_)) => Some(FieldText::partial("")),
            Some(Value::Text(text)) => Some(FieldText::fit(&text.to_string())),
        };
        Ok(Self { name, value })
    }

    /// The label.
    #[must_use]
    pub const fn name(&self) -> &FieldName {
        &self.name
    }

    /// The value; `None` shows the label alone.
    #[must_use]
    pub const fn value(&self) -> Option<&FieldText> {
        self.value.as_ref()
    }

    /// Whether the label and the value are whole.
    #[must_use]
    pub fn extent(&self) -> Extent {
        let clipped = std::iter::once(&self.name.0)
            .chain(&self.value)
            .any(|text| text.extent == Extent::Clipped);
        if clipped {
            Extent::Clipped
        } else {
            Extent::Whole
        }
    }
}
