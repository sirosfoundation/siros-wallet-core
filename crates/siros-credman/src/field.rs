//! A row as Credential Manager's field: its label and value as one short line of plain text, and
//! whether a text was cut to fit, which A9 reads.

use siros_explain::Explain;
use siros_openid4vp::rows::{Label, Row, Value};

/// The most characters of a field's label or value the matcher writes.
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
#[explain(domain = "credman.field")]
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
    /// The field of a row: its label's plain text, and its value's; a full-text row shows its
    /// label alone. An image shows clipped: a field holds text alone.
    ///
    /// # Errors
    ///
    /// [`NoName`]: the label is white space alone.
    pub fn of(row: &Row) -> Result<Self, NoName> {
        Ok(Self {
            name: FieldName::fit(&plain_label(&row.label))?,
            value: row.value.as_ref().map(|value| match value {
                Value::Image(_) => FieldText::partial(""),
                Value::Formatted { .. } => FieldText::fit(&plain_value(value)),
            }),
        })
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

/// A label's text with its styles dropped: Credential Manager draws plain text.
fn plain_label(label: &Label) -> String {
    label.spans().into_iter().map(|span| span.text).collect()
}

/// A formatted value's text with its styles dropped.
fn plain_value(value: &Value) -> String {
    match value.spans() {
        Some(spans) => spans.into_iter().map(|span| span.text).collect(),
        None => value.text().unwrap_or_default().to_owned(),
    }
}
