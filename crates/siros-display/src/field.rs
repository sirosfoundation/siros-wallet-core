//! The fields of a credential picker entry: each row's label and value as one short line, and
//! whether a text was cut to fit, which decides the wallet's display (A9).

use crate::labels::{ClaimRow, DisplayValue};
use crate::text::{LabelText, TextError};

/// The most characters of a field's label or value.
pub const FIELD_MAX: usize = 80;

/// Whether a field's text holds what it shows whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Extent {
    /// The text is whole.
    Whole,
    /// The text is cut to fit, or stands for a value a line cannot show.
    Clipped,
}

/// The text of a field: at most [`FIELD_MAX`] characters, and its extent.
#[derive(Clone, PartialEq, Eq)]
pub struct FieldText {
    text: String,
    extent: Extent,
}

/// The label of a field: [`FieldText`] with a character other than white space, which the host
/// requires of a field's name.
#[derive(Clone, PartialEq, Eq)]
pub struct FieldName(FieldText);

/// A field of a picker entry: its label, and its value when it has one.
#[derive(Clone, PartialEq, Eq)]
pub struct Field {
    name: FieldName,
    value: Option<FieldText>,
}

impl FieldName {
    /// The name of `label`.
    #[must_use]
    pub fn of(label: &LabelText) -> Self {
        Self(FieldText::fit(label.as_str().trim_start()))
    }

    /// `text` from its first character other than white space, cut to [`FIELD_MAX`]
    /// characters.
    ///
    /// # Errors
    ///
    /// [`TextError::Empty`] for white space alone.
    pub fn fit(text: &str) -> Result<Self, TextError> {
        match text.trim_start() {
            "" => Err(TextError::Empty),
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
    pub fn extent(&self) -> Extent {
        self.0.extent()
    }
}

impl FieldText {
    /// `text`, cut to [`FIELD_MAX`] characters and ending in an ellipsis when longer.
    #[must_use]
    pub fn fit(text: &str) -> Self {
        Self::fit_within(text, FIELD_MAX)
    }

    /// `text`, cut to `max` characters and ending in an ellipsis when longer.
    #[must_use]
    pub(crate) fn fit_within(text: &str, max: usize) -> Self {
        if text.chars().count() <= max {
            return Self {
                text: text.to_owned(),
                extent: Extent::Whole,
            };
        }
        let mut text: String = text.chars().take(max.saturating_sub(1)).collect();
        text.push('\u{2026}');
        Self {
            text,
            extent: Extent::Clipped,
        }
    }

    /// The text followed by a space and `marker`, with the text's extent.
    pub(crate) fn marked(self, marker: &str) -> Self {
        Self {
            text: format!("{} {marker}", self.text),
            extent: self.extent,
        }
    }

    /// `text` standing for a value a line cannot show whole.
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
    pub fn extent(&self) -> Extent {
        self.extent
    }
}

impl Field {
    /// The field of `name` and `value`.
    #[must_use]
    pub fn new(name: FieldName, value: Option<FieldText>) -> Self {
        Self { name, value }
    }

    /// The label.
    #[must_use]
    pub fn name(&self) -> &FieldName {
        &self.name
    }

    /// The value; `None` shows the label alone.
    #[must_use]
    pub fn value(&self) -> Option<&FieldText> {
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

    /// The field of a claim row: its label, and its value as one line. A `null` shows the
    /// label alone; a list of scalars shows its values joined by `, `. A byte string, a group,
    /// and a list that holds either, show clipped.
    #[must_use]
    pub fn of_claim(row: &ClaimRow) -> Self {
        Self {
            name: FieldName::of(row.label()),
            value: line(row.value()),
        }
    }
}

/// `value` as one line; `None` for `null`.
fn line(value: &DisplayValue) -> Option<FieldText> {
    match value {
        DisplayValue::Null => None,
        DisplayValue::List(values) => {
            let scalars: Option<Vec<String>> = values.iter().map(scalar).collect();
            Some(match scalars {
                Some(scalars) => FieldText::fit(&scalars.join(", ")),
                None => FieldText::partial(""),
            })
        }
        other => {
            Some(scalar(other).map_or_else(|| FieldText::partial(""), |text| FieldText::fit(&text)))
        }
    }
}

/// The text of a scalar value; `None` for a byte string, a list and a group, which no text
/// shows whole.
fn scalar(value: &DisplayValue) -> Option<String> {
    Some(match value {
        DisplayValue::Null => "null".to_owned(),
        DisplayValue::Boolean(b) => b.to_string(),
        DisplayValue::Integer(i) => i.to_string(),
        // The shortest text that reads back as the number, as JSON writes it.
        DisplayValue::Number(n) => serde_json::Number::from_f64(*n)?.to_string(),
        DisplayValue::Text(text) => text.clone(),
        DisplayValue::Date(date) => date.to_string(),
        DisplayValue::DateTime(time) => time.to_string(),
        DisplayValue::Bytes(_) | DisplayValue::List(_) | DisplayValue::Group(_) => return None,
    })
}
