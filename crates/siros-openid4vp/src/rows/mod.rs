//! The row vocabulary every plug-in renders into. A row is a label and an optional value, each a
//! [`Text`] the core renders when it is displayed, or for a transaction's overlay a
//! [`RequestText`]; a row without a value is a full-text row.

mod env;
mod https_url;

use siros_explain::{RequestText, Text};

pub use env::{BooleanText, Choice, Env, EnvError, Icon, ImageMedia, NotImageMedia, WalletText};
pub use https_url::{HttpsUrl, NoALabel, NotHttpsUrl, Shown, UnreachableUrl};
pub use siros_i18n::{
    Amounts, Bidi, Language, ModuleName, OnRenderError, RENDERER, RenderOptions, RenderingInputs,
    Selected,
};

/// An image a row shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Image {
    /// An image the matcher holds and verified.
    Embedded(ImageRef),
    /// An https image the matcher could not fetch: phase 2 fetches and verifies it before
    /// answering. The matcher's platform draws no image; the wallet UI draws one once verified.
    Remote(RemoteImage),
}

/// An image the matcher holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageRef {
    /// The https URL, or the Data URL's media type.
    pub source: String,
    /// The media type.
    pub media: String,
    /// The width in pixels.
    pub width: u32,
    /// The height in pixels.
    pub height: u32,
}

/// An https image phase 2 fetches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteImage {
    /// The URL.
    pub url: String,
    /// Its integrity metadata (W3C SRI).
    pub integrity: String,
}

/// A row's value, its text a [`Text`] or, in a transaction's overlay, a [`RequestText`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value<T = Text> {
    /// An image, which has no text.
    Image(Image),
    /// A text: a typed value where the value has a type.
    Text(T),
}

impl<T> Value<T> {
    /// The text; an image has none.
    #[must_use]
    pub const fn text(&self) -> Option<&T> {
        match self {
            Self::Image(_) => None,
            Self::Text(text) => Some(text),
        }
    }
}

impl Value<RequestText> {
    /// An https URL, shown as written with its host in A-label form.
    #[must_use]
    pub fn url(url: &HttpsUrl) -> Self {
        Self::Text(RequestText::raw(url.ascii().to_owned()))
    }
}

impl From<Value<RequestText>> for Value {
    fn from(value: Value<RequestText>) -> Self {
        match value {
            Value::Image(image) => Self::Image(image),
            Value::Text(text) => Self::Text(text.into()),
        }
    }
}

/// One row of a box, its texts [`Text`]s or, in a transaction's overlay, [`RequestText`]s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row<T = Text> {
    /// The label.
    pub label: T,
    /// The value; `None` makes a full-text row.
    pub value: Option<Value<T>>,
    /// The title of the delimited section the row sits in.
    pub section: Option<T>,
}

impl From<Row<RequestText>> for Row {
    fn from(row: Row<RequestText>) -> Self {
        Self {
            label: row.label.into(),
            value: row.value.map(Value::from),
            section: row.section.map(Text::from),
        }
    }
}

impl<T> Row<T> {
    /// A row showing a value.
    #[must_use]
    pub const fn new(label: T, value: Value<T>) -> Self {
        Self {
            label,
            value: Some(value),
            section: None,
        }
    }

    /// A full-text row: its label alone.
    #[must_use]
    pub const fn full_text(label: T) -> Self {
        Self {
            label,
            value: None,
            section: None,
        }
    }

    /// The row placed in a delimited section.
    #[must_use]
    pub fn in_section(self, section: T) -> Self {
        Self {
            section: Some(section),
            ..self
        }
    }
}
