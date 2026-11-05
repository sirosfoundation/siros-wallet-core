//! The row vocabulary every plug-in renders into. A row is a label and an optional value, each a
//! [`Text`] the core renders when it is displayed; a row without a value is a full-text row.

mod env;
mod https_url;
mod values;

use siros_explain::Text;

pub use env::{Choice, Env, EnvError, Icon, ImageMedia, NotImageMedia, WalletText};
pub use https_url::{HttpsUrl, NoALabel, NotHttpsUrl, Shown, UnreachableUrl};
pub use siros_i18n::{Amounts, Bidi, OnRenderError, RenderOptions};
pub use values::{BadValue, FormattedKind, Frequency, Parsed, Written, formatted};

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

/// A row's value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// An image, which has no text.
    Image(Image),
    /// A text: a typed value where the value has a type.
    Text(Text),
}

/// A value kind (PaSO View §3 value types).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValueKind {
    /// An image.
    Image,
    /// A kind other than an image.
    Formatted(FormattedKind),
}

impl ValueKind {
    /// The kind's name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Image => "image",
            Self::Formatted(kind) => kind.as_str(),
        }
    }
}

impl Value {
    /// The text; an image has none.
    #[must_use]
    pub const fn text(&self) -> Option<&Text> {
        match self {
            Self::Image(_) => None,
            Self::Text(text) => Some(text),
        }
    }

    /// An https URL, shown as written with its host in A-label form.
    #[must_use]
    pub fn url(url: &HttpsUrl) -> Self {
        Self::Text(Text::Raw(url.ascii().to_owned()))
    }
}

/// One row of a box.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// The label.
    pub label: Text,
    /// The value; `None` makes a full-text row.
    pub value: Option<Value>,
    /// The title of the delimited section the row sits in.
    pub section: Option<Text>,
}

impl Row {
    /// A row showing a value.
    #[must_use]
    pub const fn new(label: Text, value: Value) -> Self {
        Self {
            label,
            value: Some(value),
            section: None,
        }
    }

    /// A full-text row: its label alone.
    #[must_use]
    pub const fn full_text(label: Text) -> Self {
        Self {
            label,
            value: None,
            section: None,
        }
    }

    /// The row placed in a delimited section.
    #[must_use]
    pub fn in_section(self, section: Text) -> Self {
        Self {
            section: Some(section),
            ..self
        }
    }
}
