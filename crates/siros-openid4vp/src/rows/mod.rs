//! The row vocabulary every plug-in renders into. A row is a typed label and an optional typed
//! value: label kinds are PaSO View §3's `display_type`s, value kinds its value types; a row
//! without a value is a full-text row. A value keeps its parsed form and its text, formatted once
//! in the display locale from the wallet's own table.

mod env;
mod https_url;
mod values;

use crate::text::{Span, spans};

pub use env::{
    Amounts, Choice, DisplayLocale, Env, EnvError, Icon, IconMedia, TableLocale, WalletText,
};
pub use https_url::{HttpsUrl, NoALabel, NotHttpsUrl, Shown, UnreachableUrl};
pub use values::{
    Amount, BadValue, Currency, Date, FormattedKind, Frequency, Offset, Parsed, Time, Written,
};

/// A label kind (PaSO Proof Metadata §3.3 `display_type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LabelKind {
    /// Plain text.
    Text,
    /// `mini_markdown`.
    MiniMarkdown,
}

/// A row's label: its kind and its text as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Label {
    /// How the text renders.
    pub kind: LabelKind,
    /// The text as written.
    pub text: String,
}

impl Label {
    /// A plain-text label.
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            kind: LabelKind::Text,
            text: text.into(),
        }
    }

    /// A `mini_markdown` label.
    pub fn mini_markdown(text: impl Into<String>) -> Self {
        Self {
            kind: LabelKind::MiniMarkdown,
            text: text.into(),
        }
    }

    /// The label as styled spans: plain text is one unstyled span.
    #[must_use]
    pub fn spans(&self) -> Vec<Span> {
        match self.kind {
            LabelKind::MiniMarkdown => spans(&self.text),
            LabelKind::Text => vec![Span {
                text: self.text.clone(),
                style: crate::text::Style::PLAIN,
            }],
        }
    }
}

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
    /// Any other kind, with its text formatted once.
    Formatted {
        /// The parsed form.
        parsed: Parsed,
        /// The text in the display locale.
        text: String,
    },
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
    /// The value's kind.
    #[must_use]
    pub fn kind(&self) -> ValueKind {
        match self {
            Self::Image(_) => ValueKind::Image,
            Self::Formatted { parsed, .. } => ValueKind::Formatted(parsed.kind()),
        }
    }

    /// The text in the display locale; an image has none.
    #[must_use]
    pub fn text(&self) -> Option<&str> {
        match self {
            Self::Image(_) => None,
            Self::Formatted { text, .. } => Some(text),
        }
    }

    /// A `mini_markdown` value as styled spans; `None` for other kinds.
    #[must_use]
    pub fn spans(&self) -> Option<Vec<Span>> {
        match self {
            Self::Formatted {
                parsed: Parsed::MiniMarkdown,
                text,
            } => Some(spans(text)),
            _ => None,
        }
    }
}

/// One row of a box.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// The label.
    pub label: Label,
    /// The value; `None` makes a full-text row.
    pub value: Option<Value>,
    /// The title of the delimited section the row sits in.
    pub section: Option<String>,
}

impl Row {
    /// A row showing a value.
    #[must_use]
    pub fn new(label: Label, value: Value) -> Self {
        Self {
            label,
            value: Some(value),
            section: None,
        }
    }

    /// A full-text row: its label alone.
    #[must_use]
    pub fn full_text(label: Label) -> Self {
        Self {
            label,
            value: None,
            section: None,
        }
    }

    /// The row placed in a delimited section.
    #[must_use]
    pub fn in_section(self, section: impl Into<String>) -> Self {
        Self {
            section: Some(section.into()),
            ..self
        }
    }
}
