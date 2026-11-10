//! The row vocabulary every plug-in draws into. A row is a label and an optional value, each a
//! [`Text`] a `siros_i18n::Context` resolved; a row without a value is a full-text row.

mod env;
mod https_url;

use siros_i18n::Text;

pub use env::{
    BooleanText, Choice, ClaimText, Env, EnvError, ExactNumber, Icon, IconReference, ImageMedia,
    NotImageMedia, WalletText,
};
pub use https_url::{HttpsUrl, NotHttpsUrl};

/// An image a row shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Image {
    /// An image the matcher holds and verified.
    Embedded(ImageRef),
    /// An https image the matcher could not fetch: phase 2 fetches and verifies it before
    /// answering. The matcher's platform draws no image; the wallet UI draws one once verified.
    Remote(RemoteImage),
}

/// Where the bytes of an image the matcher holds came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageSource {
    /// A Data URL, of the image's media type.
    Data,
    /// An https URL the bytes were fetched from.
    Url(Box<HttpsUrl>),
}

/// An image's width in pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ImageWidth(u32);

impl ImageWidth {
    /// The width of this many pixels.
    #[must_use]
    pub const fn new(pixels: u32) -> Self {
        Self(pixels)
    }

    /// The pixels.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// An image's height in pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ImageHeight(u32);

impl ImageHeight {
    /// The height of this many pixels.
    #[must_use]
    pub const fn new(pixels: u32) -> Self {
        Self(pixels)
    }

    /// The pixels.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// An image the matcher holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageRef {
    source: ImageSource,
    media: ImageMedia,
    width: ImageWidth,
    height: ImageHeight,
}

impl ImageRef {
    /// The image of bytes from this source, of this media type and these dimensions.
    #[must_use]
    pub const fn new(
        source: ImageSource,
        media: ImageMedia,
        width: ImageWidth,
        height: ImageHeight,
    ) -> Self {
        Self {
            source,
            media,
            width,
            height,
        }
    }

    /// Where its bytes came from.
    #[must_use]
    pub const fn source(&self) -> &ImageSource {
        &self.source
    }

    /// The media type.
    #[must_use]
    pub const fn media(&self) -> &ImageMedia {
        &self.media
    }

    /// The width.
    #[must_use]
    pub const fn width(&self) -> ImageWidth {
        self.width
    }

    /// The height.
    #[must_use]
    pub const fn height(&self) -> ImageHeight {
        self.height
    }
}

/// Integrity metadata (W3C SRI §3.3.3) as a document wrote it: any text.
#[cfg_attr(
    feature = "sri",
    doc = "[`crate::sri::matches`] reads it through [`crate::sri::Integrity::parse`], and a text the"
)]
#[cfg_attr(
    not(feature = "sri"),
    doc = "`sri::matches`, with the feature `sri`, reads it through `sri::Integrity::parse`, and a text the"
)]
/// parser refuses matches nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SriMetadata(String);

impl SriMetadata {
    /// The metadata as written.
    #[must_use]
    pub const fn written(text: String) -> Self {
        Self(text)
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An https image phase 2 fetches and verifies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteImage {
    url: Box<HttpsUrl>,
    integrity: SriMetadata,
}

impl RemoteImage {
    /// The image at this URL under this metadata.
    #[must_use]
    pub fn new(url: HttpsUrl, integrity: SriMetadata) -> Self {
        Self {
            url: Box::new(url),
            integrity,
        }
    }

    /// The URL.
    #[must_use]
    pub const fn url(&self) -> &HttpsUrl {
        &self.url
    }

    /// Its integrity metadata.
    #[must_use]
    pub const fn integrity(&self) -> &SriMetadata {
        &self.integrity
    }
}

/// A row's value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// An image, which has no text.
    Image(Image),
    /// A text.
    Text(Text),
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
