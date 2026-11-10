//! The wallet's configuration the display reads, and the statements of its own texts.

use std::borrow::Cow;
use std::fmt;
use std::num::NonZeroU32;

use siros_explain::Explain;
use siros_i18n::Message;
use siros_syntax::{Count, Date, DateTime, Decimal};

use crate::ids::LocaleTag;
use crate::media::{MediaType, NotMediaType};

/// A text of the wallet's own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Message)]
pub enum WalletText {
    /// The denial action.
    #[message(id = "wallet.deny")]
    Deny,
    /// The confirm action of a request without a transaction.
    #[message(id = "wallet.share")]
    Share,
    /// The empty choice.
    #[message(id = "wallet.none")]
    None,
    /// A card without a name.
    #[message(id = "wallet.credential")]
    Credential,
    /// The title of a request without a transaction.
    #[message(id = "wallet.request_title")]
    RequestTitle,
    /// A claim whose path names no member.
    #[message(id = "wallet.claim")]
    Claim,
    /// A claim's `null` value.
    #[message(id = "wallet.null")]
    Null,
}

/// A text of a credential shown alone, carrying its literal text: the wallet's wording formats it
/// (`{$value :number}`, `{$value :siros:date}`) or writes it as given.
#[derive(Debug, Clone, PartialEq, Eq, Message)]
pub enum ClaimText {
    /// A string value, as the credential wrote it.
    #[message(id = "wallet.text")]
    Text {
        /// The string.
        value: String,
    },
    /// A number value as an exact number.
    #[message(id = "wallet.number")]
    Number {
        /// The number.
        value: ExactNumber,
    },
    /// A date value.
    #[message(id = "wallet.date")]
    Date {
        /// The date.
        value: Date,
    },
    /// A date and time value.
    #[message(id = "wallet.date_time")]
    DateTime {
        /// The date and time.
        value: DateTime,
    },
    /// A byte string value, shown by its `length` in bytes.
    #[message(id = "wallet.bytes")]
    Bytes {
        /// The bytes it holds.
        length: Count,
    },
    /// A label, a title or a name the credential's metadata writes, or a member name standing
    /// in for a label, as written.
    #[message(id = "wallet.label")]
    Label {
        /// The text.
        label: String,
    },
}

/// A number as an exact value. Its `Display` is its literal, which `:number` reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExactNumber {
    /// A natural number.
    Count(Count),
    /// Another number.
    Decimal(Decimal),
}

impl fmt::Display for ExactNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Count(count) => count.fmt(f),
            Self::Decimal(decimal) => decimal.fmt(f),
        }
    }
}

/// A boolean's text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Message)]
pub enum BooleanText {
    /// A true boolean.
    #[message(id = "wallet.yes")]
    Yes,
    /// A false boolean.
    #[message(id = "wallet.no")]
    No,
}

/// An image media type (RFC 6838 §4.2.3): the essence of a media type of top-level type `image`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ImageMedia(Cow<'static, str>);

/// A media type that names no image.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
pub enum NotImageMedia {
    /// The text is no media type.
    #[error(transparent)]
    Media(#[from] NotMediaType),
    /// The top-level type is another than `image` (RFC 6838 §4.2.3).
    #[error("{media} is no image media type (RFC 6838 §4.2.3)")]
    #[explain(id = "image_media.type")]
    Type {
        /// The media type.
        media: String,
    },
}

impl ImageMedia {
    /// `image/png`.
    pub const PNG: Self = Self(Cow::Borrowed("image/png"));
    /// `image/jpeg` (RFC 2046 §4.2).
    pub const JPEG: Self = Self(Cow::Borrowed("image/jpeg"));
    /// `image/svg+xml` (RFC 6838).
    pub const SVG: Self = Self(Cow::Borrowed("image/svg+xml"));

    /// The image media type of a media type: its essence when its top-level type is `image`.
    ///
    /// # Errors
    ///
    /// [`NotImageMedia::Type`]: the top-level type is another.
    pub fn of(media: &MediaType) -> Result<Self, NotImageMedia> {
        match media.essence().split_once('/') {
            Some(("image", _)) => Ok(Self(Cow::Owned(media.essence().to_owned()))),
            _ => Err(NotImageMedia::Type {
                media: media.essence().to_owned(),
            }),
        }
    }

    /// The image media type a text names.
    ///
    /// # Errors
    ///
    /// [`NotImageMedia`]: the text is no media type, or names no image.
    pub fn parse(text: &str) -> Result<Self, NotImageMedia> {
        Self::of(&MediaType::parse(text)?)
    }

    /// `type/subtype`, lowercased.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What an icon names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IconReference {
    /// A wallet asset, such as `wallet:card`.
    Asset(Cow<'static, str>),
    /// A card's logo URI.
    Logo(Cow<'static, str>),
}

impl IconReference {
    /// The asset's name or the logo's URI.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Asset(text) | Self::Logo(text) => text,
        }
    }
}

/// An icon of at least one byte: a wallet asset or a card's logo, with its image media type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Icon {
    /// What it names.
    pub reference: IconReference,
    /// The media type.
    pub media: ImageMedia,
    /// The byte length.
    pub size: NonZeroU32,
}

impl Icon {
    /// The wallet's icon for a card without a logo.
    pub const DEFAULT: Icon = Icon {
        reference: IconReference::Asset(Cow::Borrowed("wallet:card")),
        media: ImageMedia::PNG,
        size: NonZeroU32::MIN.saturating_add(4095),
    };
    /// The wallet's icon for the empty choice.
    pub const NONE: Icon = Icon {
        reference: IconReference::Asset(Cow::Borrowed("wallet:none")),
        media: ImageMedia::PNG,
        size: NonZeroU32::MIN.saturating_add(2047),
    };
}

/// How the platform offers the consent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Choice {
    /// Each slot's default preselected; the user changes one slot at a time.
    First,
    /// One set per selection.
    LetChoose,
}

/// A wallet configuration that cannot exist.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
pub enum EnvError {
    /// The priority list is empty.
    #[error("the wallet's locale priority list is empty")]
    #[explain(id = "env.no_locale")]
    NoLocale,
}

/// The wallet's configuration the display reads: the End-User's language priority list, the
/// icons resolved at issuance and the offer shape. The `siros_i18n::Context` the wallet passes
/// holds the presentation's wording in its one locale.
///
/// The priority list chooses, as given, among the entries a credential's or a transaction's
/// metadata writes per language: SD-JWT VC §7 and §8.2's display entries, PaSO View §4's Lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Env {
    priority: Vec<LocaleTag>,
    icons: Vec<(String, Icon)>,
    choice: Choice,
}

impl Env {
    /// The configuration: a non-empty priority list, the icons resolved at issuance by logo URI
    /// and the offer shape.
    ///
    /// # Errors
    ///
    /// [`EnvError::NoLocale`] for an empty priority list.
    pub fn new(
        priority: Vec<LocaleTag>,
        icons: Vec<(String, Icon)>,
        choice: Choice,
    ) -> Result<Self, EnvError> {
        if priority.is_empty() {
            return Err(EnvError::NoLocale);
        }
        Ok(Self {
            priority,
            icons,
            choice,
        })
    }

    /// The End-User's priority list, as given.
    #[must_use]
    pub fn priority(&self) -> &[LocaleTag] {
        &self.priority
    }

    /// The card's icon: the logo resolved at issuance, else the wallet's default (Credential
    /// Manager drops an entry without an icon).
    #[must_use]
    pub fn icon(&self, logo: Option<&str>) -> &Icon {
        logo.filter(|uri| !uri.is_empty())
            .and_then(|uri| self.icons.iter().find(|(known, _)| known == uri))
            .map_or(&Icon::DEFAULT, |(_, icon)| icon)
    }

    /// The offer shape.
    #[must_use]
    pub const fn choice(&self) -> Choice {
        self.choice
    }
}
