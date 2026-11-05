//! The wallet's configuration the display reads, and its own texts.

use std::borrow::Cow;
use std::num::NonZeroU32;

use siros_explain::Explain;

use siros_i18n::RenderOptions;

use crate::ids::LocaleTag;
use crate::media::{MediaType, NotMediaType};

/// A text of the wallet's own: a message of the crate's module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.wallet")]
pub enum WalletText {
    /// The denial action.
    #[error("Cancel")]
    Deny,
    /// The confirm action of a request without a transaction.
    #[error("Share")]
    Share,
    /// The empty choice.
    #[error("None")]
    None,
    /// A card without a name.
    #[error("Credential")]
    Credential,
    /// The title of a request without a transaction.
    #[error("Share your data")]
    RequestTitle,
    /// A true boolean.
    #[error("Yes")]
    Yes,
    /// A false boolean.
    #[error("No")]
    No,
    /// A claim whose path names no member.
    #[error("claim")]
    Claim,
    /// A claim's `null` value.
    #[error("None")]
    Null,
}

/// An image media type (RFC 6838 §4.2.3): the essence of a media type of top-level type `image`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ImageMedia(Cow<'static, str>);

/// A media type that names no image.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.image_media")]
pub enum NotImageMedia {
    /// The text is no media type.
    #[error(transparent)]
    Media(#[from] NotMediaType),
    /// The top-level type is another than `image` (RFC 6838 §4.2.3).
    #[error("{0} is no image media type (RFC 6838 §4.2.3)")]
    Type(#[explain(name = "media")] String),
}

impl ImageMedia {
    /// `image/png`.
    pub const PNG: Self = Self(Cow::Borrowed("image/png"));
    /// `image/jpeg` (RFC 2046 §4.2).
    pub const JPEG: Self = Self(Cow::Borrowed("image/jpeg"));

    /// The image media type of a media type: its essence when its top-level type is `image`.
    ///
    /// # Errors
    ///
    /// [`NotImageMedia::Type`]: the top-level type is another.
    pub fn of(media: &MediaType) -> Result<Self, NotImageMedia> {
        match media.essence().split_once('/') {
            Some(("image", _)) => Ok(Self(Cow::Owned(media.essence().to_owned()))),
            _ => Err(NotImageMedia::Type(media.essence().to_owned())),
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

/// An icon of at least one byte: a wallet asset or a card's logo, with its image media type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Icon {
    /// The card's logo URI, or a wallet asset.
    pub reference: Cow<'static, str>,
    /// The media type.
    pub media: ImageMedia,
    /// The byte length.
    pub size: NonZeroU32,
}

impl Icon {
    /// The wallet's icon for a card without a logo.
    pub const DEFAULT: Icon = Icon {
        reference: Cow::Borrowed("wallet:card"),
        media: ImageMedia::PNG,
        size: NonZeroU32::MIN.saturating_add(4095),
    };
    /// The wallet's icon for the empty choice.
    pub const NONE: Icon = Icon {
        reference: Cow::Borrowed("wallet:none"),
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
#[explain(domain = "openid4vp.env")]
pub enum EnvError {
    /// The priority list is empty.
    #[error("the wallet's locale priority list is empty")]
    NoLocale,
}

/// The wallet's configuration the display reads: the End-User's language priority list, the
/// app's fallback list, the rendering options, the icons resolved at issuance and the offer
/// shape.
///
/// The core uses the priority list as given: a presentation is in the first language of the list
/// that every module it draws from matches by RFC 4647 basic filtering (§3.3.1), where a tag
/// matches an equal tag and the tags extending it, so `en` matches `en-GB` and `en-US` matches
/// no `en`. Modules tag their texts by language, and by region only for a regional variant. An
/// app therefore puts each tag's generic form right after it, the language with its script when
/// the tag names one: `[en-US, en]`, `[zh-Hant-TW, zh-Hant]`. The fallback list holds the
/// languages the app shows when no tag of the priority list serves every module and none of
/// them requires a language the End-User understands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Env {
    priority: Vec<LocaleTag>,
    fallback: Vec<LocaleTag>,
    options: RenderOptions,
    icons: Vec<(String, Icon)>,
    choice: Choice,
}

impl Env {
    /// The configuration: a non-empty priority list, the fallback list, the rendering options,
    /// the icons resolved at issuance by logo URI and the offer shape.
    ///
    /// # Errors
    ///
    /// [`EnvError::NoLocale`] for an empty priority list.
    pub fn new(
        priority: Vec<LocaleTag>,
        fallback: Vec<LocaleTag>,
        options: RenderOptions,
        icons: Vec<(String, Icon)>,
        choice: Choice,
    ) -> Result<Self, EnvError> {
        if priority.is_empty() {
            return Err(EnvError::NoLocale);
        }
        Ok(Self {
            priority,
            fallback,
            options,
            icons,
            choice,
        })
    }

    /// The End-User's priority list, as given.
    #[must_use]
    pub fn priority(&self) -> &[LocaleTag] {
        &self.priority
    }

    /// The app's fallback list.
    #[must_use]
    pub fn fallback(&self) -> &[LocaleTag] {
        &self.fallback
    }

    /// The card's icon: the logo resolved at issuance, else the wallet's default (Credential
    /// Manager drops an entry without an icon).
    #[must_use]
    pub fn icon(&self, logo: Option<&str>) -> &Icon {
        logo.filter(|uri| !uri.is_empty())
            .and_then(|uri| self.icons.iter().find(|(known, _)| known == uri))
            .map_or(&Icon::DEFAULT, |(_, icon)| icon)
    }

    /// The rendering options.
    #[must_use]
    pub const fn options(&self) -> RenderOptions {
        self.options
    }

    /// The offer shape.
    #[must_use]
    pub const fn choice(&self) -> Choice {
        self.choice
    }
}
