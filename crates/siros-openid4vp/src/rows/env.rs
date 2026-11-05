//! The wallet's configuration the display reads, and its own string table.

use std::borrow::Cow;
use std::num::NonZeroU32;

use siros_explain::Explain;

use siros_i18n::RenderOptions;

use crate::ids::LocaleTag;
use crate::media::{MediaType, NotMediaType};

/// The locales of the wallet's string table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TableLocale {
    /// English.
    En,
    /// German.
    De,
}

impl TableLocale {
    /// The table locale whose language serves a display locale: its tag, as a basic language
    /// range, matches the display locale (`en` serves `en-US`).
    #[must_use]
    pub fn of(display: &LocaleTag) -> Option<Self> {
        let serves = |tag: &str| LocaleTag::parse(tag).is_ok_and(|tag| tag.filters(display));
        [(Self::En, "en"), (Self::De, "de")]
            .into_iter()
            .find(|(_, tag)| serves(tag))
            .map(|(locale, _)| locale)
    }
}

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
}

impl WalletText {
    /// The string in a table locale.
    #[must_use]
    pub const fn in_locale(self, locale: TableLocale) -> &'static str {
        match (locale, self) {
            (TableLocale::En, Self::Deny) => "Cancel",
            (TableLocale::En, Self::Share) => "Share",
            (TableLocale::En, Self::None) => "None",
            (TableLocale::En, Self::Credential) => "Credential",
            (TableLocale::En, Self::RequestTitle) => "Share your data",
            (TableLocale::En, Self::Yes) => "Yes",
            (TableLocale::En, Self::No) => "No",
            (TableLocale::De, Self::Deny) => "Abbrechen",
            (TableLocale::De, Self::Share) => "Teilen",
            (TableLocale::De, Self::None) => "Keine",
            (TableLocale::De, Self::Credential) => "Nachweis",
            (TableLocale::De, Self::RequestTitle) => "Daten teilen",
            (TableLocale::De, Self::Yes) => "Ja",
            (TableLocale::De, Self::No) => "Nein",
        }
    }
}

/// A locale of the wallet's priority list with the table locale it selects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplayLocale {
    /// The language tag.
    pub tag: LocaleTag,
    /// The table locale it selects.
    pub table: TableLocale,
}

impl DisplayLocale {
    /// The display locale of a tag; `None` when the wallet's table has no locale for it.
    #[must_use]
    pub fn of(tag: LocaleTag) -> Option<Self> {
        TableLocale::of(&tag).map(|table| Self { tag, table })
    }

    /// A string of the wallet's table in this locale.
    #[must_use]
    pub const fn text(&self, key: WalletText) -> &'static str {
        key.in_locale(self.table)
    }
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
    /// Neither the priority list nor the fallback list holds a tag the wallet's table serves.
    #[error(
        "neither the priority list from {0} nor the fallback list holds a tag the table serves"
    )]
    NotInTable(#[explain(name = "locale")] String),
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
    first: DisplayLocale,
    options: RenderOptions,
    icons: Vec<(String, Icon)>,
    choice: Choice,
}

impl Env {
    /// The configuration: a non-empty priority list, the fallback list, the rendering options,
    /// the icons resolved at issuance by logo URI and the offer shape. The wallet's own strings
    /// take the first tag of the priority list, then of the fallback list, that the wallet's
    /// table serves.
    ///
    /// # Errors
    ///
    /// [`EnvError::NoLocale`] for an empty priority list; [`EnvError::NotInTable`] when neither
    /// list holds a tag the table serves.
    pub fn new(
        priority: Vec<LocaleTag>,
        fallback: Vec<LocaleTag>,
        options: RenderOptions,
        icons: Vec<(String, Icon)>,
        choice: Choice,
    ) -> Result<Self, EnvError> {
        let shown = priority.first().ok_or(EnvError::NoLocale)?.to_string();
        let first = priority
            .iter()
            .chain(&fallback)
            .find_map(|tag| DisplayLocale::of(tag.clone()))
            .ok_or(EnvError::NotInTable(shown))?;
        Ok(Self {
            priority,
            fallback,
            first,
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

    /// The locale the wallet's own strings use.
    #[must_use]
    pub const fn first(&self) -> &DisplayLocale {
        &self.first
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
