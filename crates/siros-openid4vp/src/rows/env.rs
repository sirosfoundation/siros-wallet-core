//! The wallet's configuration the display reads, and its own string table.

use std::borrow::Cow;
use std::num::NonZeroU32;

use siros_explain::Explain;

use crate::ids::LocaleTag;
use crate::text::lookup;

/// The locales of the wallet's string table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TableLocale {
    /// English.
    En,
    /// German.
    De,
}

impl TableLocale {
    const TAGS: [&'static str; 2] = ["en", "de"];

    /// The table locale RFC 4647 Lookup selects for a display locale.
    #[must_use]
    pub fn of(display: &LocaleTag<'_>) -> Option<Self> {
        match lookup(display, &Self::TAGS).copied() {
            Some("en") => Some(Self::En),
            Some("de") => Some(Self::De),
            _ => None,
        }
    }
}

/// A string of the wallet's own table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WalletText {
    /// The denial action.
    Deny,
    /// The confirm action of a request without a transaction.
    Share,
    /// The empty choice.
    None,
    /// A card without a name.
    Credential,
    /// The title of a request without a transaction.
    RequestTitle,
    /// A true boolean.
    Yes,
    /// A false boolean.
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
    pub tag: LocaleTag<'static>,
    /// The table locale it selects.
    pub table: TableLocale,
}

impl DisplayLocale {
    /// The display locale of a tag; `None` when the wallet's table has no locale for it.
    #[must_use]
    pub fn of(tag: LocaleTag<'static>) -> Option<Self> {
        TableLocale::of(&tag).map(|table| Self { tag, table })
    }

    /// A string of the wallet's table in this locale.
    #[must_use]
    pub const fn text(&self, key: WalletText) -> &'static str {
        key.in_locale(self.table)
    }
}

/// A media type Credential Manager draws as an icon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IconMedia {
    /// `image/png`.
    Png,
    /// `image/jpeg`.
    Jpeg,
}

impl IconMedia {
    /// The media type.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Png => "image/png",
            Self::Jpeg => "image/jpeg",
        }
    }
}

/// An icon Credential Manager can draw: a PNG or JPEG of at least one byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Icon {
    /// The card's logo URI, or a wallet asset.
    pub reference: Cow<'static, str>,
    /// The media type.
    pub media: IconMedia,
    /// The byte length.
    pub size: NonZeroU32,
}

impl Icon {
    /// The wallet's icon for a card without a logo.
    pub const DEFAULT: Icon = Icon {
        reference: Cow::Borrowed("wallet:card"),
        media: IconMedia::Png,
        size: NonZeroU32::MIN.saturating_add(4095),
    };
    /// The wallet's icon for the empty choice.
    pub const NONE: Icon = Icon {
        reference: Cow::Borrowed("wallet:none"),
        media: IconMedia::Png,
        size: NonZeroU32::MIN.saturating_add(2047),
    };
}

/// How the display formats amounts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Amounts {
    /// From the wallet's table where it has a format.
    Formatted,
    /// As written.
    Raw,
}

/// How Credential Manager offers the consent.
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
    /// The wallet's table has no locale for the first tag of the priority list.
    #[error("the wallet's priority list holds {0}, which the table lacks")]
    NotInTable(#[explain(name = "locale")] String),
}

/// The wallet's configuration the display reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Env {
    first: DisplayLocale,
    later: Vec<LocaleTag<'static>>,
    icons: Vec<(String, Icon)>,
    amounts: Amounts,
    choice: Choice,
}

impl Env {
    /// The configuration: a non-empty priority list whose first tag the wallet's table serves,
    /// the icons resolved at issuance by logo URI, the amounts mode and the offer shape.
    pub fn new(
        locales: impl IntoIterator<Item = LocaleTag<'static>>,
        icons: Vec<(String, Icon)>,
        amounts: Amounts,
        choice: Choice,
    ) -> Result<Self, EnvError> {
        let mut locales = locales.into_iter();
        let tag = locales.next().ok_or(EnvError::NoLocale)?;
        let shown = tag.as_str().to_owned();
        let first = DisplayLocale::of(tag).ok_or(EnvError::NotInTable(shown))?;
        let later = locales.collect();
        Ok(Self {
            first,
            later,
            icons,
            amounts,
            choice,
        })
    }

    /// The priority list.
    pub fn locales(&self) -> impl Iterator<Item = &LocaleTag<'static>> {
        std::iter::once(&self.first.tag).chain(&self.later)
    }

    /// The first locale of the priority list, which the wallet's own strings use.
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

    /// The amounts mode.
    #[must_use]
    pub const fn amounts(&self) -> Amounts {
        self.amounts
    }

    /// The offer shape.
    #[must_use]
    pub const fn choice(&self) -> Choice {
        self.choice
    }
}
