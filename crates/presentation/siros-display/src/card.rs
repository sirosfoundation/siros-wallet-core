//! Credential cards (D2, D3).

use siros_credential::{Credential, Format};

use crate::cache::DisplayCache;
use crate::colour::Colour;
use crate::issuer::IssuerMetadata;
use crate::locale::{lookup, Locale};
use crate::logo::Logo;
use crate::text::{CardText, IssuerTemplate};
use crate::type_metadata::TypeMetadata;

/// What shows a credential to the user: its title, its issuer, its logo and its colours.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Card {
    title: CardText,
    issuer: CardText,
    logo: Option<Logo>,
    background: Option<Colour>,
    text: Option<Colour>,
}

impl Card {
    /// The title.
    pub fn title(&self) -> &CardText {
        &self.title
    }

    /// The issuer line.
    pub fn issuer(&self) -> &CardText {
        &self.issuer
    }

    /// The logo.
    pub fn logo(&self) -> Option<&Logo> {
        self.logo.as_ref()
    }

    /// The background colour.
    pub fn background(&self) -> Option<Colour> {
        self.background
    }

    /// The text colour.
    pub fn text(&self) -> Option<Colour> {
        self.text
    }
}

/// The texts the host gives cards, in the wallet's language: the title and issuer line of a card
/// whose display metadata names none, and the template of a named issuer's line. The owner's
/// wallet passes its `displayTitleFallback`, `displaySubtitleFallback` and `displaySubtitle`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardWording {
    /// The title of a card without a named display entry.
    pub title: CardText,
    /// The issuer line of a card whose Credential Issuer's display names no issuer.
    pub issuer: CardText,
    /// The issuer line around a named issuer; `None` for the name alone.
    pub issuer_template: Option<IssuerTemplate>,
}

impl DisplayCache {
    /// The card of `credential` in the wallet's `language`.
    ///
    /// [`lookup`] takes the entry from the `display` of the credential's Type Metadata, the
    /// nearest type that has one (SD-JWT VC, Section 5.5.2). Without a type entry for the
    /// language it takes it from the `credential_metadata.display` of the credential's
    /// configuration, the fallback (D3, OpenID4VCI 1.0, Section 12.2.4). The entry gives the
    /// title, logo and colours. The issuer line is the named entry of the Credential Issuer's
    /// `display` [`lookup`] takes, in `wording`'s issuer template when it has one. A title or an
    /// issuer line without a name is `wording`'s.
    pub fn card(&self, credential: &Credential, language: &Locale, wording: &CardWording) -> Card {
        let issued = self.issuer_metadata(credential);
        let type_display = self
            .types_of(credential)
            .into_iter()
            .find_map(TypeMetadata::display)
            .unwrap_or_default();
        let entry = lookup(language, type_display)
            .or_else(|| issued.and_then(|metadata| lookup(language, metadata.display())));
        let named = issued.and_then(|m| lookup(language, m.issuer_display()));
        let issuer = match (named, &wording.issuer_template) {
            (Some(named), Some(template)) => template.line(&named.text),
            (Some(named), None) => CardText::of(&named.text),
            (None, _) => wording.issuer.clone(),
        };
        let title = entry.map_or_else(|| wording.title.clone(), |entry| CardText::of(&entry.name));
        Card {
            title,
            issuer,
            logo: entry.and_then(|entry| entry.logo.clone()),
            background: entry.and_then(|entry| entry.background),
            text: entry.and_then(|entry| entry.text),
        }
    }

    /// The issuer metadata of `credential`'s configuration, when the host holds it.
    pub fn issuer_metadata(&self, credential: &Credential) -> Option<&IssuerMetadata> {
        self.issuer(credential.issuer()?, credential.configuration_id()?)
    }

    /// The Type Metadata of an SD-JWT VC's `vct` and of the types it extends.
    pub(crate) fn types_of(&self, credential: &Credential) -> Vec<&TypeMetadata> {
        match credential.format() {
            Format::SdJwtVc => self
                .type_chain(credential.credential_type().as_str())
                .collect(),
            Format::Mdoc => Vec::new(),
        }
    }
}
