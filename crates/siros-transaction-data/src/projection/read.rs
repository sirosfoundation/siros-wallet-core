//! The reading of a projection's JSON text, as [`Projected::to_json`] writes it.

use siros_codec::json::{Json, JsonFault};
use siros_codec::member::MemberFault;
use siros_display::{Locale, LocaleError};

use super::{Projected, Unmatched};
use crate::definition::{ClaimIndex, Definition, DefinitionError, Localizations, UiElementKey};
use crate::definition::{AFFIRMATIVE, DENIAL, SECURITY_HINT, TITLE};
use crate::json::{self, Fields};
use crate::sources::{Rulebook, SourceKind};

/// A member of a projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProjectionMember {
    /// `language`.
    Language,
    /// `source`.
    Source,
    /// `rulebook`.
    Rulebook,
    /// `definition`.
    Definition,
}

impl ProjectionMember {
    /// The member's name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Language => "language",
            Self::Source => "source",
            Self::Rulebook => "rulebook",
            Self::Definition => "definition",
        }
    }
}

/// Why a text is no projection.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum ProjectionError {
    /// The text is no JSON document the strict reader holds.
    Json(#[source] JsonFault),
    /// The document is no object.
    NotObject,
    /// A member is absent or of the wrong type.
    Member(ProjectionMember, #[source] MemberFault),
    /// The projection has this member, which it does not define.
    MemberUnknown(String),
    /// `language` is no language tag.
    Language(#[source] LocaleError),
    /// `source` names no source.
    Source(String),
    /// `rulebook` names no rulebook.
    Rulebook(String),
    /// `definition` breaks PaSO Proof Metadata, Section 3, under the rules of its source.
    Definition(#[source] DefinitionError),
    /// This localised array holds other than one entry.
    EntryCount(#[source] Unmatched),
    /// The one entry of this array is not the one the locale function takes for `language`.
    Unmatched(#[source] Unmatched),
}

impl ProjectionError {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Json(_) | Self::NotObject | Self::Member(..) | Self::MemberUnknown(_) => {
                "projection_malformed"
            }
            Self::Language(error) => error.code(),
            Self::Source(_) => "projection_source_unknown",
            Self::Rulebook(_) => "projection_rulebook_unknown",
            Self::Definition(error) => error.code(),
            Self::EntryCount(_) => "projection_entry_count",
            Self::Unmatched(unmatched) => unmatched.code(),
        }
    }
}

impl Projected {
    /// The projection of the JSON text `text`: `language`, `source`, `rulebook`, and a
    /// `definition` whose labels follow the rules of its source, each localised array with the
    /// one entry the locale function takes for `language`.
    ///
    /// # Errors
    ///
    /// [`ProjectionError`]: the first rule `text` breaks.
    pub fn parse(text: &str) -> Result<Self, ProjectionError> {
        let mut fields = match Json::parse_unique(text.as_bytes()).map_err(ProjectionError::Json)? {
            Json::Object(members) => Fields::new(members),
            _ => return Err(ProjectionError::NotObject),
        };
        let language = Locale::parse(&text_member(&mut fields, ProjectionMember::Language)?)
            .map_err(ProjectionError::Language)?;
        let source = text_member(&mut fields, ProjectionMember::Source)?;
        let source = SourceKind::named(&source).ok_or(ProjectionError::Source(source))?;
        let rulebook = text_member(&mut fields, ProjectionMember::Rulebook)?;
        let rulebook = Rulebook::named(&rulebook).ok_or(ProjectionError::Rulebook(rulebook))?;
        let definition = fields
            .require(ProjectionMember::Definition.as_str())
            .map_err(|fault| ProjectionError::Member(ProjectionMember::Definition, fault))?;
        if let Some(unknown) = fields.first_left() {
            return Err(ProjectionError::MemberUnknown(unknown.to_owned()));
        }
        let definition = Definition::parse(definition, source.label_rules())
            .map_err(ProjectionError::Definition)?;
        one_entry_each(&definition)?;
        definition
            .project(&language, source, rulebook)
            .map_err(ProjectionError::Unmatched)
    }
}

/// The string member `member`.
fn text_member(fields: &mut Fields, member: ProjectionMember) -> Result<String, ProjectionError> {
    fields
        .require(member.as_str())
        .and_then(json::text)
        .map_err(|fault| ProjectionError::Member(member, fault))
}

/// Checks that each localised array of `definition` holds one entry.
fn one_entry_each(definition: &Definition) -> Result<(), ProjectionError> {
    let claims = definition
        .claims()
        .iter()
        .enumerate()
        .filter_map(|(at, claim)| {
            let count = claim.display().map(|display| display.entries().len())?;
            Some((Unmatched::Claim(ClaimIndex::new(at)), count))
        });
    let ui = definition.ui_labels();
    let named: [(UiElementKey, Option<usize>); 4] = [
        (AFFIRMATIVE, ui.affirmative().map(count)),
        (DENIAL, ui.denial().map(count)),
        (TITLE, ui.title().map(count)),
        (SECURITY_HINT, ui.security_hint().map(count)),
    ];
    let elements = named
        .into_iter()
        .filter_map(|(key, count)| Some((Unmatched::UiElement(key), count?)))
        .chain(
            ui.others()
                .iter()
                .map(|(key, labels)| (Unmatched::UiElement(key.clone()), count(labels))),
        );
    match claims.chain(elements).find(|(_, count)| *count != 1) {
        Some((array, _)) => Err(ProjectionError::EntryCount(array)),
        None => Ok(()),
    }
}

/// The number of entries of `labels`.
fn count<T: siros_display::Localized>(labels: &Localizations<T>) -> usize {
    labels.entries().len()
}
