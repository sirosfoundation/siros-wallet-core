//! Why a transaction data type definition breaks PaSO Proof Metadata, Section 3. Each fault
//! makes the type unsupported by the credential it would serve (Section 3.3).

use siros_codec::member::{ArrayIndex, MemberFault};
use siros_dcql::ClaimPathError;
use siros_display::{Locale, LocaleError};

use super::text::TextFault;

siros_codec::position!(
    /// The position of a claim in a definition's `claims`.
    pub ClaimIndex
);

siros_codec::text_value!(
    /// The identifier of a UI element: a member name of `ui_labels` (Section 3.2).
    UiElementKey
);

/// A member of a definition, a claim or a localised entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DefinitionMember {
    /// `claims`.
    Claims,
    /// `ui_labels`.
    UiLabels,
    /// A claim's `path`.
    Path,
    /// A claim's `mandatory`.
    Mandatory,
    /// A claim's `value_type`.
    ValueType,
    /// A claim's `display`.
    Display,
    /// A claim's `visualisation` (EC TS12 v1.0.1, Section 3.3.2).
    Visualisation,
    /// An entry's `locale`.
    Locale,
    /// A `display` entry's `name`.
    Name,
    /// A `display` entry's `display_type`.
    DisplayType,
    /// A `ui_labels` entry's `value`.
    Value,
    /// A `display` entry's `description` (EC TS12 v1.0.1, Section 2.3).
    Description,
}

impl DefinitionMember {
    /// The member's name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Claims => "claims",
            Self::UiLabels => "ui_labels",
            Self::Path => "path",
            Self::Mandatory => "mandatory",
            Self::ValueType => "value_type",
            Self::Display => "display",
            Self::Visualisation => "visualisation",
            Self::Locale => "locale",
            Self::Name => "name",
            Self::DisplayType => "display_type",
            Self::Value => "value",
            Self::Description => "description",
        }
    }
}

/// Why a definition breaks Section 3.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum DefinitionError {
    /// The definition is no JSON object.
    NotObject,
    /// A member of the definition breaks its rule.
    Member(DefinitionMember, #[source] MemberFault),
    /// `claims` holds this many claims, more than 100 (Section 3.3).
    TooManyClaims(usize),
    /// The claim at this position breaks a rule.
    Claim(ClaimIndex, #[source] ClaimFault),
    /// The claim at this position has the `path` of an earlier one (Section 3.3).
    PathRepeated(ClaimIndex),
    /// The `ui_labels` array of this UI element breaks a rule.
    UiElement(UiElementKey, #[source] LabelsFault),
}

/// Why a claim metadata object breaks Sections 3.1 and 3.3.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum ClaimFault {
    /// The claim is no JSON object.
    NotObject,
    /// A member of the claim breaks its rule.
    Member(DefinitionMember, #[source] MemberFault),
    /// `path` is no claims path pointer.
    Path(#[source] ClaimPathError),
    /// `value_type` names no value type of PaSO View, Section 3.
    ValueTypeUnknown(String),
    /// The claim has a `value_type` and no `display` (Section 3.1).
    ValueTypeWithoutDisplay,
    /// A `label_only` claim is `mandatory` (PaSO View, Section 3).
    LabelOnlyMandatory,
    /// `visualisation` is no integer from 1 to 4 (EC TS12 v1.0.1, Section 3.3.2).
    Visualisation,
    /// The `display` array breaks a rule.
    Display(#[source] LabelsFault),
}

/// Why a `display` array or a `ui_labels` entry array breaks Sections 3.1 to 3.3.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum LabelsFault {
    /// The array is no JSON array.
    NotArray,
    /// The entry at this position breaks a rule.
    Entry(ArrayIndex, #[source] EntryFault),
    /// Two entries have this locale (Section 3.3).
    LocaleRepeated(Locale),
    /// Two entries have no locale (Section 3.3).
    DefaultRepeated,
}

/// Why an entry of a `display` or `ui_labels` array breaks Sections 3.1 to 3.3.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum EntryFault {
    /// The entry is no JSON object.
    NotObject,
    /// A member of the entry breaks its rule.
    Member(DefinitionMember, #[source] MemberFault),
    /// `locale` is no language tag (RFC 5646).
    Locale(#[source] LocaleError),
    /// The label or the description breaks a character or length rule (Section 3.3).
    Text(DefinitionMember, #[source] TextFault),
    /// A `ui_labels` entry's `value_type` is none of `mini_markdown` and
    /// `template:mini_markdown` (Section 3.3). A `display` entry with such a `display_type` is
    /// left out of its array (PaSO View, Section 3).
    Format(String),
    /// A `security_hint` entry carries a `value_type` (Section 3.3).
    HintFormat,
}

impl DefinitionError {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotObject => "definition_not_object",
            Self::Member(..) => "definition_member",
            Self::TooManyClaims(_) => "definition_too_many_claims",
            Self::Claim(_, fault) => fault.code(),
            Self::PathRepeated(_) => "definition_path_repeated",
            Self::UiElement(_, fault) => fault.code(),
        }
    }
}

impl ClaimFault {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotObject => "claim_not_object",
            Self::Member(..) => "claim_member",
            Self::Path(_) => "claim_path",
            Self::ValueTypeUnknown(_) => "claim_value_type_unknown",
            Self::ValueTypeWithoutDisplay => "claim_value_type_without_display",
            Self::LabelOnlyMandatory => "claim_label_only_mandatory",
            Self::Visualisation => "claim_visualisation",
            Self::Display(fault) => fault.code(),
        }
    }
}

impl LabelsFault {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotArray => "labels_not_array",
            Self::Entry(_, fault) => fault.code(),
            Self::LocaleRepeated(_) => "labels_locale_repeated",
            Self::DefaultRepeated => "labels_default_repeated",
        }
    }
}

impl EntryFault {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotObject => "label_entry_not_object",
            Self::Member(..) => "label_entry_member",
            Self::Locale(e) => e.code(),
            Self::Text(_, fault) => fault.code(),
            Self::Format(_) => "label_format",
            Self::HintFormat => "security_hint_format",
        }
    }
}
