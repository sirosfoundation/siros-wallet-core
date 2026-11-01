//! The one internal form of a transaction data type's definition: a `transaction_data_types`
//! entry of PaSO Proof Metadata, Section 3. Every source parses into it.

mod claim;
mod error;
mod grapheme;
mod localized;
mod text;
mod ui_labels;
mod value_type;

use rustc_hash::FxHashSet;
use siros_codec::json::Json;
use siros_codec::member::MemberFault;

use crate::json::{self, Fields};

pub use claim::{ClaimDefinition, ClaimDisplay, Mandatory, PayloadPath, Prominence};
pub use error::{
    ClaimFault, ClaimIndex, DefinitionError, DefinitionMember, EntryFault, LabelsFault,
    UiElementKey,
};
pub use grapheme::clusters as grapheme_clusters;
pub use localized::Localizations;
pub use text::{
    ActionLabel, ClaimName, Description, LabelLength, LabelRole, LabelRules, LabelText, Limit,
    OtherUiElement, SecurityHint, TextFault, TransactionTitle,
};
pub use ui_labels::{HintEntry, UiLabel, UiLabels};
pub use value_type::{BaseType, LabelFormat, ValueType};

#[cfg(feature = "wallet")]
pub(crate) use claim::{pointer, visualisation, ClaimDisplay as Display};
pub(crate) use text::bidi;
pub(crate) use ui_labels::{AFFIRMATIVE, DENIAL, SECURITY_HINT, TITLE};

/// The most claims of a definition (Section 3.3).
pub const MAX_CLAIMS: usize = 100;

/// A transaction data type's definition: its claims, its UI labels, and the additional
/// parameters it carries (Section 3).
#[derive(Debug, Clone, PartialEq)]
pub struct Definition {
    claims: Vec<ClaimDefinition>,
    ui_labels: UiLabels,
    extra: Vec<(String, Json)>,
}

impl Definition {
    /// The definition of the JSON object `value`, its labels under `rules`: `claims`, at most
    /// 100, no two with one `path`; optional `ui_labels`; and additional parameters, kept as
    /// written (Sections 3.1 to 3.3).
    ///
    /// # Errors
    ///
    /// [`DefinitionError`]: the first rule `value` breaks.
    pub fn parse(value: Json, rules: LabelRules) -> Result<Self, DefinitionError> {
        let mut fields = json::object(value).map_err(|_| DefinitionError::NotObject)?;
        let claims = claims(&mut fields, rules)?;
        let ui_labels = fields
            .take(DefinitionMember::UiLabels.as_str())
            .map(|labels| UiLabels::parse(labels, rules))
            .transpose()?
            .unwrap_or_default();
        Self::new(claims, ui_labels, fields.rest())
    }

    /// The definition of its parts.
    ///
    /// # Errors
    ///
    /// [`DefinitionError::TooManyClaims`] and [`DefinitionError::PathRepeated`] (Section 3.3).
    pub(crate) fn new(
        claims: Vec<ClaimDefinition>,
        ui_labels: UiLabels,
        extra: Vec<(String, Json)>,
    ) -> Result<Self, DefinitionError> {
        if claims.len() > MAX_CLAIMS {
            return Err(DefinitionError::TooManyClaims(claims.len()));
        }
        let mut paths = FxHashSet::default();
        if let Some(repeated) = claims.iter().position(|claim| !paths.insert(claim.path())) {
            return Err(DefinitionError::PathRepeated(ClaimIndex::new(repeated)));
        }
        Ok(Self {
            claims,
            ui_labels,
            extra,
        })
    }

    /// The claims, in their order: the display order (PaSO View, Section 2).
    #[must_use]
    pub fn claims(&self) -> &[ClaimDefinition] {
        &self.claims
    }

    /// The UI labels.
    #[must_use]
    pub fn ui_labels(&self) -> &UiLabels {
        &self.ui_labels
    }

    /// The additional parameters, as written.
    #[must_use]
    pub fn extra(&self) -> &[(String, Json)] {
        &self.extra
    }
}

/// The required `claims` of a definition: an array of claim metadata objects.
fn claims(fields: &mut Fields, rules: LabelRules) -> Result<Vec<ClaimDefinition>, DefinitionError> {
    let items = fields
        .require(DefinitionMember::Claims.as_str())
        .and_then(json::array)
        .map_err(|fault: MemberFault| DefinitionError::Member(DefinitionMember::Claims, fault))?;
    items
        .into_iter()
        .enumerate()
        .map(|(at, item)| {
            ClaimDefinition::parse(item, rules)
                .map_err(|fault| DefinitionError::Claim(ClaimIndex::new(at), fault))
        })
        .collect()
}
