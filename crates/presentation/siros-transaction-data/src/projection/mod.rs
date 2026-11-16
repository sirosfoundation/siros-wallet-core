//! A definition projected to the wallet's language: one entry per localised array, the one the
//! locale function takes (PaSO View, Section 4), with the source and the payload rulebook that
//! serve it. The other locales are stripped; everything else stays. A projection writes as JSON
//! and reads back ([`Projected::parse`]), for the credential picker's registration (K1).

mod read;
mod write;

use siros_codec::json::Json;
use siros_display::{Locale, Localized};

use crate::definition::{
    ActionLabel, ClaimDefinition, ClaimDisplay, ClaimIndex, Definition, HintEntry, Localizations,
    OtherUiElement, TransactionTitle, UiElementKey, UiLabel, AFFIRMATIVE, DENIAL, SECURITY_HINT,
    TITLE,
};
use crate::json::canonical_members;
use crate::sources::{Rulebook, SourceKind};

pub use read::{ProjectionError, ProjectionMember};

/// A definition in one language, with its source and rulebook. [`Definition::project`] and
/// [`Projected::parse`] construct it.
#[derive(Debug, Clone, PartialEq)]
pub struct Projected {
    source: SourceKind,
    rulebook: Rulebook,
    language: Locale,
    claims: Vec<ProjectedClaim>,
    affirmative: Option<UiLabel<ActionLabel>>,
    denial: Option<UiLabel<ActionLabel>>,
    title: Option<UiLabel<TransactionTitle>>,
    security_hint: Option<HintEntry>,
    others: Vec<(UiElementKey, UiLabel<OtherUiElement>)>,
    extra: Vec<(String, Json)>,
}

/// A claim in one language: its display entry, when it has a `display` array.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectedClaim {
    definition: ClaimDefinition,
    display: Option<ClaimDisplay>,
}

/// The localised array no entry of which the locale function takes for the wallet's language.
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}", self.code())]
pub enum Unmatched {
    /// The `display` array of the claim at this position.
    Claim(ClaimIndex),
    /// The `ui_labels` array of this element.
    UiElement(UiElementKey),
}

impl Unmatched {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        "language_unmatched"
    }
}

impl Definition {
    /// The definition in `language`, served by `source` under `rulebook`: every claim `display`
    /// array and every `ui_labels` array of an element PaSO defines has the entry the locale
    /// function takes (PaSO View, Section 4). An element PaSO does not define keeps its entry
    /// when it has one. The additional parameters take the member order of RFC 8785, Section
    /// 3.2.3.
    ///
    /// # Errors
    ///
    /// [`Unmatched`]: the first array without an entry for `language`. The credential then
    /// does not support the type in the wallet's language.
    pub fn project(
        &self,
        language: &Locale,
        source: SourceKind,
        rulebook: Rulebook,
    ) -> Result<Projected, Unmatched> {
        let claims = self
            .claims()
            .iter()
            .enumerate()
            .map(|(at, claim)| {
                let display = claim
                    .display()
                    .map(|display| {
                        display
                            .lookup(language)
                            .cloned()
                            .ok_or(Unmatched::Claim(ClaimIndex::new(at)))
                    })
                    .transpose()?;
                let definition = match &display {
                    Some(entry) => claim.in_one_locale(entry.clone()),
                    None => claim.clone(),
                };
                Ok(ProjectedClaim {
                    definition,
                    display,
                })
            })
            .collect::<Result<Vec<_>, Unmatched>>()?;
        let ui = self.ui_labels();
        Ok(Projected {
            source,
            rulebook,
            language: language.clone(),
            claims,
            affirmative: matched(ui.affirmative(), language, AFFIRMATIVE)?,
            denial: matched(ui.denial(), language, DENIAL)?,
            title: matched(ui.title(), language, TITLE)?,
            security_hint: matched(ui.security_hint(), language, SECURITY_HINT)?,
            others: ui
                .others()
                .iter()
                .filter_map(|(key, labels)| {
                    labels.lookup(language).map(|l| (key.clone(), l.clone()))
                })
                .collect(),
            extra: canonical_members(self.extra()),
        })
    }
}

/// The entry of `labels`, the element `key`, for `language`; `None` without the element.
fn matched<T: Localized + Clone>(
    labels: Option<&Localizations<T>>,
    language: &Locale,
    key: UiElementKey,
) -> Result<Option<T>, Unmatched> {
    labels
        .map(|labels| {
            labels
                .lookup(language)
                .cloned()
                .ok_or(Unmatched::UiElement(key))
        })
        .transpose()
}

impl Projected {
    /// Where the definition comes from.
    #[must_use]
    pub fn source(&self) -> SourceKind {
        self.source
    }

    /// The rulebook of the payload: whether the KB-JWT carries TS12's claims.
    #[must_use]
    pub fn rulebook(&self) -> Rulebook {
        self.rulebook
    }

    /// The wallet's language the definition is projected to.
    #[must_use]
    pub fn language(&self) -> &Locale {
        &self.language
    }

    /// The claims, in the definition's order.
    #[must_use]
    pub fn claims(&self) -> &[ProjectedClaim] {
        &self.claims
    }

    /// `affirmative_action_label`.
    #[must_use]
    pub fn affirmative(&self) -> Option<&UiLabel<ActionLabel>> {
        self.affirmative.as_ref()
    }

    /// `denial_action_label`.
    #[must_use]
    pub fn denial(&self) -> Option<&UiLabel<ActionLabel>> {
        self.denial.as_ref()
    }

    /// `transaction_title`.
    #[must_use]
    pub fn title(&self) -> Option<&UiLabel<TransactionTitle>> {
        self.title.as_ref()
    }

    /// `security_hint`.
    #[must_use]
    pub fn security_hint(&self) -> Option<&HintEntry> {
        self.security_hint.as_ref()
    }

    /// The elements PaSO does not define that have an entry in the language.
    #[must_use]
    pub fn others(&self) -> &[(UiElementKey, UiLabel<OtherUiElement>)] {
        &self.others
    }

    /// The additional parameters, in the member order of RFC 8785, Section 3.2.3.
    #[must_use]
    pub fn extra(&self) -> &[(String, Json)] {
        &self.extra
    }

    /// The UI elements a view of the definition shows: the title, the action labels and the
    /// security hint it has (PaSO View, Section 2).
    pub(crate) fn ui_elements(&self) -> usize {
        [
            self.title.is_some(),
            self.affirmative.is_some(),
            self.denial.is_some(),
            self.security_hint.is_some(),
        ]
        .into_iter()
        .filter(|present| *present)
        .count()
    }
}

impl ProjectedClaim {
    /// The claim's definition.
    #[must_use]
    pub fn definition(&self) -> &ClaimDefinition {
        &self.definition
    }

    /// The display entry the locale function took; `None` for an internal claim.
    #[must_use]
    pub fn display(&self) -> Option<&ClaimDisplay> {
        self.display.as_ref()
    }
}
