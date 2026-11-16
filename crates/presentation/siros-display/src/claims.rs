//! Labels, and the claim descriptions that give them to the claims at a path.

use serde_json::{Map, Value};
use siros_dcql::{ClaimPath, PathComponent};

use crate::error::{DisplayError, EntryFault};
use crate::json::{self, Entries};
use crate::locale::{Locale, Localized};
use crate::text::LabelText;

/// A label in one locale, or in an unstated one.
#[derive(Debug, Clone)]
pub(crate) struct Label {
    pub(crate) locale: Option<Locale>,
    pub(crate) text: LabelText,
}

impl Localized for Label {
    fn locale(&self) -> Option<&Locale> {
        self.locale.as_ref()
    }
}

/// The labels of the `display` member of an OpenID4VCI metadata object (OpenID4VCI 1.0, Section
/// 12.2.4 and Appendix B.2): a non-empty array of objects with an optional `name` and an
/// optional `locale`, one object per locale. An entry without a `name`, or with a blank one,
/// gives no label.
pub(crate) fn named_labels(
    object: &Map<String, Value>,
    malformed: fn(EntryFault) -> DisplayError,
) -> Result<Vec<Label>, DisplayError> {
    let entries = json::array(object, "display", Entries::AtLeastOne, malformed)?;
    let read = entries
        .unwrap_or_default()
        .iter()
        .map(|entry| {
            let entry = json::entry(entry, malformed)?;
            let locale = json::locale(entry, malformed(EntryFault::MemberType))?;
            let name = json::optional_label(entry, "name", malformed(EntryFault::MemberType))?;
            Ok((locale, name))
        })
        .collect::<Result<Vec<_>, DisplayError>>()?;
    json::distinct_locales(read.iter().map(|(locale, _)| locale.as_ref()))?;
    Ok(read
        .into_iter()
        .filter_map(|(locale, name)| name.map(|text| Label { locale, text }))
        .collect())
}

/// A claims description of OpenID4VCI issuer metadata (OpenID4VCI 1.0, Appendix B.2): the
/// path, and a label for each `display` entry that has a `name`.
#[derive(Debug, Clone)]
pub(crate) struct ClaimDescription {
    pub(crate) path: ClaimPath,
    pub(crate) labels: Vec<Label>,
}

/// The claims descriptions of `claims`, a non-empty array (OpenID4VCI 1.0, Section 12.2.4).
///
/// Each has a `path` and an optional `display` of [`named_labels`]. No two describe the same
/// claim, and no two contradict each other (Appendix B.3).
pub(crate) fn issuer_claims(claims: &[Value]) -> Result<Vec<ClaimDescription>, DisplayError> {
    let described = claims
        .iter()
        .map(|claim| {
            let claim = json::entry(claim, DisplayError::Claims)?;
            Ok(ClaimDescription {
                path: path(claim.get("path"))?,
                labels: named_labels(claim, DisplayError::Claims)?,
            })
        })
        .collect::<Result<Vec<_>, DisplayError>>()?;
    consistent(&described)?;
    Ok(described)
}

/// No path addresses the claim another addresses, and no two paths disagree on whether a claim
/// is an object or an array, or address one array both by `null` and by an index (OpenID4VCI
/// 1.0, Appendix B.3).
fn consistent(described: &[ClaimDescription]) -> Result<(), DisplayError> {
    described
        .iter()
        .enumerate()
        .flat_map(|(at, first)| {
            described
                .iter()
                .skip(at + 1)
                .map(move |second| (first, second))
        })
        .try_for_each(|(first, second)| agree(first.path.components(), second.path.components()))
}

/// Two description paths address different claims, and agree on the kind of every node they
/// share (Appendix B.3).
fn agree(first: &[PathComponent], second: &[PathComponent]) -> Result<(), DisplayError> {
    match first.iter().zip(second).find(|(a, b)| a != b) {
        None if first.len() == second.len() => Err(DisplayError::ClaimRepeated),
        None => Ok(()),
        Some((a, b)) => {
            let key = |c: &PathComponent| matches!(c, PathComponent::Key(_));
            let null = |c: &PathComponent| matches!(c, PathComponent::Null);
            if key(a) != key(b) || null(a) != null(b) {
                Err(DisplayError::ClaimContradictory)
            } else {
                Ok(())
            }
        }
    }
}

/// The required claims path pointer `value` of display metadata (OpenID4VCI 1.0, Appendix C;
/// SD-JWT VC, Section 5.6.1).
pub(crate) fn path(value: Option<&Value>) -> Result<ClaimPath, DisplayError> {
    let value = value.ok_or(DisplayError::Claims(EntryFault::MemberMissing))?;
    ClaimPath::parse(value).map_err(DisplayError::ClaimPath)
}
