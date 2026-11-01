//! The mapping of TS12 v1.0.1 claim metadata and UI elements catalogues into the definition
//! form (PaSO Proof Metadata, Section 3): `path` loses its `payload` root, `lang` becomes
//! `locale`, `label` becomes `name`, `description` stays, and `visualisation` stays as the
//! claim's prominence. The labels follow TS12's rules (Section 3.3.3).

use siros_codec::json::Json;
use siros_dcql::{ClaimPath, PathComponent};

use super::ts12::{Ts12Fault, Ts12Member};
use crate::definition::{
    pointer, visualisation, ClaimDefinition, ClaimFault, ClaimIndex, Definition, DefinitionError,
    DefinitionMember, Display, LabelRules, Localizations, Mandatory, PayloadPath, UiLabels,
    AFFIRMATIVE,
};
use crate::json::{self, Fields};

/// The definition of the TS12 `claims` array and UI elements catalogue `labels` (Sections 3.3.2
/// and 3.3.3).
pub(super) fn definition(claims: Json, labels: Json) -> Result<Definition, Ts12Fault> {
    let claims = json::array(claims)
        .map_err(|fault| Ts12Fault::Member(Ts12Member::Claims, fault))?
        .into_iter()
        .enumerate()
        .map(|(at, value)| claim(at, value))
        .collect::<Result<Vec<_>, _>>()?;
    Definition::new(claims, ui_labels(labels)?, Vec::new()).map_err(Ts12Fault::Definition)
}

/// The claim metadata object `value` at position `at` (SD-JWT VC, Section 9; Section 3.3.2).
fn claim(at: usize, value: Json) -> Result<ClaimDefinition, Ts12Fault> {
    let index = ClaimIndex::new(at);
    let claim_fault = |fault| Ts12Fault::Definition(DefinitionError::Claim(index, fault));
    let mut fields = json::object(value).map_err(|_| claim_fault(ClaimFault::NotObject))?;
    let components = fields
        .require("path")
        .and_then(json::array)
        .map_err(|fault| Ts12Fault::Member(Ts12Member::Path, fault))?;
    let path = pointer(components).map_err(claim_fault)?;
    let path = match path.components().split_first() {
        Some((PathComponent::Key(root), rest)) if root == "payload" && !rest.is_empty() => {
            PayloadPath::new(
                ClaimPath::new(rest.to_vec()).map_err(|e| claim_fault(ClaimFault::Path(e)))?,
            )
        }
        _ => return Err(Ts12Fault::PathOutsidePayload),
    };
    let prominence = visualisation(&mut fields).map_err(claim_fault)?;
    let mandatory = match fields
        .optional("mandatory", json::boolean)
        .map_err(|fault| claim_fault(ClaimFault::Member(DefinitionMember::Mandatory, fault)))?
    {
        Some(true) => Mandatory::Required,
        Some(false) | None => Mandatory::Optional,
    };
    let display = fields
        .take("display")
        .map(|entries| {
            let entries = json::array(entries)
                .map_err(|fault| Ts12Fault::Member(Ts12Member::Display, fault))?
                .into_iter()
                .map(display_entry)
                .collect::<Result<Vec<_>, _>>()?;
            Localizations::parse(Json::Array(entries), |entry| {
                Display::parse(entry, LabelRules::Ts12)
            })
            .map_err(|fault| claim_fault(ClaimFault::Display(fault)))
        })
        .transpose()?;
    ClaimDefinition::new(path, mandatory, None, display, prominence).map_err(claim_fault)
}

/// A claim `display` entry in the definition form: its language tag in exactly one of `lang`
/// (Section 2.3) and `locale` (SD-JWT VC, Section 9.2) as `locale`, `label` as `name`, and
/// `description`.
fn display_entry(entry: Json) -> Result<Json, Ts12Fault> {
    let mut fields =
        json::object(entry).map_err(|fault| Ts12Fault::Member(Ts12Member::Display, fault))?;
    let locale = language(&mut fields)?;
    let label = fields
        .require("label")
        .map_err(|fault| Ts12Fault::Member(Ts12Member::Label, fault))?;
    let mut members = vec![("locale".to_owned(), locale), ("name".to_owned(), label)];
    members.extend(
        fields
            .take("description")
            .map(|description| ("description".to_owned(), description)),
    );
    Ok(Json::Object(members))
}

/// The language tag of an entry: exactly one of `lang` and `locale`.
fn language(fields: &mut Fields) -> Result<Json, Ts12Fault> {
    match (fields.take("lang"), fields.take("locale")) {
        (Some(tag), None) | (None, Some(tag)) => Ok(tag),
        (Some(_), Some(_)) | (None, None) => Err(Ts12Fault::OneOf(Ts12Member::Lang)),
    }
}

/// The UI labels of the catalogue `labels`: each element an array of `{lang, value}`, with an
/// `affirmative_action_label` (Section 3.3.3).
fn ui_labels(labels: Json) -> Result<UiLabels, Ts12Fault> {
    let members = json::object(labels)
        .map_err(|fault| Ts12Fault::Member(Ts12Member::UiLabels, fault))?
        .rest();
    if !members.iter().any(|(name, _)| AFFIRMATIVE == name.as_str()) {
        return Err(Ts12Fault::AffirmativeAbsent);
    }
    let members = members
        .into_iter()
        .map(|(name, entries)| {
            let entries = json::array(entries)
                .map_err(|fault| Ts12Fault::Member(Ts12Member::UiLabels, fault))?
                .into_iter()
                .map(ui_entry)
                .collect::<Result<Vec<_>, _>>()?;
            Ok((name, Json::Array(entries)))
        })
        .collect::<Result<Vec<_>, Ts12Fault>>()?;
    UiLabels::parse(Json::Object(members), LabelRules::Ts12).map_err(Ts12Fault::Definition)
}

/// A catalogue entry `{lang, value}` in the definition form `{locale, value}`.
fn ui_entry(entry: Json) -> Result<Json, Ts12Fault> {
    let entry_fault = |fault| Ts12Fault::Member(Ts12Member::UiEntry, fault);
    let mut fields = json::object(entry).map_err(entry_fault)?;
    let locale = language(&mut fields)?;
    let value = fields.require("value").map_err(entry_fault)?;
    Ok(Json::Object(vec![
        ("locale".to_owned(), locale),
        ("value".to_owned(), value),
    ]))
}
