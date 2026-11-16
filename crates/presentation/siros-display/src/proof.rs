//! Proof statement rows: what a `zkp_req` option asks the wallet to prove.

use serde_json::Value;
use siros_zkp_req::{QueryOption, ReqItem, ZkpReqQuery};

use crate::error::DisplayError;
use crate::field::{Field, FieldName, FieldText, FIELD_MAX};
use crate::text::{DisplayText, LabelText};

/// The end of every row value. The rows come from a request whose signature nobody has
/// checked, so they state what is asked and nothing more.
const UNVERIFIED: &str = "(unverified request)";

/// One picker field per `_req` item of `option`, in the Verifier's order.
///
/// `age_check` shows its `range` and `pseudonym` its `config`, as given. Any other function
/// shows its `fn_id` as the label. The detail is clipped to fit with the `(unverified request)`
/// marker in [`FIELD_MAX`] characters, the label to [`FIELD_MAX`], each ending in an ellipsis
/// where clipped. The rows judge nothing: whether the request is acceptable is the wallet's
/// decision.
///
/// # Errors
///
/// - [`DisplayError::OptionItemUnknown`] when `option` names an item `query` lacks: it is
///   another query's option.
/// - [`DisplayError::Text`] when a label or a detail is unsafe to show.
// `inline` makes the matcher compile this function with its own copies of the std functions it
// calls. Compiled here, it brings a second copy of each into matcher.wasm.
#[inline]
pub fn rows(query: &ZkpReqQuery, option: &QueryOption) -> Result<Vec<Field>, DisplayError> {
    items(query, option)
        .map(|item| {
            let (label, detail) = statement(item?)?;
            // Clipping shortens the detail and keeps the marker.
            let value = match detail {
                None => FieldText::fit(UNVERIFIED),
                Some(detail) => {
                    FieldText::fit_within(detail.as_str(), FIELD_MAX - UNVERIFIED.len() - 1)
                        .marked(UNVERIFIED)
                }
            };
            Ok(Field::new(FieldName::of(&label), Some(value)))
        })
        .collect()
}

/// The `_req` items `option` names, in the Verifier's order.
///
/// # Errors
///
/// [`DisplayError::OptionItemUnknown`] for an item `query` lacks.
#[inline]
fn items<'q>(
    query: &'q ZkpReqQuery,
    option: &'q QueryOption,
) -> impl Iterator<Item = Result<&'q ReqItem, DisplayError>> {
    option.items().iter().map(move |&index| {
        query
            .item(index)
            .ok_or(DisplayError::OptionItemUnknown(index))
    })
}

/// The label of `item` and the detail it shows, as display text: the one display rule of the
/// picker's rows and the wallet's.
///
/// # Errors
///
/// [`DisplayError::Text`] for a label or a detail that is no display text.
#[inline]
fn statement(item: &ReqItem) -> Result<(LabelText, Option<DisplayText>), DisplayError> {
    let (label, detail) = parts(item);
    let label = LabelText::new(label).map_err(DisplayError::Text)?;
    let detail = detail
        .map(|detail| DisplayText::value(&detail))
        .transpose()
        .map_err(DisplayError::Text)?;
    Ok((label, detail))
}

/// The label of `item` and the detail it shows.
#[inline]
fn parts(item: &ReqItem) -> (&str, Option<String>) {
    let param = |name: &str| item.params().get(name).and_then(Value::as_str);
    match item.fn_id().as_str() {
        "age_check" => ("Age check", param("range").map(|r| format!("age {r}"))),
        "pseudonym" => ("Pseudonym", param("config").map(|c| format!("config {c}"))),
        other => (other, None),
    }
}

/// A proof statement row of a request intake verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofRow {
    label: LabelText,
    value: Option<DisplayText>,
}

impl ProofRow {
    /// The label: the function's name.
    pub fn label(&self) -> &LabelText {
        &self.label
    }

    /// The parameter the function shows; `None` for a function that shows none.
    pub fn value(&self) -> Option<&DisplayText> {
        self.value.as_ref()
    }
}

/// One row per `_req` item of `option`, in the Verifier's order, for a request intake verified.
///
/// Each row has the label and the detail of the picker's row, whole and without the marker.
///
/// # Errors
///
/// - [`DisplayError::OptionItemUnknown`] when `option` names an item `query` lacks: it is
///   another query's option.
/// - [`DisplayError::Text`] when a label or a detail is unsafe to show or too long.
pub fn verified_rows(
    query: &ZkpReqQuery,
    option: &QueryOption,
) -> Result<Vec<ProofRow>, DisplayError> {
    items(query, option)
        .map(|item| {
            let (label, value) = statement(item?)?;
            Ok(ProofRow { label, value })
        })
        .collect()
}
