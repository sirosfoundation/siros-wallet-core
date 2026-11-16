//! The claim labels of one credential in the wallet's language (D2, D3), and the claim rows they
//! label: what the wallet shows, and what a registration projection carries to the credential
//! picker (K1).

use siros_codec::date::{Date, DateTime};
use siros_credential::{ClaimSource, TypedValue};
use siros_dcql::{ClaimPath, PathComponent};

use crate::error::DisplayError;
use crate::text::LabelText;

/// A claim description of display metadata, with the label the locale function takes from it
/// for the wallet's language: `None` when it has no entry for the language.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescribedLabel {
    path: ClaimPath,
    label: Option<LabelText>,
}

/// The labels of one credential's claims in the wallet's language: the labelled claim
/// descriptions of its SD-JWT VC Type Metadata, nearest type first, then the claims descriptions
/// of its OpenID4VCI configuration, the fallback (D3).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClaimLabels {
    types: Vec<DescribedLabel>,
    issuer: Vec<DescribedLabel>,
}

/// A claim as the user sees it: its label and its value.
#[derive(Clone, PartialEq)]
pub struct ClaimRow {
    label: LabelText,
    value: DisplayValue,
}

/// A claim value, typed for display (D4). The UI formats numbers and dates for its locale.
#[derive(Clone, PartialEq)]
pub enum DisplayValue {
    /// `null`.
    Null,
    /// A boolean.
    Boolean(bool),
    /// An integer.
    Integer(i128),
    /// A number with a fraction or an exponent.
    Number(f64),
    /// Text, as the credential holds it.
    Text(String),
    /// A calendar date.
    Date(Date),
    /// A date and time in UTC.
    DateTime(DateTime),
    /// A byte string, shown by its length in bytes (D5).
    Bytes(usize),
    /// The elements of an array that the credential holds, in order.
    List(Vec<DisplayValue>),
    /// The members of an object, each with its label, in order.
    Group(Vec<ClaimRow>),
}

impl DescribedLabel {
    /// The description of the claims at `path`, labelled `label` in the wallet's language.
    #[must_use]
    pub fn new(path: ClaimPath, label: Option<LabelText>) -> Self {
        Self { path, label }
    }

    /// The description's path.
    #[must_use]
    pub fn path(&self) -> &ClaimPath {
        &self.path
    }

    /// The label in the wallet's language.
    #[must_use]
    pub fn label(&self) -> Option<&LabelText> {
        self.label.as_ref()
    }
}

impl ClaimRow {
    /// The label.
    pub fn label(&self) -> &LabelText {
        &self.label
    }

    /// The value.
    pub fn value(&self) -> &DisplayValue {
        &self.value
    }
}

impl ClaimLabels {
    /// The labels of `types`, the labelled descriptions of the Type Metadata, nearest type
    /// first, and of `issuer`, the descriptions of the configuration.
    #[must_use]
    pub fn new(types: Vec<DescribedLabel>, issuer: Vec<DescribedLabel>) -> Self {
        Self { types, issuer }
    }

    /// The labelled descriptions of the Type Metadata, nearest type first.
    #[must_use]
    pub fn types(&self) -> &[DescribedLabel] {
        &self.types
    }

    /// The descriptions of the configuration.
    #[must_use]
    pub fn issuer(&self) -> &[DescribedLabel] {
        &self.issuer
    }

    /// The label of the claims at `path`: that of the first Type Metadata description that
    /// addresses the path, else that of the first configuration description that addresses it,
    /// else the path's last key.
    ///
    /// # Errors
    ///
    /// [`DisplayError::PointerUnlabelled`] for a path without a label and without a key, and
    /// [`DisplayError::Text`] for a key that is no safe label.
    pub fn label(&self, path: &[PathComponent]) -> Result<LabelText, DisplayError> {
        let described = |descriptions: &[DescribedLabel]| {
            descriptions
                .iter()
                .find(|description| describes(&description.path, path))
                .and_then(|description| description.label.clone())
        };
        if let Some(label) = described(&self.types).or_else(|| described(&self.issuer)) {
            return Ok(label);
        }
        let key = path
            .iter()
            .rev()
            .find_map(PathComponent::as_key)
            .ok_or(DisplayError::PointerUnlabelled)?;
        LabelText::new(key).map_err(DisplayError::Text)
    }

    /// The rows of the claims `pointers` select in `claims`, one per pointer. A pointer with a
    /// `null` gives a [`DisplayValue::List`] of the values it selects. An object gives a
    /// [`DisplayValue::Group`] of rows, labelled at the member's path; an array's elements are
    /// at its path extended with `null`. A byte string shows its length (D5).
    ///
    /// # Errors
    ///
    /// [`DisplayError::Pointer`] for a pointer that selects nothing in `claims`,
    /// [`DisplayError::PointerSelectsSeveral`] for a pointer without `null` that selects more
    /// than one value, and the other [`DisplayError`]s for a label that is no safe label or for
    /// a number with no display value.
    pub fn rows(
        &self,
        claims: &impl ClaimSource,
        pointers: &[ClaimPath],
    ) -> Result<Vec<ClaimRow>, DisplayError> {
        pointers
            .iter()
            .map(|pointer| {
                let path = pointer.components();
                let values = claims.claims(pointer).map_err(DisplayError::Pointer)?;
                let value = if path.contains(&PathComponent::Null) {
                    let elements = values.into_iter().map(|value| self.value(path, value));
                    DisplayValue::List(elements.collect::<Result<_, _>>()?)
                } else {
                    match values.as_slice() {
                        [value] => self.value(path, *value)?,
                        _ => return Err(DisplayError::PointerSelectsSeveral),
                    }
                };
                Ok(ClaimRow {
                    label: self.label(path)?,
                    value,
                })
            })
            .collect()
    }

    /// `value`, the claim at `path`, for display.
    fn value(
        &self,
        path: &[PathComponent],
        value: TypedValue<'_>,
    ) -> Result<DisplayValue, DisplayError> {
        let extended = |component: PathComponent| {
            let mut extended = path.to_vec();
            extended.push(component);
            extended
        };
        Ok(match value {
            TypedValue::Null => DisplayValue::Null,
            TypedValue::Bool(b) => DisplayValue::Boolean(b),
            TypedValue::Integer(i) => DisplayValue::Integer(i),
            TypedValue::Number(n) => {
                DisplayValue::Number(n.as_f64().ok_or(DisplayError::NumberUnrepresentable)?)
            }
            TypedValue::Text(text) => DisplayValue::Text(text.to_owned()),
            TypedValue::Bytes(bytes) => DisplayValue::Bytes(bytes.len()),
            TypedValue::FullDate(date) => DisplayValue::Date(date),
            TypedValue::DateTime(time) => DisplayValue::DateTime(time),
            TypedValue::Array(array) => {
                let element = extended(PathComponent::Null);
                let elements = array.elements().map(|value| self.value(&element, value));
                DisplayValue::List(elements.collect::<Result<_, _>>()?)
            }
            TypedValue::Object(object) => {
                let members = object.members().map(|(name, value)| {
                    let member = extended(PathComponent::Key(name.to_owned()));
                    Ok(ClaimRow {
                        label: self.label(&member)?,
                        value: self.value(&member, value)?,
                    })
                });
                DisplayValue::Group(members.collect::<Result<_, DisplayError>>()?)
            }
        })
    }
}

/// Whether the description path `described` addresses the claim at `path`: the same length,
/// equal keys and indexes, and `null` addressing any index or `null` of `path`.
pub(crate) fn describes(described: &ClaimPath, path: &[PathComponent]) -> bool {
    let described = described.components();
    described.len() == path.len()
        && described.iter().zip(path).all(|(d, p)| match (d, p) {
            (PathComponent::Null, PathComponent::Index(_) | PathComponent::Null) => true,
            (d, p) => d == p,
        })
}
