//! Payload conformance (PaSO Core, Section 7.4.2, step 2; PaSO View, Section 3): every field
//! covered by a claim or the string `#integrity` companion of an image, every mandatory claim
//! present, every value of a displayed claim of its value type, and every string free of
//! directional overrides.

mod pointer;
mod time;
mod values;

use siros_codec::json::Json;
use siros_dcql::{ComponentIndex, PathComponent, PathError};

use crate::definition::{BaseType, ClaimDefinition, ClaimIndex, Mandatory, TextFault, ValueType};
use crate::image::ImageFault;

pub(crate) use pointer::Reach;
pub use pointer::{Location, Step};
pub use time::{IsoDateTime, IsoTime};
pub use values::{CurrencyAmount, Frequency, NumberText, PayloadText, Scalar, Typed};

pub(crate) use pointer::{select, Selected};
pub(crate) use values::{scalar, typed};

/// The suffix of the member that carries a sibling image's integrity metadata (PaSO View,
/// Section 3, `image`).
pub(crate) const INTEGRITY_SUFFIX: &str = "#integrity";

/// Why a payload does not conform to a definition.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum PayloadFault {
    /// The field at this location is covered by no claim's `path` (Core, Section 7.4.2).
    Uncovered(Location),
    /// The `#integrity` companion of an image at this location is no string (PaSO View,
    /// Section 3, `image`).
    IntegrityNotString(Location),
    /// The mandatory claim at this position is absent, or absent from an element its path's
    /// `null` ranges over.
    MandatoryAbsent(ClaimIndex),
    /// Processing the `path` of the claim at this position aborts (OpenID4VP 1.0, Section
    /// 7.1.1).
    Path(ClaimIndex, #[source] PathError),
    /// The value at this location of the claim at this position does not conform to its value
    /// type.
    Value(ClaimIndex, Location, #[source] ValueFault),
    /// The string at this location breaks a directional rule (Proof Metadata, Section 3.3).
    Text(Location, #[source] TextFault),
}

/// Why a value does not conform to its claim's value type (PaSO View, Section 3).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum ValueFault {
    /// A value without a value type, or of a string type, is no string.
    NotString,
    /// The value is no value of this type.
    Type(crate::definition::BaseType),
    /// The image reference breaks a rule.
    Image(#[source] ImageFault),
    /// The string breaks a directional rule (Proof Metadata, Section 3.3).
    Text(#[source] TextFault),
}

impl PayloadFault {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Uncovered(_) => "payload_field_uncovered",
            Self::IntegrityNotString(_) => "payload_integrity_not_string",
            Self::MandatoryAbsent(_) => "payload_mandatory_absent",
            Self::Path(..) => "payload_path",
            Self::Value(_, _, fault) => fault.code(),
            Self::Text(_, fault) => fault.code(),
        }
    }
}

impl ValueFault {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotString => "payload_value_not_string",
            Self::Type(_) => "payload_value_type",
            Self::Image(fault) => fault.code(),
            Self::Text(fault) => fault.code(),
        }
    }
}

/// The typed value of each displayed claim instance of a payload, by location.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Values(Vec<(Location, Typed)>);

impl Values {
    /// The values `values`.
    pub(crate) fn new(values: Vec<(Location, Typed)>) -> Self {
        Self(values)
    }

    /// The value at `location`.
    pub(crate) fn get(&self, location: &Location) -> Option<&Typed> {
        self.0
            .iter()
            .find(|(at, _)| at == location)
            .map(|(_, value)| value)
    }

    /// The values, in the order of the claims and of the payload's arrays.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &(Location, Typed)> {
        self.0.iter()
    }
}

/// The values of `payload`, the members of a `payload` object, that conform to the claims
/// `claims`.
///
/// # Errors
///
/// [`PayloadFault`]: the first rule the payload breaks, in this order: the strings' directional
/// rules, the coverage of every field, then each claim in order.
pub(crate) fn conform<'c>(
    payload: &Json,
    claims: impl Iterator<Item = &'c ClaimDefinition> + Clone,
) -> Result<Values, PayloadFault> {
    let mut fields = Vec::new();
    leaves(payload, &Location::default(), &mut fields)?;
    for field in &fields {
        covered(payload, field, claims.clone())?;
    }
    let mut values = Vec::new();
    for (at, claim) in claims.enumerate() {
        let index = ClaimIndex::new(at);
        let components = claim.path().components();
        let selected =
            select(payload, components).map_err(|error| PayloadFault::Path(index, error))?;
        if claim.mandatory() == Mandatory::Required
            && !present(payload, components, 0).map_err(|e| PayloadFault::Path(index, e))?
        {
            return Err(PayloadFault::MandatoryAbsent(index));
        }
        if claim.display().is_none() {
            continue;
        }
        for Selected {
            location, value, ..
        } in selected
        {
            let integrity = integrity_of(payload, &location);
            let value = typed(value, claim.value_type(), integrity)
                .map_err(|fault| PayloadFault::Value(index, location.clone(), fault))?;
            values.push((location, value));
        }
    }
    Ok(Values::new(values))
}

/// Adds the location of each field under `value`, at `location`, to `fields`: each value that
/// is no object or array with members, and checks each string's directional rules.
fn leaves(
    value: &Json,
    location: &Location,
    fields: &mut Vec<Location>,
) -> Result<(), PayloadFault> {
    match value {
        Json::Object(members) if !members.is_empty() => {
            members.iter().try_for_each(|(name, member)| {
                leaves(member, &location.then(Step::Key(name.clone())), fields)
            })
        }
        Json::Array(items) if !items.is_empty() => (0u64..)
            .zip(items)
            .try_for_each(|(at, item)| leaves(item, &location.then(Step::Index(at)), fields)),
        Json::String(text) => {
            crate::definition::bidi(text)
                .map_err(|fault| PayloadFault::Text(location.clone(), fault))?;
            fields.push(location.clone());
            Ok(())
        }
        Json::Null | Json::Bool(_) | Json::Number(_) | Json::Object(_) | Json::Array(_) => {
            fields.push(location.clone());
            Ok(())
        }
    }
}

/// Checks that `claims` cover the field at `field`: a claim addresses it, what contains it,
/// or, for an empty object or array, what it would contain. A field outside them is covered as
/// the `#integrity` companion of an image claim's value, or within one, when the companion is a
/// string.
///
/// # Errors
///
/// [`PayloadFault::Uncovered`], and [`PayloadFault::IntegrityNotString`] for a companion of
/// another type.
fn covered<'c>(
    payload: &Json,
    field: &Location,
    claims: impl Iterator<Item = &'c ClaimDefinition> + Clone,
) -> Result<(), PayloadFault> {
    if claims
        .clone()
        .any(|claim| field.reach(claim.path().components()) != Reach::Apart)
    {
        return Ok(());
    }
    let companion = field.prefixes().find(|prefix| {
        integrity_companion(prefix).is_some_and(|image| {
            claims.clone().any(|claim| {
                claim.value_type() == Some(ValueType::Plain(BaseType::Image))
                    && image.reach(claim.path().components()) == Reach::Addresses
            })
        })
    });
    match companion {
        None => Err(PayloadFault::Uncovered(field.clone())),
        Some(companion)
            if companion == *field
                && value_at(payload, field).is_some_and(|v| matches!(v, Json::String(_))) =>
        {
            Ok(())
        }
        Some(companion) => Err(PayloadFault::IntegrityNotString(companion)),
    }
}

/// Whether `root` holds what `components` addresses: every array a `null` ranges over exists
/// and has elements, and each of its elements holds the rest of the path. `offset` is the position of
/// `components` in the claim's path.
///
/// # Errors
///
/// [`PathError::TypeMismatch`] where a `null` meets a value that is no array.
fn present(root: &Json, components: &[PathComponent], offset: usize) -> Result<bool, PathError> {
    let mut parts = components.splitn(2, |c| *c == PathComponent::Null);
    let (Some(prefix), Some(rest)) = (parts.next(), parts.next()) else {
        return Ok(!select(root, components)?.is_empty());
    };
    let null = offset + prefix.len();
    let containers = select(root, prefix)?;
    if containers.is_empty() {
        return Ok(false);
    }
    for container in containers {
        let Json::Array(items) = container.value else {
            return Err(PathError::TypeMismatch {
                at: ComponentIndex::new(null),
            });
        };
        // A `null` over an empty array selects nothing (OpenID4VP 1.0, Section 7.1.1, step 3).
        if items.is_empty() {
            return Ok(false);
        }
        for item in items {
            if !present(item, rest, null + 1)? {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

/// The location of the member `location` accompanies when it is a `#integrity` companion: the
/// sibling named without the suffix.
fn integrity_companion(location: &Location) -> Option<Location> {
    let name = location.last_key()?.strip_suffix(INTEGRITY_SUFFIX)?;
    location.sibling(name)
}

/// The value at `location` of `payload`.
fn value_at<'j>(payload: &'j Json, location: &Location) -> Option<&'j Json> {
    location
        .steps()
        .iter()
        .try_fold(payload, |value, step| match (step, value) {
            (Step::Key(key), Json::Object(members)) => {
                members.iter().find(|(name, _)| name == key).map(|(_, v)| v)
            }
            (Step::Index(index), Json::Array(items)) => items.get(usize::try_from(*index).ok()?),
            (Step::Key(_) | Step::Index(_), _) => None,
        })
}

/// The value of the `#integrity` sibling of the member at `location`.
pub(crate) fn integrity_of<'j>(payload: &'j Json, location: &Location) -> Option<&'j Json> {
    let name = format!("{}{INTEGRITY_SUFFIX}", location.last_key()?);
    value_at(payload, &location.sibling(&name)?)
}
