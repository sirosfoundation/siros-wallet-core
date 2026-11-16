//! `template:` interpolation (PaSO View, Section 3): `{<index>}` placeholders replaced, in one
//! pass, by the value of the claim at that position of the `claims` array. The result is a
//! list of segments: the template's own text, and the values, which the UI formats by their
//! types (step 3).

use siros_codec::json::Json;

use crate::definition::{BaseType, ClaimIndex, ValueType};
use crate::payload::{select, Location, PayloadText, Scalar, Typed, ValueFault, Values};
use crate::projection::ProjectedClaim;
use crate::view::Segment;

/// Why a template does not interpolate. The entry is then not compatible.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum TemplateFault {
    /// The placeholder names the claim at this position, which is an `image`, a `label_only`
    /// or a `template:` claim.
    Reference(ClaimIndex),
    /// The claim at this position has more `null`s in its path than the referencing claim.
    Wildcards(ClaimIndex),
    /// The claim at this position has no value type, and its value is no string.
    NotString(ClaimIndex),
    /// The string of the claim at this position, which has no value type, breaks a rule.
    Value(ClaimIndex, #[source] ValueFault),
    /// The claim at this position is absent from the payload: the locale entry is discarded,
    /// and no other locale is left.
    Absent(ClaimIndex),
}

impl TemplateFault {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Reference(_) => "template_reference",
            Self::Wildcards(_) => "template_wildcards",
            Self::NotString(_) => "template_not_string",
            Self::Value(_, fault) => fault.code(),
            Self::Absent(_) => "template_absent",
        }
    }
}

/// What a template reads: the claims, the payload and its typed values.
pub(super) struct Sources<'s> {
    pub(super) claims: &'s [ProjectedClaim],
    pub(super) payload: &'s Json,
    pub(super) values: &'s Values,
}

/// The segments of `template` with each placeholder replaced by its value, `wildcards` the
/// array positions the `null`s of the referencing claim's path took. A placeholder past the end
/// of `claims` stays as written, and a replaced value is never read again.
///
/// # Errors
///
/// [`TemplateFault`]: the first placeholder that does not resolve.
pub(super) fn interpolate(
    template: &str,
    wildcards: &[u64],
    sources: &Sources<'_>,
) -> Result<Vec<Segment>, TemplateFault> {
    let mut segments: Vec<Segment> = Vec::new();
    let mut text = String::new();
    let mut rest = template;
    while let Some((before, tail)) = rest.split_once('{') {
        text.push_str(before);
        match placeholder(tail).filter(|(index, _)| *index < sources.claims.len()) {
            Some((index, after)) => {
                let value = value(ClaimIndex::new(index), wildcards, sources)?;
                segments
                    .extend((!text.is_empty()).then(|| Segment::Text(std::mem::take(&mut text))));
                segments.push(Segment::Value(value));
                rest = after;
            }
            None => {
                text.push('{');
                rest = tail;
            }
        }
    }
    text.push_str(rest);
    segments.extend((!text.is_empty()).then_some(Segment::Text(text)));
    Ok(segments)
}

/// The claim index of the placeholder `tail` starts with, after its `{`, and the text after
/// its `}`: decimal digits, then `}`.
fn placeholder(tail: &str) -> Option<(usize, &str)> {
    let digits = tail.bytes().take_while(u8::is_ascii_digit).count();
    let index: usize = tail.get(..digits)?.parse().ok()?;
    tail.get(digits..)?
        .strip_prefix('}')
        .map(|after| (index, after))
}

/// The value of the claim at `index`, its `null`s resolved to `wildcards`: a typed value, or the
/// string of a claim without a value type as plain text.
fn value(
    index: ClaimIndex,
    wildcards: &[u64],
    sources: &Sources<'_>,
) -> Result<Scalar, TemplateFault> {
    let claim = sources
        .claims
        .get(index.value())
        .map(ProjectedClaim::definition)
        .ok_or(TemplateFault::Absent(index))?;
    match claim.value_type() {
        Some(ValueType::Template(_))
        | Some(ValueType::Plain(BaseType::Image | BaseType::LabelOnly)) => {
            return Err(TemplateFault::Reference(index))
        }
        Some(ValueType::Plain(_)) | None => {}
    }
    let count = claim.path().wildcards();
    let bound = wildcards
        .get(..count)
        .ok_or(TemplateFault::Wildcards(index))?;
    let location =
        Location::bound(claim.path().components(), bound).ok_or(TemplateFault::Wildcards(index))?;
    match sources.values.get(&location) {
        Some(Typed::Scalar(scalar)) => return Ok(scalar.clone()),
        Some(Typed::Image(_) | Typed::LabelOnly | Typed::Template(..)) => {
            return Err(TemplateFault::Reference(index))
        }
        None => {}
    }
    // An internal claim: its value is a string of the payload.
    let selected = select(sources.payload, claim.path().components())
        .map_err(|_| TemplateFault::Absent(index))?;
    match selected
        .iter()
        .find(|selected| selected.location == location)
        .map(|selected| selected.value)
    {
        Some(Json::String(text)) => PayloadText::parse(text.clone())
            .map(Scalar::Text)
            .map_err(|fault| TemplateFault::Value(index, fault)),
        Some(_) => Err(TemplateFault::NotString(index)),
        None => Err(TemplateFault::Absent(index)),
    }
}
