//! `trusted_authorities` (§6.1.1): the authorities a Verifier names for the issuer of a
//! Credential. Which credential an authority admits is the caller's to decide.

use serde::Serialize;
use serde_json::Value;

use crate::meta::text_value;
use crate::query::Position;

text_value!(
    /// The `type` of a trusted authority, as the Verifier sends it: `aki`, `etsi_tl`,
    /// `openid_federation`, or a type of a later version.
    AuthorityType
);

text_value!(
    /// A value of a trusted authority, as the Verifier sends it: what identifies the authority
    /// within its `type`.
    AuthorityValue
);

/// An entry of `trusted_authorities`: a `type` and its `values`, at least one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TrustedAuthority {
    #[serde(rename = "type")]
    kind: AuthorityType,
    values: Vec<AuthorityValue>,
}

impl TrustedAuthority {
    /// `type`.
    #[must_use]
    pub fn kind(&self) -> &AuthorityType {
        &self.kind
    }

    /// `values`, at least one, in the Verifier's order.
    #[must_use]
    pub fn values(&self) -> &[AuthorityValue] {
        &self.values
    }
}

/// `trusted_authorities`: its entries, at least one, in the Verifier's order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct TrustedAuthorities(Vec<TrustedAuthority>);

impl TrustedAuthorities {
    /// The entries.
    #[must_use]
    pub fn entries(&self) -> &[TrustedAuthority] {
        &self.0
    }

    /// The `trusted_authorities` member `value`: "a non-empty array of objects", each with a
    /// string `type` and a non-empty array of string `values` (§6.1.1).
    pub(crate) fn parse(value: &Value) -> Result<Self, TrustedAuthorityError> {
        let entries = value.as_array().ok_or(TrustedAuthorityError::NotArray)?;
        if entries.is_empty() {
            return Err(TrustedAuthorityError::Empty);
        }
        let mut parsed = Vec::with_capacity(entries.len());
        for entry in entries {
            parsed.push(TrustedAuthority::parse(entry)?);
        }
        Ok(Self(parsed))
    }
}

impl TrustedAuthority {
    fn parse(entry: &Value) -> Result<Self, TrustedAuthorityError> {
        let entry = entry
            .as_object()
            .ok_or(TrustedAuthorityError::EntryNotObject)?;
        let kind = match entry.get("type") {
            Some(Value::String(kind)) => AuthorityType::new(kind),
            Some(_) => return Err(TrustedAuthorityError::TypeNotString),
            None => return Err(TrustedAuthorityError::TypeAbsent),
        };
        let values = match entry.get("values") {
            Some(Value::Array(values)) => values,
            Some(_) => return Err(TrustedAuthorityError::ValuesNotArray),
            None => return Err(TrustedAuthorityError::ValuesAbsent),
        };
        if values.is_empty() {
            return Err(TrustedAuthorityError::ValuesEmpty);
        }
        let values = values
            .iter()
            .enumerate()
            .map(|(position, value)| match value {
                Value::String(value) => Ok(AuthorityValue::new(value)),
                _ => Err(TrustedAuthorityError::ValueNotString(Position::new(
                    position,
                ))),
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { kind, values })
    }
}

/// Why a `trusted_authorities` member breaks §6.1.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}", self.code())]
pub enum TrustedAuthorityError {
    /// The member is no array.
    NotArray,
    /// The array is empty.
    Empty,
    /// An entry is no object.
    EntryNotObject,
    /// An entry has no `type`.
    TypeAbsent,
    /// An entry's `type` is no string.
    TypeNotString,
    /// An entry has no `values`.
    ValuesAbsent,
    /// An entry's `values` is no array.
    ValuesNotArray,
    /// An entry's `values` is empty.
    ValuesEmpty,
    /// The entry of an entry's `values` at this position is no string.
    ValueNotString(Position),
}

impl TrustedAuthorityError {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::NotArray => "trusted_authorities_not_array",
            Self::Empty => "trusted_authorities_empty",
            Self::EntryNotObject => "trusted_authority_not_object",
            Self::TypeAbsent | Self::TypeNotString => "trusted_authority_type",
            Self::ValuesAbsent
            | Self::ValuesNotArray
            | Self::ValuesEmpty
            | Self::ValueNotString(_) => "trusted_authority_values",
        }
    }
}
