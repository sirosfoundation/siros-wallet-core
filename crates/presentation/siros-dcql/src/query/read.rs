//! The one parse of a DCQL query from its JSON value (§6): each member read once, each rule
//! refused with its cause.

use rustc_hash::FxHashMap;
use serde_json::{Map, Number, Value};

use super::error::{
    ClaimMember, CredentialMember, FormFault, Member, Position, QueryError, SetMember,
};
use super::{
    ClaimOption, ClaimRequest, ClaimsQuery, CredentialQuery, CredentialSetQuery, DcqlQuery,
    HolderBinding, Multiplicity, NamedClaim, SetRequirement,
};
use crate::authority::TrustedAuthorities;
use crate::id::{ClaimId, QueryId};
use crate::meta::CredentialFormat;
use crate::path::{mdoc_components, ClaimPath};

/// The format whose claims paths are a namespace and an element identifier (§7.2.1).
const MSO_MDOC: &str = "mso_mdoc";

/// The members of a Credential Query that §6.1 defines.
const CREDENTIAL_MEMBERS: [&str; 8] = [
    "id",
    "format",
    "multiple",
    "meta",
    "trusted_authorities",
    "require_cryptographic_holder_binding",
    "claims",
    "claim_sets",
];

/// The query `document`.
pub(super) fn query(document: &Value) -> Result<DcqlQuery, QueryError> {
    let document = object(document, Member::Query)?;
    let credentials = non_empty(document.get("credentials"), Member::Credentials)?
        .iter()
        .enumerate()
        .map(|(position, credential)| credential_query(Position::new(position), credential))
        .collect::<Result<Vec<_>, _>>()?;
    let mut ids = Positions::default();
    for (position, credential) in credentials.iter().enumerate() {
        if ids.insert(credential.id.as_str(), position).is_some() {
            return Err(QueryError::DuplicateCredentialId(credential.id.clone()));
        }
    }
    let credential_sets = match document.get("credential_sets") {
        None => None,
        Some(sets) => Some(credential_sets(sets, &ids)?),
    };
    Ok(DcqlQuery {
        credentials,
        credential_sets,
    })
}

/// The position of each id of a list, by its text.
type Positions<'a> = FxHashMap<&'a str, usize>;

fn form(member: Member, fault: FormFault) -> QueryError {
    QueryError::Form { member, fault }
}

/// The JSON object `value`.
fn object(value: &Value, member: Member) -> Result<&Map<String, Value>, QueryError> {
    value
        .as_object()
        .ok_or_else(|| form(member, FormFault::WrongType))
}

/// The non-empty array member `value`.
fn non_empty(value: Option<&Value>, member: Member) -> Result<&[Value], QueryError> {
    match value {
        None => Err(form(member, FormFault::Absent)),
        Some(Value::Array(items)) if items.is_empty() => Err(form(member, FormFault::Empty)),
        Some(Value::Array(items)) => Ok(items),
        Some(_) => Err(form(member, FormFault::WrongType)),
    }
}

/// The string member `value`.
fn string(value: Option<&Value>, member: Member) -> Result<&str, QueryError> {
    match value {
        None => Err(form(member, FormFault::Absent)),
        Some(Value::String(text)) => Ok(text),
        Some(_) => Err(form(member, FormFault::WrongType)),
    }
}

/// The boolean member `value`: `stated` when absent, `on` when `true`, `off` when `false`.
fn flag<T>(
    value: Option<&Value>,
    member: Member,
    stated: T,
    on: T,
    off: T,
) -> Result<T, QueryError> {
    match value {
        None => Ok(stated),
        Some(Value::Bool(true)) => Ok(on),
        Some(Value::Bool(false)) => Ok(off),
        Some(_) => Err(form(member, FormFault::WrongType)),
    }
}

/// The Credential Query at `position` (§6.1).
pub(super) fn credential_query(
    position: Position,
    value: &Value,
) -> Result<CredentialQuery, QueryError> {
    let query = object(value, Member::Credential(position))?;
    let member = |field| Member::CredentialMember(position, field);
    let id = QueryId::parse(string(query.get("id"), member(CredentialMember::Id))?)
        .map_err(QueryError::Id)?;
    let format = CredentialFormat::new(string(
        query.get("format"),
        member(CredentialMember::Format),
    )?);
    let multiple = flag(
        query.get("multiple"),
        member(CredentialMember::Multiple),
        Multiplicity::One,
        Multiplicity::Several,
        Multiplicity::One,
    )?;
    let meta = match query.get("meta") {
        Some(Value::Object(meta)) => meta.clone(),
        None => return Err(form(member(CredentialMember::Meta), FormFault::Absent)),
        Some(_) => return Err(form(member(CredentialMember::Meta), FormFault::WrongType)),
    };
    let trusted_authorities = match query.get("trusted_authorities") {
        None => None,
        Some(authorities) => Some(TrustedAuthorities::parse(authorities).map_err(|error| {
            QueryError::TrustedAuthorities {
                credential: id.clone(),
                error,
            }
        })?),
    };
    let holder_binding = flag(
        query.get("require_cryptographic_holder_binding"),
        member(CredentialMember::HolderBinding),
        HolderBinding::Required,
        HolderBinding::Required,
        HolderBinding::Optional,
    )?;
    let claims = match query.get("claims") {
        None => Vec::new(),
        claims => non_empty(claims, member(CredentialMember::Claims))?
            .iter()
            .enumerate()
            .map(|(claim, value)| claims_query(position, Position::new(claim), &id, value))
            .collect::<Result<_, _>>()?,
    };
    let named = check_claims(&id, &format, &claims)?;
    let claims = match query.get("claim_sets") {
        None if claims.is_empty() => ClaimRequest::Nothing,
        None => ClaimRequest::All(claims),
        // "`claim_sets` MUST NOT be present if `claims` is absent" (§6.4.1).
        Some(_) if claims.is_empty() => return Err(QueryError::ClaimSetsWithoutClaims(id)),
        Some(sets) => ClaimRequest::Sets {
            options: claim_sets(sets, position, &id, &claims, &named)?,
            claims,
        },
    };
    let mut extensions = Vec::new();
    for (name, value) in query {
        if !CREDENTIAL_MEMBERS.contains(&name.as_str()) {
            extensions.push((name.clone(), value.clone()));
        }
    }
    Ok(CredentialQuery {
        id,
        format,
        multiple,
        meta,
        trusted_authorities,
        holder_binding,
        claims,
        extensions,
    })
}

/// The claims of a Credential Query: their ids each once (§6.3), and for `mso_mdoc` each path
/// a namespace and an element identifier (§7.2.1). Gives the position of each id.
fn check_claims<'c>(
    credential: &QueryId,
    format: &CredentialFormat,
    claims: &'c [ClaimsQuery],
) -> Result<Positions<'c>, QueryError> {
    let mut ids = Positions::default();
    for (position, claim) in claims.iter().enumerate() {
        if let Some(id) = &claim.id {
            if ids.insert(id.as_str(), position).is_some() {
                return Err(QueryError::DuplicateClaimId {
                    credential: credential.clone(),
                    claim: id.clone(),
                });
            }
        }
        if *format == MSO_MDOC && mdoc_components(&claim.path).is_err() {
            return Err(QueryError::MdocPath {
                credential: credential.clone(),
                claim: Position::new(position),
            });
        }
    }
    Ok(ids)
}

/// `claim_sets` of the Credential Query at `position`: a non-empty array of arrays of ids of
/// its `claims` (§6.1), each resolved through `named` to its claims query. Each claims query
/// has an `id` (§6.3).
fn claim_sets(
    value: &Value,
    position: Position,
    credential: &QueryId,
    claims: &[ClaimsQuery],
    named: &Positions<'_>,
) -> Result<Vec<ClaimOption>, QueryError> {
    let member = Member::CredentialMember(position, CredentialMember::ClaimSets);
    let sets = non_empty(Some(value), member)?;
    if let Some(claim) = claims.iter().position(|claim| claim.id.is_none()) {
        let id = Member::ClaimMember(position, Position::new(claim), ClaimMember::Id);
        return Err(form(id, FormFault::Absent));
    }
    sets.iter()
        .enumerate()
        .map(|(option, set)| {
            let entry = || form(member, FormFault::Entry(Position::new(option)));
            let Value::Array(ids) = set else {
                return Err(entry());
            };
            ids.iter()
                .map(|id| {
                    let text = id.as_str().ok_or_else(entry)?;
                    let id = ClaimId::parse(text).map_err(|error| QueryError::ClaimId {
                        credential: credential.clone(),
                        error,
                    })?;
                    let claim = named
                        .get(id.as_str())
                        .and_then(|&claim| claims.get(claim))
                        .cloned()
                        .ok_or_else(|| QueryError::UnknownClaimId {
                            credential: credential.clone(),
                            claim: id.clone(),
                        })?;
                    Ok(NamedClaim { id, claim })
                })
                .collect::<Result<_, _>>()
                .map(ClaimOption)
        })
        .collect()
}

/// The claims query at `claim` of the Credential Query at `credential` (§6.3).
fn claims_query(
    credential: Position,
    claim: Position,
    query: &QueryId,
    value: &Value,
) -> Result<ClaimsQuery, QueryError> {
    let object = object(value, Member::Claim(credential, claim))?;
    let member = |field| Member::ClaimMember(credential, claim, field);
    let id = match object.get("id") {
        None => None,
        Some(Value::String(text)) => {
            Some(ClaimId::parse(text).map_err(|error| QueryError::ClaimId {
                credential: query.clone(),
                error,
            })?)
        }
        Some(_) => return Err(form(member(ClaimMember::Id), FormFault::WrongType)),
    };
    let path = object
        .get("path")
        .ok_or_else(|| form(member(ClaimMember::Path), FormFault::Absent))?;
    let path = ClaimPath::parse(path).map_err(|error| QueryError::ClaimPath {
        credential: query.clone(),
        claim,
        error,
    })?;
    let values = match object.get("values") {
        None => None,
        values => Some(expected_values(values, member(ClaimMember::Values))?),
    };
    Ok(ClaimsQuery { id, path, values })
}

/// `values`: "a non-empty array of strings, integers or boolean values" (§6.3).
fn expected_values(value: Option<&Value>, member: Member) -> Result<Vec<Value>, QueryError> {
    let values = non_empty(value, member)?;
    if let Some(position) = values.iter().position(|value| match value {
        Value::String(_) | Value::Bool(_) => false,
        Value::Number(number) => !integer(number),
        Value::Null | Value::Array(_) | Value::Object(_) => true,
    }) {
        return Err(form(member, FormFault::Entry(Position::new(position))));
    }
    Ok(values.to_vec())
}

/// Whether `number` has no fractional part: a JSON Schema `integer`.
fn integer(number: &Number) -> bool {
    number.is_i64() || number.is_u64() || number.as_f64().is_some_and(|value| value.fract() == 0.0)
}

/// `credential_sets` (§6.2): a non-empty array whose options name Credential Queries of `ids`.
fn credential_sets(
    value: &Value,
    ids: &Positions<'_>,
) -> Result<Vec<CredentialSetQuery>, QueryError> {
    non_empty(Some(value), Member::CredentialSets)?
        .iter()
        .enumerate()
        .map(|(position, set)| credential_set(Position::new(position), set, ids))
        .collect()
}

fn credential_set(
    position: Position,
    value: &Value,
    ids: &Positions<'_>,
) -> Result<CredentialSetQuery, QueryError> {
    let set = object(value, Member::CredentialSet(position))?;
    let member = |field| Member::CredentialSetMember(position, field);
    let options = non_empty(set.get("options"), member(SetMember::Options))?
        .iter()
        .enumerate()
        .map(|(option, names)| {
            let entry = || {
                form(
                    member(SetMember::Options),
                    FormFault::Entry(Position::new(option)),
                )
            };
            // "a non-empty array of identifiers" (§6.2).
            let names = match names {
                Value::Array(names) if !names.is_empty() => names,
                _ => return Err(entry()),
            };
            names
                .iter()
                .map(|id| {
                    let id =
                        QueryId::parse(id.as_str().ok_or_else(entry)?).map_err(QueryError::Id)?;
                    if !ids.contains_key(id.as_str()) {
                        return Err(QueryError::UnknownCredentialId(id));
                    }
                    Ok(id)
                })
                .collect()
        })
        .collect::<Result<_, _>>()?;
    let required = flag(
        set.get("required"),
        member(SetMember::Required),
        SetRequirement::Required,
        SetRequirement::Required,
        SetRequirement::Optional,
    )?;
    let purpose = set.get("purpose").cloned();
    Ok(CredentialSetQuery {
        options,
        required,
        purpose,
    })
}
