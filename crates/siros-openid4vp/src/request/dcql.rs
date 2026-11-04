//! DCQL (OpenID4VP 1.0 §6): the Credential Queries and Credential Sets of `dcql_query`. The
//! protocol reads `id`, `format`, `multiple`, `require_cryptographic_holder_binding` and
//! `trusted_authorities`; the whole query object goes to its format.

use serde_json::value::RawValue;

use super::rules::DcqlRule;
use super::sets::{MAX_POSITIONS, QueryIndex};
use crate::ids::{AuthorityType, AuthorityValue, FormatId, QueryId};
use crate::json::{self, RawObject};
use crate::refusal::Refusal;

/// How many credentials a query takes (§6.1 `multiple`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Multiplicity {
    /// One credential.
    One,
    /// One or more distinct credentials.
    Many,
}

/// Whether the query requires cryptographic holder binding (§6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HolderBinding {
    /// Required, the default.
    Required,
    /// Waived by the Verifier.
    Waived,
}

/// A Trusted Authorities Query (§6.1.1): a type and the values one of which a credential's
/// issuer must match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedAuthority<'a> {
    /// The type.
    pub kind: AuthorityType<'a>,
    /// The values, at least one.
    pub values: Vec<AuthorityValue<'a>>,
}

/// A Credential Query. Only [`Request::parse`](super::Request::parse) makes one, its object
/// parsed as JSON with unique member names.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Query<'a> {
    /// The identifier.
    pub id: QueryId<'a>,
    /// The format, which selects the format plug-in.
    pub format: FormatId<'a>,
    /// How many credentials it takes.
    pub multiple: Multiplicity,
    /// Whether it requires holder binding.
    pub holder_binding: HolderBinding,
    /// The Trusted Authorities Queries; empty when absent.
    pub trusted_authorities: Vec<TrustedAuthority<'a>>,
    /// The whole query object, for its format.
    pub object: &'a RawValue,
}

/// A Credential Set Query (§6.2): options of queries, one of which a selection presents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialSet {
    /// The options, each a list of queries in the Verifier's order.
    pub options: Vec<Vec<QueryIndex>>,
    /// Whether a selection must satisfy the set.
    pub required: bool,
}

/// `dcql_query`: the queries, and the Credential Sets when present.
pub(crate) struct Dcql<'a> {
    pub(crate) queries: Vec<Query<'a>>,
    pub(crate) sets: Option<Vec<CredentialSet>>,
}

fn refuse(rule: DcqlRule) -> Refusal {
    Refusal::new(rule)
}

impl<'a> Dcql<'a> {
    pub(crate) fn parse(raw: &'a RawValue) -> Result<Self, Refusal> {
        let object = RawObject::parse(raw.get()).map_err(|e| refuse(DcqlRule::NotObject(e)))?;
        let credentials: Vec<&'a RawValue> = object
            .get("credentials")
            .and_then(|credentials| serde_json::from_str(credentials.get()).ok())
            .filter(|credentials: &Vec<&RawValue>| !credentials.is_empty())
            .ok_or_else(|| refuse(DcqlRule::Credentials))?;
        if credentials.len() > MAX_POSITIONS {
            return Err(refuse(DcqlRule::TooMany));
        }
        let queries = credentials
            .into_iter()
            .map(Query::parse)
            .collect::<Result<Vec<_>, _>>()?;
        if let Some(twice) = queries.iter().enumerate().find_map(|(k, q)| {
            queries
                .get(..k)
                .and_then(|before| before.iter().find(|earlier| earlier.id == q.id))
        }) {
            return Err(refuse(DcqlRule::IdTwice {
                id: twice.id.to_string(),
            }));
        }
        let sets = object
            .get("credential_sets")
            .map(|sets| CredentialSet::parse_all(sets, &queries))
            .transpose()?;
        Ok(Self { queries, sets })
    }
}

impl<'a> Query<'a> {
    fn parse(raw: &'a RawValue) -> Result<Self, Refusal> {
        let object =
            RawObject::parse(raw.get()).map_err(|e| refuse(DcqlRule::QueryNotObject(e)))?;
        let text = |name: &str| object.get(name).and_then(|value| json::string(value).ok());
        let id = text("id")
            .and_then(|id| QueryId::parse(id).ok())
            .ok_or_else(|| refuse(DcqlRule::QueryId))?;
        let format = text("format")
            .and_then(|format| FormatId::parse(format).ok())
            .ok_or_else(|| {
                refuse(DcqlRule::Format {
                    query: id.to_string(),
                })
            })?;
        let flag = |name: &'static str, absent: bool| match object.get(name) {
            None => Ok(absent),
            Some(value) => serde_json::from_str::<bool>(value.get()).map_err(|_| {
                refuse(DcqlRule::Flag {
                    query: id.to_string(),
                    name,
                })
            }),
        };
        let multiple = if flag("multiple", false)? {
            Multiplicity::Many
        } else {
            Multiplicity::One
        };
        let holder_binding = if flag("require_cryptographic_holder_binding", true)? {
            HolderBinding::Required
        } else {
            HolderBinding::Waived
        };
        let trusted_authorities = match object.get("trusted_authorities") {
            None => Vec::new(),
            Some(value) => TrustedAuthority::parse_all(value).ok_or_else(|| {
                refuse(DcqlRule::TrustedAuthorities {
                    query: id.to_string(),
                })
            })?,
        };
        Ok(Self {
            id,
            format,
            multiple,
            holder_binding,
            trusted_authorities,
            object: raw,
        })
    }
}

impl<'a> TrustedAuthority<'a> {
    fn parse_all(raw: &'a RawValue) -> Option<Vec<Self>> {
        let items: Vec<&'a RawValue> = serde_json::from_str(raw.get()).ok()?;
        if items.is_empty() {
            return None;
        }
        items.into_iter().map(Self::parse).collect()
    }

    fn parse(raw: &'a RawValue) -> Option<Self> {
        let object = RawObject::parse(raw.get()).ok()?;
        let kind = AuthorityType::parse(json::string(object.get("type")?).ok()?).ok()?;
        let values: Vec<&'a RawValue> = serde_json::from_str(object.get("values")?.get()).ok()?;
        let values = values
            .into_iter()
            .map(|value| {
                json::string(value)
                    .ok()
                    .and_then(|value| AuthorityValue::parse(value).ok())
            })
            .collect::<Option<Vec<_>>>()?;
        (!values.is_empty()).then_some(Self { kind, values })
    }
}

impl CredentialSet {
    fn parse_all(raw: &RawValue, queries: &[Query<'_>]) -> Result<Vec<Self>, Refusal> {
        let sets: Vec<&RawValue> = serde_json::from_str(raw.get())
            .ok()
            .filter(|sets: &Vec<&RawValue>| !sets.is_empty())
            .ok_or_else(|| refuse(DcqlRule::Sets))?;
        sets.into_iter()
            .map(|set| Self::parse(set, queries))
            .collect()
    }

    fn parse(raw: &RawValue, queries: &[Query<'_>]) -> Result<Self, Refusal> {
        let malformed = || refuse(DcqlRule::Set);
        let object = RawObject::parse(raw.get()).map_err(|_| malformed())?;
        let options: Vec<Vec<&RawValue>> = object
            .get("options")
            .and_then(|options| serde_json::from_str(options.get()).ok())
            .filter(|options: &Vec<Vec<&RawValue>>| {
                !options.is_empty() && options.iter().all(|o| !o.is_empty())
            })
            .ok_or_else(malformed)?;
        let options = options
            .into_iter()
            .map(|option| {
                option
                    .into_iter()
                    .map(|id| {
                        let id = json::string(id).map_err(|_| malformed())?;
                        queries
                            .iter()
                            .position(|q| q.id == *id)
                            .and_then(QueryIndex::new)
                            .ok_or_else(|| refuse(DcqlRule::SetQuery { id: id.to_string() }))
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()?;
        let required = match object.get("required") {
            None => true,
            Some(value) => serde_json::from_str(value.get()).map_err(|_| malformed())?,
        };
        Ok(Self { options, required })
    }
}
