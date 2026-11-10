//! DCQL (OpenID4VP 1.0 §6): the Credential Queries and Credential Sets of `dcql_query`. The
//! protocol reads `id`, `format`, `multiple`, `require_cryptographic_holder_binding` and
//! `trusted_authorities`; the whole query object goes to its format.

use serde_json::value::RawValue;

use super::rules::DcqlRule;
use super::sets::QueryIndex;
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
/// issuer must match. Only its parse makes one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedAuthority<'a> {
    kind: AuthorityType<'a>,
    values: Vec<AuthorityValue<'a>>,
}

/// Whether a selection must satisfy a Credential Set (§6.2 `required`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SetNeed {
    /// It must, the default.
    Required,
    /// It need not.
    Optional,
}

/// A Credential Query. [`Request::parse`](super::Request::parse) makes one, its object parsed as
/// JSON with unique member names; [`Query::read_all`] makes those of a `dcql_query` alone.
#[derive(Debug, Clone)]
pub struct Query<'a> {
    index: QueryIndex,
    id: QueryId<'a>,
    format: FormatId<'a>,
    multiple: Multiplicity,
    holder_binding: HolderBinding,
    trusted_authorities: Vec<TrustedAuthority<'a>>,
    object: &'a RawValue,
}

/// A Credential Set Query (§6.2): options of queries, one of which a selection presents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialSet {
    options: Vec<Vec<QueryIndex>>,
    need: SetNeed,
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
        let sets = object
            .get("credential_sets")
            .map(|sets| {
                serde_json::from_str(sets.get())
                    .ok()
                    .filter(|sets: &Vec<&RawValue>| !sets.is_empty())
                    .ok_or_else(|| refuse(DcqlRule::Sets))
            })
            .transpose()?;
        Self::of(credentials, sets)
    }

    /// The query of its Credential Queries and its Credential Sets, each as written: one query of
    /// a `dcql_query`, or the union of the queries registered scope values stand for.
    pub(crate) fn of(
        credentials: Vec<&'a RawValue>,
        sets: Option<Vec<&'a RawValue>>,
    ) -> Result<Self, Refusal> {
        let queries = credentials
            .into_iter()
            .enumerate()
            .map(|(k, raw)| {
                let index = QueryIndex::new(k).ok_or_else(|| refuse(DcqlRule::TooMany))?;
                Query::parse(index, raw)
            })
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
        let sets = sets
            .map(|sets| {
                sets.into_iter()
                    .map(|set| CredentialSet::parse(set, &queries))
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;
        Ok(Self { queries, sets })
    }
}

impl<'a> Query<'a> {
    /// The identifier.
    #[must_use]
    pub const fn id(&self) -> &QueryId<'a> {
        &self.id
    }

    /// The format, which selects the format plug-in.
    #[must_use]
    pub const fn format(&self) -> &FormatId<'a> {
        &self.format
    }

    /// How many credentials it takes.
    #[must_use]
    pub const fn multiple(&self) -> Multiplicity {
        self.multiple
    }

    /// Whether it requires holder binding.
    #[must_use]
    pub const fn holder_binding(&self) -> HolderBinding {
        self.holder_binding
    }

    /// The Trusted Authorities Queries; empty when absent.
    #[must_use]
    pub fn trusted_authorities(&self) -> &[TrustedAuthority<'a>] {
        &self.trusted_authorities
    }

    /// The query's position in `credentials`.
    #[must_use]
    pub const fn index(&self) -> QueryIndex {
        self.index
    }

    /// The whole query object, for its format.
    #[must_use]
    pub const fn object(&self) -> &'a RawValue {
        self.object
    }

    /// The Credential Queries of `dcql_query` as [`Request::parse`](super::Request::parse) reads
    /// them (§6.1, §6.2), for a Verifier that checks its own query under the wallet's rules.
    ///
    /// # Errors
    ///
    /// The first [`DcqlRule`] the query breaks.
    pub fn read_all(dcql_query: &'a RawValue) -> Result<Vec<Self>, Refusal> {
        Dcql::parse(dcql_query).map(|dcql| dcql.queries)
    }

    fn parse(index: QueryIndex, raw: &'a RawValue) -> Result<Self, Refusal> {
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
            index,
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
    /// The type.
    #[must_use]
    pub const fn kind(&self) -> &AuthorityType<'a> {
        &self.kind
    }

    /// The values, at least one.
    #[must_use]
    pub fn values(&self) -> &[AuthorityValue<'a>] {
        &self.values
    }

    /// The query, owning its texts.
    #[must_use]
    pub fn into_owned(self) -> TrustedAuthority<'static> {
        TrustedAuthority {
            kind: self.kind.into_owned(),
            values: self
                .values
                .into_iter()
                .map(AuthorityValue::into_owned)
                .collect(),
        }
    }

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
        let need = match object.get("required") {
            None => SetNeed::Required,
            Some(value) => {
                if serde_json::from_str(value.get()).map_err(|_| malformed())? {
                    SetNeed::Required
                } else {
                    SetNeed::Optional
                }
            }
        };
        Ok(Self { options, need })
    }

    /// The options, at least one, each at least one query in the Verifier's order.
    #[must_use]
    pub fn options(&self) -> &[Vec<QueryIndex>] {
        &self.options
    }

    /// Whether a selection must satisfy the set.
    #[must_use]
    pub const fn need(&self) -> SetNeed {
        self.need
    }
}
