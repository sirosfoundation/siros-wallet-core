//! The DCQL query model — OpenID4VP 1.0 §6.
//!
//! A query is constructed only by parsing ([`DcqlQuery::from_json`], [`DcqlQuery::parse`] or
//! its `Deserialize`, and [`CredentialQuery::parse`] for one Credential Query). The parse reads
//! each member once and refuses what §6.1, §6.1.1, §6.2, §6.3 and §7 forbid:
//!
//! - a member of the wrong JSON type, `null` included, and an absent REQUIRED member, `meta`
//!   among them;
//! - an empty `credentials`, `claims`, `claim_sets`, `credential_sets`, `options`,
//!   `trusted_authorities` or `values` array;
//! - a `values` element other than a string, an integer or a boolean;
//! - an identifier of the wrong syntax or repeated;
//! - a claims query without `id` in a Credential Query with `claim_sets`;
//! - `claim_sets` without `claims`;
//! - an empty `credential_sets` option, and a `claim_sets` or `credential_sets` option naming an
//!   unknown id;
//! - a malformed claims path, and an `mso_mdoc` claims path other than a namespace and an
//!   element.
//!
//! "Implementations MUST ignore any unknown properties" (§6): a Credential Query keeps them as
//! its extension members, for the profile of its format to read.

mod error;
mod read;

use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

use crate::authority::TrustedAuthorities;
use crate::id::{ClaimId, QueryId};
use crate::meta::CredentialFormat;
use crate::path::ClaimPath;

pub use error::{
    ClaimMember, CredentialMember, FormFault, Member, Position, QueryError, QueryTextError,
    SetMember,
};

/// A complete DCQL query (§6).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DcqlQuery {
    credentials: Vec<CredentialQuery>,
    #[serde(skip_serializing_if = "Option::is_none")]
    credential_sets: Option<Vec<CredentialSetQuery>>,
}

/// One requested credential (§6.1), with the defaults §6.1 states.
#[derive(Debug, Clone, PartialEq)]
pub struct CredentialQuery {
    id: QueryId,
    format: CredentialFormat,
    multiple: Multiplicity,
    meta: Map<String, Value>,
    trusted_authorities: Option<TrustedAuthorities>,
    holder_binding: HolderBinding,
    claims: ClaimRequest,
    extensions: Vec<(String, Value)>,
}

/// The claims a Credential Query requests (§6.4.1).
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ClaimRequest {
    /// `claims` is absent: no selectively disclosable claim is requested.
    Nothing,
    /// `claims` without `claim_sets`: every claim is requested.
    All(Vec<ClaimsQuery>),
    /// `claims` with `claim_sets`: the first option the credential satisfies.
    Sets {
        claims: Vec<ClaimsQuery>,
        options: Vec<ClaimOption>,
    },
}

/// A `claim_sets` option (§6.1): the claims queries it names, in its order.
#[derive(Debug, Clone, PartialEq)]
pub struct ClaimOption(Vec<NamedClaim>);

/// A claims query an option names, with the id that names it.
#[derive(Debug, Clone, PartialEq)]
struct NamedClaim {
    id: ClaimId,
    claim: ClaimsQuery,
}

/// One requested claim (§6.3).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ClaimsQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<ClaimId>,
    path: ClaimPath,
    #[serde(skip_serializing_if = "Option::is_none")]
    values: Option<Vec<Value>>,
}

/// A constraint on which combinations of credentials satisfy the request (§6.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CredentialSetQuery {
    options: Vec<Vec<QueryId>>,
    required: SetRequirement,
    #[serde(skip_serializing_if = "Option::is_none")]
    purpose: Option<Value>,
}

/// Whether a Credential Query accepts several credentials (§6.1 `multiple`, `false` when
/// absent).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Multiplicity {
    /// One credential answers the query.
    One,
    /// "multiple Credentials can be returned for this Credential Query".
    Several,
}

/// Whether a Credential Query requires cryptographic holder binding (§6.1
/// `require_cryptographic_holder_binding`, `true` when absent).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HolderBinding {
    /// The presentation proves possession of the credential's key.
    Required,
    /// The presentation may go without a proof of possession.
    Optional,
}

/// Whether a credential set must be satisfied (§6.2 `required`, `true` when absent).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SetRequirement {
    /// The request is satisfied only with one of the set's options.
    Required,
    /// The Wallet may add one of the set's options.
    Optional,
}

/// Declares the wire form of a flag: the boolean of its member, `$true` for `true`.
macro_rules! flag {
    ($name:ident, $true:ident) => {
        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_bool(*self == Self::$true)
            }
        }
    };
}

flag!(Multiplicity, Several);
flag!(HolderBinding, Required);
flag!(SetRequirement, Required);

impl Serialize for ClaimOption {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.ids())
    }
}

/// The members as the query holds them, its extension members last.
impl Serialize for CredentialQuery {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut query = serializer.serialize_map(None)?;
        query.serialize_entry("id", &self.id)?;
        query.serialize_entry("format", &self.format)?;
        query.serialize_entry("multiple", &self.multiple)?;
        query.serialize_entry("meta", &self.meta)?;
        if let Some(authorities) = &self.trusted_authorities {
            query.serialize_entry("trusted_authorities", authorities)?;
        }
        if self.holder_binding == HolderBinding::Optional {
            query.serialize_entry("require_cryptographic_holder_binding", &self.holder_binding)?;
        }
        match &self.claims {
            ClaimRequest::Nothing => {}
            ClaimRequest::All(claims) => query.serialize_entry("claims", claims)?,
            ClaimRequest::Sets { claims, options } => {
                query.serialize_entry("claims", claims)?;
                query.serialize_entry("claim_sets", options)?;
            }
        }
        for (name, value) in &self.extensions {
            query.serialize_entry(name, value)?;
        }
        query.end()
    }
}

impl<'de> Deserialize<'de> for DcqlQuery {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::parse(&Value::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

impl DcqlQuery {
    /// The DCQL query of the JSON text `json`, as [`Self::parse`] reads its value.
    ///
    /// # Errors
    ///
    /// [`QueryTextError`]: text that is no JSON, or the [`QueryError`] of its value.
    pub fn from_json(json: &str) -> Result<Self, QueryTextError> {
        let document = serde_json::from_str(json).map_err(QueryTextError::Json)?;
        Self::parse(&document).map_err(QueryTextError::Query)
    }

    /// The DCQL query of the JSON value `document`.
    ///
    /// # Errors
    ///
    /// [`QueryError`]: the first rule of §6.1, §6.1.1, §6.2, §6.3 or §7 the document breaks.
    /// Unknown properties are ignored (§6).
    pub fn parse(document: &Value) -> Result<Self, QueryError> {
        read::query(document)
    }

    /// The requested credentials (§6.1), in the Verifier's order.
    #[must_use]
    pub fn credentials(&self) -> &[CredentialQuery] {
        &self.credentials
    }

    /// The constraints on which combinations to return (§6.2).
    ///
    /// Absent means something specific: "If `credential_sets` is not provided, the Verifier
    /// requests presentations for all Credentials in `credentials`" (§6.4).
    #[must_use]
    pub fn credential_sets(&self) -> Option<&[CredentialSetQuery]> {
        self.credential_sets.as_deref()
    }

    /// The credential query with the given id.
    #[must_use]
    pub fn credential(&self, id: &str) -> Option<&CredentialQuery> {
        self.credentials.iter().find(|c| c.id == *id)
    }
}

impl CredentialQuery {
    /// The Credential Query `value` alone (§6.1). Its errors name it at position 0.
    ///
    /// # Errors
    ///
    /// [`QueryError`]: the first rule of §6.1, §6.1.1, §6.3 or §7 the query breaks.
    pub fn parse(value: &Value) -> Result<Self, QueryError> {
        read::credential_query(Position::new(0), value)
    }

    /// Identifies this query in the response and in `credential_sets`.
    #[must_use]
    pub fn id(&self) -> &QueryId {
        &self.id
    }

    /// The requested credential format.
    #[must_use]
    pub fn format(&self) -> &CredentialFormat {
        &self.format
    }

    /// Whether more than one credential may be returned for this query.
    #[must_use]
    pub fn multiplicity(&self) -> Multiplicity {
        self.multiple
    }

    /// Format-specific constraints on metadata and validity. "If empty, no specific
    /// constraints are placed" (§6.1).
    #[must_use]
    pub fn meta(&self) -> &Map<String, Value> {
        &self.meta
    }

    /// The extension member `name`: a member §6.1 leaves undefined, as the Verifier sent it. A
    /// profile of the format defines its own, such as `zkp_req`'s `_req`.
    #[must_use]
    pub fn extension(&self, name: &str) -> Option<&Value> {
        self.extensions
            .iter()
            .find(|(member, _)| member == name)
            .map(|(_, value)| value)
    }

    /// Authorities whose issuance the Verifier accepts (§6.1.1), when it names any.
    #[must_use]
    pub fn trusted_authorities(&self) -> Option<&TrustedAuthorities> {
        self.trusted_authorities.as_ref()
    }

    /// Whether cryptographic holder binding is required.
    #[must_use]
    pub fn holder_binding(&self) -> HolderBinding {
        self.holder_binding
    }

    /// Claims requested from this credential (§6.3).
    #[must_use]
    pub fn claims(&self) -> &[ClaimsQuery] {
        match &self.claims {
            ClaimRequest::Nothing => &[],
            ClaimRequest::All(claims) | ClaimRequest::Sets { claims, .. } => claims,
        }
    }

    /// The `claim_sets` options of [`Self::claims`] (§6.1), in the Verifier's order of
    /// preference.
    #[must_use]
    pub fn claim_sets(&self) -> Option<&[ClaimOption]> {
        match &self.claims {
            ClaimRequest::Sets { options, .. } => Some(options),
            ClaimRequest::Nothing | ClaimRequest::All(_) => None,
        }
    }

    pub(crate) fn claim_request(&self) -> &ClaimRequest {
        &self.claims
    }

    /// The claims query with the given id. The parse refuses duplicated claim ids, so the id
    /// names at most one.
    #[must_use]
    pub fn claim(&self, id: &str) -> Option<&ClaimsQuery> {
        self.claims()
            .iter()
            .find(|c| c.id.as_ref().is_some_and(|own| *own == *id))
    }
}

impl ClaimsQuery {
    /// Identifies this claim. "REQUIRED if `claim_sets` is present in the Credential Query;
    /// OPTIONAL otherwise" (§6.3).
    #[must_use]
    pub fn id(&self) -> Option<&ClaimId> {
        self.id.as_ref()
    }

    /// The claims path pointer to the claim (§7).
    #[must_use]
    pub fn path(&self) -> &ClaimPath {
        &self.path
    }

    /// Expected values. "the Wallet SHOULD return the claim only if the type and value of the
    /// claim both match exactly for at least one of the elements in the array" (§6.3).
    #[must_use]
    pub fn values(&self) -> Option<&[Value]> {
        self.values.as_deref()
    }
}

impl ClaimOption {
    /// The ids the option names, in its order.
    pub fn ids(&self) -> impl Iterator<Item = &ClaimId> {
        self.0.iter().map(|named| &named.id)
    }

    /// The claims queries the option names, in its order.
    pub fn claims(&self) -> impl Iterator<Item = &ClaimsQuery> {
        self.0.iter().map(|named| &named.claim)
    }
}

impl CredentialSetQuery {
    /// The options: each a set of Credential Query ids that together satisfy this use case.
    #[must_use]
    pub fn options(&self) -> &[Vec<QueryId>] {
        &self.options
    }

    /// Whether this set must be satisfied.
    #[must_use]
    pub fn requirement(&self) -> SetRequirement {
        self.required
    }

    /// `purpose`, as sent: why the Verifier wants this combination, for showing to the user.
    /// OpenID4VP's drafts defined it as a string, an integer or an object; Section 6.2 of 1.0
    /// defines no such member, so the parse keeps whatever value it holds.
    #[must_use]
    pub fn purpose(&self) -> Option<&Value> {
        self.purpose.as_ref()
    }
}
