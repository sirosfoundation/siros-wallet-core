//! Why a document is no DCQL query (§6), each with a stable code and its cause.

use crate::authority::TrustedAuthorityError;
use crate::id::{ClaimId, ClaimIdError, QueryId, QueryIdError};
use crate::path::ClaimPathError;

crate::position!(
    /// The position of an entry in an array of the query, from 0.
    Position
);

/// A member of a Credential Query (§6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CredentialMember {
    /// `id`.
    Id,
    /// `format`.
    Format,
    /// `multiple`.
    Multiple,
    /// `meta`.
    Meta,
    /// `require_cryptographic_holder_binding`.
    HolderBinding,
    /// `claims`.
    Claims,
    /// `claim_sets`.
    ClaimSets,
}

/// A member of a claims query (§6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClaimMember {
    /// `id`.
    Id,
    /// `path`.
    Path,
    /// `values`.
    Values,
}

/// A member of a credential set query (§6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SetMember {
    /// `options`.
    Options,
    /// `required`.
    Required,
}

/// Where in a DCQL query a member breaks its form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Member {
    /// The query itself.
    Query,
    /// `credentials`.
    Credentials,
    /// The Credential Query at this position.
    Credential(Position),
    /// A member of the Credential Query at this position.
    CredentialMember(Position, CredentialMember),
    /// The claims query at the second position of the Credential Query at the first.
    Claim(Position, Position),
    /// A member of that claims query.
    ClaimMember(Position, Position, ClaimMember),
    /// `credential_sets`.
    CredentialSets,
    /// The credential set query at this position.
    CredentialSet(Position),
    /// A member of the credential set query at this position.
    CredentialSetMember(Position, SetMember),
}

/// What breaks the form of a member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum FormFault {
    /// It is absent.
    #[error("it is absent")]
    Absent,
    /// It has another JSON type than §6 gives it.
    #[error("it has another JSON type than §6 gives it")]
    WrongType,
    /// It is an empty array.
    #[error("it is an empty array")]
    Empty,
    /// The entry at this position has another JSON type than §6 gives it.
    #[error("the entry at position {0} has another JSON type than §6 gives it")]
    Entry(Position),
}

/// Why a JSON value is no usable DCQL query.
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
pub enum QueryError {
    /// A member breaks the form §6 gives it.
    #[error("{code}: {member:?} {fault:?}", code = self.code())]
    Form {
        /// The member.
        member: Member,
        /// What breaks its form.
        #[source]
        fault: FormFault,
    },
    /// A credential query `id`, or one a `credential_sets` option names, breaks §6.1.
    #[error("{}", self.code())]
    Id(#[source] QueryIdError),
    /// A claims query `id`, or one a `claim_sets` option names, breaks §6.3.
    #[error("{code}: {credential}", code = self.code())]
    ClaimId {
        /// The `id` of the credential query holding it.
        credential: QueryId,
        /// Why.
        #[source]
        error: ClaimIdError,
    },
    /// `trusted_authorities` breaks §6.1.1.
    #[error("{code}: {credential}", code = self.code())]
    TrustedAuthorities {
        /// The `id` of the credential query holding it.
        credential: QueryId,
        /// Why.
        #[source]
        error: TrustedAuthorityError,
    },
    /// Two credential queries share this `id`, which §6.1 requires to "be unique across all
    /// Credential Query objects".
    #[error("{code}: {0}", code = self.code())]
    DuplicateCredentialId(QueryId),
    /// Two claims queries within one credential query share this `id`, which §6.3 requires to be
    /// unique "within the particular claims array".
    #[error("{code}: {credential}, claim id {claim}", code = self.code())]
    DuplicateClaimId {
        /// The `id` of the credential query holding the duplicate.
        credential: QueryId,
        /// The duplicated claims query `id`.
        claim: ClaimId,
    },
    /// The `path` of a claims query is no claims path pointer (§7).
    #[error("{code}: {credential}, claims[{claim}]", code = self.code())]
    ClaimPath {
        /// The `id` of the credential query holding it.
        credential: QueryId,
        /// The claims query's position.
        claim: Position,
        /// Why.
        #[source]
        error: ClaimPathError,
    },
    /// A `claim_sets` option names this id, which no claims query of the credential query has
    /// (§6.1).
    #[error("{code}: {credential}, claim id {claim}", code = self.code())]
    UnknownClaimId {
        /// The `id` of the credential query.
        credential: QueryId,
        /// The id the option names.
        claim: ClaimId,
    },
    /// The Credential Query of this `id` has `claim_sets` and no claims: "`claim_sets` MUST NOT
    /// be present if `claims` is absent" (§6.4.1).
    #[error("{code}: {0}", code = self.code())]
    ClaimSetsWithoutClaims(QueryId),
    /// A `credential_sets` option names this id, which no Credential Query has (§6.2).
    #[error("{code}: {0}", code = self.code())]
    UnknownCredentialId(QueryId),
    /// A claims query of an `mso_mdoc` Credential Query has a `path` other than a namespace and
    /// an element identifier, two strings (§7.2.1).
    #[error("{code}: {credential}, claims[{claim}]", code = self.code())]
    MdocPath {
        /// The `id` of the credential query.
        credential: QueryId,
        /// The claims query's position.
        claim: Position,
    },
}

impl QueryError {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Form { .. } => "dcql_malformed",
            Self::Id(error) => error.code(),
            Self::ClaimId { error, .. } => error.code(),
            Self::TrustedAuthorities { error, .. } => error.code(),
            Self::ClaimPath { error, .. } => error.code(),
            Self::DuplicateCredentialId(_) => "query_id_not_unique",
            Self::DuplicateClaimId { .. } => "claim_id_not_unique",
            Self::UnknownClaimId { .. } => "claim_id_unknown",
            Self::ClaimSetsWithoutClaims(_) => "claim_sets_without_claims",
            Self::UnknownCredentialId(_) => "query_id_unknown",
            Self::MdocPath { .. } => "mdoc_path_malformed",
        }
    }
}

/// Why JSON text is no usable DCQL query.
#[derive(Debug, thiserror::Error)]
pub enum QueryTextError {
    /// The text is no JSON.
    #[error("{code}: {0}", code = self.code())]
    Json(#[source] serde_json::Error),
    /// The JSON value is no usable DCQL query.
    #[error(transparent)]
    Query(QueryError),
}

impl QueryTextError {
    /// A stable identifier: `dcql_malformed` for text that is no JSON, else the query's.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Json(_) => "dcql_malformed",
            Self::Query(error) => error.code(),
        }
    }
}
