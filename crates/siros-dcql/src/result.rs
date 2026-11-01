//! What evaluating a query gives (§6.4): the candidates of each Credential Query, and whether
//! the request can be satisfied.

use crate::id::{ClaimId, QueryId};
use crate::meta::CredentialRef;
use crate::path::{ClaimPath, PathError};
use crate::query::{CredentialSetQuery, Multiplicity};

/// A claim the wallet would disclose for a match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedClaim {
    claim_id: Option<ClaimId>,
    path: ClaimPath,
}

/// One credential that satisfies one credential query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    credential_id: CredentialRef,
    claims: Vec<SelectedClaim>,
}

/// A credential whose claims path processing gives an error (§7.1.1, §7.2.1), and the error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("claims path processing of credential {credential_id} gives an error (§7.1.1, §7.2.1)")]
pub struct ClaimPathRefusal {
    credential_id: CredentialRef,
    #[source]
    error: PathError,
}

/// The candidates for one credential query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryMatch {
    query_id: QueryId,
    candidates: Vec<Candidate>,
    refusals: Vec<ClaimPathRefusal>,
    multiple: Multiplicity,
}

/// Whether the wallet can satisfy a request at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Satisfaction {
    /// Every required credential set, or every query without sets, has a candidate.
    Satisfiable,
    /// The wallet "MUST NOT return any Credential(s)" (§6.4): the part that matched is
    /// withheld too.
    Unsatisfiable,
}

/// The outcome of evaluating a query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryResult {
    matches: Vec<QueryMatch>,
    satisfaction: Satisfaction,
    credential_sets: Option<Vec<CredentialSetQuery>>,
}

impl SelectedClaim {
    pub(crate) fn new(claim_id: Option<ClaimId>, path: ClaimPath) -> Self {
        Self { claim_id, path }
    }

    /// `id` of the claims query this satisfies, when it had one.
    #[must_use]
    pub fn claim_id(&self) -> Option<&ClaimId> {
        self.claim_id.as_ref()
    }

    /// The path that selected it.
    #[must_use]
    pub fn path(&self) -> &ClaimPath {
        &self.path
    }

    /// The path that selected it, taken.
    #[must_use]
    pub fn into_path(self) -> ClaimPath {
        self.path
    }
}

impl ClaimPathRefusal {
    pub(crate) fn new(credential_id: CredentialRef, error: PathError) -> Self {
        Self {
            credential_id,
            error,
        }
    }

    /// The credential's own identifier.
    #[must_use]
    pub fn credential_id(&self) -> &CredentialRef {
        &self.credential_id
    }

    /// The error of its claims path processing.
    #[must_use]
    pub fn error(&self) -> &PathError {
        &self.error
    }
}

impl Candidate {
    pub(crate) fn new(credential_id: CredentialRef, claims: Vec<SelectedClaim>) -> Self {
        Self {
            credential_id,
            claims,
        }
    }

    /// The credential's own identifier.
    #[must_use]
    pub fn credential_id(&self) -> &CredentialRef {
        &self.credential_id
    }

    /// Claims to disclose — exactly these, and no others (§6.4).
    #[must_use]
    pub fn claims(&self) -> &[SelectedClaim] {
        &self.claims
    }
}

impl QueryMatch {
    pub(crate) fn new(
        query_id: QueryId,
        multiple: Multiplicity,
        candidates: Vec<Candidate>,
        refusals: Vec<ClaimPathRefusal>,
    ) -> Self {
        Self {
            query_id,
            candidates,
            refusals,
            multiple,
        }
    }

    /// The credential query's `id`.
    #[must_use]
    pub fn query_id(&self) -> &QueryId {
        &self.query_id
    }

    /// Credentials that satisfy it, in the order the wallet holds them.
    #[must_use]
    pub fn candidates(&self) -> &[Candidate] {
        &self.candidates
    }

    /// The credentials the policy admits whose claims path processing gives an error, in the
    /// order the wallet holds them. None of them is a candidate.
    #[must_use]
    pub fn refusals(&self) -> &[ClaimPathRefusal] {
        &self.refusals
    }

    /// Whether the query accepts more than one credential (§6.1 `multiple`), for enumerating
    /// combinations without the query.
    #[must_use]
    pub fn multiplicity(&self) -> Multiplicity {
        self.multiple
    }

    /// Whether any credential satisfies this query.
    #[must_use]
    pub fn is_satisfied(&self) -> bool {
        !self.candidates.is_empty()
    }
}

impl Satisfaction {
    pub(crate) fn of(satisfiable: bool) -> Self {
        if satisfiable {
            Self::Satisfiable
        } else {
            Self::Unsatisfiable
        }
    }
}

impl QueryResult {
    pub(crate) fn new(
        matches: Vec<QueryMatch>,
        satisfaction: Satisfaction,
        credential_sets: Option<Vec<CredentialSetQuery>>,
    ) -> Self {
        Self {
            matches,
            satisfaction,
            credential_sets,
        }
    }

    /// Per-credential-query candidates, in query order.
    #[must_use]
    pub fn matches(&self) -> &[QueryMatch] {
        &self.matches
    }

    /// Whether the wallet can satisfy the request at all.
    #[must_use]
    pub fn satisfaction(&self) -> Satisfaction {
        self.satisfaction
    }

    /// The request's credential sets, kept so combinations can be enumerated without the query
    /// alongside its own result.
    #[must_use]
    pub fn credential_sets(&self) -> Option<&[CredentialSetQuery]> {
        self.credential_sets.as_deref()
    }

    /// The candidates for a given query id.
    #[must_use]
    pub fn query(&self, id: &str) -> Option<&QueryMatch> {
        self.matches.iter().find(|m| m.query_id == *id)
    }
}
