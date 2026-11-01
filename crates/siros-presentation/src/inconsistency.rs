//! How a plan or an offer contradicts the matching it was built from.

use siros_transaction_data::EntryPosition;

use crate::ids::{CandidateIndex, QueryIndex};

/// A position an offer or a binding names that the matching or the transactions it came from
/// lack: a bug of the core, with no outside input behind it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}", self.code())]
pub enum Inconsistency {
    /// A member names a query the matching lacks.
    Query(QueryIndex),
    /// A member names a candidate its query lacks.
    Candidate(QueryIndex, CandidateIndex),
    /// A candidate takes an entry the transactions lack.
    Entry(EntryPosition),
    /// A proof answers a query without a nym_auth query.
    ZkpQuery(QueryIndex),
    /// A proof answers a request the nym_auth policy refuses.
    NymAuthRequest,
}

impl Inconsistency {
    /// A stable identifier.
    pub fn code(self) -> &'static str {
        match self {
            Self::Query(_) => "plan_query_unknown",
            Self::Candidate(..) => "plan_candidate_unknown",
            Self::Entry(_) => "plan_entry_unknown",
            Self::ZkpQuery(_) => "plan_zkp_query_missing",
            Self::NymAuthRequest => "plan_nym_auth_request_refused",
        }
    }
}
