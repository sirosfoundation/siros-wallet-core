//! The rules a request's parsing applies: its parameters' structure and presence, DCQL's
//! structure (§6) and rule C0 on each `transaction_data` entry.

use siros_explain::Explain;

use super::EntryIndex;
use super::entry::Malformed;
use super::sets::MAX_POSITIONS;
use crate::json::JsonError;
use crate::refusal::{ErrorCode, RequestRule};

/// A rule on the request parameters' structure (OpenID4VP 1.0 §5, Annex A).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
pub enum StructureRule {
    /// `dcql_query` is absent.
    #[error("dcql_query is absent")]
    #[explain(id = "structure.dcql_absent")]
    DcqlAbsent,
    /// `nonce` is absent or empty.
    #[error("nonce is not a non-empty string")]
    #[explain(id = "structure.nonce")]
    Nonce,
    /// `expected_origins` is no array of strings.
    #[error("expected_origins is not an array of strings")]
    #[explain(id = "structure.expected_origins")]
    ExpectedOrigins,
    /// `transaction_data` is no non-empty array of strings.
    #[error("transaction_data is not a non-empty array of strings")]
    #[explain(id = "structure.transaction_data")]
    TransactionData,
}

impl RequestRule for StructureRule {
    fn code(&self) -> ErrorCode {
        ErrorCode::INVALID_REQUEST
    }
}

/// A rule on a parameter's presence or form, beside its structure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
pub enum ParameterRule {
    /// S3: a `scope` value by URI that names no registered scope query (§5.5, §8.5).
    #[error("S3 scope value {scope} names no DCQL query the wallet registers")]
    #[explain(id = "parameters.s3")]
    Scope {
        /// The scope value.
        scope: String,
    },
    /// S4: `dcql_query` beside a `scope` naming a query (§5.1: "but not both").
    #[error("S4 dcql_query and a scope naming a DCQL query are both present")]
    #[explain(id = "parameters.s4")]
    ScopeAndQuery,
    /// N1: `nonce` not URL-safe ASCII (§5.2).
    #[error("N1 nonce is not URL-safe ASCII")]
    #[explain(id = "parameters.n1")]
    Nonce,
    /// P7: a URI request with a query waiving holder binding and no `state` (§5.3).
    #[error("P7 a query waives holder binding and state is absent")]
    #[explain(id = "parameters.p7")]
    StateRequired,
}

impl RequestRule for ParameterRule {
    fn code(&self) -> ErrorCode {
        match self {
            Self::Scope { .. } => ErrorCode::INVALID_SCOPE,
            Self::ScopeAndQuery | Self::Nonce | Self::StateRequired => ErrorCode::INVALID_REQUEST,
        }
    }
}

/// Rule C0: a `transaction_data` entry that does not decode.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(id = "rules.c0")]
#[error("C0 entry {entry}: {malformed}")]
pub struct UndecodedEntry {
    /// The entry's position.
    pub entry: EntryIndex,
    /// Why it does not decode.
    #[source]
    pub malformed: Malformed,
}

impl RequestRule for UndecodedEntry {
    fn code(&self) -> ErrorCode {
        ErrorCode::INVALID_TRANSACTION_DATA
    }
}

/// A rule of DCQL's structure (§6) that `dcql_query` breaks.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
pub enum DcqlRule {
    /// `dcql_query` is no JSON object with unique member names.
    #[error("dcql_query: not a JSON object: {0}")]
    #[explain(id = "dcql.not_object")]
    NotObject(#[source] JsonError),
    /// `credentials` is no non-empty array.
    #[error("dcql_query: credentials is not a non-empty array")]
    #[explain(id = "dcql.credentials")]
    Credentials,
    /// More Credential Queries than the wallet's positions.
    #[error("dcql_query: more than {} Credential Queries", MAX_POSITIONS)]
    #[explain(id = "dcql.too_many")]
    TooMany,
    /// Two Credential Queries share an id.
    #[error("dcql_query: the id {id} names two Credential Queries")]
    #[explain(id = "dcql.id_twice")]
    IdTwice {
        /// The id.
        id: String,
    },
    /// A Credential Query is no JSON object with unique member names.
    #[error("dcql_query: a Credential Query is not a JSON object: {0}")]
    #[explain(id = "dcql.query_not_object")]
    QueryNotObject(#[source] JsonError),
    /// A Credential Query's id breaks its rule.
    #[error(
        "dcql_query: a Credential Query id is not a non-empty string of letters, digits, _ and -"
    )]
    #[explain(id = "dcql.query_id")]
    QueryId,
    /// A Credential Query's `format` is absent or empty.
    #[error("dcql_query: {query}: format is not a non-empty string")]
    #[explain(id = "dcql.format")]
    Format {
        /// The query's id.
        query: String,
    },
    /// A Credential Query's flag is no boolean.
    #[error("dcql_query: {query}: {name} is not a boolean")]
    #[explain(id = "dcql.flag")]
    Flag {
        /// The query's id.
        query: String,
        /// The flag.
        name: &'static str,
    },
    /// A Credential Query's `trusted_authorities` breaks §6.1.1.
    #[error(
        "dcql_query: {query}: trusted_authorities is not a non-empty array of type and non-empty values"
    )]
    #[explain(id = "dcql.trusted_authorities")]
    TrustedAuthorities {
        /// The query's id.
        query: String,
    },
    /// `credential_sets` is no non-empty array.
    #[error("dcql_query: credential_sets is not a non-empty array")]
    #[explain(id = "dcql.sets")]
    Sets,
    /// A Credential Set breaks §6.2.
    #[error("dcql_query: a Credential Set is not an object of non-empty options of query ids")]
    #[explain(id = "dcql.set")]
    Set,
    /// A Credential Set names an id no Credential Query has.
    #[error("dcql_query: a Credential Set names {id}, which no Credential Query has")]
    #[explain(id = "dcql.set_query")]
    SetQuery {
        /// The id.
        id: String,
    },
}

impl RequestRule for DcqlRule {
    fn code(&self) -> ErrorCode {
        ErrorCode::INVALID_REQUEST
    }
}
