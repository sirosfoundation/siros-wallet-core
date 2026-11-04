//! The rules a request's parsing applies: its parameters' structure and presence, DCQL's
//! structure (§6) and rule C0 on each `transaction_data` entry.

use siros_explain::Explain;

use super::entry::Malformed;
use super::sets::MAX_POSITIONS;
use crate::json::JsonError;
use crate::refusal::{ErrorCode, RequestRule};

/// A rule on the request parameters' structure (OpenID4VP 1.0 §5, Annex A).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.structure")]
pub enum StructureRule {
    /// `dcql_query` is absent.
    #[error("dcql_query is absent")]
    DcqlAbsent,
    /// `nonce` is absent or empty.
    #[error("nonce is not a non-empty string")]
    Nonce,
    /// `expected_origins` is no array of strings.
    #[error("expected_origins is not an array of strings")]
    ExpectedOrigins,
    /// `transaction_data` is no non-empty array of strings.
    #[error("transaction_data is not a non-empty array of strings")]
    TransactionData,
}

impl RequestRule for StructureRule {
    fn code(&self) -> ErrorCode {
        ErrorCode::INVALID_REQUEST
    }
}

/// A rule on a parameter's presence or form, beside its structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.parameters")]
pub enum ParameterRule {
    /// S3: `scope` in a URI request; the wallet maps no scope value to a DCQL query (§5.5,
    /// reading 12).
    #[error("S3 scope is present; the wallet maps no scope value to a DCQL query")]
    #[explain(id = "s3")]
    Scope,
    /// N1: `nonce` not URL-safe ASCII (§5.2).
    #[error("N1 nonce is not URL-safe ASCII")]
    #[explain(id = "n1")]
    Nonce,
    /// P7: a URI request with a query waiving holder binding and no `state` (§5.3).
    #[error("P7 a query waives holder binding and state is absent")]
    #[explain(id = "p7")]
    StateRequired,
}

impl RequestRule for ParameterRule {
    fn code(&self) -> ErrorCode {
        match self {
            Self::Scope => ErrorCode::INVALID_SCOPE,
            Self::Nonce | Self::StateRequired => ErrorCode::INVALID_REQUEST,
        }
    }
}

/// Rule C0: a `transaction_data` entry that does not decode.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.rules", id = "c0")]
#[error("C0 entry {entry}: {malformed}")]
pub struct UndecodedEntry {
    /// The entry's position.
    pub entry: usize,
    /// Why it does not decode.
    pub malformed: Malformed,
}

impl RequestRule for UndecodedEntry {
    fn code(&self) -> ErrorCode {
        ErrorCode::INVALID_TRANSACTION_DATA
    }
}

/// A rule of DCQL's structure (§6) that `dcql_query` breaks.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.dcql")]
pub enum DcqlRule {
    /// `dcql_query` is no JSON object with unique member names.
    #[error("dcql_query: not a JSON object: {0}")]
    NotObject(#[explain(name = "cause")] JsonError),
    /// `credentials` is no non-empty array.
    #[error("dcql_query: credentials is not a non-empty array")]
    Credentials,
    /// More Credential Queries than the wallet's positions.
    #[error("dcql_query: more than {} Credential Queries", MAX_POSITIONS)]
    TooMany,
    /// Two Credential Queries share an id.
    #[error("dcql_query: the id {id} names two Credential Queries")]
    IdTwice {
        /// The id.
        id: String,
    },
    /// A Credential Query is no JSON object with unique member names.
    #[error("dcql_query: a Credential Query is not a JSON object: {0}")]
    QueryNotObject(#[explain(name = "cause")] JsonError),
    /// A Credential Query's id breaks its rule.
    #[error(
        "dcql_query: a Credential Query id is not a non-empty string of letters, digits, _ and -"
    )]
    QueryId,
    /// A Credential Query's `format` is absent or empty.
    #[error("dcql_query: {query}: format is not a non-empty string")]
    Format {
        /// The query's id.
        query: String,
    },
    /// A Credential Query's flag is no boolean.
    #[error("dcql_query: {query}: {name} is not a boolean")]
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
    TrustedAuthorities {
        /// The query's id.
        query: String,
    },
    /// `credential_sets` is no non-empty array.
    #[error("dcql_query: credential_sets is not a non-empty array")]
    Sets,
    /// A Credential Set breaks §6.2.
    #[error("dcql_query: a Credential Set is not an object of non-empty options of query ids")]
    Set,
    /// A Credential Set names an id no Credential Query has.
    #[error("dcql_query: a Credential Set names {id}, which no Credential Query has")]
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
