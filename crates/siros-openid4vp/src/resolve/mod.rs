//! Phase 2: the response to a selection, from the request, the ids the platform returns,
//! the wallet's credentials, its configuration, the resources its caller fetches and its host's
//! modules. Each id is a record the matcher wrote. Phase 2 trusts the user's choice of records
//! alone: it derives every record itself, with the matcher's code, from the request it holds and
//! its own data, answers only records equal to its own, and falls back on any other. A record
//! commits to the request the matcher displayed, so a request that differs between the matcher
//! and phase 2 makes them differ.
//!
//! Its steps: [`Prepared::prepare`] derives and checks the records and asks for the resources
//! their profiles revalidate with; the caller fetches each of [`Prepared::questions`];
//! [`Prepared::respond`] takes the fetches and builds the response.

mod prepared;
mod response;
mod selection;

pub use prepared::Prepared;
pub use response::{
    Body, DcApiData, Delivery, FormMedia, NotObject, PostBody, Response, RouteKey, VpToken,
};

use siros_explain::{AllOf, Explain, Explained};

use crate::host::{AuthenticationNeed, Categories};
use crate::matching::RecordError;
use crate::plugins::{Fault, FindingData, ProfileFinding};
use crate::refusal::{QuotedList, Refused};

/// What phase 2 found for one record, by its position in the selection.
#[derive(Debug)]
pub enum Finding {
    /// The record is none the wallet derives from the request and its data.
    Diverged {
        /// The record's position.
        record: usize,
    },
    /// Its credential can no longer be presented.
    Unusable {
        /// The record's position.
        record: usize,
    },
    /// Its profile found that something the matcher assumed no longer holds.
    Revalidation {
        /// The record's position.
        record: usize,
        /// The profile's finding.
        finding: ProfileFinding,
    },
    /// Its format found that something phase 1 assumed of the credential and the option no
    /// longer holds.
    Format {
        /// The record's position.
        record: usize,
        /// The format's finding.
        finding: Box<dyn FindingData>,
    },
}

/// How a mode's route breaks its registration, the cause of phase 2's fault: the mode broke its
/// contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.route_breach")]
pub enum RouteBreach {
    /// A mode registered for errors alone routed an answer.
    #[error("a mode that carries errors routed an answer")]
    ErrorsAnswered,
    /// A mode in the clear chose a key.
    #[error("a mode in the clear chose a key")]
    KeyInTheClear,
    /// A JWE mode chose no key.
    #[error("a JWE mode chose no key")]
    NoKey,
    /// A JWE mode chose a key or an `enc` the sealing module does not state.
    #[error("a mode chose a key or an enc the sealing module does not state")]
    Unstated,
    /// A JWE mode chose an `enc` the Verifier does not list (§5.1, §8.3).
    #[error("a mode chose an enc the Verifier does not list")]
    Unlisted,
}

/// Why phase 2 rejects a selection: its ids are no records, or no selection the request allows.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.rejection")]
pub enum Rejection {
    /// An id that is no record.
    #[error(transparent)]
    NotARecord(#[from] RecordError),
    /// A query takes one record without `multiple`, distinct credentials with it.
    #[error("{query}: {records} records, {credentials} credentials")]
    QueryRecords {
        /// The query.
        query: String,
        /// Its records.
        records: usize,
        /// Their distinct credentials.
        credentials: usize,
    },
    /// Two records carry transactions.
    #[error("two records carry transactions; one confirmation carries one")]
    TwoTransactions,
    /// The queries presented are none of the request's alternatives.
    #[error("the queries {} are none of the request's alternatives", QuotedList(.0))]
    NoAlternative(#[explain(skip)] Vec<String>),
}

/// Why phase 2 answers nothing.
#[derive(Debug, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.outcome")]
pub enum Outcome {
    /// The request breaks a rule.
    #[error(transparent)]
    Refused(#[from] Refused),
    /// The ids are no records, or no selection the request allows.
    #[error(transparent)]
    Rejected(#[from] Rejection),
    /// A record is none the wallet derives, or something the matcher assumed no longer holds. The
    /// wallet re-runs the consent from the request it holds, the credentials that cannot be
    /// presented left out. The re-run and the phase 2 that follows use the registry
    /// [informed](crate::plugins::Registry::informed) of the findings. The user confirms again in
    /// the wallet's own UI.
    #[error("{} finding(s) make phase 2 fall back", .0.items().len())]
    Fallback(#[explain(skip)] AllOf<Finding>),
    /// The wallet failed to authenticate the End-User (OpenID4VP §8.5 `access_denied`).
    #[error("the Wallet failed to authenticate the End-User")]
    UserUnauthenticated,
    /// The End-User's authentication covers fewer PSD2 categories than a record's profile needs
    /// (CS-12 §5 item 4; TS12 §3.6).
    #[error(
        "the End-User's authentication covers {covered} PSD2 categories, and a {need} need asks for more"
    )]
    AuthenticationTooWeak {
        /// The strongest need of the records' profiles.
        need: AuthenticationNeed,
        /// The categories the factors cover.
        covered: Categories,
    },
    /// A format made no presentation: a step failed without a bug, such as a cancelled key
    /// prompt (OpenID4VP §8.5 `access_denied`).
    #[error("the presentation failed: {0}")]
    NotPresented(#[explain(name = "reason")] Box<dyn Explained>),
    /// A plug-in failed.
    #[error(transparent)]
    Fault(#[from] Fault),
}
