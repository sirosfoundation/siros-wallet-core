//! The rules a claims query breaks, the kit's and its format's, and the exclusion by the
//! Verifier's algorithms.

use std::borrow::Cow;

use siros_explain::{Explain, Explained};

use super::super::ClaimsError;
use crate::json::JsonError;
use crate::plugins::Exclusion;
use crate::refusal::{ErrorCode, ReprList, RequestRule};

/// A rule a claims query breaks, under its format and its id: `invalid_request`.
#[derive(Debug, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.claims_query", id = "rule")]
#[error("{format} {query}: {rule}")]
pub struct QueryRule<R: Explained> {
    /// The format identifier.
    pub format: &'static str,
    /// The query's id.
    pub query: String,
    /// The rule.
    pub rule: R,
}

impl<R: Explained> RequestRule for QueryRule<R> {
    fn code(&self) -> ErrorCode {
        ErrorCode::InvalidRequest
    }
}

/// A rule the kit applies to every claims query, or the format's rule it reports.
#[derive(Debug, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.claims_kit")]
pub enum KitRule {
    /// The query is no JSON with unique member names.
    #[error("{0}")]
    Json(#[explain(name = "cause")] JsonError),
    /// The format's rule on `meta`.
    #[error("{0}")]
    Meta(#[explain(name = "rule")] Box<dyn Explained>),
    /// The Verifier's `vp_formats_supported` value breaks the format's rule.
    #[error("vp_formats_supported is not an object of non-empty algorithm arrays")]
    VpFormats,
    /// The claims break DCQL's structure.
    #[error("{0}")]
    Claims(#[explain(name = "cause")] ClaimsError),
    /// A claims path pointer the format's credentials cannot hold.
    #[error("claims[{claim}].path {rule}")]
    Pointer {
        /// The claim's position.
        claim: usize,
        /// The format's rule.
        rule: Box<dyn Explained>,
    },
}

/// The Verifier's `vp_formats_supported` member admits no identifier the credential's
/// presentation can match.
#[derive(Debug, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.claims_kit", id = "no_algorithm")]
#[error("{member} {listed} admits no algorithm of the credential ({matched})")]
pub struct NoAlgorithm {
    /// The member.
    pub member: &'static str,
    /// The member's identifiers.
    pub listed: ReprList,
    /// The identifiers the presentation can match.
    pub matched: ReprList,
    /// The format's OpenID4VP appendix.
    #[explain(skip)]
    pub appendix: &'static str,
}

impl Exclusion for NoAlgorithm {
    fn clause(&self) -> Cow<'static, str> {
        Cow::Owned(format!("OpenID4VP {} vp_formats_supported", self.appendix))
    }
}
