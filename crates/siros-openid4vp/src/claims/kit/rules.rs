//! The rules a claims query breaks, the kit's and its format's, and the exclusion by the
//! Verifier's algorithms.

use std::fmt;

use siros_explain::Explain;
use siros_i18n::ResolveError;
use siros_syntax::Malformed;

use super::super::{ClaimsError, PathError};
use crate::ids::{FormatName, QueryId};
use crate::json::JsonError;
use crate::plugins::{Clause, Exclusion};
use crate::refusal::{ErrorCode, ReprList, RequestRule};
use crate::text::TextError;

/// A member of a format's `vp_formats_supported` value that lists algorithm identifiers
/// (Appendix B).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VpFormatsMember(&'static str);

impl VpFormatsMember {
    /// The member of this name.
    #[must_use]
    pub const fn new(name: &'static str) -> Self {
        Self(name)
    }

    /// The name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for VpFormatsMember {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// A rule a claims query breaks, under its format and its id: `invalid_request`.
#[derive(Debug, thiserror::Error, Explain)]
#[explain(id = "claims_query.rule")]
#[error("{format} {query}: {rule}")]
pub struct QueryRule<R: Explain> {
    /// The format identifier.
    pub format: FormatName,
    /// The query's id.
    pub query: QueryId<'static>,
    /// The rule.
    #[source]
    pub rule: R,
}

impl<R: Explain> RequestRule for QueryRule<R> {
    fn code(&self) -> ErrorCode {
        ErrorCode::INVALID_REQUEST
    }
}

/// A rule the kit applies to every claims query, or the format's rule it reports.
#[derive(Debug, thiserror::Error, Explain)]
pub enum KitRule {
    /// The query is no JSON with unique member names.
    #[error("{0}")]
    #[explain(id = "claims_kit.json")]
    Json(#[source] JsonError),
    /// The format's rule on `meta`.
    #[error("{0}")]
    #[explain(id = "claims_kit.meta")]
    Meta(#[source] Box<dyn Explain>),
    /// The Verifier's `vp_formats_supported` value breaks the format's rule.
    #[error("vp_formats_supported is not an object of non-empty algorithm arrays")]
    #[explain(id = "claims_kit.vp_formats")]
    VpFormats,
    /// The claims break DCQL's structure.
    #[error("{0}")]
    #[explain(id = "claims_kit.claims")]
    Claims(#[source] ClaimsError),
    /// A claims path pointer the format's credentials cannot hold.
    #[error("claims[{claim}].path {rule}")]
    #[explain(id = "claims_kit.pointer")]
    Pointer {
        /// The claim's position.
        claim: usize,
        /// The format's rule.
        #[source]
        rule: Box<dyn Explain>,
    },
}

/// Why a credential's view shows no card.
#[derive(Debug, thiserror::Error, Explain)]
pub enum CardError {
    /// A claim's pointer selects nothing the values hold.
    #[error("{0}")]
    #[explain(id = "claims_kit.path")]
    Path(#[source] PathError),
    /// A metadata text, or a member name that stands in for one, breaks the rule of display text.
    #[error("{0}")]
    #[explain(id = "claims_kit.text")]
    Text(#[source] TextError),
    /// A count of the view, a byte string's length or a claim's natural number, is no count
    /// literal.
    #[error("{0}")]
    #[explain(id = "claims_kit.count")]
    Count(#[source] Malformed),
}

/// Why the kit draws no card.
#[derive(Debug, thiserror::Error, Explain)]
pub enum DrawError {
    /// The view shows no card.
    #[error(transparent)]
    Card(#[from] CardError),
    /// The context words no text for a statement of the card.
    #[error("a text of the card: {0}")]
    #[explain(id = "claims_kit.unworded")]
    Unworded(#[from] ResolveError),
}

/// A credential's metadata text, or a member name that stands in for one, breaks the rule of
/// display text: the End-User is not offered the credential.
#[derive(Debug, thiserror::Error, Explain)]
#[explain(id = "claims_kit.refused_text")]
#[error("a text of the credential: {cause}")]
pub struct RefusedText {
    /// The rule the text breaks.
    #[source]
    pub cause: TextError,
}

impl Exclusion for RefusedText {
    fn clause(&self) -> Clause {
        Clause::cited("the rule of display text")
    }
}

/// The Verifier's `vp_formats_supported` member admits no identifier the credential's
/// presentation can match.
#[derive(Debug, thiserror::Error, Explain)]
#[explain(id = "claims_kit.no_algorithm")]
#[error(
    "{member} {} admits no algorithm of the credential ({})",
    .listed.repr_text(),
    .matched.repr_text()
)]
pub struct NoAlgorithm {
    /// The member.
    pub member: VpFormatsMember,
    /// The member's identifiers.
    pub listed: ReprList,
    /// The identifiers the presentation can match.
    pub matched: ReprList,
    /// The clause of the format's `vp_formats_supported`.
    #[explain(skip)]
    pub clause: Clause,
}

impl Exclusion for NoAlgorithm {
    fn clause(&self) -> Clause {
        self.clause
    }
}
