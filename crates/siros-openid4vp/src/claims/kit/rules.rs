//! The rules a claims query breaks, the kit's and its format's, and the exclusion by the
//! Verifier's algorithms.

use std::borrow::Cow;
use std::fmt;

use siros_explain::{Explain, Explained, IntoArg, kind};

use super::super::{ClaimsError, PathError};
use crate::ids::{FormatName, QueryId};
use crate::json::JsonError;
use crate::plugins::Exclusion;
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

/// A member is named by its text in a message.
impl IntoArg for VpFormatsMember {
    type Kind = kind::Name;

    fn arg(&self) -> &'static str {
        self.0
    }
}

/// A rule a claims query breaks, under its format and its id: `invalid_request`.
#[derive(Debug, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.claims_query", id = "rule")]
#[error("{format} {query}: {rule}")]
pub struct QueryRule<R: Explained> {
    /// The format identifier.
    pub format: FormatName,
    /// The query's id.
    pub query: QueryId<'static>,
    /// The rule.
    pub rule: R,
}

impl<R: Explained> RequestRule for QueryRule<R> {
    fn code(&self) -> ErrorCode {
        ErrorCode::INVALID_REQUEST
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

/// Why a credential's view shows no card.
#[derive(Debug, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.claims_kit")]
pub enum CardError {
    /// A claim's pointer selects nothing the values hold.
    #[error("{0}")]
    Path(#[explain(name = "cause")] PathError),
    /// A metadata text, or a member name that stands in for one, breaks the rule of display text.
    #[error("{0}")]
    Text(#[explain(name = "cause")] TextError),
}

/// A credential's metadata text, or a member name that stands in for one, breaks the rule of
/// display text: the End-User is not offered the credential.
#[derive(Debug, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.claims_kit", id = "refused_text")]
#[error("a text of the credential: {cause}")]
pub struct RefusedText {
    /// The rule the text breaks.
    pub cause: TextError,
}

impl Exclusion for RefusedText {
    fn clause(&self) -> Cow<'static, str> {
        Cow::Borrowed("the rule of display text")
    }
}

/// The Verifier's `vp_formats_supported` member admits no identifier the credential's
/// presentation can match.
#[derive(Debug, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.claims_kit", id = "no_algorithm")]
#[error("{member} {listed} admits no algorithm of the credential ({matched})")]
pub struct NoAlgorithm {
    /// The member.
    pub member: VpFormatsMember,
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
