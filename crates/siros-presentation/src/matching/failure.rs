//! Why a request cannot be matched, why a Credential Query has no candidate, and why a request
//! has no offer.

use siros_dcql::QueryId;
use siros_trust::AuthorityError;
use siros_zkp_req::ErrorCode;

use super::{Answered, Exclusion, ZkpRefusal};
use crate::credential::MatchCredential;

/// Why a Credential Query has no candidate whatever the wallet holds.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum QueryRefusal {
    /// `trusted_authorities` holds an `aki` value that encodes no keyIdentifier (TR3).
    Authorities(#[source] AuthorityError),
    /// The `zkp_req` query is refused.
    Zkp(#[source] ZkpRefusal),
}

impl QueryRefusal {
    /// A stable identifier.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Authorities(error) => error.code(),
            Self::Zkp(refusal) => refusal.code(),
        }
    }

    /// The `zkp_req.md`, Section 5 code: `invalid_request` for `trusted_authorities`.
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::Authorities(_) => ErrorCode::InvalidRequest,
            Self::Zkp(refusal) => refusal.error_code(),
        }
    }
}

/// Why a request has no offer. `U` is why a query's authorities refuse an issuer, `R` why a
/// `zkp_req` candidate answers no option.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum Failure<U, R> {
    /// A Credential Query is refused.
    Refused {
        /// The query.
        query: QueryId,
        /// Why.
        #[source]
        refusal: QueryRefusal,
    },
    /// Credentials of a query's format and type exist, and the query excludes each.
    Excluded {
        /// The query.
        query: QueryId,
        /// Why it excludes each credential.
        reasons: Vec<Exclusion<U, R>>,
    },
    /// No combination of the candidates satisfies the request.
    Unsatisfied,
}

impl<U, R> Failure<U, R> {
    /// A stable identifier: the refusal's code, `excluded` or `unsatisfied`.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Refused { refusal, .. } => refusal.code(),
            Self::Excluded { .. } => "excluded",
            Self::Unsatisfied => "unsatisfied",
        }
    }

    /// The `zkp_req.md`, Section 5 code: the refusal's, else `access_denied`.
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::Refused { refusal, .. } => refusal.error_code(),
            Self::Excluded { .. } | Self::Unsatisfied => ErrorCode::AccessDenied,
        }
    }
}

impl<C: MatchCredential, R: Clone> Answered<'_, C, R> {
    /// The refusal of the first Credential Query that makes the request invalid
    /// (`invalid_request`, `zkp_req.md`, Section 5). One invalid Credential Query refuses the
    /// whole request, whatever the other queries answer.
    pub fn invalid_request(&self) -> Option<Failure<C::Unadmitted, R>> {
        self.queries.iter().find_map(|answers| {
            let refusal = answers
                .refusal()
                .filter(|refusal| refusal.error_code() == ErrorCode::InvalidRequest)?;
            Some(Failure::Refused {
                query: answers.id().clone(),
                refusal: refusal.clone(),
            })
        })
    }

    /// Why the request has no offer (`zkp_req.md`, Section 5): the first refused query whose
    /// code comes first of `invalid_request` and `vp_formats_not_supported`; else the first
    /// query with no candidate that excludes credentials; else no combination.
    pub fn failure(&self) -> Failure<C::Unadmitted, R> {
        let refused = self
            .queries
            .iter()
            .filter_map(|answers| Some((answers.id(), answers.refusal()?)))
            .min_by_key(|(_, refusal)| precedence(refusal.error_code()));
        if let Some((query, refusal)) = refused {
            return Failure::Refused {
                query: query.clone(),
                refusal: refusal.clone(),
            };
        }
        let excluding = self
            .queries
            .iter()
            .find(|answers| answers.candidates().is_empty() && !answers.excluded().is_empty());
        match excluding {
            Some(answers) => Failure::Excluded {
                query: answers.id().clone(),
                reasons: answers
                    .excluded()
                    .iter()
                    .map(|excluded| excluded.reason().clone())
                    .collect(),
            },
            None => Failure::Unsatisfied,
        }
    }
}

/// The order of the codes of Section 5: `invalid_request` first.
fn precedence(code: ErrorCode) -> u8 {
    match code {
        ErrorCode::InvalidRequest => 0,
        ErrorCode::VpFormatsNotSupported => 1,
        ErrorCode::AccessDenied => 2,
    }
}
