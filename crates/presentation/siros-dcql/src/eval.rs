//! Selecting claims and credentials — OpenID4VP 1.0 §6.4.
//!
//! Two rules here change what a wallet offers:
//!
//! - "If the Wallet cannot deliver all claims requested by the Verifier according to these
//!   rules, it MUST NOT return the respective Credential" (§6.4.1). A credential that lacks a
//!   requested claim answers nothing.
//! - "If `credential_sets` is not provided, the Verifier requests presentations for all
//!   Credentials in `credentials`" (§6.4). Absent means *every* query must be satisfied.

use serde_json::Value;

use crate::meta::{CredentialFormat, CredentialRef};
use crate::path::{ClaimPath, PathError};
use crate::query::{
    ClaimRequest, ClaimsQuery, CredentialQuery, DcqlQuery, HolderBinding, SetRequirement,
};
use crate::result::{
    Candidate, ClaimPathRefusal, QueryMatch, QueryResult, Satisfaction, SelectedClaim,
};

/// A credential the wallet holds, as far as DCQL is concerned.
pub trait Credential {
    /// Stable identifier, echoed back in match results.
    fn id(&self) -> &CredentialRef;
    /// Storage format, e.g. `mso_mdoc`.
    fn format(&self) -> &CredentialFormat;
    /// The values `path` selects in this credential (§7).
    ///
    /// # Errors
    ///
    /// [`PathError`] as the processing rules of this credential's format give it.
    /// [`PathError::Empty`], the credential lacking the claim, is the ordinary case.
    fn claim(&self, path: &ClaimPath) -> Result<Vec<Value>, PathError>;

    /// Whether this credential is cryptographically bound to its holder.
    ///
    /// Answers §6.1's `require_cryptographic_holder_binding`, whose default is `true`: a
    /// verifier that says nothing still means "bound". A query that requires binding never
    /// receives a credential that answers [`CryptographicBinding::Unbound`].
    ///
    /// Each implementor answers it: a blanket answer would assert a security property on behalf
    /// of credentials whose implementor never considered the question.
    fn binding(&self) -> CryptographicBinding;
}

/// Whether a credential is cryptographically bound to its holder (§6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CryptographicBinding {
    /// A presentation can prove possession of the credential's key.
    Bound,
    /// The credential is bound to no key.
    Unbound,
}

/// Format and metadata matching, which DCQL leaves format-specific.
///
/// §6.1 defines `meta` as "an object defining additional properties ... defined per
/// Credential Format", which only a format-aware policy interprets. Anything a deployment
/// layers on top, such as a format another stored format satisfies, or a capability the wallet
/// must have, belongs here too.
pub trait Policy<C: Credential + ?Sized> {
    /// Whether this credential can satisfy this query's format, metadata and
    /// any deployment-specific constraints. Claims are checked separately.
    fn matches(&self, query: &CredentialQuery, credential: &C) -> bool;
}

/// Format equality and nothing else.
///
/// Enough to use the crate standalone, and the default for a caller with no `meta` conventions
/// of its own. A deployment's own [`Policy`] reads `doctype_value` and `vct_values`.
#[derive(Debug, Clone, Copy, Default)]
pub struct ExactFormat;

impl<C: Credential + ?Sized> Policy<C> for ExactFormat {
    fn matches(&self, query: &CredentialQuery, credential: &C) -> bool {
        *query.format() == *credential.format()
    }
}

/// Evaluate a DCQL query against the credentials a wallet holds.
///
/// `policy` decides format and metadata matching; this function owns the claim selection and
/// set logic the spec defines generically. A credential whose claims path processing gives an
/// error (§7.1.1, §7.2.1) answers nothing, and its [`QueryMatch::refusals`] say why.
pub fn execute<C: Credential>(
    query: &DcqlQuery,
    credentials: &[C],
    policy: &impl Policy<C>,
) -> QueryResult {
    let matches: Vec<QueryMatch> = query
        .credentials()
        .iter()
        .map(|cq| {
            let (candidates, refusals) = candidates(cq, credentials, policy);
            QueryMatch::new(cq.id().clone(), cq.multiplicity(), candidates, refusals)
        })
        .collect();
    let satisfaction = Satisfaction::of(satisfiable(query, &matches));
    QueryResult::new(
        matches,
        satisfaction,
        query.credential_sets().map(<[_]>::to_vec),
    )
}

/// The credentials of `credentials` that answer `cq`, each with the claims it discloses, and
/// those whose claims path processing gives an error.
fn candidates<C: Credential>(
    cq: &CredentialQuery,
    credentials: &[C],
    policy: &impl Policy<C>,
) -> (Vec<Candidate>, Vec<ClaimPathRefusal>) {
    let mut candidates = Vec::new();
    let mut refusals = Vec::new();
    // §6.1 `require_cryptographic_holder_binding`, default true, before the policy and the
    // claims: an unbound credential is disqualified for a query that requires binding.
    let eligible = credentials
        .iter()
        .filter(|c| {
            cq.holder_binding() == HolderBinding::Optional
                || c.binding() == CryptographicBinding::Bound
        })
        .filter(|c| policy.matches(cq, *c));
    for credential in eligible {
        match select_claims(cq, credential) {
            Ok(Some(claims)) => candidates.push(Candidate::new(credential.id().clone(), claims)),
            Ok(None) => {}
            Err(error) => refusals.push(ClaimPathRefusal::new(credential.id().clone(), error)),
        }
    }
    (candidates, refusals)
}

/// Whether the wallet can satisfy `query` with `matches`.
fn satisfiable(query: &DcqlQuery, matches: &[QueryMatch]) -> bool {
    let required_sets_met = match query.credential_sets() {
        // "If `credential_sets` is not provided, the Verifier requests presentations for all
        // Credentials in `credentials`" (§6.4): every query must be satisfied.
        None => matches.iter().all(QueryMatch::is_satisfied),
        // Otherwise every required set must have at least one satisfiable option; optional
        // sets impose nothing.
        Some(sets) => sets
            .iter()
            .filter(|s| s.requirement() == SetRequirement::Required)
            .all(|set| {
                set.options().iter().any(|option| {
                    option.iter().all(|id| {
                        matches
                            .iter()
                            .any(|m| m.query_id() == id && m.is_satisfied())
                    })
                })
            }),
    };
    // A request whose sets are all optional passes the check above with nothing matched,
    // because "all required sets are satisfied" is vacuously true. Conformant, and useless in a
    // picker: the wallet would be offered to the user with no credential behind it.
    let anything_to_offer = matches.iter().any(QueryMatch::is_satisfied);
    required_sets_met && anything_to_offer
}

/// Which claims `credential` discloses for `query` (§6.4.1); `None` when it lacks one.
///
/// The three cases are the spec's, in its order:
///
/// - `claims` absent: no selectively disclosable claims are requested.
/// - `claims` present, `claim_sets` absent: all of them are requested, and every one must
///   resolve.
/// - both present: the first option the credential satisfies wins, because "The order of the
///   options ... expresses the Verifier's preference".
///
/// # Errors
///
/// [`PathError`]: the processing of a claims path gives an error other than an empty
/// selection (§7.1.1, §7.2.1). With `claim_sets`, the first such error, when no option is
/// satisfied.
pub fn select_claims<C: Credential + ?Sized>(
    query: &CredentialQuery,
    credential: &C,
) -> Result<Option<Vec<SelectedClaim>>, PathError> {
    match query.claim_request() {
        // Mandatory-to-present claims are the format's business.
        ClaimRequest::Nothing => Ok(Some(Vec::new())),
        // Any one claim missing disqualifies the whole credential: "MUST NOT return the
        // respective Credential" (§6.4.1).
        ClaimRequest::All(claims) => every(claims.iter(), credential),
        ClaimRequest::Sets { options, .. } => {
            let mut first_error = None;
            for option in options {
                match every(option.claims(), credential) {
                    Ok(Some(selected)) => return Ok(Some(selected)),
                    Ok(None) => {}
                    Err(error) => {
                        first_error.get_or_insert(error);
                    }
                }
            }
            first_error.map_or(Ok(None), Err)
        }
    }
}

/// The claims of `claims` that `credential` discloses, when it holds every one.
fn every<'q, C: Credential + ?Sized>(
    claims: impl Iterator<Item = &'q ClaimsQuery>,
    credential: &C,
) -> Result<Option<Vec<SelectedClaim>>, PathError> {
    let mut selected = Vec::new();
    for claim in claims {
        match resolve(claim, credential)? {
            Some(found) => selected.push(found),
            None => return Ok(None),
        }
    }
    Ok(Some(selected))
}

/// One claims query against a credential, honouring `values`; `None` when the credential lacks
/// the claim.
///
/// A claim a `values` restriction excludes "should be treated the same as if it did not exist
/// in the Credential" (§6.4.1).
fn resolve<C: Credential + ?Sized>(
    claim: &ClaimsQuery,
    credential: &C,
) -> Result<Option<SelectedClaim>, PathError> {
    let found = match credential.claim(claim.path()) {
        Ok(found) => found,
        Err(PathError::Empty) => return Ok(None),
        Err(error) => return Err(error),
    };
    // An empty selection is step 3's `Empty` (§7.1.1).
    if found.is_empty() {
        return Ok(None);
    }
    if let Some(expected) = claim.values() {
        // "the type and value of the claim both match exactly for at least one of the
        // elements" (§6.3). serde_json's PartialEq is exact on both: `true` differs from
        // `"true"`, and 1 from "1".
        if !found.iter().any(|v| expected.contains(v)) {
            return Ok(None);
        }
    }
    Ok(Some(SelectedClaim::new(
        claim.id().cloned(),
        claim.path().clone(),
    )))
}
