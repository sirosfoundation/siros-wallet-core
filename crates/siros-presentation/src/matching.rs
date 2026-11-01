//! Matching (A1, A2): the candidates of each Credential Query of a request, one instance per
//! batch (C5).

mod asked;
mod failure;
mod zkp;

use std::convert::Infallible;

use itertools::{Either, Itertools};
use serde_json::Value;
use siros_codec::date::Date;
use siros_credential::{least_used, Format};
use siros_dcql::eval::select_claims;
use siros_dcql::{
    ClaimPath, CredentialFormat, CredentialQuery, CredentialRef, CredentialSetQuery,
    CryptographicBinding, HolderBinding, PathError, QueryId,
};
use siros_trust::QueryAuthorities;
use siros_wallet_state::PresentationRecord;
use siros_zkp_req_nym_auth::catalogue::ATTESTATION_TYPES;
use siros_zkp_req_nym_auth::policy::RequestRefusal;
use siros_zkp_req_nym_auth::system::NymAuthSystem;

use crate::credential::{KeyHolding, MatchCredential};
use crate::ids::{CandidateIndex, QueryIndex};
use crate::request::MatchRequest;

pub use asked::{AskedType, QueryTypes};
pub use failure::{Failure, QueryRefusal};
pub use zkp::{ChoiceError, ProofChoice, ZkpQuery, ZkpRefusal};

/// The request as the matching reads it: its Credential Queries, each with its `id`, its
/// credential sets, and the Verifier metadata.
#[derive(Debug, Clone)]
pub struct Asked<'r> {
    queries: Vec<AskedQuery<'r>>,
    credential_sets: Option<&'r [CredentialSetQuery]>,
    client_metadata: Option<&'r Value>,
}

/// A Credential Query of a request, with its `id`.
#[derive(Debug, Clone)]
struct AskedQuery<'r> {
    id: QueryId,
    query: &'r CredentialQuery,
}

impl<'r> Asked<'r> {
    /// The Credential Queries, credential sets and Verifier metadata of `request`: the wallet's
    /// verified request, or the credential picker's [`siros_oid4vp::UnverifiedRequest`].
    pub fn of(request: &'r impl MatchRequest) -> Self {
        let query = request.dcql_query();
        Self {
            queries: query
                .credentials()
                .iter()
                .map(|credential| AskedQuery {
                    id: credential.id().clone(),
                    query: credential,
                })
                .collect(),
            credential_sets: query.credential_sets(),
            client_metadata: request.client_metadata(),
        }
    }

    /// Each Credential Query's `id`, with the credential types its matching reads: a matching
    /// over the credentials of those types alone gives what a matching over all of them gives.
    pub fn types(&self) -> Vec<QueryTypes> {
        self.queries
            .iter()
            .map(|asked| QueryTypes {
                query: asked.id.clone(),
                types: AskedType::of(asked.query),
            })
            .collect()
    }
}

/// What a member of an offer answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// The claims an SD-JWT VC or an mdoc discloses.
    Claims(Claims),
    /// The proof of a `zkp_req` option.
    Proof(ProofChoice),
}

/// The claims a member discloses: the pointers of the claims DCQL selected (OpenID4VP 1.0,
/// Section 6.4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claims {
    pointers: Vec<ClaimPath>,
    holder_binding: HolderBinding,
}

impl Claims {
    /// The claims path pointers, in the order of the claims query; `[namespace, element]` for an
    /// mdoc.
    pub fn pointers(&self) -> &[ClaimPath] {
        &self.pointers
    }

    /// Whether the query requires cryptographic holder binding.
    pub fn holder_binding(&self) -> HolderBinding {
        self.holder_binding
    }
}

/// The credentials that can answer each Credential Query, before the `zkp_req` credential
/// tests.
pub struct Matching<'r, C: MatchCredential> {
    credential_sets: Option<&'r [CredentialSetQuery]>,
    queries: Vec<(AskedQuery<'r>, Outcome<C>)>,
}

enum Outcome<C: MatchCredential> {
    Claims(Matched<C, Claims>),
    Proof {
        zkp: Box<ZkpQuery>,
        matched: Matched<C, ()>,
    },
    Refused(QueryRefusal),
}

/// A credential that matched a query, what it answers, and the admission of its issuer.
struct Admitted<C: MatchCredential, T> {
    credential: C,
    found: T,
    admission: C::Admission,
}

/// The credentials of a query's format and type before the `zkp_req` tests: those that match
/// it, each with what it answers, and those it excludes.
struct Matched<C: MatchCredential, T> {
    found: Vec<Admitted<C, T>>,
    excluded: Vec<Excluded<C, Infallible>>,
}

impl<C: MatchCredential, T> Matched<C, T> {
    fn new() -> Self {
        Self {
            found: Vec::new(),
            excluded: Vec::new(),
        }
    }

    /// Add `credential`, which answers with `found`, when `authorities` admit its issuer
    /// through `trust` (TR3); else exclude it with the refusal.
    fn admit(&mut self, credential: C, found: T, authorities: &QueryAuthorities, trust: &C::Trust) {
        match credential.admission(authorities, trust) {
            Ok(admission) => self.found.push(Admitted {
                credential,
                found,
                admission,
            }),
            Err(refusal) => self.excluded.push(Excluded {
                credential,
                reason: Exclusion::Unadmitted(refusal),
            }),
        }
    }
}

impl<'r, C: MatchCredential + Clone> Matching<'r, C> {
    /// The matching of `asked` over `credentials`, usable at the proof date `date`.
    ///
    /// One instance of each batch is matched: the one [`least_used`] chooses from `records`
    /// (C5). The format table (A1):
    ///
    /// | Query format | Credentials | `meta` |
    /// | --- | --- | --- |
    /// | `mso_mdoc` | mdocs | `doctype_value` is the `docType` |
    /// | `dc+sd-jwt` | SD-JWT VCs | `vct_values` lists the `vct` |
    /// | `zkp_req` | of `meta.source_format`, through the nym_auth catalogue (A2) | `zkp_req.md`, Section 1.1 |
    ///
    /// Any other format matches nothing. A query that requires holder binding matches only a
    /// credential whose key the wallet holds, and an mdoc always needs its key. No query other
    /// than `zkp_req` matches a nym_auth attestation, whose attributes are undisclosable. Claims
    /// are selected by DCQL (OpenID4VP 1.0, Section 6.4.1); a credential whose claims path
    /// processing gives an error (Sections 7.1.1 and 7.2.1) is excluded with it. `policy` says
    /// whether the request meets the nym_auth policy; a nym_auth query of a request that does
    /// not is refused.
    ///
    /// A credential whose issuer the query's `trusted_authorities` refuse through `trust` is
    /// excluded with the refusal (TR3); a query with a malformed `aki` value is refused.
    pub fn new(
        asked: Asked<'r>,
        credentials: &[C],
        trust: &C::Trust,
        records: &[PresentationRecord],
        systems: &[NymAuthSystem],
        date: Date,
        policy: Result<(), RequestRefusal>,
    ) -> Self {
        let instances = least_used(credentials, records);
        let client_metadata = asked.client_metadata;
        let queries = asked
            .queries
            .into_iter()
            .map(|asked| {
                let authorities = match QueryAuthorities::of(asked.query) {
                    Ok(authorities) => authorities,
                    Err(error) => {
                        return (asked, Outcome::Refused(QueryRefusal::Authorities(error)))
                    }
                };
                let outcome = match asked.query.format().as_str() {
                    "zkp_req" => {
                        match ZkpQuery::read(asked.query, client_metadata, policy, systems, date) {
                            Ok(zkp) => {
                                let mut matched = Matched::new();
                                for credential in zkp.provable(&instances) {
                                    matched.admit(credential, (), &authorities, trust);
                                }
                                Outcome::Proof {
                                    zkp: Box::new(zkp),
                                    matched,
                                }
                            }
                            Err(refusal) => Outcome::Refused(QueryRefusal::Zkp(refusal)),
                        }
                    }
                    _ => Outcome::Claims(answering(asked.query, &instances, &authorities, trust)),
                };
                (asked, outcome)
            })
            .collect();
        Self {
            credential_sets: asked.credential_sets,
            queries,
        }
    }

    /// The answers of every query: `choose` gives the [`ProofChoice`] of each `zkp_req`
    /// candidate, admitted as it is, one of [`ZkpQuery::choices`], or the reason the candidate
    /// answers none. The wallet applies the credential tests there (A2); the picker, which
    /// cannot, takes the first.
    pub fn answer<R>(
        self,
        mut choose: impl FnMut(&C, &C::Admission, &ZkpQuery) -> Result<ProofChoice, R>,
    ) -> Answered<'r, C, R> {
        let queries = self
            .queries
            .into_iter()
            .map(|(asked, outcome)| {
                let outcome = match outcome {
                    Outcome::Claims(matched) => QueryOutcome::Claims {
                        candidates: matched
                            .found
                            .into_iter()
                            .map(|found| Candidate {
                                credential: found.credential,
                                answer: Answer::Claims(found.found),
                                admission: found.admission,
                            })
                            .collect(),
                        excluded: matched.excluded.into_iter().map(Excluded::widen).collect(),
                    },
                    Outcome::Proof { zkp, matched } => {
                        let (candidates, unproven): (Vec<_>, Vec<_>) =
                            matched.found.into_iter().partition_map(|found| {
                                match choose(&found.credential, &found.admission, &zkp) {
                                    Ok(choice) => Either::Left(Candidate {
                                        credential: found.credential,
                                        answer: Answer::Proof(choice),
                                        admission: found.admission,
                                    }),
                                    Err(reason) => Either::Right(Excluded {
                                        credential: found.credential,
                                        reason: Exclusion::Unproven(reason),
                                    }),
                                }
                            });
                        let mut excluded: Vec<Excluded<C, R>> =
                            matched.excluded.into_iter().map(Excluded::widen).collect();
                        excluded.extend(unproven);
                        QueryOutcome::Proof {
                            zkp,
                            candidates,
                            excluded,
                        }
                    }
                    Outcome::Refused(refusal) => QueryOutcome::Refused(refusal),
                };
                Answers { asked, outcome }
            })
            .collect();
        Answered {
            credential_sets: self.credential_sets,
            queries,
        }
    }
}

/// The instances of `instances` that answer `query`, each with the claims it discloses and the
/// admission of its issuer by `authorities` through `trust`, and those of the query's format
/// and type it excludes, in the order of `instances`.
fn answering<C: MatchCredential + Clone>(
    query: &CredentialQuery,
    instances: &[&C],
    authorities: &QueryAuthorities,
    trust: &C::Trust,
) -> Matched<C, Claims> {
    let types = AskedType::of(query);
    let mut matched = Matched::new();
    for &credential in instances {
        match claims(query, &types, credential) {
            Ok(Some(claims)) => matched.admit(credential.clone(), claims, authorities, trust),
            Ok(None) => {}
            Err(error) => matched.excluded.push(Excluded {
                credential: credential.clone(),
                reason: Exclusion::ClaimPath(error),
            }),
        }
    }
    matched
}

/// The claims `query` selects in `credential`, when the credential is of a type of `types`, the
/// types the query asks for (A1), and holds every claim the query asks for; `None` when it does
/// not answer.
///
/// # Errors
///
/// [`PathError`]: the processing of a claims path in `credential` gives an error other than an
/// empty selection.
fn claims<C: MatchCredential>(
    query: &CredentialQuery,
    types: &[AskedType],
    credential: &C,
) -> Result<Option<Claims>, PathError> {
    let holder_binding = query.holder_binding();
    let Some(asked) = types.iter().find(|asked| asked.holds(credential)) else {
        return Ok(None);
    };
    let format = asked.format();
    let needs_key = format == Format::Mdoc || holder_binding == HolderBinding::Required;
    let undisclosable = ATTESTATION_TYPES.contains(&credential.credential_type());
    if undisclosable || (needs_key && credential.key_holding() == KeyHolding::NotHeld) {
        return Ok(None);
    }
    let held = Held {
        credential,
        id: CredentialRef::new(&credential.entry().credential_id().to_string()),
        format: CredentialFormat::new(format.identifier()),
    };
    Ok(select_claims(query, &held)?.map(|selected| Claims {
        pointers: selected
            .into_iter()
            .map(|claim| claim.into_path())
            .collect(),
        holder_binding,
    }))
}

/// A credential as DCQL's claim selection reads it, with its decimal `credentialId` and its
/// format's identifier.
struct Held<'c, C> {
    credential: &'c C,
    id: CredentialRef,
    format: CredentialFormat,
}

impl<C: MatchCredential> siros_dcql::Credential for Held<'_, C> {
    fn id(&self) -> &CredentialRef {
        &self.id
    }

    fn format(&self) -> &CredentialFormat {
        &self.format
    }

    fn claim(&self, path: &ClaimPath) -> Result<Vec<Value>, PathError> {
        self.credential.claim_values(path)
    }

    fn binding(&self) -> CryptographicBinding {
        match self.credential.key_holding() {
            KeyHolding::Held => CryptographicBinding::Bound,
            KeyHolding::NotHeld => CryptographicBinding::Unbound,
        }
    }
}

/// The candidates of every Credential Query, each with its answer. `R` is why a `zkp_req`
/// candidate answers no option.
pub struct Answered<'r, C: MatchCredential, R> {
    credential_sets: Option<&'r [CredentialSetQuery]>,
    queries: Vec<Answers<'r, C, R>>,
}

/// The candidates of one Credential Query.
pub struct Answers<'r, C: MatchCredential, R> {
    asked: AskedQuery<'r>,
    outcome: QueryOutcome<C, R>,
}

/// What the matching gives a Credential Query.
enum QueryOutcome<C: MatchCredential, R> {
    /// The credentials that disclose the claims it asks, and those it excludes.
    Claims {
        candidates: Vec<Candidate<C>>,
        excluded: Vec<Excluded<C, R>>,
    },
    /// The nym_auth query of a `zkp_req` query, the credentials that answer an option, and
    /// those that answer none.
    Proof {
        zkp: Box<ZkpQuery>,
        candidates: Vec<Candidate<C>>,
        excluded: Vec<Excluded<C, R>>,
    },
    /// The query is refused whatever the wallet holds.
    Refused(QueryRefusal),
}

/// A credential that answers a Credential Query, its answer, and the admission of its issuer
/// for the query.
pub struct Candidate<C: MatchCredential> {
    credential: C,
    answer: Answer,
    admission: C::Admission,
}

/// A credential of a query's format and type that the query excludes, and why.
pub struct Excluded<C: MatchCredential, R> {
    credential: C,
    reason: Exclusion<C::Unadmitted, R>,
}

/// Why a query excludes a credential of its format and type. `U` is why the query's
/// authorities refuse its issuer, `R` why it answers no option of a `zkp_req` query.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Exclusion<U, R> {
    /// The query's `trusted_authorities` refuse its issuer (TR3).
    #[error("the query's `trusted_authorities` refuse its issuer (TR3)")]
    Unadmitted(#[source] U),
    /// Its claims path processing gives an error (OpenID4VP 1.0, Sections 7.1.1 and 7.2.1).
    #[error("its claims path processing gives an error (OpenID4VP 1.0, Sections 7.1.1 and 7.2.1)")]
    ClaimPath(#[source] PathError),
    /// It answers no option of the `zkp_req` query.
    #[error("it answers no option of the `zkp_req` query")]
    Unproven(#[source] R),
}

impl<C: MatchCredential> Excluded<C, Infallible> {
    /// The exclusion, before the `zkp_req` tests, among the exclusions of any `R`.
    fn widen<R>(self) -> Excluded<C, R> {
        Excluded {
            credential: self.credential,
            reason: match self.reason {
                Exclusion::Unadmitted(refusal) => Exclusion::Unadmitted(refusal),
                Exclusion::ClaimPath(error) => Exclusion::ClaimPath(error),
                Exclusion::Unproven(never) => match never {},
            },
        }
    }
}

impl<'r, C: MatchCredential, R> Answered<'r, C, R> {
    /// The candidates of each Credential Query, in the order of the DCQL query.
    pub fn queries(&self) -> &[Answers<'r, C, R>] {
        &self.queries
    }

    /// The candidates of each Credential Query, with its position.
    pub fn indexed(&self) -> impl Iterator<Item = (QueryIndex, &Answers<'r, C, R>)> {
        self.queries
            .iter()
            .enumerate()
            .map(|(index, answers)| (QueryIndex::new(index), answers))
    }

    /// The candidates of the Credential Query at `index`.
    pub fn answers(&self, index: QueryIndex) -> Option<&Answers<'r, C, R>> {
        self.queries.get(index.value())
    }

    /// The position of the Credential Query `id`.
    pub fn index_of(&self, id: &str) -> Option<QueryIndex> {
        self.indexed()
            .find(|(_, answers)| answers.asked.id == *id)
            .map(|(index, _)| index)
    }

    /// The request's `credential_sets`.
    pub fn credential_sets(&self) -> Option<&'r [CredentialSetQuery]> {
        self.credential_sets
    }
}

impl<'r, C: MatchCredential, R> Answers<'r, C, R> {
    /// The Credential Query's `id`.
    pub fn id(&self) -> &QueryId {
        &self.asked.id
    }

    /// The Credential Query.
    pub fn query(&self) -> &'r CredentialQuery {
        self.asked.query
    }

    /// The credentials that answer it, in the order of the wallet's credentials.
    pub fn candidates(&self) -> &[Candidate<C>] {
        match &self.outcome {
            QueryOutcome::Claims { candidates, .. } | QueryOutcome::Proof { candidates, .. } => {
                candidates
            }
            QueryOutcome::Refused(_) => &[],
        }
    }

    /// The candidate at `index`.
    pub fn candidate(&self, index: CandidateIndex) -> Option<&Candidate<C>> {
        self.candidates().get(index.value())
    }

    /// The nym_auth query of a `zkp_req` query that has a usable pair.
    pub fn zkp(&self) -> Option<&ZkpQuery> {
        match &self.outcome {
            QueryOutcome::Proof { zkp, .. } => Some(zkp),
            QueryOutcome::Claims { .. } | QueryOutcome::Refused(_) => None,
        }
    }

    /// Why the query has no candidate whatever the wallet holds.
    pub fn refusal(&self) -> Option<&QueryRefusal> {
        match &self.outcome {
            QueryOutcome::Refused(refusal) => Some(refusal),
            QueryOutcome::Claims { .. } | QueryOutcome::Proof { .. } => None,
        }
    }

    /// The credentials of the query's format and type that it excludes, and why.
    pub fn excluded(&self) -> &[Excluded<C, R>] {
        match &self.outcome {
            QueryOutcome::Claims { excluded, .. } | QueryOutcome::Proof { excluded, .. } => {
                excluded
            }
            QueryOutcome::Refused(_) => &[],
        }
    }
}

impl<C: MatchCredential> Candidate<C> {
    /// The credential.
    pub fn credential(&self) -> &C {
        &self.credential
    }

    /// The answer.
    pub fn answer(&self) -> &Answer {
        &self.answer
    }

    /// The admission of the credential's issuer for the query (TR3).
    pub fn admission(&self) -> &C::Admission {
        &self.admission
    }
}

impl<C: MatchCredential, R> Excluded<C, R> {
    /// The credential.
    pub fn credential(&self) -> &C {
        &self.credential
    }

    /// Why the query excludes it.
    pub fn reason(&self) -> &Exclusion<C::Unadmitted, R> {
        &self.reason
    }
}
