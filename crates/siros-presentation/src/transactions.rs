//! Transaction data in the matching (PaSO Core, Section 7.4): the entries of the request, the
//! entry each candidate of a targeted query takes or why it takes none, and the offers over the
//! candidates the first match leaves (T1, T4). The wallet's plan and the credential picker run
//! it alike; the picker's selection defers to the wallet the ad-hoc metadata it cannot verify
//! (K2).

use std::convert::Infallible;

use itertools::Itertools;
use siros_credential::EntryRef;
use siros_dcql::QueryId;
use siros_transaction_data::{
    check_request, Entry, EntryPosition, Exclusion, Selection, Taken, TransactionDataError,
};

use crate::credential::MatchCredential;
use crate::ids::{CandidateIndex, QueryIndex};
use crate::inconsistency::Inconsistency;
use crate::matching::{Answered, Answers, Candidate, Failure};
use crate::offers::{Member, Offers};
use crate::request::MatchRequest;

/// What gives a candidate credential the entry it takes: the wallet's sources, or the
/// definitions the credential picker's registration records.
pub trait TransactionSource<C> {
    /// Why the selection defers an entry to the wallet: never, for the wallet's own.
    type Deferral;

    /// What `credential` takes of `entries`, those that target it in array order (PaSO Core,
    /// Section 7.4.2, steps 2 and 3).
    ///
    /// # Errors
    ///
    /// [`TransactionDataError::Unsigned`] when the request arrived unsigned and PaSO metadata
    /// serves an entry (PaSO Core, Section 3).
    fn first_match(
        &self,
        entries: &[&Entry],
        credential: &C,
    ) -> Result<Selection<Self::Deferral>, TransactionDataError>;

    /// Whether a source defines `entry`'s type for `credential` (OpenID4VP 1.0, Section 5.1),
    /// though the entry may not be compatible.
    fn knows(&self, entry: &Entry, credential: &C) -> bool;
}

/// The presented credential a transaction entry binds to (T4): the Credential Query it answers,
/// and its entry, named by `credentialId` and instance.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Bound {
    pub(crate) query: QueryId,
    pub(crate) credential: EntryRef,
}

impl Bound {
    /// The credential `candidate` presented for the query of `answers`.
    pub(crate) fn of<C: MatchCredential, R>(
        answers: &Answers<'_, C, R>,
        candidate: &Candidate<C>,
    ) -> Self {
        Self {
            query: answers.id().clone(),
            credential: candidate.credential().entry(),
        }
    }
}

/// An entry a presented credential binds (T4): the credential, the entry, and the view it took.
pub struct BoundEntry<'t> {
    pub(crate) bound: Bound,
    pub(crate) entry: &'t Entry,
    pub(crate) taken: &'t Taken,
}

impl<'t> BoundEntry<'t> {
    /// Whether the entry binds to `candidate`, a candidate of the query of `answers`.
    pub fn binds<C: MatchCredential, R>(
        &self,
        answers: &Answers<'_, C, R>,
        candidate: &Candidate<C>,
    ) -> bool {
        self.bound == Bound::of(answers, candidate)
    }

    /// The entry.
    pub fn entry(&self) -> &'t Entry {
        self.entry
    }

    /// What the credential takes of it: its view, and the payment it names.
    pub fn taken(&self) -> &'t Taken {
        self.taken
    }
}

/// A member of an offer as the matching answers it: its query, and each of its candidates.
pub(crate) struct Offered<'w, 'a, C: MatchCredential, R> {
    pub(crate) query: QueryIndex,
    pub(crate) answers: &'w Answers<'a, C, R>,
    pub(crate) candidates: Vec<(CandidateIndex, &'w Candidate<C>)>,
}

#[cfg(feature = "wallet")]
impl<C: MatchCredential, R> Offered<'_, '_, C, R> {
    /// Whether the entry of `bound` binds to the member's candidate `candidate`.
    pub(crate) fn carries(&self, bound: &Bound, candidate: &Candidate<C>) -> bool {
        *bound == Bound::of(self.answers, candidate)
    }
}

/// Each member of `members` as the matching answers it, in order.
///
/// # Errors
///
/// [`Inconsistency`]: a member names a query or a candidate `answered` lacks.
pub(crate) fn offered<'w, 'a, C: MatchCredential, R>(
    answered: &'w Answered<'a, C, R>,
    members: &[Member],
) -> Result<Vec<Offered<'w, 'a, C, R>>, Inconsistency> {
    members
        .iter()
        .map(|member| {
            let query = member.query();
            let answers = answered.answers(query).ok_or(Inconsistency::Query(query))?;
            let candidates = member
                .candidates()
                .iter()
                .map(|&index| {
                    answers
                        .candidate(index)
                        .map(|candidate| (index, candidate))
                        .ok_or(Inconsistency::Candidate(query, index))
                })
                .collect::<Result<_, _>>()?;
            Ok(Offered {
                query,
                answers,
                candidates,
            })
        })
        .collect()
}

/// A candidate of a targeted query, its entry, and what it takes.
pub(crate) struct Candidacy<D> {
    pub(crate) query: QueryIndex,
    pub(crate) candidate: CandidateIndex,
    pub(crate) credential: EntryRef,
    pub(crate) selection: Selection<D>,
}

impl<D> Candidacy<D> {
    /// The credential and why it takes no entry, when the first match excluded it.
    fn exclusion(&self) -> Option<Exclusion> {
        match &self.selection {
            Selection::Excluded(causes) => Some(Exclusion {
                credential: self.credential,
                causes: causes.clone(),
            }),
            Selection::Takes(_) | Selection::Deferred(..) => None,
        }
    }

    /// Whether the candidate may take an entry: it takes one, or the wallet decides.
    fn served(&self) -> bool {
        !matches!(self.selection, Selection::Excluded(_))
    }
}

/// The `transaction_data` entries of a request, and the selection of each candidate of a query
/// they target. `D` is why the selection defers an entry to the wallet.
pub struct Transactions<D = Infallible> {
    pub(crate) entries: Vec<Entry>,
    pub(crate) candidacies: Vec<Candidacy<D>>,
}

/// Why a request has no offer: its transaction data, or the matching.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NoOffer<U, R> {
    /// The queries the request's entries target have no candidate: the referenced credentials
    /// are not available (OpenID4VP 1.0, Section 8.5).
    #[error(
        "the queries the request's entries target have no candidate: the referenced \
         credentials are not available (OpenID4VP 1.0, Section 8.5)"
    )]
    CredentialUnavailable,
    /// Why the matching gives no offer.
    #[error(transparent)]
    Unmatched(Failure<U, R>),
}

/// The `transaction_data` entries of a request: each read against its DCQL query, and all of
/// them checked against its signature and its credential sets (PaSO Core, Sections 3 and
/// 7.4.1).
#[derive(Debug, Clone)]
pub struct RequestEntries(Vec<Entry>);

impl RequestEntries {
    /// The entries of `request`.
    ///
    /// # Errors
    ///
    /// [`TransactionDataError`]: an entry that does not read; an unsigned request with a
    /// PaSO-targeted entry; credential sets that break Section 7.4.1.
    pub fn read(request: &impl MatchRequest) -> Result<Self, TransactionDataError> {
        let query = request.dcql_query();
        let entries: Vec<Entry> = request
            .transaction_data()
            .iter()
            .enumerate()
            .map(|(at, raw)| {
                let position = EntryPosition::new(at);
                Entry::parse(position, raw, query)
                    .map_err(|refusal| TransactionDataError::Entry(position, refusal))
            })
            .try_collect()?;
        check_request(&entries, query, request.signature())?;
        Ok(Self(entries))
    }

    /// The entries, in the request's order.
    pub fn entries(&self) -> &[Entry] {
        &self.0
    }
}

impl<D> Transactions<D> {
    /// The entries of `request` and the first match of each candidate of `answered` whose query
    /// an entry targets, through `source` (PaSO Core, Sections 7.4.1 and 7.4.2):
    /// [`RequestEntries::read`], then [`Transactions::select`].
    ///
    /// # Errors
    ///
    /// [`TransactionDataError`]: the first error of either step.
    pub fn read<C: MatchCredential, R>(
        request: &impl MatchRequest,
        answered: &Answered<'_, C, R>,
        source: &impl TransactionSource<C, Deferral = D>,
    ) -> Result<Self, TransactionDataError> {
        Self::select(RequestEntries::read(request)?, answered, source)
    }

    /// The first match of each candidate of `answered` whose query an entry of `entries`
    /// targets, through `source` (PaSO Core, Section 7.4.2).
    ///
    /// # Errors
    ///
    /// [`TransactionDataError`]: an unsigned request a PaSO source needs signed; a type no
    /// source defines for any candidate, unless the first match serves every credential the
    /// entry targets (OpenID4VP 1.0, Section 5.1); or no compatible candidate left.
    pub fn select<C: MatchCredential, R>(
        entries: RequestEntries,
        answered: &Answered<'_, C, R>,
        source: &impl TransactionSource<C, Deferral = D>,
    ) -> Result<Self, TransactionDataError> {
        let RequestEntries(entries) = entries;
        let mut candidacies = Vec::new();
        for (index, answers) in answered.indexed() {
            let targeting: Vec<&Entry> = entries.iter().filter(|e| e.names(answers.id())).collect();
            if targeting.is_empty() {
                continue;
            }
            for (at, candidate) in answers.candidates().iter().enumerate() {
                let credential = candidate.credential();
                let selection = source.first_match(&targeting, credential)?;
                candidacies.push(Candidacy {
                    query: index,
                    candidate: CandidateIndex::new(at),
                    credential: credential.entry(),
                    selection,
                });
            }
        }
        let transactions = Self {
            entries,
            candidacies,
        };
        transactions.known(answered, source)?;
        transactions.compatible_left()?;
        Ok(transactions)
    }

    /// Checks each entry whose type the wallet knows from no source for any candidate it
    /// targets: the first match then serves every such candidate (OpenID4VP 1.0, Section 5.1;
    /// PaSO Core, Section 7.4.2).
    fn known<C: MatchCredential, R>(
        &self,
        answered: &Answered<'_, C, R>,
        source: &impl TransactionSource<C, Deferral = D>,
    ) -> Result<(), TransactionDataError> {
        for entry in &self.entries {
            let targets: Vec<(&Candidacy<D>, &C)> = self
                .candidacies
                .iter()
                .filter_map(|c| {
                    let answers = answered.answers(c.query).filter(|a| entry.names(a.id()))?;
                    Some((c, answers.candidate(c.candidate)?.credential()))
                })
                .collect();
            if targets.iter().all(|(c, _)| c.served()) {
                continue;
            }
            if !targets
                .iter()
                .any(|(_, credential)| source.knows(entry, credential))
            {
                let exclusions = targets.iter().filter_map(|(c, _)| c.exclusion()).collect();
                return Err(TransactionDataError::TypeUnknown(
                    entry.position(),
                    exclusions,
                ));
            }
        }
        Ok(())
    }

    /// Checks that a candidate takes an entry when some candidate is targeted (PaSO Core,
    /// Section 7.4.2, step 4).
    fn compatible_left(&self) -> Result<(), TransactionDataError> {
        if self.candidacies.is_empty() || self.candidacies.iter().any(Candidacy::served) {
            return Ok(());
        }
        Err(TransactionDataError::NoCompatibleCredential(
            self.candidacies
                .iter()
                .filter_map(Candidacy::exclusion)
                .collect(),
        ))
    }

    /// Whether the request carries `transaction_data` entries.
    pub fn carried(&self) -> bool {
        !self.entries.is_empty()
    }

    /// Whether `candidate` of `query` may be offered: it takes an entry, the wallet decides, or
    /// no entry targets its query.
    pub fn eligible(&self, query: QueryIndex, candidate: CandidateIndex) -> bool {
        self.selection(query, candidate)
            .is_none_or(|selection| !matches!(selection, Selection::Excluded(_)))
    }

    /// What `candidate` of `query` takes; `None` when no entry targets its query.
    pub fn selection(&self, query: QueryIndex, candidate: CandidateIndex) -> Option<&Selection<D>> {
        self.candidacies
            .iter()
            .find(|c| c.query == query && c.candidate == candidate)
            .map(|c| &c.selection)
    }

    /// Whether the request carries entries and none of the queries they target has a
    /// candidate: the referenced credentials are not available (OpenID4VP 1.0, Section 8.5).
    fn unavailable(&self) -> bool {
        !self.entries.is_empty() && self.candidacies.is_empty()
    }

    /// The entries the presented credentials of `members` bind, one group (T4): each credential
    /// binds the entry it takes, and an entry two of them take binds to the one whose query
    /// comes first in its `credential_ids`, then the first presented (OpenID4VP 1.0, Section
    /// 5.1). An entry the wallet decides after selection binds nothing here (K2).
    ///
    /// # Errors
    ///
    /// [`Inconsistency`]: a member names a query or a candidate `answered` lacks, or a candidate
    /// takes an entry these transactions lack.
    pub fn bind<'t, C: MatchCredential, R>(
        &'t self,
        answered: &Answered<'_, C, R>,
        members: &[Member],
    ) -> Result<Vec<BoundEntry<'t>>, Inconsistency> {
        let presented: Vec<(Bound, &'t Candidacy<D>)> = offered(answered, members)?
            .iter()
            .flat_map(|member| {
                member
                    .candidates
                    .iter()
                    .filter_map(move |&(index, candidate)| {
                        let candidacy = self
                            .candidacies
                            .iter()
                            .find(|c| c.query == member.query && c.candidate == index)?;
                        Some((Bound::of(member.answers, candidate), candidacy))
                    })
            })
            .collect();
        let mut bound: Vec<BoundEntry<'t>> = Vec::new();
        for (credential, candidacy) in &presented {
            let Selection::Takes(taken) = &candidacy.selection else {
                continue;
            };
            let entry = self
                .entries
                .get(taken.entry().value())
                .ok_or(Inconsistency::Entry(taken.entry()))?;
            let rank = |query: &QueryId| entry.credential_ids().iter().position(|id| id == query);
            let first = presented
                .iter()
                .filter(|(_, other)| {
                    matches!(&other.selection, Selection::Takes(t) if t.entry() == taken.entry())
                })
                .min_by_key(|(other, _)| rank(&other.query))
                .map(|(other, _)| other);
            if first == Some(credential) {
                bound.push(BoundEntry {
                    bound: credential.clone(),
                    entry,
                    taken,
                });
            }
        }
        Ok(bound)
    }

    /// The offers of `answered` over the candidates the first match leaves.
    ///
    /// # Errors
    ///
    /// [`NoOffer`] when no offer remains: [`NoOffer::CredentialUnavailable`] when the queries
    /// the entries target have no candidate, else why the matching gives no offer.
    pub fn offers<C: MatchCredential, R: Clone>(
        &self,
        answered: &Answered<'_, C, R>,
    ) -> Result<Offers, NoOffer<C::Unadmitted, R>> {
        let offers = Offers::of(answered, |query, candidate| self.eligible(query, candidate));
        if !offers.offers().is_empty() {
            return Ok(offers);
        }
        if self.unavailable() {
            return Err(NoOffer::CredentialUnavailable);
        }
        Err(NoOffer::Unmatched(answered.failure()))
    }
}
