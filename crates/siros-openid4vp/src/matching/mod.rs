//! Phase 1: the request rules, matching, consent, and the display with the records its entries
//! carry.
//!
//! One confirmation carries one transaction: the header (title, confirm, cancel) belongs to the
//! whole request, so a selection holds at most one credential that authorizes a
//! `transaction_data` entry.

mod consent;
mod display;
mod offer;
mod record;
mod rules;

pub use consent::{Consent, Slot, answer_slots, option_of};
pub use display::{
    Choice, Display, EntryView, Selection, SelectionError, StaticBox, Views, display, option_items,
    wallet_header,
};
pub use offer::{OfferSet, Offered, each, fills, flatten, offer, ways};
pub use record::{Record, RecordError, RecordId, ReturnedRecord};
pub use rules::{Accepted, CoreRule, Transaction};

use crate::plugins::registry::ErasedProfile;
use crate::plugins::{Binding, Bound, Carriage, Exclude, Fault, Member, NoCandidate, OptionIndex};
use crate::request::{AgreeableKey, HolderBinding, Query, QueryIndex, Request};
use crate::rows::Env;
use crate::wallet::{Credential, Holder, Wallet};
use crate::{FAULT, detail};
use rules::Formatted;

/// A candidate by its position among a query's candidates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CandidateIndex(pub usize);

/// One entry of the consent: a query, one of its candidates, one option it answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Pick {
    /// The query.
    pub query: QueryIndex,
    /// The candidate.
    pub candidate: CandidateIndex,
    /// The option.
    pub option: OptionIndex,
}

/// A credential that can answer a query.
#[derive(Debug, Clone)]
pub struct Candidate<'m> {
    /// The credential.
    pub credential: &'m Credential<'m>,
    /// The query's options it answers, in the Verifier's order.
    pub options: Vec<OptionIndex>,
    /// The transaction it authorizes for the query.
    pub bound: Option<Bound>,
}

/// A credential a plug-in excluded for a query.
#[derive(Debug)]
pub struct Excluded<'m> {
    /// The query.
    pub query: QueryIndex,
    /// The credential.
    pub credential: &'m Credential<'m>,
    /// The plug-in's reason.
    pub exclude: Exclude,
}

/// Each query's candidates.
pub struct Match<'m> {
    accepted: &'m Accepted<'m>,
    candidates: Vec<Vec<Candidate<'m>>>,
    excluded: Vec<Excluded<'m>>,
}

impl<'m> Match<'m> {
    /// Each query's candidates, in the wallet's order: the credentials of the query's format the
    /// query trusts and, unless the query waives it, bound to a key; that the Verifier's
    /// algorithms admit; for a query transaction data names, to which its profile binds entries;
    /// and which answer an option, a claim naming one of the profile's response members included.
    pub fn run(
        accepted: &'m Accepted<'m>,
        wallet: &'m Wallet<'m>,
        env: &Env,
    ) -> Result<Self, Fault> {
        let keys = accepted.metadata().agreeable_keys();
        let mut candidates = Vec::new();
        let mut excluded = Vec::new();
        for (index, query) in accepted.request().indexed_queries() {
            let mut found = Vec::new();
            if let Some(matcher) = QueryMatcher::of(accepted, index, query, &keys, env) {
                for credential in wallet.credentials().iter().filter(|c| matcher.eligible(c)) {
                    match matcher.consider(credential)? {
                        Considered::Candidate(candidate) => found.push(candidate),
                        Considered::Excluded(exclude) => excluded.push(Excluded {
                            query: index,
                            credential,
                            exclude,
                        }),
                        Considered::Unanswered => {}
                    }
                }
            }
            candidates.push(found);
        }
        Ok(Self {
            accepted,
            candidates,
            excluded,
        })
    }

    /// The accepted request.
    #[must_use]
    pub fn accepted(&self) -> &'m Accepted<'m> {
        self.accepted
    }

    /// A query's candidates.
    #[must_use]
    pub fn candidates(&self, query: QueryIndex) -> &[Candidate<'m>] {
        self.candidates.get(query.get()).map_or(&[], Vec::as_slice)
    }

    /// A candidate.
    #[must_use]
    pub fn candidate(
        &self,
        query: QueryIndex,
        candidate: CandidateIndex,
    ) -> Option<&Candidate<'m>> {
        self.candidates(query).get(candidate.0)
    }

    /// The credentials the plug-ins excluded, per query.
    #[must_use]
    pub fn excluded(&self) -> &[Excluded<'m>] {
        &self.excluded
    }

    /// Whether some credential can answer the query.
    #[must_use]
    pub fn held(&self, query: QueryIndex) -> bool {
        !self.candidates(query).is_empty()
    }
}

/// What matching a credential against a query gives.
#[expect(clippy::large_enum_variant, reason = "consumed where it is returned")]
enum Considered<'m> {
    /// A candidate.
    Candidate(Candidate<'m>),
    /// A plug-in excluded it.
    Excluded(Exclude),
    /// It answers no option.
    Unanswered,
}

/// One query with what matching its credentials needs: its format, and the transaction naming
/// it with its profile and the members the profile writes in the format.
struct QueryMatcher<'m, 'k> {
    query: &'m Query<'m>,
    request: &'m Request<'m>,
    formatted: &'m Formatted<'m>,
    transaction: Option<(&'m Transaction, &'m dyn ErasedProfile)>,
    members: Option<&'m [Member]>,
    keys: &'k [AgreeableKey<'k>],
    env: &'k Env,
}

impl<'m, 'k> QueryMatcher<'m, 'k> {
    /// The matcher of a query whose format has a plug-in.
    fn of(
        accepted: &'m Accepted<'m>,
        index: QueryIndex,
        query: &'m Query<'m>,
        keys: &'k [AgreeableKey<'k>],
        env: &'k Env,
    ) -> Option<Self> {
        let formatted = accepted.plan(index)?.formatted.as_ref()?;
        let transaction = accepted.transaction(index).and_then(|t| {
            accepted
                .registry()
                .profile_ref(t.profile)
                .map(|profile| (t, profile))
        });
        let members = transaction.and_then(|(_, profile)| {
            formatted
                .format
                .placement()
                .and_then(|placement| profile.members(placement))
        });
        Some(Self {
            query,
            request: accepted.request(),
            formatted,
            transaction,
            members,
            keys,
            env,
        })
    }

    /// OpenID4VP §6.1: the query's format, an issuer the query trusts, and a key the credential
    /// is bound to unless the query waives holder binding.
    fn eligible(&self, credential: &Credential<'_>) -> bool {
        let holder = self.query.holder_binding == HolderBinding::Waived
            || credential.facts.holder == Holder::Bound;
        credential.format == self.query.format && credential.trusted_for(self.query) && holder
    }

    /// The credential as a candidate, when the plug-ins admit and bind it and it answers an
    /// option.
    fn consider(&self, credential: &'m Credential<'m>) -> Result<Considered<'m>, Fault> {
        let bound = match self
            .formatted
            .query
            .admits(credential, self.keys)
            .and_then(|()| self.bind(credential))
        {
            Ok(bound) => bound,
            Err(NoCandidate::Excluded(exclude)) => return Ok(Considered::Excluded(exclude)),
            Err(NoCandidate::Fault(fault)) => return Err(fault),
        };
        let provided = match (&bound, self.members) {
            (Some(_), Some(members)) => members,
            _ => &[],
        };
        let options = self
            .formatted
            .query
            .answerable(credential, self.env, provided)?;
        let count = self.formatted.query.options().len();
        let ascending = options
            .windows(2)
            .all(|pair| matches!(pair, [a, b] if a < b));
        if !ascending || options.iter().any(|option| option.0 >= count) {
            return Err(Fault::new(
                FAULT,
                detail!(
                    "{query}: the format answered options {options:?} of {count}",
                    query = self.query.id.to_string()
                ),
            ));
        }
        Ok(if options.is_empty() {
            Considered::Unanswered
        } else {
            Considered::Candidate(Candidate {
                credential,
                options,
                bound,
            })
        })
    }

    /// The entries the profile binds to the credential, for a query transaction data names.
    fn bind(&self, credential: &'m Credential<'m>) -> Result<Option<Bound>, NoCandidate> {
        let Some((transaction, profile)) = self.transaction else {
            return Ok(None);
        };
        let carriage = match self.members {
            Some(members) if self.formatted.query.carries(credential, members)? => {
                Carriage::Carried
            }
            _ => Carriage::Uncarried,
        };
        let binding = Binding {
            request: self.request,
            query: self.query,
            credential,
            entries: &transaction.entries,
            placement: self.formatted.format.placement(),
            carriage,
        };
        let bound = profile.bind(binding, self.env)?;
        if bound
            .entries
            .entries()
            .iter()
            .all(|entry| transaction.entries.contains(entry))
        {
            Ok(Some(bound))
        } else {
            Err(Fault::new(
                FAULT,
                detail!(
                    "{query}: a profile bound entries no entry naming the query offered",
                    query = self.query.id.to_string()
                ),
            )
            .into())
        }
    }
}
