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
    Choice, ChoiceId, Display, DisplaySet, EntryView, Selection, SelectionError, SetIndex,
    StaticEntry, Views, display, option_items, wallet_header,
};
pub use offer::{OfferSet, Offered, each, fills, flatten, offer, ways};
pub use record::{Record, RecordError, RecordId, RenderingInput, ReturnedRecord};
pub use rules::{Accepted, CoreRule, Transaction};

use std::borrow::Cow;

use siros_explain::Explain;

use crate::plugins::registry::{Catalog, ErasedProfile};
use crate::plugins::{
    Binding, Bound, Carriage, Exclude, Exclusion, Fault, Member, NoCandidate, OptionIndex,
    ProfileHandle,
};
use crate::refusal::ErrorCode;
use crate::rendering::Rendering;
use crate::request::{AgreeableKey, HolderBinding, Query, QueryIndex, Request};
use crate::rows::{Env, RenderingInputs};
use crate::wallet::{Credential, Holder, Wallet};
use crate::{FAULT, detail};
use rules::Formatted;

/// A candidate by its position among a query's candidates. Only the core's match makes one
/// ([`Match::indexed_candidates`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CandidateIndex(usize);

impl CandidateIndex {
    /// The position among the query's candidates.
    #[must_use]
    pub const fn position(self) -> usize {
        self.0
    }
}

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
    /// The transaction it authorizes for the query with the profile's binding: present for each
    /// candidate of a query transaction data names.
    pub bound: Option<TransactionBinding<'m>>,
    /// What its texts render with: the language and its fallback flag, each module's digest,
    /// the rendering options and the renderer's version.
    pub inputs: RenderingInputs,
}

/// A candidate's transaction: its query's `Transaction` and the `Bound` the transaction's profile
/// gave the credential, one value. Phase 2 reads a record's transaction from it alone.
#[derive(Debug, Clone)]
pub struct TransactionBinding<'m> {
    /// The transaction data naming the query.
    pub transaction: &'m Transaction,
    /// The entries and display facts the profile bound.
    pub bound: Bound,
}

/// A credential a plug-in excluded for a query.
#[derive(Debug)]
pub struct Excluded<'m> {
    /// The query.
    pub query: QueryIndex,
    /// The credential.
    pub credential: &'m Credential<'m>,
    /// The plug-in that excluded it.
    pub by: ExcludedBy,
    /// The plug-in's reason.
    pub exclude: Exclude,
}

/// A profile keeps the credential for its own transactions, and no entry of that profile names the
/// query ([`crate::plugins::Profile::reserves`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.matching", id = "reserved")]
#[error("a profile reserves the credential for a query its own entries name")]
pub struct ReservedCredential;

impl Exclusion for ReservedCredential {
    fn clause(&self) -> Cow<'static, str> {
        Cow::Borrowed("the profile's reservation")
    }
}

/// The plug-in that excluded a credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExcludedBy {
    /// The query's format: the Verifier's `vp_formats_supported` admits no algorithm the
    /// credential's presentation can use (`FormatQuery::admits`).
    Format,
    /// The profile of the transaction naming the query binds none of its entries, or another
    /// profile reserves the credential.
    Profile,
    /// The entry's texts cannot render: no language serves its modules, or the package holds
    /// no module whose locale its profile selected (section 4.14 of the design).
    Language,
    /// The query's format: what the End-User could be shown of the credential must not reach them
    /// (`FormatQuery::displayable`).
    Display,
}

/// The code of a request the wallet does not meet (§8.5, §15.4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnmetCode {
    /// `access_denied`: no credentials, a decline, a failed End-User authentication, a failed
    /// proof, which a Verifier cannot tell apart (§15.4.1, §15.9).
    AccessDenied,
    /// `vp_formats_not_supported`: every alternative of the request holds a query whose format
    /// admits none of the wallet's credentials under the Verifier's `vp_formats_supported`,
    /// which leaves the Verifier a fallback to another format.
    VpFormatsNotSupported,
}

impl UnmetCode {
    /// The code the Verifier receives.
    #[must_use]
    pub const fn code(self) -> ErrorCode {
        match self {
            Self::AccessDenied => ErrorCode::ACCESS_DENIED,
            Self::VpFormatsNotSupported => ErrorCode::VP_FORMATS_NOT_SUPPORTED,
        }
    }
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
    /// Each candidate's texts take their language over `rendering`'s modules; an entry no
    /// language serves is excluded.
    pub fn run(
        accepted: &'m Accepted<'m>,
        wallet: &'m Wallet<'m>,
        env: &Env,
        rendering: &Rendering<'_>,
    ) -> Result<Self, Fault> {
        let keys = accepted.metadata().agreeable_keys();
        let mut candidates = Vec::new();
        let mut excluded = Vec::new();
        for (index, query) in accepted.request().indexed_queries() {
            let mut found = Vec::new();
            let matcher = QueryMatcher::of(accepted, index, query, &keys, env, rendering)?;
            if let Some(matcher) = matcher {
                for credential in wallet.credentials().iter().filter(|c| matcher.eligible(c)) {
                    match matcher.consider(credential)? {
                        Considered::Candidate(candidate) => found.push(candidate),
                        Considered::Excluded(by, exclude) => excluded.push(Excluded {
                            query: index,
                            credential,
                            by,
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

    /// A query's candidates with their indices.
    pub fn indexed_candidates(
        &self,
        query: QueryIndex,
    ) -> impl Iterator<Item = (CandidateIndex, &Candidate<'m>)> {
        self.candidates(query)
            .iter()
            .enumerate()
            .map(|(position, candidate)| (CandidateIndex(position), candidate))
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

    /// The code of the request when the wallet does not meet it: `vp_formats_not_supported`
    /// when every alternative holds a query no credential answers and whose format excluded one
    /// under the Verifier's `vp_formats_supported`; `access_denied` otherwise.
    #[must_use]
    pub fn unmet(&self) -> UnmetCode {
        let unsupported = |query: &QueryIndex| {
            !self.held(*query)
                && self
                    .excluded
                    .iter()
                    .any(|excluded| excluded.query == *query && excluded.by == ExcludedBy::Format)
        };
        let alternatives = self.accepted.request().alternatives();
        if !alternatives.is_empty()
            && alternatives
                .iter()
                .all(|alternative| alternative.queries().iter().any(unsupported))
        {
            UnmetCode::VpFormatsNotSupported
        } else {
            UnmetCode::AccessDenied
        }
    }
}

/// What matching a credential against a query gives.
#[expect(clippy::large_enum_variant, reason = "consumed where it is returned")]
enum Considered<'m> {
    /// A candidate.
    Candidate(Candidate<'m>),
    /// A plug-in excluded it.
    Excluded(ExcludedBy, Exclude),
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
    catalog: &'m dyn Catalog,
    keys: &'k [AgreeableKey<'k>],
    env: &'k Env,
    rendering: &'k Rendering<'k>,
}

impl<'m, 'k> QueryMatcher<'m, 'k> {
    /// The matcher of a query whose format has a plug-in; `None` for another query.
    ///
    /// # Errors
    ///
    /// The transaction naming the query names a profile the registry does not hold.
    fn of(
        accepted: &'m Accepted<'m>,
        index: QueryIndex,
        query: &'m Query<'m>,
        keys: &'k [AgreeableKey<'k>],
        env: &'k Env,
        rendering: &'k Rendering<'k>,
    ) -> Result<Option<Self>, Fault> {
        let Some(formatted) = accepted
            .plan(index)
            .and_then(|plan| plan.formatted.as_ref())
        else {
            return Ok(None);
        };
        let transaction = accepted
            .transaction(index)
            .map(|t| {
                accepted
                    .registry()
                    .profile_ref(t.profile)
                    .map(|profile| (t, profile))
                    .ok_or_else(|| {
                        Fault::new(
                            FAULT,
                            detail!("a transaction names a profile the registry does not hold"),
                        )
                    })
            })
            .transpose()?;
        let members = transaction.and_then(|(_, profile)| {
            formatted
                .placement
                .and_then(|placement| profile.members(placement))
        });
        Ok(Some(Self {
            query,
            request: accepted.request(),
            formatted,
            transaction,
            members,
            catalog: accepted.registry(),
            keys,
            env,
            rendering,
        }))
    }

    /// OpenID4VP §6.1: the query's format, an issuer the query trusts, and a key the credential
    /// is bound to unless the query waives holder binding.
    fn eligible(&self, credential: &Credential<'_>) -> bool {
        let holder = self.query.holder_binding() == HolderBinding::Waived
            || credential.facts.holder == Holder::Bound;
        credential.format == *self.query.format() && credential.trusted_for(self.query) && holder
    }

    /// The credential as a candidate, when the plug-ins admit and bind it and it answers an
    /// option.
    fn consider(&self, credential: &'m Credential<'m>) -> Result<Considered<'m>, Fault> {
        let bound = match self
            .formatted
            .query
            .admits(credential, self.keys)
            .map_err(|refused| (ExcludedBy::Format, refused))
            .and_then(|()| {
                self.bind(credential)
                    .map_err(|refused| (ExcludedBy::Profile, refused))
            }) {
            Ok(bound) => bound,
            Err((by, NoCandidate::Excluded(exclude))) => {
                return Ok(Considered::Excluded(by, exclude));
            }
            Err((_, NoCandidate::Fault(fault))) => return Err(fault),
        };
        let selected = bound
            .as_ref()
            .and_then(|binding| binding.bound.selected.as_ref());
        let card_module = self.formatted.query.card_module(credential)?;
        let inputs = match self.rendering.renderer(
            selected,
            card_module,
            Some(credential.id.as_str()),
            self.env,
        )? {
            Ok(renderer) => renderer.inputs(),
            Err(unrendered) => {
                return Ok(Considered::Excluded(
                    ExcludedBy::Language,
                    Exclude::new(unrendered),
                ));
            }
        };
        let provided = match (&bound, self.members) {
            (Some(_), Some(members)) => members,
            _ => &[],
        };
        let options = self
            .formatted
            .query
            .answerable(credential, self.env, provided)?;
        let own = self.formatted.query.options();
        let ascending = options
            .windows(2)
            .all(|pair| matches!(pair, [a, b] if a < b));
        if !ascending || options.iter().any(|option| own.get(*option).is_none()) {
            return Err(Fault::new(
                FAULT,
                detail!(
                    "{query}: the format answered options {options:?} of its query's {count}",
                    query = self.query.id().to_string(),
                    count = own.iter().count()
                ),
            ));
        }
        if options.is_empty() {
            return Ok(Considered::Unanswered);
        }
        if self.reserved_elsewhere(credential)? {
            return Ok(Considered::Excluded(
                ExcludedBy::Profile,
                Exclude::new(ReservedCredential),
            ));
        }
        match self
            .formatted
            .query
            .displayable(credential, &options, self.env)
        {
            Ok(()) => Ok(Considered::Candidate(Candidate {
                credential,
                options,
                bound,
                inputs,
            })),
            Err(NoCandidate::Excluded(exclude)) => {
                Ok(Considered::Excluded(ExcludedBy::Display, exclude))
            }
            Err(NoCandidate::Fault(fault)) => Err(fault),
        }
    }

    /// Whether a profile reserves the credential whose entries name no part of this query.
    fn reserved_elsewhere(&self, credential: &'m Credential<'m>) -> Result<bool, Fault> {
        let additions = self.formatted.format.additions(credential)?;
        let own: Option<ProfileHandle> = self.transaction.map(|(t, _)| t.profile);
        Ok(self
            .catalog
            .reserving(credential, &*additions)?
            .into_iter()
            .any(|profile| Some(profile) != own))
    }

    /// The entries the profile binds to the credential with the transaction, for a query
    /// transaction data names.
    fn bind(
        &self,
        credential: &'m Credential<'m>,
    ) -> Result<Option<TransactionBinding<'m>>, NoCandidate> {
        let Some((transaction, profile)) = self.transaction else {
            return Ok(None);
        };
        let carriage = match self.members {
            Some(members) => self.formatted.query.carries(credential, members)?,
            None => Carriage::Uncarried,
        };
        let additions = self.formatted.format.additions(credential)?;
        let binding = Binding {
            request: self.request,
            query: self.query,
            credential,
            entries: &transaction.entries,
            placement: self.formatted.placement,
            additions: &*additions,
            carriage,
        };
        let bound = profile.bind(binding, self.env)?;
        if bound
            .entries
            .entries()
            .iter()
            .all(|entry| transaction.entries.contains(entry))
        {
            Ok(Some(TransactionBinding { transaction, bound }))
        } else {
            Err(Fault::new(
                FAULT,
                detail!(
                    "{query}: a profile bound entries no entry naming the query offered",
                    query = self.query.id().to_string()
                ),
            )
            .into())
        }
    }
}
