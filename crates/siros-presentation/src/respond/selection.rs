//! The user's selection, parsed against the plan (A3, A4), and the refusal of a background
//! fulfilment that needs the wallet's display (A9).

use siros_dcql::{Multiplicity, QueryId};
use siros_wallet_state::CredentialId;

use crate::display_rule::{DisplayFacts, HostDisplay, WalletDisplay};
use crate::error::PresentationError;
use crate::ids::{AdditionIndex, CandidateIndex, OfferIndex, QueryIndex};
use crate::inconsistency::Inconsistency;
use crate::offers::{Addition, Member, Offer};
use crate::plan::{PlanDigest, Planned};

/// The user's choice in a consent view, as the UI returns it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Selection {
    digest: PlanDigest,
    offer: OfferIndex,
    additions: Vec<AdditionIndex>,
    subsets: Vec<Subset>,
}

/// The credentials chosen for the member of a `multiple` Credential Query, by `credentialId`:
/// a set, whatever order it lists them in.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Subset {
    query: QueryId,
    credentials: Vec<CredentialId>,
}

/// Why the credentials a subset names are refused (A3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}", self.code())]
pub enum SubsetError {
    /// The subset names no credential.
    Empty,
    /// The subset names this credential twice.
    Repeated(CredentialId),
    /// The member holds no credential of this `credentialId`.
    Unknown(CredentialId),
}

impl SubsetError {
    /// A stable identifier.
    pub fn code(self) -> &'static str {
        match self {
            Self::Empty => "selection_subset_empty",
            Self::Repeated(_) => "selection_subset_credential_repeated",
            Self::Unknown(_) => "selection_subset_credential_unknown",
        }
    }
}

impl Subset {
    /// The credentials `credentials` for the member of the query `query`.
    pub fn new(query: QueryId, credentials: Vec<CredentialId>) -> Self {
        Self { query, credentials }
    }
}

impl Selection {
    /// The choice of the offer at `offer`, of its additions at `additions`, and of `subsets`
    /// for members of `multiple` queries, in the view whose
    /// [`ConsentView::digest`](crate::ConsentView::digest) is `digest`. A `multiple` member
    /// without a subset presents every credential the view shows for it.
    pub fn new(
        digest: PlanDigest,
        offer: OfferIndex,
        additions: Vec<AdditionIndex>,
        subsets: Vec<Subset>,
    ) -> Self {
        Self {
            digest,
            offer,
            additions,
            subsets,
        }
    }

    /// The plan's offer the selection chooses.
    pub fn offer(&self) -> OfferIndex {
        self.offer
    }
}

/// How the wallet fulfils a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Fulfilment {
    /// On its own UI, where the user consented.
    WalletUi,
    /// From its background service, after the user consented on the picker's display, which
    /// showed the picked entries as this says: skipped when a picked entry's metadata says
    /// `display_skipped`.
    Background(HostDisplay),
}

/// An offer and additions of a plan that the user chose, with the credentials chosen for each
/// member.
pub struct Chosen<'p, 'a> {
    pub(crate) planned: &'p Planned<'a>,
    /// The plan's offer: its entries bind as the view showed them.
    pub(crate) offer: &'p Offer,
    /// The chosen additions: their entries bind as the view showed them.
    pub(crate) additions: Vec<&'p Addition>,
    /// The offer's members, in its order, each with the chosen candidates.
    pub(crate) members: Vec<Member>,
    /// The members of the chosen additions.
    pub(crate) added: Vec<Member>,
}

impl<'a> Planned<'a> {
    /// The offer `selection` chose in this plan, fulfilled as `fulfilment` says.
    ///
    /// # Errors
    ///
    /// [`PresentationError`]: the digest of another plan; an unknown offer or addition; two
    /// additions of one optional set or answering one query; a subset of no `multiple` query
    /// or of one no chosen member answers, a second subset for one member, or a subset
    /// refused; a choice that leaves out a credential a transaction entry binds to; or a
    /// background fulfilment of an offer that needs the wallet's display.
    pub fn choose(
        &self,
        selection: &Selection,
        fulfilment: Fulfilment,
    ) -> Result<Chosen<'_, 'a>, PresentationError> {
        if selection.digest != *self.view.digest() {
            return Err(PresentationError::DigestMismatch);
        }
        let view = self
            .view
            .offers()
            .get(selection.offer.value())
            .ok_or(PresentationError::OfferUnknown(selection.offer))?;
        let offer = view.offer();
        let additions = self.additions(offer, &selection.additions)?;
        let mut members = offer.members().to_vec();
        let mut added: Vec<Member> = additions
            .iter()
            .flat_map(|addition| addition.members().iter().cloned())
            .collect();
        for (at, subset) in selection.subsets.iter().enumerate() {
            if selection
                .subsets
                .iter()
                .take(at)
                .any(|s| s.query == subset.query)
            {
                return Err(PresentationError::SubsetRepeated(subset.query.clone()));
            }
            let query = self.multiple_query(&subset.query)?;
            let member = members
                .iter_mut()
                .chain(added.iter_mut())
                .find(|member| member.query() == query)
                .ok_or_else(|| PresentationError::SubsetMember(subset.query.clone()))?;
            let held = self.held(member)?;
            *member = chosen(member, &held, &subset.credentials)?;
        }
        self.keeps_bound_credentials(offer.members(), &members)?;
        for addition in &additions {
            self.keeps_bound_credentials(addition.members(), &added)?;
        }
        if let Fulfilment::Background(host) = fulfilment {
            let facts = DisplayFacts {
                host,
                ..view.facts()
            };
            if WalletDisplay::of(&facts) == WalletDisplay::Needed {
                return Err(PresentationError::WalletDisplayNeeded);
            }
        }
        Ok(Chosen {
            planned: self,
            offer,
            additions,
            members,
            added,
        })
    }

    /// The additions of `offer` at `chosen`, at most one per optional set, none answering a
    /// query another answers (A3).
    fn additions<'o>(
        &self,
        offer: &'o Offer,
        chosen: &[AdditionIndex],
    ) -> Result<Vec<&'o Addition>, PresentationError> {
        let mut additions: Vec<&Addition> = Vec::with_capacity(chosen.len());
        for &index in chosen {
            let addition = offer
                .additions()
                .get(index.value())
                .ok_or(PresentationError::AdditionUnknown(index))?;
            if additions.iter().any(|a| a.set() == addition.set()) {
                return Err(PresentationError::AdditionSetRepeated(addition.set()));
            }
            let shared = addition.members().iter().find(|member| {
                additions
                    .iter()
                    .flat_map(|a| a.members())
                    .any(|other| other.query() == member.query())
            });
            if let Some(member) = shared {
                return Err(PresentationError::AdditionQueryRepeated(
                    self.query_id(member.query())?,
                ));
            }
            additions.push(addition);
        }
        Ok(additions)
    }

    /// The position of the `multiple` Credential Query `id`.
    fn multiple_query(&self, id: &QueryId) -> Result<QueryIndex, PresentationError> {
        self.answered
            .index_of(id.as_str())
            .filter(|&index| {
                self.answered
                    .answers(index)
                    .is_some_and(|answers| answers.query().multiplicity() == Multiplicity::Several)
            })
            .ok_or_else(|| PresentationError::SubsetQuery(id.clone()))
    }

    /// Each candidate of `member`, a member of an offer of this plan, with the `credentialId`
    /// of its credential.
    ///
    /// # Errors
    ///
    /// [`Inconsistency`]: `member` names a query or a candidate the plan's matching lacks.
    pub(super) fn held(
        &self,
        member: &Member,
    ) -> Result<Vec<(CandidateIndex, CredentialId)>, Inconsistency> {
        Ok(
            crate::transactions::offered(&self.answered, std::slice::from_ref(member))?
                .into_iter()
                .flat_map(|offered| offered.candidates)
                .map(|(index, c)| (index, c.credential().credential().entry().credential_id()))
                .collect(),
        )
    }

    /// Checks that `chosen` keep every credential a transaction entry binds to among `planned`,
    /// the members of the offer or of an addition as the view showed them, so the binding of the
    /// chosen credentials is the plan's (T4).
    fn keeps_bound_credentials(
        &self,
        planned: &[Member],
        chosen: &[Member],
    ) -> Result<(), PresentationError> {
        let chosen = crate::transactions::offered(&self.answered, chosen)?;
        for binding in self.transactions.bind(&self.answered, planned)? {
            let kept = chosen.iter().any(|member| {
                member
                    .candidates
                    .iter()
                    .any(|&(_, candidate)| member.carries(&binding.bound, candidate))
            });
            if !kept {
                return Err(PresentationError::BoundCredentialOmitted {
                    entry: binding.entry.position(),
                    credential: binding.bound.credential,
                });
            }
        }
        Ok(())
    }

    /// The `id` of the Credential Query at `index`, a query of an offer of this plan.
    ///
    /// # Errors
    ///
    /// [`Inconsistency::Query`] when the plan's matching has no query at `index`.
    pub(super) fn query_id(&self, index: QueryIndex) -> Result<QueryId, Inconsistency> {
        self.answered
            .answers(index)
            .map(|answers| answers.id().clone())
            .ok_or(Inconsistency::Query(index))
    }
}

/// The member of the candidates of `member` whose `credentialId` `credentials` names, in the
/// member's order. `held` holds each candidate with its `credentialId`.
///
/// # Errors
///
/// [`SubsetError`]: no credential, one named twice, or one the member does not hold.
fn chosen(
    member: &Member,
    held: &[(CandidateIndex, CredentialId)],
    credentials: &[CredentialId],
) -> Result<Member, SubsetError> {
    if credentials.is_empty() {
        return Err(SubsetError::Empty);
    }
    let repeated = credentials
        .iter()
        .enumerate()
        .find(|&(at, id)| credentials.iter().take(at).any(|other| other == id));
    if let Some((_, &id)) = repeated {
        return Err(SubsetError::Repeated(id));
    }
    if let Some(&unknown) = credentials
        .iter()
        .find(|&id| held.iter().all(|(_, held)| held != id))
    {
        return Err(SubsetError::Unknown(unknown));
    }
    Ok(member.keeping(|candidate| {
        held.iter()
            .any(|(c, id)| *c == candidate && credentials.contains(id))
    }))
}
