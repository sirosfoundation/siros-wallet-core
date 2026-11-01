//! The selection the user makes by picking credential picker entries (K3).

use siros_dcql::{Multiplicity, QueryId};
use siros_wallet_state::CredentialId;

use super::selection::{Selection, Subset};
use crate::error::PresentationError;
use crate::ids::{AdditionIndex, OfferIndex, QueryIndex};
use crate::inconsistency::Inconsistency;
use crate::offers::{Addition, Member, Offer};
use crate::pick::Pick;
use crate::plan::Planned;

/// Why the picked entries make no selection (K3).
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}", self.code())]
pub enum PickError {
    /// The user picked no entry.
    Empty,
    /// The picks name two offers: the first pick's, then this one.
    Offers(OfferIndex, OfferIndex),
    /// Two picks name this credential for this Credential Query.
    Repeated {
        /// The Credential Query.
        query: QueryId,
        /// The credential.
        credential: CredentialId,
    },
    /// No member of the offer or of its additions answers this Credential Query.
    Query(QueryId),
    /// No member of the offer or of its additions answers this Credential Query with this
    /// credential.
    Credential {
        /// The Credential Query.
        query: QueryId,
        /// The credential.
        credential: CredentialId,
    },
    /// No pick names a credential of the offer's member of this Credential Query.
    Missing(QueryId),
    /// No additions of the offer, at most one per optional set, answer exactly the picked
    /// queries the offer's members leave.
    Additions,
    /// No offer of the plan holds the picks: each of its members picked, each pick a credential
    /// of a member or of its additions. Each offer, with why it does not.
    Unmatched(Vec<(OfferIndex, PickError)>),
    /// These offers of the plan each hold the picks: by their members alone, or, when no
    /// offer's members alone hold them, through their additions.
    Ambiguous(Vec<OfferIndex>),
}

impl PickError {
    /// A stable identifier.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Empty => "pick_empty",
            Self::Offers(..) => "pick_offers",
            Self::Repeated { .. } => "pick_repeated",
            Self::Query(_) => "pick_query_unknown",
            Self::Credential { .. } => "pick_credential_unknown",
            Self::Missing(_) => "pick_member_missing",
            Self::Additions => "pick_additions",
            Self::Unmatched(_) => "pick_unmatched",
            Self::Ambiguous(_) => "pick_ambiguous",
        }
    }
}

/// The credentials the picks name for one Credential Query, in the order of the picks.
struct Picked {
    query: QueryIndex,
    id: QueryId,
    credentials: Vec<CredentialId>,
}

impl Picked {
    /// Checks that `held` holds each picked credential.
    fn held_in(&self, held: &[CredentialId]) -> Result<(), PickError> {
        match self.credentials.iter().find(|id| !held.contains(id)) {
            Some(&credential) => Err(PickError::Credential {
                query: self.id.clone(),
                credential,
            }),
            None => Ok(()),
        }
    }
}

impl Planned<'_> {
    /// The selection the user made by picking `picks` (K3): the one offer of the plan that
    /// holds them, with the additions whose members they name, and for each `multiple` member
    /// the picked credentials. The picks hold their Credential Queries and `credentialId`s;
    /// the offer they name is the picker's, which numbers offers the wallet leaves out under a
    /// K2 exception, so the plan's offer is the one that holds them. The picker shows an
    /// offer's members, and the plan holds one offer per set of members: the offer whose
    /// members alone hold the picks is selected first, and an offer through its additions
    /// only when no offer's members alone hold them.
    ///
    /// When several combinations of additions answer the picked queries, the first in the
    /// offer's order is chosen: each presents the picked credentials.
    ///
    /// # Errors
    ///
    /// [`PresentationError::Pick`]: no pick; picks of two of the picker's offers; a pick
    /// repeated or of a query the request lacks; no offer that holds the picks, or several.
    pub fn picked(&self, picks: &[Pick]) -> Result<Selection, PresentationError> {
        let first = picks.first().ok_or(PickError::Empty)?;
        if let Some(other) = picks.iter().find(|pick| pick.offer != first.offer) {
            return Err(PickError::Offers(first.offer, other.offer).into());
        }
        let repeated = picks
            .iter()
            .enumerate()
            .find(|&(at, pick)| picks.iter().take(at).any(|other| other == pick));
        if let Some((_, pick)) = repeated {
            return Err(PickError::Repeated {
                query: pick.query.clone(),
                credential: pick.credential,
            }
            .into());
        }
        let picked = self.by_query(picks)?;
        let (mut alone, mut through, mut unheld) = (Vec::new(), Vec::new(), Vec::new());
        for (at, view) in self.view.offers().iter().enumerate() {
            let at = OfferIndex::new(at);
            let members = view.offer().members();
            let by_members = picked
                .iter()
                .all(|picked| members.iter().any(|member| member.query() == picked.query));
            match self.held_by(at, view.offer(), &picked) {
                Ok(selection) if by_members => alone.push(selection),
                Ok(selection) => through.push(selection),
                Err(PresentationError::Pick(why)) => unheld.push((at, why)),
                Err(error) => return Err(error),
            }
        }
        let held = if alone.is_empty() { through } else { alone };
        match <[Selection; 1]>::try_from(held) {
            Ok([selection]) => Ok(selection),
            Err(held) if held.is_empty() => Err(PickError::Unmatched(unheld).into()),
            Err(held) => {
                Err(PickError::Ambiguous(held.iter().map(Selection::offer).collect()).into())
            }
        }
    }

    /// The selection of `offer`, the plan's offer at `at`, that `picked` makes.
    ///
    /// # Errors
    ///
    /// [`PresentationError::Pick`]: a pick no member of the offer or of its additions holds;
    /// an offer member without a pick; or picked queries no combination of additions answers.
    fn held_by(
        &self,
        at: OfferIndex,
        offer: &Offer,
        picked: &[Picked],
    ) -> Result<Selection, PresentationError> {
        let mut subsets = Vec::new();
        for member in offer.members() {
            let named = match picked.iter().find(|picked| picked.query == member.query()) {
                Some(named) => named,
                None => return Err(PickError::Missing(self.query_id(member.query())?).into()),
            };
            named.held_in(&self.ids([member])?)?;
            subsets.extend(self.subset(named)?);
        }
        let left: Vec<&Picked> = picked
            .iter()
            .filter(|picked| offer.members().iter().all(|m| m.query() != picked.query))
            .collect();
        let additions: Vec<(AdditionIndex, &Addition)> = offer
            .additions()
            .iter()
            .enumerate()
            .map(|(at, addition)| (AdditionIndex::new(at), addition))
            .collect();
        for named in &left {
            self.held_by_additions(&additions, named)?;
            subsets.extend(self.subset(named)?);
        }
        let mut fitting: Vec<(AdditionIndex, &Addition)> = Vec::new();
        for (index, addition) in additions {
            if self.fits(addition, &left)? {
                fitting.push((index, addition));
            }
        }
        let mut queries: Vec<QueryIndex> = left.iter().map(|picked| picked.query).collect();
        queries.sort_unstable();
        let mut chosen = cover(&fitting, &queries).ok_or(PickError::Additions)?;
        chosen.sort_unstable();
        Ok(Selection::new(*self.view.digest(), at, chosen, subsets))
    }

    /// The picks of `picks` grouped by Credential Query, in the order of their first pick.
    fn by_query(&self, picks: &[Pick]) -> Result<Vec<Picked>, PickError> {
        let mut picked: Vec<Picked> = Vec::new();
        for pick in picks {
            match picked.iter_mut().find(|picked| picked.id == pick.query) {
                Some(same) => same.credentials.push(pick.credential),
                None => picked.push(Picked {
                    query: self
                        .answered
                        .index_of(&pick.query)
                        .ok_or_else(|| PickError::Query(pick.query.clone()))?,
                    id: pick.query.clone(),
                    credentials: vec![pick.credential],
                }),
            }
        }
        Ok(picked)
    }

    /// The `credentialId`s of the candidates of `members`.
    ///
    /// # Errors
    ///
    /// [`Inconsistency`]: a member names a query or a candidate the plan's matching lacks.
    fn ids<'m>(
        &self,
        members: impl IntoIterator<Item = &'m Member>,
    ) -> Result<Vec<CredentialId>, Inconsistency> {
        let mut ids = Vec::new();
        for member in members {
            ids.extend(self.held(member)?.into_iter().map(|(_, id)| id));
        }
        Ok(ids)
    }

    /// Checks that the members of `additions` that answer the query of `picks` hold each of its
    /// credentials.
    fn held_by_additions(
        &self,
        additions: &[(AdditionIndex, &Addition)],
        picks: &Picked,
    ) -> Result<(), PresentationError> {
        let members: Vec<&Member> = additions
            .iter()
            .flat_map(|(_, addition)| addition.members())
            .filter(|member| member.query() == picks.query)
            .collect();
        if members.is_empty() {
            return Err(PickError::Query(picks.id.clone()).into());
        }
        Ok(picks.held_in(&self.ids(members)?)?)
    }

    /// Whether the picks `left` name a credential of each member of `addition`, and only
    /// credentials the member holds for its query.
    ///
    /// # Errors
    ///
    /// [`Inconsistency`]: a member names a query or a candidate the plan's matching lacks.
    fn fits(&self, addition: &Addition, left: &[&Picked]) -> Result<bool, Inconsistency> {
        for member in addition.members() {
            let Some(picks) = left.iter().find(|picked| picked.query == member.query()) else {
                return Ok(false);
            };
            if picks.held_in(&self.ids([member])?).is_err() {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// The subset of `picks` when they answer a `multiple` Credential Query.
    ///
    /// # Errors
    ///
    /// [`Inconsistency::Query`] when the plan's matching has no query at `picks.query`.
    fn subset(&self, picks: &Picked) -> Result<Option<Subset>, Inconsistency> {
        let answers = self
            .answered
            .answers(picks.query)
            .ok_or(Inconsistency::Query(picks.query))?;
        Ok((answers.query().multiplicity() == Multiplicity::Several)
            .then(|| Subset::new(picks.id.clone(), picks.credentials.clone())))
    }
}

/// The additions among `fitting` that answer each query of `queries`, in the request's order,
/// once, at most one per optional set: the first such combination in the order of `fitting`.
fn cover(
    fitting: &[(AdditionIndex, &Addition)],
    queries: &[QueryIndex],
) -> Option<Vec<AdditionIndex>> {
    let Some(&first) = queries.first() else {
        return Some(Vec::new());
    };
    fitting
        .iter()
        .filter(|(_, addition)| {
            let answers = |query| addition.members().iter().any(|m| m.query() == query);
            answers(first)
                && addition
                    .members()
                    .iter()
                    .all(|m| queries.contains(&m.query()))
        })
        .find_map(|&(index, addition)| {
            let rest: Vec<QueryIndex> = queries
                .iter()
                .copied()
                .filter(|&query| addition.members().iter().all(|m| m.query() != query))
                .collect();
            let others: Vec<(AdditionIndex, &Addition)> = fitting
                .iter()
                .copied()
                .filter(|(_, other)| other.set() != addition.set())
                .collect();
            let mut chosen = cover(&others, &rest)?;
            chosen.push(index);
            Some(chosen)
        })
}
