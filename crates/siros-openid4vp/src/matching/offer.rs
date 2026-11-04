//! The consent's shape on the platform: sets of slots of alternative entries, in the shape
//! the wallet chooses.

use super::{CandidateIndex, Consent, Match, Pick};
use crate::product::product;
use crate::request::{Multiplicity, QueryIndex};
use crate::rows::Choice;

/// An entry of a slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Offered {
    /// A pick.
    Pick(Pick),
    /// The empty choice: "none".
    Nothing,
}

/// A slot: its alternative entries.
pub type OfferSlot = Vec<Offered>;
/// A set: its slots, one entry chosen per slot.
pub type OfferSet = Vec<OfferSlot>;
/// One way to show something as slots.
type Way = Vec<OfferSlot>;

/// A candidate's entries: one per answerable option.
fn entries(matched: &Match<'_>, query: QueryIndex, candidate: CandidateIndex) -> OfferSlot {
    matched
        .candidate(query, candidate)
        .map(|found| {
            found
                .options
                .iter()
                .map(|option| {
                    Offered::Pick(Pick {
                        query,
                        candidate,
                        option: *option,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Each way to show the query's fills as slots of entries. Without `multiple`: one slot of every
/// candidate's entries. With it: per first member, that member's slot, the transaction-bearing
/// member it takes in when it carries none itself, then each later candidate without a
/// transaction with "none"; every fill appears exactly once.
#[must_use]
pub fn ways(matched: &Match<'_>, query: QueryIndex) -> Vec<Way> {
    let candidates = matched.candidates(query);
    let indices = (0..candidates.len()).map(CandidateIndex);
    let multiple = matched
        .accepted()
        .request()
        .query(query)
        .is_some_and(|q| q.multiple == Multiplicity::Many);
    if !multiple {
        return vec![vec![
            indices
                .flat_map(|candidate| entries(matched, query, candidate))
                .collect(),
        ]];
    }
    let bearing = |k: usize| {
        candidates
            .get(k)
            .is_some_and(|candidate| candidate.bound.is_some())
    };
    let mut out = Vec::new();
    for first in 0..candidates.len() {
        let later = first + 1..candidates.len();
        let plain: Vec<usize> = later.clone().filter(|k| !bearing(*k)).collect();
        let joining: Vec<Option<usize>> = std::iter::once(None)
            .chain(later.filter(|k| !bearing(first) && bearing(*k)).map(Some))
            .collect();
        for joined in joining {
            let mut way = vec![entries(matched, query, CandidateIndex(first))];
            way.extend(joined.map(|k| entries(matched, query, CandidateIndex(k))));
            for k in &plain {
                let mut slot = entries(matched, query, CandidateIndex(*k));
                slot.push(Offered::Nothing);
                way.push(slot);
            }
            out.push(way);
        }
    }
    out
}

/// Each way to answer the query, as its picks, in the order its ways show them.
#[must_use]
pub fn fills(matched: &Match<'_>, query: QueryIndex) -> Vec<Vec<Pick>> {
    ways(matched, query)
        .iter()
        .flat_map(|way| product(way))
        .map(|combination| {
            combination
                .into_iter()
                .filter_map(|offered| match offered {
                    Offered::Pick(pick) => Some(pick),
                    Offered::Nothing => None,
                })
                .collect()
        })
        .collect()
}

/// The queries of an option in the order they first appear across the alternatives.
fn ordered(matched: &Match<'_>, option: crate::request::QuerySet) -> Vec<QueryIndex> {
    matched
        .accepted()
        .request()
        .query_order()
        .iter()
        .copied()
        .filter(|query| option.contains(*query))
        .collect()
}

/// The consent's shape when the wallet preselects each slot's default: sets of slots of
/// alternative entries. Per consent slot, in the order of its options: each run of ways that are
/// single slots joins one slot, with "none" for ∅; every other way is a branch of its own; the
/// sets are the product of the branches. The user meets each slot's options in their order, and
/// the first set's first entries are the defaults.
#[must_use]
pub fn flatten(matched: &Match<'_>, consent: &Consent) -> Vec<OfferSet> {
    let per_slot: Vec<Vec<Way>> = consent
        .slots
        .iter()
        .map(|slot| {
            let mut branches: Vec<Way> = Vec::new();
            let mut merged: Option<usize> = None;
            for option in &slot.options {
                let contributions: Vec<Way> = if option.is_empty() {
                    vec![vec![vec![Offered::Nothing]]]
                } else {
                    let per_query: Vec<Vec<Way>> = ordered(matched, *option)
                        .into_iter()
                        .map(|q| ways(matched, q))
                        .collect();
                    product(&per_query)
                        .into_iter()
                        .map(|combination| combination.into_iter().flatten().collect())
                        .collect()
                };
                for way in contributions {
                    match <[OfferSlot; 1]>::try_from(way) {
                        Ok([single]) => match merged
                            .and_then(|k| branches.get_mut(k))
                            .and_then(|branch| branch.first_mut())
                        {
                            Some(open) => open.extend(single),
                            None => {
                                merged = Some(branches.len());
                                branches.push(vec![single]);
                            }
                        },
                        Err(way) => {
                            branches.push(way);
                            merged = None;
                        }
                    }
                }
            }
            branches
        })
        .collect();
    product(&per_slot)
        .into_iter()
        .map(|combination| combination.into_iter().flatten().collect())
        .collect()
}

/// The consent's shape when the wallet lets the user choose: one set per selection,
/// every slot holding one entry, "none" for ∅. The sets follow each slot's options in order and
/// open on the same selection as [`flatten`]'s.
#[must_use]
pub fn each(matched: &Match<'_>, consent: &Consent) -> Vec<OfferSet> {
    let per_slot: Vec<Vec<Way>> = consent
        .slots
        .iter()
        .map(|slot| {
            slot.options
                .iter()
                .flat_map(|option| -> Vec<Way> {
                    if option.is_empty() {
                        return vec![vec![vec![Offered::Nothing]]];
                    }
                    let per_query: Vec<Vec<Vec<Pick>>> = ordered(matched, *option)
                        .into_iter()
                        .map(|q| fills(matched, q))
                        .collect();
                    product(&per_query)
                        .into_iter()
                        .map(|combination| {
                            combination
                                .into_iter()
                                .flatten()
                                .map(|pick| vec![Offered::Pick(pick)])
                                .collect()
                        })
                        .collect()
                })
                .collect()
        })
        .collect();
    product(&per_slot)
        .into_iter()
        .map(|combination| combination.into_iter().flatten().collect())
        .collect()
}

/// The consent's sets for the wallet's choice.
#[must_use]
pub fn offer(matched: &Match<'_>, consent: &Consent, choice: Choice) -> Vec<OfferSet> {
    match choice {
        Choice::First => flatten(matched, consent),
        Choice::LetChoose => each(matched, consent),
    }
}
