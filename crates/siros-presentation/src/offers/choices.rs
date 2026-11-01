//! The ways to satisfy a credential set or a request, enumerated lazily, and the limits of what
//! an enumeration examines.

use std::ops::Deref;

use itertools::Itertools;
use serde_json::Value;
use siros_dcql::{CredentialSetQuery, Dropped, Multiplicity};

use super::{Member, MAX_EXAMINED};
use crate::credential::MatchCredential;
use crate::ids::{CandidateIndex, QueryIndex};
use crate::matching::Answered;

/// A Credential Query of an option, and its eligible candidates, at least one. A query of
/// [`Multiplicity::One`] is answered by one of them in one combination, one of
/// [`Multiplicity::Several`] by every one.
#[derive(Debug, Clone)]
struct Slot {
    query: QueryIndex,
    multiplicity: Multiplicity,
    candidates: Vec<CandidateIndex>,
}

impl Slot {
    /// The slot of `query`'s eligible `candidates`; `None` without one.
    fn of(
        query: QueryIndex,
        multiplicity: Multiplicity,
        candidates: Vec<CandidateIndex>,
    ) -> Option<Self> {
        (!candidates.is_empty()).then_some(Self {
            query,
            multiplicity,
            candidates,
        })
    }

    /// The number of ways to answer the query in one combination.
    fn width(&self) -> usize {
        match self.multiplicity {
            Multiplicity::One => self.candidates.len(),
            Multiplicity::Several => 1,
        }
    }

    /// The member of each way, in the order of the candidates.
    fn ways(&self) -> impl Iterator<Item = Member> + Clone + '_ {
        let ways: Vec<Vec<CandidateIndex>> = match self.multiplicity {
            Multiplicity::One => self.candidates.iter().map(|&c| vec![c]).collect(),
            Multiplicity::Several => vec![self.candidates.clone()],
        };
        ways.into_iter().map(move |candidates| Member {
            query: self.query,
            candidates,
        })
    }
}

/// The Credential Queries of a request, each with its slot, or none without an eligible
/// candidate.
pub(super) struct Space<'a> {
    queries: Vec<(&'a str, Option<Slot>)>,
}

impl<'a> Space<'a> {
    /// The queries of `answered`, each with the candidates `eligible` accepts.
    pub(super) fn of<C: MatchCredential, R>(
        answered: &'a Answered<'_, C, R>,
        eligible: &impl Fn(QueryIndex, CandidateIndex) -> bool,
    ) -> Self {
        let queries = answered
            .indexed()
            .map(|(query, answers)| {
                let candidates = (0..answers.candidates().len())
                    .map(CandidateIndex::new)
                    .filter(|&candidate| eligible(query, candidate))
                    .collect();
                let slot = Slot::of(query, answers.query().multiplicity(), candidates);
                (answers.id().as_str(), slot)
            })
            .collect();
        Self { queries }
    }

    /// The slot of the Credential Query `id`; `None` when no query has the id or the query has
    /// no eligible candidate.
    fn slot(&self, id: &str) -> Option<Slot> {
        self.queries
            .iter()
            .find(|(query, _)| *query == id)
            .and_then(|(_, slot)| slot.clone())
    }
}

/// The ways to satisfy a credential set, or the whole request: an option, and a way to answer
/// each query of the option.
pub(super) struct Choices {
    purpose: Option<Value>,
    options: Vec<Vec<Slot>>,
    /// `None` when the count overflows.
    count: Option<usize>,
}

impl Choices {
    /// Every query at once: the request without `credential_sets`.
    pub(super) fn all(space: &Space<'_>) -> Self {
        let option = space.queries.iter().map(|(_, slot)| slot.clone()).collect();
        Self::of_options(None, [option])
    }

    /// The options of `set` whose every query has a candidate. An option that names a query
    /// the request lacks is one no credential satisfies (Section 6.4).
    pub(super) fn of_set(space: &Space<'_>, set: &CredentialSetQuery) -> Self {
        let options = set
            .options()
            .iter()
            .map(|ids| ids.iter().map(|id| space.slot(id)).collect());
        Self::of_options(set.purpose().cloned(), options)
    }

    /// The choices of the `options` that have a slot for each query.
    fn of_options(
        purpose: Option<Value>,
        options: impl IntoIterator<Item = Option<Vec<Slot>>>,
    ) -> Self {
        let options: Vec<Vec<Slot>> = options
            .into_iter()
            .flatten()
            .filter(|slots| !slots.is_empty())
            .collect();
        let count = sum(options
            .iter()
            .map(|slots| product(slots.iter().map(|slot| Some(slot.width())))));
        Self {
            purpose,
            options,
            count,
        }
    }

    /// The set's `purpose`.
    pub(super) fn purpose(&self) -> Option<&Value> {
        self.purpose.as_ref()
    }

    /// The number of choices; `None` when it overflows.
    pub(super) fn count(&self) -> Option<usize> {
        self.count
    }

    /// Each choice: the options in order, and in each the ways of its queries, the last query
    /// varying fastest.
    pub(super) fn iter(&self) -> impl Iterator<Item = Vec<Member>> + Clone + '_ {
        self.options.iter().flat_map(|slots| {
            slots
                .iter()
                .map(|slot| slot.ways())
                .multi_cartesian_product()
        })
    }
}

/// The product of `factors`: zero with a zero factor, else `None` on overflow or for an
/// overflowed factor.
pub(super) fn product(factors: impl Iterator<Item = Option<usize>>) -> Option<usize> {
    let factors: Vec<Option<usize>> = factors.collect();
    if factors.contains(&Some(0)) {
        return Some(0);
    }
    factors
        .into_iter()
        .try_fold(1usize, |product, factor| product.checked_mul(factor?))
}

/// The sum of `terms`; `None` on overflow or for an overflowed term.
pub(super) fn sum(mut terms: impl Iterator<Item = Option<usize>>) -> Option<usize> {
    terms.try_fold(0usize, |sum, term| sum.checked_add(term?))
}

/// An enumeration that gives at most [`MAX_EXAMINED`] items, and counts those it gave.
pub(super) struct Examining<I> {
    items: std::iter::Take<I>,
    examined: usize,
}

/// A number of combinations examined, at most [`MAX_EXAMINED`].
#[derive(Debug, Clone, Copy)]
pub(super) struct Examined(usize);

impl<I: Iterator> Examining<I> {
    pub(super) fn new(items: I) -> Self {
        Self {
            items: items.take(MAX_EXAMINED),
            examined: 0,
        }
    }

    /// How many items it gave so far.
    pub(super) fn examined(&self) -> Examined {
        Examined(self.examined)
    }
}

impl<I: Iterator> Iterator for Examining<I> {
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        let item = self.items.next()?;
        self.examined += 1;
        Some(item)
    }
}

impl Examined {
    /// What remains of `total` combinations; at least what remains of `usize::MAX` when the
    /// total overflows.
    pub(super) fn unexamined(self, total: Option<usize>) -> Dropped {
        match total {
            Some(total) => Dropped::Exact(total.saturating_sub(self.0)),
            None => Dropped::AtLeast(usize::MAX.saturating_sub(self.0)),
        }
    }
}

/// At most `N` items: the first `N` of what it is collected from.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct Capped<T, const N: usize>(Vec<T>);

impl<T, const N: usize> FromIterator<T> for Capped<T, N> {
    fn from_iter<I: IntoIterator<Item = T>>(items: I) -> Self {
        Self(items.into_iter().take(N).collect())
    }
}

impl<T, const N: usize> Deref for Capped<T, N> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        &self.0
    }
}
