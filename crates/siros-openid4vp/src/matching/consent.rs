//! The consent: the independent choices the request's alternatives factor into, each with the
//! options the wallet can meet.

use super::{Candidate, Match};
use crate::plugins::{OptionIndex, OptionItems, Options};
use crate::request::{ItemSet, QuerySet, factor, project};

/// One independent choice: its queries, and its options in request order, the default first;
/// the empty set is ∅, presenting none of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Slot {
    block: QuerySet,
    options: Vec<QuerySet>,
}

impl Slot {
    /// The queries the choice decides.
    #[must_use]
    pub const fn block(&self) -> QuerySet {
        self.block
    }

    /// The options the wallet can meet, at least one.
    #[must_use]
    pub fn options(&self) -> &[QuerySet] {
        &self.options
    }
}

/// The independent choices of a request the wallet can meet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Consent {
    slots: Vec<Slot>,
}

impl Consent {
    /// The choices in request order.
    #[must_use]
    pub fn slots(&self) -> &[Slot] {
        &self.slots
    }

    /// The independent choices; `None` when the wallet cannot meet the request. Each slot lists
    /// its options in the order they first appear across the request's alternatives, which puts
    /// the first alternative's selection first (PaSO Core §7.4.1). An option naming a query
    /// without candidates is left out (OpenID4VP §6.4.2), so the first option listed is the
    /// default.
    #[must_use]
    pub fn of(matched: &Match<'_>) -> Option<Self> {
        let request = matched.accepted().request();
        let alternatives = request.alternative_sets();
        let slots: Vec<Slot> = factor(&alternatives, request.query_order())
            .into_iter()
            .map(|block| Slot {
                block,
                options: project(&alternatives, block)
                    .into_iter()
                    .filter(|option| option.iter().all(|query| matched.held(query)))
                    .collect(),
            })
            .collect();
        slots
            .iter()
            .all(|slot| !slot.options.is_empty())
            .then_some(Self { slots })
    }
}

/// The candidate's answerable options factored into independent choices, by the factoring the
/// Credential Sets use: the answerable options can couple items the Verifier's options leave
/// independent. Each choice with its options as item sets.
#[must_use]
pub fn answer_slots(options: &Options, candidate: &Candidate<'_>) -> Vec<(ItemSet, Vec<ItemSet>)> {
    let answerable: Vec<&OptionItems> = candidate
        .options
        .iter()
        .filter_map(|option| options.get(*option))
        .collect();
    let family: Vec<ItemSet> = answerable.iter().map(|option| option.set()).collect();
    let mut order = Vec::new();
    for item in answerable.iter().flat_map(|option| option.items()) {
        if !order.contains(item) {
            order.push(*item);
        }
    }
    factor(&family, &order)
        .into_iter()
        .map(|block| (block, project(&family, block)))
        .collect()
}

/// The option the chosen items answer: the first answerable option holding exactly them.
#[must_use]
pub fn option_of(
    options: &Options,
    candidate: &Candidate<'_>,
    items: ItemSet,
) -> Option<OptionIndex> {
    candidate
        .options
        .iter()
        .copied()
        .find(|option| options.get(*option).is_some_and(|o| o.set() == items))
}
