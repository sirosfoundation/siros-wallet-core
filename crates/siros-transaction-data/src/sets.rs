//! Transaction data and DCQL credential sets (PaSO Core, Section 7.4.1): the targeted Credential
//! Queries sit in the options of one credential set, and the alternatives that involve them are
//! transposable.

use siros_dcql::{CredentialSetQuery, DcqlQuery, QueryId};

use crate::entry::Entry;

siros_codec::position!(
    /// The position of a credential set in `credential_sets`.
    pub SetPosition
);

/// Why the credential sets of a request break PaSO Core, Section 7.4.1.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum SetsFault {
    /// This targeted Credential Query appears in the options of no credential set, or of
    /// another set than the first targeted query's.
    Split(QueryId),
    /// This targeted Credential Query also appears in the options of a second credential set.
    Repeated(QueryId),
    /// The alternatives of the credential set at this position that involve a targeted query
    /// cannot be decomposed into independent slots.
    NotTransposable(SetPosition),
}

impl SetsFault {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Split(_) => "credential_sets_split",
            Self::Repeated(_) => "credential_sets_repeated",
            Self::NotTransposable(_) => "credential_sets_not_transposable",
        }
    }
}

/// Checks the credential sets of `query` against the queries `entries` target: without
/// `credential_sets` every query is required together, which holds. With them, one set's
/// options name every targeted query and no other set's options name one, and that set's
/// alternatives that name one are transposable.
///
/// # Errors
///
/// [`SetsFault`]: the first rule the sets break.
pub(crate) fn check(entries: &[Entry], query: &DcqlQuery) -> Result<(), SetsFault> {
    let Some(sets) = query.credential_sets() else {
        return Ok(());
    };
    let mut targeted: Vec<&QueryId> = Vec::new();
    for id in entries.iter().flat_map(Entry::credential_ids) {
        if !targeted.contains(&id) {
            targeted.push(id);
        }
    }
    let Some(first) = targeted.first() else {
        return Ok(());
    };
    let names = |set: &CredentialSetQuery, id: &QueryId| {
        set.options().iter().any(|option| option.contains(id))
    };
    let (position, set) = sets
        .iter()
        .enumerate()
        .find(|(_, set)| names(set, first))
        .ok_or_else(|| SetsFault::Split((*first).clone()))?;
    if let Some(split) = targeted.iter().find(|id| !names(set, id)) {
        return Err(SetsFault::Split((*split).clone()));
    }
    let repeated = targeted.iter().find(|id| {
        sets.iter()
            .enumerate()
            .any(|(other, set)| other != position && names(set, id))
    });
    if let Some(repeated) = repeated {
        return Err(SetsFault::Repeated((*repeated).clone()));
    }
    let alternatives: Vec<Vec<&str>> = set
        .options()
        .iter()
        .filter(|option| option.iter().any(|named| targeted.contains(&named)))
        .map(|option| sorted_set(option.iter().map(QueryId::as_str)))
        .collect();
    if transposable(alternatives) {
        Ok(())
    } else {
        Err(SetsFault::NotTransposable(SetPosition::new(position)))
    }
}

/// Whether `alternatives`, each a set of query ids, are exactly every combination of a choice
/// from each of some independent slots (Section 7.4.1).
///
/// Two ids of one slot never appear together, and two of different slots appear together in
/// some alternative. So the slots are the classes of "never together", which must be an
/// equivalence; a slot is optional when an alternative names none of its ids; and the distinct
/// alternatives number the product of each slot's choices.
fn transposable(alternatives: Vec<Vec<&str>>) -> bool {
    let alternatives = sorted_set(alternatives);
    let ids = sorted_set(alternatives.iter().flatten().copied());
    let together = |a: &str, b: &str| {
        alternatives
            .iter()
            .any(|alt| alt.contains(&a) && alt.contains(&b))
    };
    let apart = |a: &str, b: &str| a != b && !together(a, b);
    let equivalence = ids.iter().all(|&a| {
        ids.iter()
            .all(|&b| !apart(a, b) || ids.iter().all(|&c| a == c || !apart(b, c) || apart(a, c)))
    });
    if !equivalence {
        return false;
    }
    let mut slots: Vec<Vec<&str>> = Vec::new();
    for &id in &ids {
        match slots
            .iter_mut()
            .find(|slot| slot.iter().any(|&other| apart(id, other)))
        {
            Some(slot) => slot.push(id),
            None => slots.push(vec![id]),
        }
    }
    let product = slots.iter().try_fold(1usize, |product, slot| {
        let optional = alternatives
            .iter()
            .any(|alt| slot.iter().all(|id| !alt.contains(id)));
        product.checked_mul(slot.len() + usize::from(optional))
    });
    product == Some(alternatives.len())
}

/// `items` in order, each once.
fn sorted_set<T: Ord>(items: impl IntoIterator<Item = T>) -> Vec<T> {
    let mut set: Vec<T> = Vec::new();
    for item in items {
        let (mut before, after): (Vec<T>, Vec<T>) =
            set.into_iter().partition(|other| *other < item);
        // `after` starts with the least member not below `item`: `item` itself, when present.
        if after.first() != Some(&item) {
            before.push(item);
        }
        before.extend(after);
        set = before;
    }
    set
}
