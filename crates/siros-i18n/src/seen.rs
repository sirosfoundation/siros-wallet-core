//! Repeats among a source's items, found in one pass.

use std::hash::Hash;

use rustc_hash::FxHashSet;

/// The first item an earlier one equals.
pub(crate) fn repeated<T: Copy + Eq + Hash>(items: impl IntoIterator<Item = T>) -> Option<T> {
    let mut seen = FxHashSet::default();
    items.into_iter().find(|item| !seen.insert(*item))
}
