//! Repeats among a source's items, found in one pass.

use std::hash::Hash;

use rustc_hash::{FxBuildHasher, FxHashSet};

/// The first item an earlier one equals.
pub(crate) fn repeated<T: Copy + Eq + Hash>(items: impl IntoIterator<Item = T>) -> Option<T> {
    let mut items = items.into_iter();
    let mut seen = FxHashSet::with_capacity_and_hasher(items.size_hint().0, FxBuildHasher);
    items.find(|item| !seen.insert(*item))
}
