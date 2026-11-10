//! The factoring of a family of sets into independent choices: the finest partition of its
//! positions over which the family is a product. The common refinement of two such partitions
//! is one, so the finest partition is unique.

use rustc_hash::FxHashSet;

use super::sets::{Position, Set};

/// The distinct intersections of the family's sets with `block`, in order of first appearance.
#[must_use]
pub fn project<P: Position>(family: &[Set<P>], block: Set<P>) -> Vec<Set<P>> {
    let mut out: Vec<Set<P>> = Vec::new();
    for set in family {
        let part = set.intersection(block);
        if !out.contains(&part) {
            out.push(part);
        }
    }
    out
}

/// Whether the family is the product of its projections on `block` and on `rest`.
#[must_use]
pub fn splits<P: Position>(family: &[Set<P>], block: Set<P>, rest: Set<P>) -> bool {
    let left = project(family, block);
    let right = project(family, rest);
    let products: FxHashSet<Set<P>> = left
        .iter()
        .flat_map(|x| right.iter().map(|y| x.union(*y)))
        .collect();
    let sets: FxHashSet<Set<P>> = family.iter().copied().collect();
    products == sets
}

/// The finest partition of the family's positions over which the family is a product, its
/// blocks in `order` of their first position. The block of each pivot is the smallest set holding
/// it that splits what remains: any splitting set holds the finest factoring's block.
#[must_use]
pub fn factor<P: Position>(family: &[Set<P>], order: &[P]) -> Vec<Set<P>> {
    let present = family.iter().fold(Set::empty(), |all, set| all.union(*set));
    let mut remaining: Vec<P> = order
        .iter()
        .copied()
        .filter(|p| present.contains(*p))
        .collect();
    let ordered = Set::of(remaining.iter().copied());
    remaining.extend(present.difference(ordered).iter());
    let mut blocks = Vec::new();
    let mut current = family.to_vec();
    while let Some((&pivot, others)) = remaining.split_first() {
        let all = Set::of(remaining.iter().copied());
        // The whole remainder always splits: its rest is empty.
        let found = (0..others.len())
            .flat_map(|size| Combinations::new(others, size))
            .map(|extra| extra.with(pivot))
            .find(|block| splits(&current, *block, all.difference(*block)))
            .unwrap_or(all);
        blocks.push(found);
        remaining.retain(|p| !found.contains(*p));
        current = project(&current, Set::of(remaining.iter().copied()));
    }
    blocks
}

/// The `size`-element combinations of `items` as sets, in lexicographic order of positions.
struct Combinations<'i, P> {
    items: &'i [P],
    indices: Vec<usize>,
    done: bool,
}

impl<'i, P: Position> Combinations<'i, P> {
    fn new(items: &'i [P], size: usize) -> Self {
        Self {
            items,
            indices: (0..size).collect(),
            done: size > items.len(),
        }
    }
}

impl<P: Position> Iterator for Combinations<'_, P> {
    type Item = Set<P>;

    fn next(&mut self) -> Option<Set<P>> {
        if self.done {
            return None;
        }
        let set = Set::of(
            self.items
                .iter()
                .enumerate()
                .filter(|(at, _)| self.indices.contains(at))
                .map(|(_, item)| *item),
        );
        let n = self.items.len();
        let k = self.indices.len();
        // Advance the rightmost index that can still move, then reset those after it.
        match self
            .indices
            .iter()
            .enumerate()
            .rev()
            .find(|&(i, &at)| at < n - k + i)
            .map(|(i, &at)| (i, at + 1))
        {
            Some((i, start)) => {
                for (offset, index) in self.indices.iter_mut().skip(i).enumerate() {
                    *index = start + offset;
                }
            }
            None => self.done = true,
        }
        Some(set)
    }
}
