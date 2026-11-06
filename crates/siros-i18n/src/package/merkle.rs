//! RFC 9162 §2.1's Merkle tree over a package's entries: its root and nodes when a package is
//! built, and an entry's audit path checked against the root through ct-merkle when it is read.
//! ct-merkle keeps its tree's nodes private, so the builder hashes them in array order itself.

use ct_merkle::{InclusionProof, RootHash, indices_for_inclusion_proof};
#[cfg(feature = "load")]
use sha2::Digest as _;
use sha2::Sha256;

/// The array-order indices of the nodes of entry `index`'s audit path in a tree of `entries`
/// leaves; `None` for an index outside the tree.
pub(super) fn path(entries: usize, index: usize) -> Option<Vec<u64>> {
    let (entries, index) = (u64::try_from(entries).ok()?, u64::try_from(index).ok()?);
    (index < entries).then(|| indices_for_inclusion_proof(entries, index))
}

/// Whether `entry` is leaf `index` of the tree of `entries` leaves whose root is `root`, through
/// the audit path `nodes`.
pub(super) fn includes(
    root: [u8; 32],
    entries: usize,
    index: usize,
    entry: &[u8],
    nodes: &[[u8; 32]],
) -> bool {
    let (Ok(entries), Ok(index)) = (u64::try_from(entries), u64::try_from(index)) else {
        return false;
    };
    let digests: Vec<_> = nodes.iter().map(|&node| node.into()).collect();
    let proof = InclusionProof::<Sha256>::from_digests(&digests);
    RootHash::<Sha256>::new(root.into(), entries)
        .verify_inclusion(&entry, index, &proof)
        .is_ok()
}

/// The array-order index of the root of a tree of `entries` leaves, one or more:
/// 2^⌈log2 entries⌉ − 1. `None` for no leaf.
pub(super) fn root_index(entries: usize) -> Option<u64> {
    let width = u64::try_from(entries).ok()?.checked_next_power_of_two()?;
    width.checked_sub(1).filter(|_| entries > 0)
}

/// The tree over `entries` in array order, which is the in-order walk of RFC 9162 §2.1.1's
/// tree: a tree of more than one leaf splits at the largest power of two below its size into a
/// left tree, its root, and a right tree.
#[cfg(feature = "load")]
pub(super) fn tree(entries: &[Vec<u8>]) -> Tree {
    match entries {
        [] => Tree::empty(),
        [entry] => Tree::leaf(entry),
        _ => {
            let split = entries.len().next_power_of_two() / 2;
            [entries.get(..split), entries.get(split..)]
                .into_iter()
                .flatten()
                .map(tree)
                .fold(Tree::empty(), Tree::join)
        }
    }
}

/// A tree's root and its nodes in array order.
#[cfg(feature = "load")]
pub(super) struct Tree {
    pub(super) root: [u8; 32],
    pub(super) nodes: Vec<[u8; 32]>,
}

#[cfg(feature = "load")]
impl Tree {
    /// The tree of no entry: `SHA-256()`, and no node.
    fn empty() -> Self {
        Self {
            root: Sha256::digest([]).into(),
            nodes: Vec::new(),
        }
    }

    /// The tree of one entry: its leaf hash, `SHA-256(0x00 || entry)`, which is its one node.
    fn leaf(entry: &[u8]) -> Self {
        let root = Sha256::new()
            .chain_update([0])
            .chain_update(entry)
            .finalize()
            .into();
        Self {
            root,
            nodes: vec![root],
        }
    }

    /// `self` and `right` under a parent `SHA-256(0x01 || left || right)`, its node between
    /// theirs. A tree of no entry is no child: the other tree stands alone.
    fn join(self, right: Self) -> Self {
        if self.nodes.is_empty() {
            return right;
        }
        if right.nodes.is_empty() {
            return self;
        }
        let parent = Sha256::new()
            .chain_update([1])
            .chain_update(self.root)
            .chain_update(right.root);
        let root = parent.finalize().into();
        let mut nodes = self.nodes;
        nodes.push(root);
        nodes.extend(right.nodes);
        Self { root, nodes }
    }
}
