//! Sets of at most 64 positions: the Credential Queries of an alternative, the items of an
//! option. The factoring and the consent compute over them.

use std::fmt;
use std::marker::PhantomData;

/// The largest number of positions a set holds.
pub const MAX_POSITIONS: usize = 64;

/// A position number below [`MAX_POSITIONS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Slot(u8);

impl Slot {
    /// The slot `at`, when `at` is below [`MAX_POSITIONS`].
    #[must_use]
    pub fn new(at: usize) -> Option<Self> {
        u8::try_from(at)
            .ok()
            .filter(|at| usize::from(*at) < MAX_POSITIONS)
            .map(Self)
    }

    /// The number.
    #[must_use]
    pub const fn get(self) -> usize {
        self.0 as usize
    }

    /// Every slot in ascending order.
    fn all() -> impl Iterator<Item = Self> {
        (0..MAX_POSITIONS as u8).map(Self)
    }

    /// The slot's bit in a set.
    const fn bit(self) -> u64 {
        1 << self.0
    }
}

/// A position a [`Set`] holds.
pub trait Position: Copy + Eq + Ord + std::hash::Hash + fmt::Debug {
    /// The position at `slot`.
    fn at(slot: Slot) -> Self;
    /// The position's slot.
    fn slot(self) -> Slot;
}

/// A Credential Query by its position in the request's `credentials`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct QueryIndex(Slot);

impl QueryIndex {
    /// The position in the request's `credentials`.
    #[must_use]
    pub const fn get(self) -> usize {
        self.0.get()
    }

    /// The query at `at`, when `at` is below [`MAX_POSITIONS`].
    #[must_use]
    pub fn new(at: usize) -> Option<Self> {
        Slot::new(at).map(Self)
    }
}

impl Position for QueryIndex {
    fn at(slot: Slot) -> Self {
        Self(slot)
    }

    fn slot(self) -> Slot {
        self.0
    }
}

/// An item of a Credential Query's options, as its format numbers them (a claim, a request).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Item(Slot);

impl Item {
    /// The item `at`, when `at` is below [`MAX_POSITIONS`].
    #[must_use]
    pub fn new(at: usize) -> Option<Self> {
        Slot::new(at).map(Self)
    }

    /// The item's number.
    #[must_use]
    pub const fn get(self) -> usize {
        self.0.get()
    }
}

impl Position for Item {
    fn at(slot: Slot) -> Self {
        Self(slot)
    }

    fn slot(self) -> Slot {
        self.0
    }
}

/// A set of positions.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Set<P> {
    bits: u64,
    kind: PhantomData<P>,
}

impl<P: Position> Set<P> {
    /// The empty set.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            bits: 0,
            kind: PhantomData,
        }
    }

    /// The set of these positions.
    pub fn of(positions: impl IntoIterator<Item = P>) -> Self {
        positions.into_iter().fold(Self::empty(), Self::with)
    }

    /// The set with one more position.
    #[must_use]
    pub fn with(self, position: P) -> Self {
        self.union(Self {
            bits: position.slot().bit(),
            kind: PhantomData,
        })
    }

    /// Whether the set holds the position.
    #[must_use]
    pub fn contains(self, position: P) -> bool {
        self.bits & position.slot().bit() != 0
    }

    /// The union.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self {
            bits: self.bits | other.bits,
            kind: PhantomData,
        }
    }

    /// The intersection.
    #[must_use]
    pub const fn intersection(self, other: Self) -> Self {
        Self {
            bits: self.bits & other.bits,
            kind: PhantomData,
        }
    }

    /// The positions of `self` outside `other`.
    #[must_use]
    pub const fn difference(self, other: Self) -> Self {
        Self {
            bits: self.bits & !other.bits,
            kind: PhantomData,
        }
    }

    /// Whether the set is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.bits == 0
    }

    /// The number of positions.
    #[must_use]
    pub const fn len(self) -> usize {
        self.bits.count_ones() as usize
    }

    /// The positions in ascending order.
    pub fn iter(self) -> impl Iterator<Item = P> {
        Slot::all()
            .filter(move |slot| self.bits & slot.bit() != 0)
            .map(P::at)
    }
}

impl<P: Position> fmt::Debug for Set<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.iter()).finish()
    }
}

impl<P: Position> FromIterator<P> for Set<P> {
    fn from_iter<I: IntoIterator<Item = P>>(positions: I) -> Self {
        Self::of(positions)
    }
}

/// A set of Credential Queries.
pub type QuerySet = Set<QueryIndex>;
/// A set of items.
pub type ItemSet = Set<Item>;
