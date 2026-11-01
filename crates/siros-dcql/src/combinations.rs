//! The combinations of candidates that satisfy a request (§6.4): what a picker offers, each as
//! one choice.

use serde_json::Value;

use crate::id::QueryId;
use crate::query::{Multiplicity, SetRequirement};
use crate::result::{Candidate, QueryMatch, QueryResult, Satisfaction};

/// One way to satisfy the whole request.
///
/// Every member is presented *together*: this is what the picker offers as a
/// single choice, and what the user consents to as a unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Combination {
    members: Vec<(QueryId, Candidate)>,
    purposes: Vec<Value>,
}

/// How many combinations were left out.
///
/// The number of combinations is a product of the per-query widths, and a wallet holding enough
/// credentials overflows it: the count is then a lower bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dropped {
    /// Exactly this many were left out.
    Exact(usize),
    /// At least this many were left out: the true product overflows `usize`.
    AtLeast(usize),
}

/// The combinations that satisfy a request, and whether the list was cut short.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Combinations {
    combinations: Vec<Combination>,
    dropped: Dropped,
}

impl Combination {
    /// Which credential answers which query, with the claims to disclose.
    #[must_use]
    pub fn members(&self) -> &[(QueryId, Candidate)] {
        &self.members
    }

    /// Why the verifier asked for this, from the `purpose` of each credential set this
    /// combination satisfies (§6.2), in set order.
    ///
    /// Carried per combination because that is where it is needed: a request with several
    /// credential sets offers several combinations, and the reason shown beside one of them is
    /// the reason belonging to *its* set. Empty when the verifier gave no reason, which
    /// includes every request without `credential_sets`.
    #[must_use]
    pub fn purposes(&self) -> &[Value] {
        &self.purposes
    }
}

impl Dropped {
    /// The number, exact or a bound. Pair it with [`Self::is_exact`] before showing it to
    /// anyone.
    #[must_use]
    pub fn count(self) -> usize {
        match self {
            Self::Exact(n) | Self::AtLeast(n) => n,
        }
    }

    /// Whether [`Self::count`] is the true number.
    #[must_use]
    pub fn is_exact(self) -> bool {
        matches!(self, Self::Exact(_))
    }

    /// Whether anything was dropped at all.
    #[must_use]
    pub fn any(self) -> bool {
        self.count() > 0
    }

    /// Both counts together.
    ///
    /// A bound when either side is one, or when the sum overflows, which two exact counts can
    /// do.
    fn add(self, other: Self) -> Self {
        match self.count().checked_add(other.count()) {
            Some(total) if self.is_exact() && other.is_exact() => Self::Exact(total),
            Some(total) => Self::AtLeast(total),
            None => Self::AtLeast(usize::MAX),
        }
    }
}

impl Combinations {
    /// Ways to satisfy the request, in wallet order.
    #[must_use]
    pub fn combinations(&self) -> &[Combination] {
        &self.combinations
    }

    /// How many were left out to stay within the caller's limit. A picker that shows the first
    /// few of many without saying so tells the user those are the only options they have.
    #[must_use]
    pub fn dropped(&self) -> Dropped {
        self.dropped
    }

    fn none() -> Self {
        Self {
            combinations: Vec::new(),
            dropped: Dropped::Exact(0),
        }
    }
}

/// A required group: the purpose of its set, and the options whose every query is satisfied,
/// each as one wheel per query.
struct Group<'r> {
    purpose: Option<&'r Value>,
    options: Vec<Vec<Wheel<'r>>>,
}

impl QueryResult {
    /// Enumerate the ways this wallet can satisfy the request.
    ///
    /// A combination is a set of credentials presented *together*, which is what a picker
    /// offers as one selectable option. Alternatives are separate combinations.
    ///
    /// `limit` bounds the result, because the count is a product: three queries with four
    /// candidates each is sixty-four combinations. [`Combinations::dropped`] counts whatever is
    /// left out.
    ///
    /// Optional credential sets (§6.2 `required: false`) are left out. The wallet MAY include
    /// them, so whether to offer one is a UI decision about what to ask the user for, and
    /// folding them in here would multiply the combination count for choices the verifier can
    /// do without.
    #[must_use]
    pub fn combinations(&self, limit: usize) -> Combinations {
        if self.satisfaction() == Satisfaction::Unsatisfiable {
            return Combinations::none();
        }
        let groups = self.required_groups();
        // Every set optional: nothing is required, so there is no combination to enumerate.
        // One empty combination here would hand the picker an option holding no credential.
        // What to offer from the optional sets is the caller's decision.
        if groups.is_empty() {
            return Combinations::none();
        }

        // Choose one option per required group, then one candidate per query in the chosen
        // options.
        let mut out: Vec<Combination> = vec![Combination {
            members: Vec::new(),
            purposes: Vec::new(),
        }];
        let mut dropped = Dropped::Exact(0);

        for group in &groups {
            let mut next: Vec<Combination> = Vec::new();
            for partial in &out {
                for option in &group.options {
                    // Generate only what still fits, and count what is skipped from the
                    // arithmetic: the full product can be enormous.
                    let budget = limit.saturating_sub(next.len());
                    let (products, skipped) = candidate_products(option, budget);
                    dropped = dropped.add(skipped);
                    for members in products {
                        let mut combined = partial.members.clone();
                        combined.extend(members);
                        let mut purposes = partial.purposes.clone();
                        purposes.extend(group.purpose.cloned());
                        next.push(Combination {
                            members: combined,
                            purposes,
                        });
                    }
                }
            }
            out = next;
            if out.is_empty() {
                break;
            }
        }

        Combinations {
            combinations: out,
            dropped,
        }
    }

    /// Each required group: the queries one combination must all answer. Without
    /// `credential_sets` that is every query (§6.4); with them it is one satisfied option per
    /// required set.
    fn required_groups(&self) -> Vec<Group<'_>> {
        match self.credential_sets() {
            None => vec![Group {
                purpose: None,
                options: self
                    .matches()
                    .iter()
                    .map(Wheel::of)
                    .collect::<Option<Vec<_>>>()
                    .into_iter()
                    .collect(),
            }],
            Some(sets) => sets
                .iter()
                .filter(|s| s.requirement() == SetRequirement::Required)
                .map(|set| Group {
                    purpose: set.purpose(),
                    options: set
                        .options()
                        .iter()
                        .filter_map(|option| self.wheels(option))
                        .collect(),
                })
                .collect(),
        }
    }

    /// One wheel per query of `option`, when every query it names has a candidate.
    fn wheels(&self, option: &[QueryId]) -> Option<Vec<Wheel<'_>>> {
        option
            .iter()
            .map(|id| self.query(id).and_then(Wheel::of))
            .collect()
    }
}

/// Up to `budget` ways to answer the queries of `option`, and how many further ways existed.
///
/// The count is a product of the per-query widths, computed without building the combinations
/// it counts.
fn candidate_products(
    option: &[Wheel<'_>],
    budget: usize,
) -> (Vec<Vec<(QueryId, Candidate)>>, Dropped) {
    // Whether the product ran out of `usize` on the way. Tracked apart from the value, since a
    // genuine product can also reach `usize::MAX`; the clamped value is then a bound.
    let mut overflowed = false;
    let total = option.iter().fold(1_usize, |total, wheel| {
        total.checked_mul(wheel.width()).unwrap_or_else(|| {
            overflowed = true;
            usize::MAX
        })
    });
    let take = total.min(budget);
    // How many members each combination holds, the same for every product.
    let members: usize = option.iter().map(|wheel| wheel.members().len()).sum();

    // An odometer over the wheels, the first turning fastest: only the products wanted are
    // built.
    let mut wheels = option.to_vec();
    let mut products = Vec::new();
    for _ in 0..take {
        let mut product = Vec::with_capacity(members);
        for wheel in &wheels {
            let id = wheel.query.query_id();
            product.extend(
                wheel
                    .members()
                    .iter()
                    .map(|candidate| (id.clone(), candidate.clone())),
            );
        }
        products.push(product);
        turn(&mut wheels);
    }

    let remaining = total - take;
    let dropped = if overflowed {
        Dropped::AtLeast(remaining)
    } else {
        Dropped::Exact(remaining)
    };
    (products, dropped)
}

/// Advance the odometer `wheels` by one product.
fn turn(wheels: &mut [Wheel<'_>]) {
    for wheel in wheels {
        if wheel.turn() == Carry::Within {
            return;
        }
    }
}

/// The ways one query with at least one candidate answers within a combination, and the way
/// the odometer stands at.
///
/// One way per candidate. A query that set §6.1 `multiple` is answered by all its candidates
/// together, one way: "multiple Credentials can be returned for this Credential Query". That
/// reading gives the flag its effect, collapses the combination count, and the holder still
/// consents to the combination as a whole.
#[derive(Clone)]
struct Wheel<'r> {
    query: &'r QueryMatch,
    first: &'r Candidate,
    rest: &'r [Candidate],
    current: &'r Candidate,
    next: core::slice::Iter<'r, Candidate>,
}

/// Whether turning a wheel passed its last way and turns the next wheel too.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Carry {
    /// The wheel moved to its next way.
    Within,
    /// The wheel went back to its first way.
    Over,
}

impl<'r> Wheel<'r> {
    /// The wheel of `query` at its first way; `None` when the query has no candidate.
    fn of(query: &'r QueryMatch) -> Option<Self> {
        let (first, rest) = query.candidates().split_first()?;
        Some(Self {
            query,
            first,
            rest,
            current: first,
            next: rest.iter(),
        })
    }

    /// How many ways the query answers, at least one.
    fn width(&self) -> usize {
        match self.query.multiplicity() {
            Multiplicity::Several => 1,
            Multiplicity::One => self.rest.len() + 1,
        }
    }

    /// The candidates of the way the wheel stands at.
    fn members(&self) -> &'r [Candidate] {
        match self.query.multiplicity() {
            Multiplicity::Several => self.query.candidates(),
            Multiplicity::One => core::slice::from_ref(self.current),
        }
    }

    /// Move to the next way.
    fn turn(&mut self) -> Carry {
        if self.query.multiplicity() == Multiplicity::One {
            if let Some(candidate) = self.next.next() {
                self.current = candidate;
                return Carry::Within;
            }
        }
        self.current = self.first;
        self.next = self.rest.iter();
        Carry::Over
    }
}
