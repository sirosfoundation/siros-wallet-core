//! The factoring of a request's alternatives into independent choices, over seeded random
//! requests: it reproduces the alternatives exactly (P1), and it is the meet of every
//! factoring found by brute force over all partitions of the queries, the unique finest (P2).

mod common;

use rand::seq::{IndexedRandom, SliceRandom};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use rustc_hash::FxHashSet;
use siros_openid4vp::request::{QueryIndex, QuerySet, factor, project};

use common::{parameters, request_of, unsigned};

/// A request as check.py's random run draws one: up to `max` queries; usually Credential Sets of
/// random options, sometimes listing the product of independent slots in any order.
fn random_request(rng: &mut ChaCha8Rng, max: usize) -> String {
    let ids: Vec<String> = (0..rng.random_range(1..=max))
        .map(|i| format!("q{i}"))
        .collect();
    let quoted = |option: &[&String]| {
        format!(
            "[{}]",
            option
                .iter()
                .map(|q| format!("\"{q}\""))
                .collect::<Vec<_>>()
                .join(",")
        )
    };
    let mut sets: Vec<String> = Vec::new();
    if rng.random_bool(0.8) {
        for _ in 0..rng.random_range(1..=3) {
            let options: Vec<String> = (0..rng.random_range(1..=3))
                .map(|_| {
                    let size = rng.random_range(1..=ids.len());
                    quoted(&ids.choose_multiple(rng, size).collect::<Vec<_>>())
                })
                .collect();
            let required = rng.random_bool(0.6);
            sets.push(format!(
                r#"{{"options":[{}],"required":{required}}}"#,
                options.join(",")
            ));
        }
        if ids.len() > 1 && rng.random_bool(0.4) {
            let mut pool: Vec<&String> = ids.iter().collect();
            pool.shuffle(rng);
            let count = rng.random_range(1..=2.min(pool.len() - 1));
            let mut cuts: Vec<usize> = (1..pool.len())
                .collect::<Vec<_>>()
                .choose_multiple(rng, count)
                .copied()
                .collect();
            cuts.sort_unstable();
            let bounds: Vec<usize> = std::iter::once(0)
                .chain(cuts)
                .chain(std::iter::once(pool.len()))
                .collect();
            let mut listed: Vec<Vec<&String>> = vec![Vec::new()];
            for (k, pair) in bounds.windows(2).enumerate() {
                let slot = &pool[pair[0]..pair[1]];
                let empty = k > 0 && rng.random_bool(0.5);
                let choices: Vec<Option<&String>> = slot
                    .iter()
                    .map(|q| Some(*q))
                    .chain(empty.then_some(None))
                    .collect();
                listed = listed
                    .iter()
                    .flat_map(|prefix| {
                        choices
                            .iter()
                            .map(move |c| prefix.iter().copied().chain(*c).collect())
                    })
                    .collect();
            }
            listed.shuffle(rng);
            let product: Vec<String> = listed.iter().map(|option| quoted(option)).collect();
            let required = rng.random_bool(0.6);
            let first = format!(
                r#"{{"options":[{}],"required":{required}}}"#,
                product.join(",")
            );
            sets = if rng.random_bool(0.5) {
                std::iter::once(first)
                    .chain(sets.into_iter().skip(1))
                    .collect()
            } else {
                vec![first]
            };
        }
    }
    let queries: Vec<String> = ids
        .iter()
        .map(|id| format!(r#"{{"id":"{id}","format":"test"}}"#))
        .collect();
    let sets = if sets.is_empty() {
        String::new()
    } else {
        format!(r#","credential_sets":[{}]"#, sets.join(","))
    };
    format!(r#"{{"credentials":[{}]{sets}}}"#, queries.join(","))
}

/// Every partition of the items into blocks.
fn partitions(items: &[QueryIndex]) -> Vec<Vec<QuerySet>> {
    let Some((head, tail)) = items.split_first() else {
        return vec![Vec::new()];
    };
    let mut out = Vec::new();
    for partition in partitions(tail) {
        let mut alone = vec![QuerySet::of([*head])];
        alone.extend(partition.iter().copied());
        out.push(alone);
        for k in 0..partition.len() {
            let mut joined = partition.clone();
            joined[k] = joined[k].with(*head);
            out.push(joined);
        }
    }
    out
}

/// The family is the product of its projections on the blocks.
fn rebuilds(family: &[QuerySet], blocks: &[QuerySet]) -> bool {
    let mut products: FxHashSet<QuerySet> = std::iter::once(QuerySet::empty()).collect();
    for block in blocks {
        let parts = project(family, *block);
        products = products
            .iter()
            .flat_map(|prefix| parts.iter().map(move |part| prefix.union(*part)))
            .collect();
    }
    products == family.iter().copied().collect()
}

/// The common refinement of two partitions.
fn meet(a: &FxHashSet<QuerySet>, b: &[QuerySet]) -> FxHashSet<QuerySet> {
    a.iter()
        .flat_map(|x| b.iter().map(move |y| x.intersection(*y)))
        .filter(|part| !part.is_empty())
        .collect()
}

#[test]
fn the_factoring_is_the_unique_finest_product() {
    let mut rng = ChaCha8Rng::seed_from_u64(1);
    let mut multi_block = 0;
    for k in 0..1500 {
        let text = parameters(&random_request(&mut rng, 6), "");
        let received = unsigned(&text).expect("received");
        let request = request_of(&received).expect("request");
        let family = request.alternative_sets();
        let blocks = factor(&family, request.query_order());
        assert!(rebuilds(&family, &blocks), "P1 at request {k}: {text}");
        let universe: Vec<QueryIndex> = family
            .iter()
            .fold(QuerySet::empty(), |all, set| all.union(*set))
            .iter()
            .collect();
        let mut finest: FxHashSet<QuerySet> = if universe.is_empty() {
            FxHashSet::default()
        } else {
            std::iter::once(QuerySet::of(universe.iter().copied())).collect()
        };
        for partition in partitions(&universe) {
            if rebuilds(&family, &partition) {
                finest = meet(&finest, &partition);
            }
        }
        assert_eq!(
            blocks.iter().copied().collect::<FxHashSet<_>>(),
            finest,
            "P2 at request {k}: {text}"
        );
        assert_eq!(blocks.len(), finest.len(), "each block once at request {k}");
        multi_block += usize::from(blocks.len() > 1);
    }
    assert!(
        multi_block > 100,
        "the generator reaches requests with independent choices: {multi_block}"
    );
}
