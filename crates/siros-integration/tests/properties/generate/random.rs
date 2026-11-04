//! check.py's `random_run`: an abstract request and wallet, drawn from a seed.

use crate::common::HaipHost;
use rand::Rng;
use rand::seq::SliceRandom;
use rand_chacha::ChaCha8Rng;
use serde_json::json;
use siros_openid4vp::ids::{TransactionType, TypePrefix};
use siros_openid4vp::matching::Accepted;
use siros_openid4vp::plugins::Registry;

use siros_testkit::fixtures::{self, NONCE};
use siros_testkit::verifier::{self};
use siros_testkit::{Binds, TestFormat, TestProfile};

use super::{ALGS, Obj, pick, product, sample, string};

/// An abstract Credential Query of check.py's core run.
pub(super) struct AbstractQuery {
    pub(super) id: String,
    /// "test", else a format no plug-in handles.
    pub(super) registered: bool,
    pub(super) multiple: bool,
    pub(super) holder_binding: bool,
    /// The options over four items; none gives the query one option of no item.
    pub(super) options: Vec<Vec<usize>>,
}

/// An abstract entry: `t1`, `t2` or `t9` and the queries it names.
pub(super) struct AbstractEntry {
    pub(super) kind: &'static str,
    pub(super) credential_ids: Vec<String>,
    pub(super) algs: Option<&'static [&'static str]>,
}

/// An abstract credential: the queries it answers and the abstract types it supports.
pub(super) struct AbstractCredential {
    pub(super) id: String,
    pub(super) answers: Vec<String>,
    pub(super) supports: Vec<&'static str>,
}

/// A Credential Set: its options and whether it is required.
pub(super) type Set = (Vec<Vec<String>>, bool);

pub(super) struct Abstract {
    pub(super) queries: Vec<AbstractQuery>,
    pub(super) sets: Option<Vec<Set>>,
    pub(super) entries: Vec<AbstractEntry>,
}

pub(super) fn sets_json(sets: &[Set]) -> String {
    json!(
        sets.iter()
            .map(|(options, required)| json!({"options": options, "required": required}))
            .collect::<Vec<_>>()
    )
    .to_string()
}

impl Abstract {
    /// check.py's random request: queries, Credential Sets (often the transposable product of
    /// independent slots), entries of `t1`, `t2` or `t9`.
    pub(super) fn draw(rng: &mut ChaCha8Rng, max_queries: usize) -> Self {
        let ids: Vec<String> = (0..rng.random_range(1..=max_queries))
            .map(|i| format!("q{i}"))
            .collect();
        let mut sets = None;
        if rng.random_bool(0.8) {
            let drawn: Vec<Set> = (0..rng.random_range(1..=3))
                .map(|_| {
                    let options = (0..rng.random_range(1..=3))
                        .map(|_| {
                            let k = rng.random_range(1..=ids.len());
                            sample(rng, &ids, k)
                        })
                        .collect();
                    (options, rng.random_bool(0.6))
                })
                .collect();
            sets = Some(drawn);
            // A set listing the product of independent slots in any order: PaSO Core §7.4.1's
            // transposable alternatives. The first slot has no ∅.
            if ids.len() > 1 && rng.random_bool(0.4) {
                let pool = sample(rng, &ids, ids.len());
                let positions: Vec<usize> = (1..pool.len()).collect();
                let count = rng.random_range(1..=2.min(pool.len() - 1));
                let mut cuts = sample(rng, &positions, count);
                cuts.sort_unstable();
                let starts = std::iter::once(0).chain(cuts.iter().copied());
                let ends = cuts.iter().copied().chain(std::iter::once(pool.len()));
                let choices: Vec<Vec<Vec<String>>> = starts
                    .zip(ends)
                    .enumerate()
                    .map(|(k, (from, to))| {
                        let mut choice: Vec<Vec<String>> =
                            pool[from..to].iter().map(|q| vec![q.clone()]).collect();
                        if k > 0 && rng.random_bool(0.5) {
                            choice.push(Vec::new());
                        }
                        choice
                    })
                    .collect();
                let mut listed: Vec<Vec<String>> = product(&choices)
                    .into_iter()
                    .map(|combination| combination.concat())
                    .collect();
                listed.shuffle(rng);
                let drawn = sets.take().expect("drawn sets");
                let required = drawn[0].1;
                let mut transposable = vec![(listed, required)];
                if rng.random_bool(0.5) {
                    transposable.extend(drawn.into_iter().skip(1));
                }
                sets = Some(transposable);
            }
        }
        let queries = ids
            .iter()
            .map(|id| AbstractQuery {
                id: id.clone(),
                registered: rng.random_bool(0.95),
                multiple: rng.random_bool(0.15),
                holder_binding: rng.random_bool(0.9),
                options: (0..rng.random_range(0..=3))
                    .map(|_| {
                        let k = rng.random_range(1..=3);
                        let mut option = sample(rng, &[0, 1, 2, 3], k);
                        option.sort_unstable();
                        option
                    })
                    .collect(),
            })
            .collect();
        let entries = (0..rng.random_range(0..=3))
            .map(|_| {
                let kind = if rng.random_bool(0.95) {
                    pick(rng, &["t1", "t2"])
                } else {
                    "t9"
                };
                let k = rng.random_range(1..=2.min(ids.len()));
                let mut credential_ids = sample(rng, &ids, k);
                if rng.random_bool(0.03) {
                    credential_ids.push("qX".to_owned());
                }
                let algs = if rng.random_bool(0.97) {
                    pick(rng, &ALGS)
                } else {
                    Some(&["md5"][..])
                };
                AbstractEntry {
                    kind,
                    credential_ids,
                    algs,
                }
            })
            .collect();
        Self {
            queries,
            sets,
            entries,
        }
    }

    /// Whether the core with the test plug-ins accepts the request: t1 and t2 one profile or two,
    /// t2 by its identifier or as a prefix, as check.py registers them.
    pub(super) fn accepted(&self, rng: &mut ChaCha8Rng) -> bool {
        let one = TestProfile::new(if rng.random_bool(0.5) {
            Binds::Every
        } else {
            Binds::First
        });
        let shared = rng.random_bool(0.5);
        let two = if rng.random_bool(0.5) {
            Binds::Every
        } else {
            Binds::First
        };
        let by_prefix = rng.random_bool(0.5);
        let mut builder = Registry::<HaipHost>::builder();
        builder.format(TestFormat::new().expect("the test format"));
        let first = builder.profile(one);
        let second = if shared {
            first
        } else {
            builder.profile(TestProfile::new(two))
        };
        builder.exact(TransactionType::parse("t1").expect("t1"), first);
        if by_prefix {
            builder.prefix(TypePrefix::parse("t2").expect("t2"), second);
        } else {
            builder.exact(TransactionType::parse("t2").expect("t2"), second);
        }
        let registry = builder.build().expect("the test registry");
        let queries: Vec<String> = self
            .queries
            .iter()
            .map(|q| {
                let mut object = Obj::default()
                    .with("id", string(&q.id))
                    .with(
                        "format",
                        string(if q.registered { "test" } else { "unregistered" }),
                    )
                    .with("multiple", q.multiple.to_string())
                    .with(
                        "require_cryptographic_holder_binding",
                        q.holder_binding.to_string(),
                    );
                if !q.options.is_empty() {
                    object.put("options", json!(q.options).to_string());
                }
                object.text()
            })
            .collect();
        let entries: Vec<String> = self
            .entries
            .iter()
            .map(|e| {
                let mut object = Obj::default()
                    .with("type", string(e.kind))
                    .with("credential_ids", json!(e.credential_ids).to_string());
                if let Some(algs) = e.algs {
                    object.put("transaction_data_hashes_alg", json!(algs).to_string());
                }
                verifier::encode(&object.text()).expect("an entry")
            })
            .collect();
        let parameters = parameters(
            &queries,
            self.sets.as_deref(),
            &entries,
            "dc_api",
            "{}",
            None,
        );
        let received = fixtures::unsigned(&parameters).expect("an abstract request arrives");
        let request = fixtures::request_of(&received).expect("an abstract request parses");
        Accepted::new(&request, &registry).is_ok()
    }
}

/// The request parameters a Verifier sends over the DC API (oracle/export.py `parameters`).
pub(super) fn parameters(
    queries: &[String],
    sets: Option<&[Set]>,
    entries: &[String],
    response_mode: &str,
    client_metadata: &str,
    expected_origins: Option<&[&str]>,
) -> String {
    let mut dcql = format!("{{\"credentials\": [{}]", queries.join(", "));
    if let Some(sets) = sets {
        dcql.push_str(&format!(", \"credential_sets\": {}", sets_json(sets)));
    }
    dcql.push('}');
    let mut out = Obj::default()
        .with("response_type", string("vp_token"))
        .with("response_mode", string(response_mode))
        .with("nonce", string(NONCE))
        .with("client_metadata", client_metadata)
        .with("dcql_query", dcql);
    if !entries.is_empty() {
        out.put("transaction_data", json!(entries).to_string());
    }
    if let Some(origins) = expected_origins {
        out.put("expected_origins", json!(origins).to_string());
    }
    out.text()
}

impl AbstractCredential {
    /// check.py's random wallet credential over the request's queries.
    pub(super) fn draw(rng: &mut ChaCha8Rng, k: usize, queries: &[AbstractQuery]) -> Self {
        let ids: Vec<String> = queries.iter().map(|q| q.id.clone()).collect();
        let count = rng.random_range(0..=ids.len());
        let answers = sample(rng, &ids, count);
        let count = rng.random_range(0..=2);
        let supports = sample(rng, &["t1", "t2"], count);
        Self {
            id: format!("c{k}"),
            answers,
            supports,
        }
    }
}
