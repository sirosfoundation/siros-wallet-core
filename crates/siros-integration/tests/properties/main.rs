//! The reference model's dressed-run properties (check_props.py `check_dressed` and every check
//! it calls but the DC API renderer's), over seeded random requests and wallets as check.py
//! draws them, dressed with the real plug-ins as check_props.py's `dress` dresses them, through
//! the core with every real plug-in registered at once. Each property's oracle is computed here
//! from the specification's rule.

mod by_uri;
#[path = "../common/mod.rs"]
mod common;
mod display;
mod dressed;
mod generate;
mod outcome;
mod response;
mod spec;
mod tally;

use spec::Spec;
use tally::Tally;

/// Every branch of the checks, by its tally name.
const BRANCHES: [&str; 71] = [
    "dressed wallets",
    "outcome TransactionView",
    "outcome Excluded [View §4]",
    "outcome NotCompatible [Core §7.4.2 step 2]",
    "outcome NotCompatible [Proof Metadata §3.3]",
    "outcome NotCompatible [Proof Metadata §5.3]",
    "outcome NotCompatible [Risk Signals §4.1]",
    "outcome NotCompatible [Risk Signals §7.3]",
    "outcome Unsupported [Proof Metadata §3.3]",
    "outcome Unsupported [Proof Metadata §3.3; View §3]",
    "renderings by the Mandate rulebook",
    "rows checked for kind",
    "full-text rows",
    "ui labels checked for locale",
    "refused C4",
    "refused C7",
    "refused C8",
    "refused PaSO",
    "refused QES",
    "refused dc+sd-jwt",
    "not candidates: holder binding without a key",
    "excluded by the Verifier's algorithms",
    "credentials for queries no entry names",
    "bound by first match",
    "excluded View §4",
    "excluded no compatible entry",
    "QES bound",
    "QES excluded",
    "entries",
    "format boxes",
    "proxied",
    "QES boxes",
    "payment boxes",
    "PaSO standard boxes",
    "hints on entries",
    "static boxes",
    "display selections",
    "selections with a transaction",
    "selections with the wallet's header",
    "foreign selections refused",
    "responses",
    "responses plain",
    "responses encrypted",
    "responses falling back",
    "findings: a credential the runtime refuses",
    "findings: PaSO's ad-hoc metadata expired",
    "findings: PaSO's images failing",
    "findings: QES's documents failing",
    "fallbacks re-run",
    "KB-JWTs",
    "KB-JWTs with holder binding waived",
    "SD-JWTs without a key",
    "mdoc deviceSignature",
    "mdoc deviceMac",
    "PaSO responses dc+sd-jwt",
    "PaSO responses mso_mdoc",
    "QES responses dc+sd-jwt",
    "QES responses mso_mdoc",
    "responses without risk signals",
    "risk signals plain",
    "risk signals encrypted",
    "risk envelopes ok",
    "risk envelopes denied",
    "risk envelopes unavailable",
    "tampered selections rejected",
    "tampered records falling back",
    "fallbacks: metadata renewed after the display",
    "URI requests by GET",
    "URI requests by POST",
    "URI selections prepared",
    "URI foreign records falling back",
];

fn run(seeds: &[u64], requests: usize) -> Tally {
    let spec = Spec::read();
    let mut tally = Tally::default();
    for seed in seeds {
        dressed_stream(*seed, requests, &spec, &mut tally);
    }
    for (name, count) in tally.counts() {
        println!("{count:>7} {name}");
    }
    tally
}

/// The dressed cases of the seeded stream, each checked over the DC API and by URI.
fn dressed_stream(seed: u64, requests: usize, spec: &Spec, tally: &mut Tally) {
    use rand::SeedableRng;
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);
    let mut k = 0;
    for _ in 0..requests {
        for dressed in generate::cases(&mut rng, 4) {
            tally.add("dressed wallets");
            dressed::check(&dressed, spec, tally);
            by_uri::check(&dressed, k, tally);
            k += 1;
        }
    }
}

fn unreached(tally: &Tally) -> Vec<&'static str> {
    BRANCHES
        .into_iter()
        .filter(|branch| tally.count(branch) == 0)
        .collect()
}

/// Seeds whose first ten requests reach every branch together: a greedy cover of [`BRANCHES`]
/// over seeds 1 to 325 at ten requests each, the widest reach first. A change to the
/// generator moves the streams and calls for a new cover: the model-sized test prints each
/// branch's count for the seeds and request count `WALLET_RS_SEEDS` and `WALLET_RS_REQUESTS`
/// give.
const SEEDS: [u64; 7] = [15, 224, 1, 128, 94, 10, 14];

#[test]
fn every_dressed_case_holds_the_stated_properties() {
    let tally = run(&SEEDS, 10);
    let unreached = unreached(&tally);
    assert!(unreached.is_empty(), "no case reached {unreached:?}");
}

fn setting(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_owned())
}

#[test]
#[ignore = "the model's run size: minutes unoptimized; run per merge"]
fn the_model_sized_dressed_run_holds_the_stated_properties() {
    let seeds: Vec<u64> = setting("WALLET_RS_SEEDS", "1,2,3")
        .split(',')
        .map(|seed| seed.trim().parse().expect("a seed"))
        .collect();
    let requests = setting("WALLET_RS_REQUESTS", "1500")
        .trim()
        .parse()
        .expect("a count");
    let tally = run(&seeds, requests);
    let unreached = unreached(&tally);
    assert!(unreached.is_empty(), "no case reached {unreached:?}");
}
