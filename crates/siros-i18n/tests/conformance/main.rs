//! The message-format-wg test suite at `16372a6a02f41728be472a5921ba7c91774edeac`
//! (github.com/unicode-org/message-format-wg, `test/tests`), its syntax, data model, pattern
//! selection, fallback, bidi and `u:` options suites and its function suites of the stable
//! functions (`:string`, `:number`, `:integer`, `:offset`, `:currency`, `:percent`), copied into
//! `tests/mf2` under the Unicode License beside them. A module in a test's locale takes the CLDR
//! tool's format sections for its language.
//!
//! Each test's message is the one message of a module in the test's locale, loaded and rendered
//! as plain text. A test with errors passes when the loader or the renderer refuses the message
//! with one of the test's error types: the engine shows no fallback value. A test without errors
//! passes when the rendered text equals `exp`, or renders when it has none. A test skips only
//! under an entry of [`skips::SKIPS`], which names its reason.
//!
//! Each message that loads renders through three packages, one holding its text
//! precomputed, one holding its key compiled and one compiled from the live module, with 0
//! differences; each package built twice, and read back and written again, gives the same
//! bytes.

#[path = "../support/cldr.rs"]
mod cldr;
mod harness;
mod skips;
mod test_function;

use harness::{Outcome, run};

/// The suites, under `tests/mf2`.
const SUITES: [&str; 13] = [
    "syntax.json",
    "syntax-errors.json",
    "data-model-errors.json",
    "pattern-selection.json",
    "fallback.json",
    "bidi.json",
    "u-options.json",
    "functions/string.json",
    "functions/number.json",
    "functions/integer.json",
    "functions/offset.json",
    "functions/currency.json",
    "functions/percent.json",
];

#[test]
fn the_suite_passes() {
    let mut used = vec![0usize; skips::SKIPS.len()];
    let mut failures = Vec::new();
    let mut packaged = 0;
    for suite in SUITES {
        let path = format!("{}/tests/mf2/{suite}", env!("CARGO_MANIFEST_DIR"));
        let text = std::fs::read_to_string(&path).expect("the suite");
        let file: serde_json::Value = serde_json::from_str(&text).expect("JSON");
        let defaults = file
            .get("defaultTestProperties")
            .cloned()
            .unwrap_or_default();
        let tests = file["tests"].as_array().expect("tests");
        let (mut passed, mut failed, mut skipped) = (0, 0, 0);
        for test in tests {
            let src = test["src"].as_str().expect("src");
            let skip = skips::SKIPS
                .iter()
                .position(|skip| skip.suite == suite && skip.src == src);
            if let Some(index) = skip {
                used[index] += 1;
                skipped += 1;
                println!("{suite} skip {src:?}: {}", skips::SKIPS[index].reason);
                continue;
            }
            match run(&defaults, test) {
                Outcome::Pass { packaged: through } => {
                    passed += 1;
                    packaged += usize::from(through);
                }
                Outcome::Fail(detail) => {
                    failed += 1;
                    failures.push(format!("{suite} {src:?}: {detail}"));
                }
            }
        }
        println!(
            "{suite}: {} tests, {passed} passed, {failed} failed, {skipped} skipped",
            tests.len()
        );
    }
    println!("{packaged} passing texts rendered through three packages each, 0 differences");
    let stale: Vec<_> = skips::SKIPS
        .iter()
        .zip(&used)
        .filter(|(_, n)| **n == 0)
        .map(|(skip, _)| (skip.suite, skip.src))
        .collect();
    assert!(
        stale.is_empty(),
        "skip entries matching no test: {stale:#?}"
    );
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
