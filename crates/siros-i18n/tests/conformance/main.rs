//! The message-format-wg test suite at `16372a6a02f41728be472a5921ba7c91774edeac`
//! (github.com/unicode-org/message-format-wg, `test/tests`), its syntax, data model, pattern
//! selection, fallback, bidi and `u:` options suites and its function suites of the stable
//! functions (`:string`, `:number`, `:integer`, `:offset`, `:currency`, `:percent`), copied into
//! `tests/mf2` under the Unicode License beside them.
//!
//! Each test's message is the one message of a module in the test's locale, after the module
//! of the CLDR tool's format sections for its language, and resolves over the test's params,
//! each given as text: a JSON string as it is, a JSON number as written. A test with errors
//! passes when the context refuses the message, at load or at resolution, with one of the test's
//! error types: the context shows no fallback value. A test without errors passes when the
//! resolved text equals `exp`, or resolves when it has none. A test skips only under an entry of
//! [`skips::SKIPS`], which names its reason.

#[path = "../support/cldr.rs"]
mod cldr;
mod harness;
mod skips;

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
                Outcome::Pass => passed += 1,
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
