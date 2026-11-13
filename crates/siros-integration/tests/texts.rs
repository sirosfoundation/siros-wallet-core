//! `check` over every crate the integration links (spec section 4): the rows the derives register
//! are the crates' `#[explain(id` and `#[message(id` attributes, counted in their sources, and the
//! test app's context words each statement once, reading only its arguments.

use std::path::Path;

use siros_i18n::Context;
use siros_testkit::render::Language;

// Each crate of `LINKED` the test names nowhere else, so that its rows link.
use siros_credman as _;
use siros_explain as _;
use siros_mdoc as _;
use siros_openid4vp as _;
use siros_paso as _;
use siros_qes as _;
use siros_sdjwt as _;
use siros_syntax as _;
use siros_ts12 as _;
use siros_wallet_state as _;
use siros_webuild as _;
use siros_x509 as _;

/// The workspace crates this binary links: the integration's dependencies.
const LINKED: [&str; 14] = [
    "siros-openid4vp",
    "siros-sdjwt",
    "siros-mdoc",
    "siros-paso",
    "siros-qes",
    "siros-credman",
    "siros-webuild",
    "siros-ts12",
    "siros-x509",
    "siros-testkit",
    "siros-wallet-state",
    "siros-i18n",
    "siros-explain",
    "siros-syntax",
];

/// Every row: its id and its keys.
fn rows() -> Vec<(&'static str, &'static [&'static str])> {
    siros_explain::check::rows()
        .map(|row| (row.id, row.keys))
        .chain(siros_i18n::check::rows().map(|row| (row.id, row.keys)))
        .collect()
}

/// The lines of the Rust files under the directory `dir` that start with a derive's id
/// attribute.
fn attributes(dir: &Path) -> usize {
    std::fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("{}: {error}", dir.display()))
        .map(|entry| {
            let path = entry.expect("an entry").path();
            if path.is_dir() {
                attributes(&path)
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                std::fs::read_to_string(&path)
                    .expect("a source")
                    .lines()
                    .map(str::trim_start)
                    .filter(|line| {
                        line.starts_with("#[explain(id") || line.starts_with("#[message(id")
                    })
                    .count()
            } else {
                0
            }
        })
        .sum()
}

/// A module in `language` that words every error row, reading each of its keys: the test app
/// words statements alone.
fn errors_worded(language: Language) -> String {
    let mut module = format!("@locale {}\n---\n", language.tag());
    for (id, keys) in rows() {
        if id.starts_with("err.") {
            let reads: String = keys.iter().map(|key| format!("{{${key}}}")).collect();
            module.push_str(&format!("{id} = x{reads}\n"));
        }
    }
    module
}

/// Catches a derive whose row does not link, a crate that registers an id another crate
/// registers, a statement the test app does not word, and a wording that reads an argument its
/// statement lacks.
#[test]
fn the_rows_are_the_linked_crates_derives_and_the_test_app_words_each_statement() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the crates directory");
    let counted: Vec<(&str, usize)> = LINKED
        .iter()
        .map(|name| (*name, attributes(&crates.join(name).join("src"))))
        .collect();
    assert_eq!(
        rows().len(),
        counted.iter().map(|(_, count)| count).sum::<usize>(),
        "{counted:?}"
    );
    for language in Language::ALL {
        let context: Context = language
            .context()
            .expect("the test app's context")
            .module(&errors_worded(language))
            .expect("the errors' wording");
        assert_eq!(context.check(), Ok(()), "{}", language.tag());
    }
}
