//! `Context::check` over the rows of every derived error and statement this binary links: the rows
//! are the derives' ids, and the check refuses a row no module words and a wording that reads an
//! argument its row lacks.

use std::path::Path;

use siros_i18n::{CheckError, Context};

siros_i18n::scope!("checked");

/// A statement only its row uses.
#[derive(siros_i18n::Message)]
#[message(id = "greeting")]
#[expect(
    dead_code,
    reason = "its row is the fixture; the binary builds no value of it"
)]
struct Greeting {
    name: String,
}

/// Every row: its id and its keys.
fn rows() -> Vec<(&'static str, &'static [&'static str])> {
    siros_explain::check::rows()
        .map(|row| (row.id, row.keys))
        .chain(siros_i18n::check::rows().map(|row| (row.id, row.keys)))
        .collect()
}

/// The lines of `path`, a Rust file or a directory of them, that start with a derive's id
/// attribute.
fn attributes(path: &Path) -> usize {
    if path.is_dir() {
        let entries = std::fs::read_dir(path).expect("a directory");
        return entries
            .map(|entry| attributes(&entry.expect("an entry").path()))
            .sum();
    }
    if path.extension().is_none_or(|extension| extension != "rs") {
        return 0;
    }
    std::fs::read_to_string(path)
        .expect("a source")
        .lines()
        .map(str::trim_start)
        .filter(|line| line.starts_with("#[explain(id") || line.starts_with("#[message(id"))
        .count()
}

/// The linked crates that derive are siros-i18n, siros-syntax and siros-explain, and this file.
#[test]
fn the_rows_are_the_linked_crates_derives() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crates = manifest.parent().expect("the crates directory");
    let counted = [
        crates.join("siros-i18n/src"),
        crates.join("siros-syntax/src"),
        crates.join("siros-explain/src"),
        manifest.join("tests/check.rs"),
    ]
    .map(|path| attributes(&path));
    assert_eq!(rows().len(), counted.iter().sum::<usize>(), "{counted:?}");
}

/// A module that words every row, each wording reading its row's keys: `greeting` left out, or
/// reading `extra` beside its key.
fn wording(greeting: Option<&str>) -> String {
    let mut module = "@locale en\n---\n".to_owned();
    for (id, keys) in rows() {
        let reads: String = keys.iter().map(|key| format!("{{${key}}}")).collect();
        match (id, greeting) {
            ("checked.greeting", None) => {}
            ("checked.greeting", Some(extra)) => {
                module.push_str(&format!("{id} = x{reads}{{${extra}}}\n"));
            }
            _ => module.push_str(&format!("{id} = x{reads}\n")),
        }
    }
    module
}

#[test]
fn check_refuses_an_unworded_row_and_an_unknown_key() {
    let check = |module: String| {
        Context::new()
            .module(&module)
            .expect("the module loads")
            .check()
    };
    assert_eq!(check(wording(Some("name"))), Ok(()));
    assert_eq!(
        check(wording(None)),
        Err(CheckError::Unworded {
            id: "checked.greeting".to_owned()
        })
    );
    assert_eq!(
        check(wording(Some("nobody"))),
        Err(CheckError::Unknown {
            id: "checked.greeting".to_owned(),
            key: "nobody".to_owned()
        })
    );
}
