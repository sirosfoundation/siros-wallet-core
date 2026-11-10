//! With siros-explain's `check`, the rows are the ids `#[explain(id = "…")]` declares in the code
//! of the crates this binary links, counted in their sources: siros-syntax's, whose errors the
//! binary never builds, siros-explain's and this file's. A transparent error adds none, and each
//! row's keys are its error's arguments.

use std::fs;
use std::path::{Path, PathBuf};

use siros_explain::Explain;
use siros_explain::check::rows;
use siros_syntax as _;

siros_explain::scope!("check");

#[derive(Debug, thiserror::Error, Explain)]
enum Local {
    #[error("{count} held")]
    #[explain(id = "held")]
    Held {
        count: u8,
        limit: Option<u8>,
        #[explain(skip)]
        secret: u8,
        #[source]
        cause: std::fmt::Error,
    },
    #[error("none held")]
    #[explain(id = "none")]
    None,
    #[error(transparent)]
    Boxed(Box<dyn Explain>),
}

/// The Rust files at `path`, a file or a directory.
fn rust_files(path: &Path) -> Vec<PathBuf> {
    if path.is_file() {
        return vec![path.to_owned()];
    }
    let mut files = Vec::new();
    for entry in fs::read_dir(path).expect("a source directory") {
        let path = entry.expect("an entry").path();
        if path.is_dir() {
            files.extend(rust_files(&path));
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
    files
}

/// Each id declared in the code lines (comments left out) of the Rust files at `path`, under the
/// crate's `scope`.
fn declared(path: &Path, scope: &str) -> Vec<String> {
    let attribute = concat!("#[explain", "(id = \"");
    let mut ids = Vec::new();
    for file in rust_files(path) {
        let source = fs::read_to_string(&file).expect("a source file");
        let code = source
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"));
        for line in code {
            for (at, _) in line.match_indices(attribute) {
                let id = &line[at + attribute.len()..];
                let id = &id[..id.find('"').expect("a closed id")];
                ids.push(format!("err.{scope}.{id}"));
            }
        }
    }
    ids
}

#[test]
fn the_rows_are_the_linked_crates_ids() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut expected = [
        declared(&crates.join("src"), "syntax"),
        declared(&crates.join("../siros-explain/src"), "explain"),
        declared(&crates.join("tests/check.rs"), "check"),
    ]
    .concat();
    expected.sort();
    let mut found: Vec<&str> = rows().map(|row| row.id).collect();
    found.sort_unstable();
    assert_eq!(found, expected);

    let held = Local::Held {
        count: 2,
        limit: None,
        secret: 7,
        cause: std::fmt::Error,
    };
    let boxed = Local::Boxed(Box::new(Local::None));
    let keys: [(&dyn Explain, &[&str]); 3] = [
        (&held, &["count", "limit"]),
        (&Local::None, &[]),
        (&boxed, &[]),
    ];
    for (error, expected) in keys {
        let mut given = Vec::new();
        error.args(&mut |key, _| given.push(key));
        let row = rows()
            .find(|row| row.id == error.id())
            .expect("a row per id");
        assert_eq!(
            (row.keys, given.as_slice()),
            (expected, expected),
            "{error:?}"
        );
    }
    let syntax: Vec<_> = rows()
        .filter(|row| row.id.starts_with("err.syntax."))
        .map(|row| (row.id, row.keys))
        .collect();
    assert!(syntax.contains(&("err.syntax.malformed", &["of", "at"][..])));
    assert!(syntax.contains(&("err.syntax.repeated", &["key"][..])));
}
