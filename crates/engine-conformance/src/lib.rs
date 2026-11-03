//! The vector runner: loads the `engine-vectors` repository's scenarios
//! and runs them against the engine core — the referee the plan names,
//! the container host the conformance runs use.
//!
//! Every vector is validated against the repository's
//! `vector-schema.json` before it runs; a schema violation fails the
//! run rather than passing silently. A go-observed vector past its
//! `review_by` refuses to gate unless it carries a `review_reason`
//! (the provenance sunset, the runner contract).
//!
//! `ENGINE_VECTORS_DIR` overrides the search; the local default is the
//! sibling checkout `../../../engine-vectors` (three levels up from
//! `crates/engine-conformance`).

#![deny(missing_docs)]
#![deny(unsafe_code)]
// Nothing panics outside the tests. scripts/check_panic_sites.py refuses an
// allow of these lints there and finds the panics they cannot see.
#![cfg_attr(
    not(test),
    deny(
        clippy::panic,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::indexing_slicing,
        clippy::disallowed_methods
    )
)]

pub mod matchers;
pub mod runner;
pub mod schema;
pub mod script;
pub mod world;

use std::path::PathBuf;

/// Where the vectors repository is: the override, else the sibling
/// checkout.
pub fn repository_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("ENGINE_VECTORS_DIR") {
        return PathBuf::from(dir);
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.join("../../../engine-vectors")
}

/// Where the vectors live: the repository's `vectors` directory.
pub fn vectors_dir() -> PathBuf {
    repository_dir().join("vectors")
}

/// Where the schema lives: the repository's `vector-schema.json`.
pub fn schema_path() -> PathBuf {
    repository_dir().join("vector-schema.json")
}

/// Loads and validates every vector in the vectors directory. Errors
/// are the file's violations; a file that fails the schema refuses the
/// whole run (an unvalidated vector is a typo away from testing
/// nothing).
pub fn load() -> Result<Vec<script::VectorFile>, String> {
    let dir = vectors_dir();
    if !dir.is_dir() {
        return Err(format!(
            "the vectors directory {} does not exist",
            dir.display()
        ));
    }
    let schema_text =
        std::fs::read_to_string(schema_path()).map_err(|err| format!("read the schema: {err}"))?;
    let schema: serde_json::Value =
        serde_json::from_str(&schema_text).map_err(|err| format!("parse the schema: {err}"))?;

    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .map(|entries| entries.filter_map(|e| e.ok()).collect())
        .unwrap_or_default();
    entries.sort_by_key(|e| e.path());

    let mut vectors = Vec::new();
    for entry in entries {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        // The schema document itself is not a vector.
        if path.file_name().and_then(|n| n.to_str()) == Some("vector-schema.json") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let document: serde_json::Value = serde_json::from_str(&text)
            .map_err(|err| format!("{}: not JSON — {err}", path.display()))?;
        schema::validate(&schema, &document)
            .map_err(|errors| format!("{}: {errors:?}", path.display()))?;
        let vector: script::VectorFile = serde_json::from_value(document).map_err(|err| {
            format!(
                "{}: the vector does not deserialize — {err}",
                path.display()
            )
        })?;
        vectors.push(vector);
    }
    Ok(vectors)
}

/// Runs every loadable vector against the engine, returning the report.
/// Vectors that cannot load are skipped with the reason, never
/// silently passed.
pub fn run_all() -> runner::Report {
    let mut report = runner::Report::default();
    let vectors = match load() {
        Ok(vectors) => vectors,
        Err(reason) => {
            report.skipped.push(("all".to_owned(), reason));
            return report;
        }
    };
    for vector in &vectors {
        let verdict = runner::run_vector(vector);
        report.record(&vector.id, &vector.provenance, verdict);
    }
    report
}
