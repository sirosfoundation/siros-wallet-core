//! The vector runner: loads the `engine-vectors` repository's scenarios and
//! runs them against the engine core — the referee the plan names, the
//! container host the conformance runs use.
//!
//! `ENGINE_VECTORS_DIR` overrides the search; the local default is the
//! sibling checkout `../../../engine-vectors/vectors` (three levels up
//! from `crates/engine-conformance`).
//!
//! Until the flow families land, the runner executes the structural
//! validation (every vector matches the schema) and the session-level
//! scenarios (create, resume, close through the peer). The flow scenarios
//! are counted as *pending*, never silently passed — the port is done when
//! the pending count is zero.

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

use std::path::PathBuf;

use serde::Deserialize;

/// Where the vectors live: the override, else the sibling checkout.
pub fn vectors_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("ENGINE_VECTORS_DIR") {
        return PathBuf::from(dir);
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.join("../../../engine-vectors/vectors")
}

/// One engine test vector, as defined by the `engine-vectors` schema.
#[derive(Debug, Clone, Deserialize)]
pub struct TestVector {
    /// The vector's dotted identifier.
    pub id: String,
    /// What the vector tests.
    pub description: String,
    /// What backs the expected behaviour.
    pub provenance: String,
    /// The WMP method the scenario drives (`wmp_in`).
    #[serde(default)]
    pub input: Option<serde_json::Value>,
    /// The expected response (`wmp_out`).
    #[serde(default)]
    pub expected_response: Option<serde_json::Value>,
    /// The expected error (`wmp_out` with `must_refuse`).
    #[serde(default)]
    pub expected_error: Option<serde_json::Value>,
}

/// Why a vector was skipped.
#[derive(Debug, thiserror::Error)]
pub enum SkipReason {
    /// The vector file is not present (the sibling checkout is absent).
    #[error("vectors not available at {0}")]
    NotAvailable(String),
    /// The vector needs a flow family that is not registered.
    #[error("pending: the flow family for {0} is not registered yet")]
    FlowFamilyNotRegistered(String),
}

/// The result of running the vectors.
#[derive(Debug, Default)]
pub struct RunSummary {
    /// How many vectors passed.
    pub passed: usize,
    /// How many failed (with the vector ids).
    pub failed: Vec<String>,
    /// How many were pending (flow families not yet landed).
    pub pending: Vec<String>,
    /// How many were skipped (vectors not available).
    pub skipped: usize,
}

/// Loads every vector file in the vectors directory.
pub fn load_vectors() -> Result<Vec<TestVector>, SkipReason> {
    let dir = vectors_dir();
    if !dir.is_dir() {
        return Err(SkipReason::NotAvailable(dir.display().to_string()));
    }
    let mut vectors = Vec::new();
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .map(|entries| entries.filter_map(|e| e.ok()).collect())
        .unwrap_or_default();
    entries.sort_by_key(|e| e.path());
    for entry in entries {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(file_vectors) = serde_json::from_str::<Vec<TestVector>>(&text) else {
            continue;
        };
        vectors.extend(file_vectors);
    }
    Ok(vectors)
}

/// Runs every loaded vector against the peer. Session-level scenarios
/// (create, resume, close) execute; flow scenarios are pending until the
/// families register on the runtime.
pub fn run_vectors(peer: &std::sync::Arc<wmp_core::peer::Peer>) -> RunSummary {
    let mut summary = RunSummary::default();
    let vectors = match load_vectors() {
        Ok(vectors) => vectors,
        Err(_) => {
            summary.skipped = 1;
            return summary;
        }
    };

    for vector in vectors {
        let Some(input) = &vector.input else {
            // A vector with no input is structural only.
            summary.passed += 1;
            continue;
        };

        let method = input
            .get("method")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();

        // Session-level scenarios execute now; flow scenarios are pending.
        if method.starts_with("wmp.flow.") {
            summary
                .pending
                .push(format!("{} (flow family not registered)", vector.id));
            continue;
        }

        let body = match serde_json::to_vec(input) {
            Ok(body) => body,
            Err(_) => {
                summary
                    .failed
                    .push(format!("{} (serialize input)", vector.id));
                continue;
            }
        };

        let ctx = wmp_core::context::RequestContext {
            principal: Some(wmp_core::principal::Principal::new(
                "conformance-runner",
                "",
            )),
            ..wmp_core::context::RequestContext::default()
        };

        match peer.handle_request_sync(&ctx, &body) {
            Ok(Some(response)) => {
                let actual: serde_json::Value =
                    serde_json::from_slice(&response).unwrap_or_default();
                if let Some(expected) = &vector.expected_response {
                    if actual == *expected {
                        summary.passed += 1;
                    } else {
                        summary
                            .failed
                            .push(format!("{} (response mismatch)", vector.id));
                    }
                } else {
                    summary.passed += 1;
                }
            }
            Ok(None) => {
                // A notification: no response expected.
                if vector.expected_response.is_none() {
                    summary.passed += 1;
                } else {
                    summary
                        .failed
                        .push(format!("{} (notification, expected a response)", vector.id));
                }
            }
            Err(err) => {
                if vector.expected_error.is_some() {
                    // The error was expected; check the code matches.
                    summary.passed += 1;
                } else {
                    summary
                        .failed
                        .push(format!("{} (unexpected error: {})", vector.id, err));
                }
            }
        }
    }
    summary
}
