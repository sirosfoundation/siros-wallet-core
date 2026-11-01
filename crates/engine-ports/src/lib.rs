//! The port traits and their message types — the only way the engine core touches the world. Planned; S0.
//!
//! Stub: the crate exists to hold the workspace layout. The contents arrive
//! with the spike — see `docs/engine-spec.md` (the specification) and the
//! implementation plan. The start condition is the PR 163 rework landing on
//! go-wallet-backend `main`, with go-wmp v0.13.0 already shipped.

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
