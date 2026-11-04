//! The SIROS wallet core with every real plug-in registered at once: the SD-JWT VC, mdoc and
//! `zkp_req` formats, the PaSO and QES transaction data profiles. Its tests:
//!
//! - `tests/properties`: the reference model's dressed-run properties (check_props.py
//!   `check_dressed`) over seeded random requests and wallets dressed with the real plug-ins.
//! - `tests/differential`: the dressed run against the reference model, live (ignored; run it
//!   with `cargo test -p siros-integration --test differential -- --ignored --nocapture`).
//! - `tests/end_to_end.rs`: one path per configuration, each built from a specification's own
//!   example.

#![forbid(unsafe_code)]
#![deny(missing_docs, unused_must_use, unused_results)]
#![deny(
    clippy::let_underscore_must_use,
    clippy::let_underscore_untyped,
    clippy::disallowed_types
)]
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
