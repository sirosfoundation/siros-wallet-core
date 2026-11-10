//! The SIROS wallet core with every real plug-in registered at once: the SD-JWT VC and mdoc
//! formats, the X.509 Client Identifier Prefixes, the PaSO, TS12 and QES transaction data profiles,
//! WE BUILD's CS-02 rules and Credential Manager's entries. Its tests:
//!
//! - `tests/properties`: the reference model's dressed-run properties (check_props.py
//!   `check_dressed`) over seeded random requests and wallets dressed with the real plug-ins.
//! - `tests/end_to_end`: one path per configuration, and every flow of the design, F1 to F13, to
//!   its `Delivery` or `Reply` over the HAIP build (`flows`), and the WE BUILD build's own
//!   (`we_build`), each built from a specification's own example.
//! - `tests/texts.rs`: `Context::check` over every crate the tests link: one row per derived
//!   error and statement, each id once, and the test app words every statement.

#![forbid(unsafe_code)]
#![deny(missing_docs, unused_must_use, unused_results)]
#![deny(
    clippy::let_underscore_must_use,
    clippy::let_underscore_untyped,
    clippy::disallowed_types
)]
#![deny(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::unreachable,
    clippy::todo,
    clippy::unimplemented,
    clippy::indexing_slicing,
    clippy::disallowed_methods
)]
