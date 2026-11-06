//! The SIROS wallet core with every real plug-in registered at once: the SD-JWT VC and mdoc
//! formats, the X.509 Client Identifier Prefixes, the PaSO and QES transaction data profiles,
//! WE BUILD's CS-02 rules and Credential Manager's entries. Its tests:
//!
//! - `tests/properties`: the reference model's dressed-run properties (check_props.py
//!   `check_dressed`) over seeded random requests and wallets dressed with the real plug-ins.
//! - `tests/end_to_end`: one path per configuration, and every flow of the design, F1 to F13, to
//!   its `Delivery` or `Reply` over the HAIP and WE BUILD builds (`flows`), each built from a
//!   specification's own example.
//! - `tests/messages.rs`: one identifier names one message across the crates.

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
