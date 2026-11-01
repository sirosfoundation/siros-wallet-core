//! The Wallet Messaging Protocol in Rust: messages, session state, peer,
//! flows, validators and error codes.
//!
//! This crate mirrors [go-wmp](https://github.com/sirosfoundation/go-wmp) at
//! v0.13.0 against the [wmp specification](https://github.com/sirosfoundation/wmp)
//! and its vectors. The vectors are the referee: `tests/conformance.rs` runs
//! `wmp/vectors/*.json` against this crate, and the port is complete when it
//! runs them all.
//!
//! The crate is sans-network: a [`transport::Transport`] trait is defined for
//! adapters to implement, and no module here opens a socket, reads a clock or
//! samples randomness itself — entropy and time are arguments. See
//! `docs/wmp-core-port.md` in the repository for the module map and the
//! staging plan.

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

pub mod error;
pub mod jsonrpc;
pub mod methods;
pub mod principal;
pub mod session;
pub mod token;
pub mod types;
pub mod version;
