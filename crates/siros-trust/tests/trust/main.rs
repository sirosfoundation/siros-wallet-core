//! Issuer trust: the `aki` known answer, the path validation rules of TR3, the picker's
//! admission from the TR5 facts, and the trust store's refusals (TR1).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod chain;
mod known_answer;
mod store;
mod support;
