//! Issuer trust: the `aki` known answers, the path validation rules of TR3, and the trust store's
//! refusals (TR1).

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
