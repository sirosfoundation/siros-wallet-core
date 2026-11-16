//! The tests of siros-presentation, in one binary.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    dead_code
)]

use siros_presentation::testing::{host, verifier, wallet};

mod digest;
mod display;
mod mdoc;
mod nym_request;
mod offers;
mod refusals;
mod sd_jwt;
mod seed;
mod transactions;
mod trust;
mod usable;
mod zkp;
