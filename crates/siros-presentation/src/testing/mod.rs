//! The wallet, its host and the verifier that this crate's tests and the credential picker's
//! differential test drive the plan with: credentials issued here, requests signed and taken
//! through intake, responses decrypted with JWE and COSE code of their own.
//!
//! Behind the `test-fixtures` feature: a dev-time facility, outside the shipped surface. It
//! panics on a broken fixture, as a test does.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    missing_docs,
    unused_results
)]

pub mod host;
pub mod paso;
pub mod verifier;
pub mod wallet;
