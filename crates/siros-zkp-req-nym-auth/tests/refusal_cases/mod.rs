//! The fixtures of `refusals.rs`, by the side that refuses.

mod request;
mod verifier;
mod wallet;

use crate::Got;

/// A fixture: its name, what it gives, and what it must give.
pub type Case = (&'static str, Got, Got);

/// Every fixture: the request rules, then the Wallet's refusals, then the Verifier's.
pub fn all() -> Vec<Case> {
    [request::cases(), wallet::cases(), verifier::cases()]
        .into_iter()
        .flatten()
        .collect()
}
