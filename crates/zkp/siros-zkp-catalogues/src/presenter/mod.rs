//! The session a presentation is bound to, and, with the feature `request`, the presenter of a
//! nym_auth answer: the answer of an option by a usable attestation, its statement in the
//! session of a nym_auth request, the device signature, the prover's job and the presentation.
//!
//! It does no input or output. The host signs the data the presenter gives it with the device
//! key and runs a system's prover on the [`ProofJob`](crate::prover::ProofJob).

#[cfg(feature = "request")]
mod answer;
#[cfg(feature = "request")]
mod proving;

use siros_oid4vp::Handover;

use crate::verifier_id::VerifierId;

#[cfg(feature = "request")]
pub use answer::{Answer, Unanswerable};
#[cfg(feature = "request")]
pub use proving::{Prepared, ProveError};

/// The session a presentation is bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// The `Handover` of the channel the request arrived on.
    pub handover: Handover,
    /// `verifier_id`, in the form the trust framework fixes.
    pub verifier_id: VerifierId,
}
