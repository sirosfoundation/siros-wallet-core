//! The nym_auth function catalogue of `zkp_req`, its systems, and the presenter and verifier
//! around a host's prover.
//!
//! The normative texts are `nym_auth_rulebook.md` (0.5), `systems/longfellow-nym_auth-v1.md`
//! and `systems/vega-nym_auth-v1.md` of the nym_auth rulebook repository at commit `e65861c`.
//!
//! | Module | Defines | Source |
//! | --- | --- | --- |
//! | [`catalogue`] | `pseudonym`, `age_check`, the nym_auth query | Function catalogue |
//! | [`age`] | `range`, E and C | `age_check` |
//! | [`verifier_id`] | `verifier_id`, `verifier_input`, the `sha-256` pseudonym | `pseudonym` |
//! | [`system`] | The systems and the options each supports | System rulebooks, Sections 1 to 3 |
//! | [`policy`] | The rules of signed requests and encrypted responses | Binding, Response confidentiality |
//! | [`request_object`] | A Request Object the host validated, checked against the policy, and its session | Binding, Response confidentiality |
//! | [`request`] | The verified request that meets the policy (N2) | Binding, Response confidentiality, Verifier identity |
//! | [`pair`] | The options of a query and the usable pair of a system for one | `zkp_req`, Section 1.3 |
//! | [`mdoc`] | The nym_auth form of the ISO/IEC 18013-5 attestation | Attestation |
//! | [`attestation`] | The tested attestation; the usable attestation, its Document Signer admitted for the query (N3); the opened seed | System rulebooks, Section 7 |
//! | [`presenter`] | The answer of an option, then the statement, the prover's job and the presentation | `zkp_req`, Sections 3, 4 |
//! | [`prover`] | The statement and the prover interface | System rulebooks, Sections 3, 4, 7 |
//! | [`verify`] | The Verifier's checks | `zkp_req`, Section 4.1; system rulebooks, Section 9 |
//!
//! The provers stay outside. A host implements [`prover::NymAuthProver`] and
//! [`prover::NymAuthProofVerifier`] with a system's prover and verifier.
//!
//! Without the default feature `credential`, the crate holds the catalogue, the systems, the usable
//! pairs and the policy: what the credential picker needs. The feature `request` adds
//! [`request::NymAuthRequest`] over `siros-oid4vp`'s verified request, and the statement and
//! presentation of an answer in its session.

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::cognitive_complexity)]
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

pub mod age;
pub mod catalogue;
pub mod outcome;
pub mod pair;
pub mod policy;
pub mod system;
pub mod verifier_id;

#[cfg(feature = "credential")]
pub mod attestation;
#[cfg(feature = "credential")]
pub mod mdoc;
#[cfg(feature = "credential")]
pub mod presenter;
#[cfg(feature = "credential")]
pub mod prover;
#[cfg(feature = "request")]
pub mod request;
#[cfg(feature = "credential")]
pub mod request_object;
#[cfg(feature = "credential")]
pub mod verify;

#[cfg(feature = "test-fixtures")]
pub mod testing;
