//! The `zkp_req` protocol layer: one implementation for the matcher, the wallet and the
//! verifier.
//!
//! The normative text is `zkp_req.md` of the nym_auth rulebook repository, draft 0.1 at commit
//! `e65861c`. This crate holds what the protocol defines for every function catalogue and
//! every system:
//!
//! | Module | Defines | `zkp_req` |
//! | --- | --- | --- |
//! | [`query`] | The Credential Query, `_req` and `_req_sets` | Sections 1.1, 2, 2.1 |
//! | [`ids`] | The identifiers and positions of queries and presentations | Sections 1.2, 2, 4 |
//! | [`formats`] | `vp_formats_supported.zkp_req` | Section 1.2 |
//! | [`select`] | The usable pair of a system and a proof backend | Section 1.3 |
//! | [`presentation`] | `ZkpPresentation`, the backends' `Proof`, the `vp_token` | Sections 3, 4, 6.1 |
//! | [`structure`] | The Verifier's checks of a presentation, steps 1 to 5 | Section 4.1 |
//! | `vp_token` (feature `vp-token`) | The presentations of a query in a JSON `vp_token` | Section 6.1 |
//! | [`outcome`] | The error codes and the request rules | Section 5 |
//!
//! A function catalogue, such as `siros-zkp-req-nym-auth`, adds its functions and systems.
//! Proving stays outside: a host implements it behind the catalogue's prover interface.
//!
//! Nothing here panics on any input: the matcher runs this code inside the credential picker,
//! where a trap reads as "no matching credential".

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

pub mod formats;
pub mod ids;
mod json;
pub mod outcome;
pub mod presentation;
pub mod query;
pub mod select;
pub mod structure;
#[cfg(feature = "vp-token")]
pub mod vp_token;

pub use formats::ZkpFormats;
pub use ids::{
    FnId, FnIdError, InputName, ItemIndex, PresentationIndex, ProofBackend, ReqSetIndex, ResultKey,
    ReturnHandle, ReturnHandleError, SystemId, W3cType,
};
pub use outcome::{
    ErrorCode, IdentifierFault, OptionFault, RequestRule, ReturnFault, TypeValueFault,
};
pub use presentation::{
    vp_token_cbor, vp_token_json, EncodingError, Member, ProofContent, ProofEnvelope, ZkProof,
    ZkpPresentation,
};
pub use query::{CredentialType, QueryOption, ReqItem, ReqSets, ZkpReqQuery};
pub use select::{usable_backend, PairRefusal, System};
pub use structure::{answered_option, StructureRejection};
#[cfg(feature = "vp-token")]
pub use vp_token::{presentations_of, VpTokenError};
