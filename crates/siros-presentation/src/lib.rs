//! Presentation for the SIROS wallet core. Phase 1 maps a request and the wallet state to the
//! plan and its consent view; phase 2 maps the user's selection to the response and the
//! presentation record.
//!
//! | Requirement | API |
//! | --- | --- |
//! | A1: the format table, `meta`, holder binding, usable credentials, no undisclosable nym_auth attribute; why a request has no offer | [`Matching::new`] over [`MatchCredential`]s, [`Failure`] |
//! | A2: `zkp_req` matching as one selection, then the usable attestation and the opened seed | [`ZkpQuery`], [`Matching::answer`]; the wallet's tests in [`plan`] |
//! | A3: offers over the eligible candidates, optional additions (one option per set), all-optional sets, the subset of a `multiple` member by `credentialId` | [`Offers::of`], [`Selection`] with [`Subset`] |
//! | Transaction data selection (PaSO Core, Section 7.4): the targeted queries in one credential set whose alternatives are transposable; each candidate takes its first compatible entry, a candidate with none excluded; an entry no chosen credential takes unused; the transaction metadata the host holds as input | [`plan`], [`PlanInput::held`], [`CredentialView::transaction`] |
//! | A4: the digest of what the user consents to; the selection parsed against the recomputed plan | [`ConsentView::digest`], [`PlanDigest::parse`], [`Selection`], [`Planned::choose`] gives a [`Chosen`] |
//! | A5: every signing input a `Sign` effect; the signatures parsed against them, each verifying under its key | [`Chosen::prepare`] gives [`Sign`]s, [`Prepared::finish`] |
//! | A6: the SD-JWT `aud` | [`Chosen::prepare`] |
//! | A7: the SessionTranscript of the request's `Handover` | [`Chosen::prepare`] |
//! | A8: one `vp_token`; `access_denied` on a decline; the record names the instances used | [`Prepared::finish`], [`Planned::decline`] |
//! | A9: the wallet's display, and its refusal in a background fulfilment | [`WalletDisplay::of`], [`Fulfilment`] |
//! | T4: each transaction entry bound to one credential, named by `credentialId` and instance in the view and the digest, with the source and rulebook of its definition; phase 2 binds by it; a selection that leaves it out refused | [`CredentialView::entry`], [`CredentialView::transaction`], [`PresentationError::BoundCredentialOmitted`] |
//! | K3: the selection from the credential picker's picked entries, checked against the plan | [`Pick`], [`Planned::picked`] |
//! | N2: the nym_auth request of a verified request, its `verifier_id` from the request's certificate | [`siros_zkp_req_nym_auth::request::NymAuthRequest`], built by [`plan`] from [`PlanInput::verifier_id`] |
//!
//! Without the default feature `wallet` the crate holds the matching ([`Matching`], [`Offers`],
//! [`WalletDisplay`]), for the credential picker to run over its registration projection (K2).
//! It builds with Rust 1.82 and links no crypto, prover or display resolution.
//!
//! The crate performs no I/O. The plan takes the transaction metadata the host holds as input,
//! and carries each transaction image to the consent view for the UI to resolve; phase 2 asks the
//! host for each signature, randomness comes from the caller's CSPRNG, and the time is an input.

#![deny(missing_docs)]
// Links to the items of `wallet` resolve with it, where rustdoc checks them.
#![cfg_attr(not(feature = "wallet"), allow(rustdoc::broken_intra_doc_links))]
#![deny(unsafe_code)]
#![deny(unused_results)]
#![deny(clippy::cognitive_complexity)]
#![deny(clippy::let_underscore_must_use, clippy::let_underscore_untyped)]
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

mod credential;
mod display_rule;
mod ids;
mod inconsistency;
mod matching;
mod offers;
mod pick;
mod request;
mod transactions;

pub use credential::{KeyHolding, MatchCredential};
pub use display_rule::{
    Choice, DisplayFacts, HostDisplay, Presentability, Rows, TransactionData, WalletDisplay,
};
pub use ids::{AdditionIndex, CandidateIndex, OfferIndex, OptionIndex, QueryIndex, SetIndex};
pub use inconsistency::Inconsistency;
pub use matching::{
    Answer, Answered, Answers, Asked, AskedType, Candidate, ChoiceError, Claims, Excluded,
    Exclusion, Failure, Matching, ProofChoice, QueryRefusal, QueryTypes, ZkpQuery, ZkpRefusal,
};
pub use offers::{Addition, Member, Offer, Offers, MAX_ADDITIONS, MAX_EXAMINED, MAX_OFFERS};
pub use pick::{Pick, PickFault};
pub use request::MatchRequest;
pub use transactions::{BoundEntry, NoOffer, RequestEntries, TransactionSource, Transactions};

#[cfg(feature = "wallet")]
mod error;
#[cfg(feature = "wallet")]
mod plan;
#[cfg(feature = "wallet")]
mod respond;
#[cfg(feature = "test-fixtures")]
pub mod testing;

#[cfg(feature = "wallet")]
pub use error::PresentationError;
#[cfg(feature = "wallet")]
pub use plan::{
    plan, refusal, AdditionView, BoundTransaction, ConsentView, CredentialView, DigestError,
    MemberView, NoSeed, OfferView, OptionRefusal, PlanDigest, PlanInput, Planned, Shown, Unproven,
};
#[cfg(feature = "wallet")]
pub use respond::{
    Chosen, Fulfilment, PickError, Prepared, Response, Selection, Sign, SignId, SignatureError,
    Subset, SubsetError,
};
