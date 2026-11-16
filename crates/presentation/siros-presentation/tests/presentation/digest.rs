//! A4: a selection made on a plan parses only against the same plan. A changed `nonce`, and a
//! presentation record that makes another instance of a batch the least used (C5), each make
//! another plan.

use serde_json::json;
use siros_oid4vp::VerifiedRequest;
use siros_presentation::{Fulfilment, OfferIndex, PresentationError, Selection};

use crate::verifier::{redirect_unsigned, NONCE};
use crate::wallet::{ready, sd_jwt, Held, Wallet, VCT};

/// A request for the pid in `direct_post`, with `nonce`.
fn request(nonce: &str) -> VerifiedRequest {
    redirect_unsigned(&json!({
        "response_type": "vp_token",
        "response_mode": "direct_post",
        "nonce": nonce,
        "dcql_query": {"credentials": [{"id": "pid", "format": "dc+sd-jwt",
            "meta": {"vct_values": [VCT]}, "claims": [{"path": ["given_name"]}]}]}
    }))
}

/// Two instances of one batch: credentials 1 and 2. `records` name credentials as used.
fn wallet(records: Vec<Vec<u64>>) -> Wallet {
    let instance = |id| Held {
        batch: 7,
        ..Held::new(
            id,
            "dc+sd-jwt",
            sd_jwt(VCT, &[("given_name", json!("Erika"))]),
        )
    };
    Wallet::with_records(vec![instance(1), instance(2)], records)
}

#[test]
fn a_selection_parses_against_its_own_plan_only() {
    let first = wallet(Vec::new());
    let original = request(NONCE);
    let digest = *ready(&first.input(&original)).unwrap().view().digest();
    let selection = Selection::new(digest, OfferIndex::new(0), Vec::new(), Vec::new());

    // (case, wallet, request, refusal)
    let other_nonce = request("another-nonce-1234");
    let flipped = wallet(vec![vec![1]]);
    let cases = [
        ("the same plan", &first, &original, None),
        (
            "another nonce",
            &first,
            &other_nonce,
            Some(PresentationError::DigestMismatch),
        ),
        (
            "instance 2 the least used",
            &flipped,
            &original,
            Some(PresentationError::DigestMismatch),
        ),
    ];
    for (case, wallet, request, refusal) in cases {
        let planned = ready(&wallet.input(request)).unwrap();
        let chosen = planned.choose(&selection, Fulfilment::WalletUi);
        assert_eq!(chosen.err(), refusal, "{case}");
    }
}
