//! A9: an offer needs the wallet's display unless every member is presentable without its UI,
//! the request carries no transaction data, every row shows whole and nothing is left to
//! choose, neither an addition nor a subset; a background fulfilment of an offer that needs it is refused with `access_denied`.

use serde_json::{json, Value};
use siros_codec::cbor::Value as Cbor;
use siros_oid4vp::{Outcome, PostParameters, Submission, VerifiedRequest};
use siros_presentation::{
    Fulfilment, HostDisplay, OfferIndex, PresentationError, Selection, WalletDisplay,
};
use siros_zkp_req_nym_auth::testing::{query, Spec};

use crate::sd_jwt::{payment, type_metadata};
use crate::verifier::{
    client_metadata, decrypt_jwe, redirect_signed, redirect_unsigned, Rng, NONCE, STATE,
};
use crate::wallet::{mdoc, nym_auth, ready, sd_jwt, Held, Wallet, MDL, MDL_NS, VCT};

fn pid() -> Value {
    json!({"id": "pid", "format": "dc+sd-jwt", "meta": {"vct_values": [VCT]},
        "claims": [{"path": ["given_name"]}]})
}

/// The `pid` query answered by every matching credential.
fn every_pid() -> Value {
    let mut query = pid();
    query["multiple"] = json!(true);
    query
}

fn unsigned(dcql: Value, transaction_data: Option<Vec<String>>) -> VerifiedRequest {
    let mut params = json!({
        "response_type": "vp_token",
        "response_mode": "direct_post",
        "nonce": NONCE,
        "state": STATE,
        "dcql_query": dcql
    });
    if let Some(entries) = transaction_data {
        params["transaction_data"] = json!(entries);
    }
    redirect_unsigned(&params)
}

fn proof(range: &str) -> VerifiedRequest {
    redirect_signed(&json!({
        "response_type": "vp_token",
        "response_mode": "direct_post.jwt",
        "nonce": NONCE,
        "client_metadata": client_metadata(),
        "dcql_query": {"credentials": [query(Some(range), false)]}
    }))
}

/// The wallet: two SD-JWT VCs, an mDL and the nym_auth attestation, each presentable without
/// its UI when `background`.
fn wallet(background: bool) -> Wallet {
    let (data, auxiliary) = nym_auth(&Spec::default());
    let mut nym = Held::new(3, "mso_mdoc", data);
    nym.metadata = Some(auxiliary);
    let mut wallet = Wallet::new(vec![
        Held::new(
            1,
            "dc+sd-jwt",
            sd_jwt(VCT, &[("given_name", json!("Erika"))]),
        ),
        Held::new(
            2,
            "mso_mdoc",
            mdoc(MDL, MDL_NS, &[("family_name", Cbor::text("Doe"))]),
        ),
        nym,
        Held::new(4, "dc+sd-jwt", sd_jwt(VCT, &[("given_name", json!("Max"))])),
    ]);
    wallet.metadata = crate::host::holding(vec![(VCT, type_metadata())]);
    if background {
        wallet = wallet.all_in_background();
    }
    wallet
}

/// The `error` of a refusal posted in the form of the request's Response Mode.
fn error_of(request: &VerifiedRequest, refusal: &Submission) -> String {
    if request.encryption().is_some() {
        return decrypt_jwe(refusal)["error"].as_str().unwrap().to_owned();
    }
    let Submission::Post(post) = refusal else {
        panic!("a POST")
    };
    let PostParameters::Form(parameters) = post.parameters() else {
        panic!("direct_post, got {post:?}")
    };
    let Outcome::Error(code) = parameters.outcome() else {
        panic!("an error, got {parameters:?}")
    };
    code.as_str().to_owned()
}

#[test]
fn an_offer_needs_the_wallet_display_unless_a9_holds() {
    let mdl = json!({"id": "mdl", "format": "mso_mdoc", "meta": {"doctype_value": MDL},
        "claims": [{"path": [MDL_NS, "family_name"]}]});
    // (case, background, request, display)
    let cases = [
        (
            "an SD-JWT VC in the background",
            true,
            unsigned(json!({"credentials": [pid()]}), None),
            WalletDisplay::NotNeeded,
        ),
        (
            "a credential the wallet presents only on its UI",
            false,
            unsigned(json!({"credentials": [pid()]}), None),
            WalletDisplay::Needed,
        ),
        (
            "transaction data",
            true,
            unsigned(json!({"credentials": [pid()]}), Some(vec![payment()])),
            WalletDisplay::Needed,
        ),
        (
            "an optional addition",
            true,
            unsigned(
                json!({"credentials": [pid(), mdl], "credential_sets": [
                    {"options": [["pid"]]}, {"options": [["mdl"]], "required": false}]}),
                None,
            ),
            WalletDisplay::Needed,
        ),
        (
            "a subset of a multiple query",
            true,
            unsigned(json!({"credentials": [every_pid()]}), None),
            WalletDisplay::Needed,
        ),
        (
            "a proof statement shown whole",
            true,
            proof("18+"),
            WalletDisplay::NotNeeded,
        ),
    ];
    for (case, background, request, display) in cases {
        let wallet = wallet(background);
        let input = wallet.input(&request);
        let planned = ready(&input).unwrap();
        let offer = &planned.view().offers()[0];
        assert_eq!(offer.wallet_display(), display, "{case}");

        let selection = Selection::new(
            *planned.view().digest(),
            OfferIndex::new(0),
            Vec::new(),
            Vec::new(),
        );
        let background = planned.choose(&selection, Fulfilment::Background(HostDisplay::Full));
        match display {
            WalletDisplay::NotNeeded => {
                assert!(background.is_ok(), "{case}");
                // K4: an offer the host showed only in part needs the wallet's display.
                let skipped =
                    planned.choose(&selection, Fulfilment::Background(HostDisplay::Skipped));
                assert_eq!(
                    skipped.err(),
                    Some(PresentationError::WalletDisplayNeeded),
                    "{case}"
                );
            }
            WalletDisplay::Needed => {
                let error = background.err().unwrap();
                assert_eq!(error, PresentationError::WalletDisplayNeeded, "{case}");
                let refusal =
                    siros_presentation::refusal(&request, error.error_code(), &mut Rng(1)).unwrap();
                assert_eq!(error_of(&request, &refusal), "access_denied", "{case}");
            }
        }
    }
}
