//! Transaction data in the plan (PaSO Core, Section 7.4; OpenID4VP 1.0, Sections 5.1 and 8.5):
//! the honest path from signed credential metadata to the KB-JWT, Annex A.5's offers, the next
//! entry for a credential that supports no type of the first, and a refusal per plan rule with
//! the error the verifier receives.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use siros_codec::base64url;
use siros_oid4vp::ErrorCode;
use siros_presentation::testing::paso::{approval, entry, paso_wallet, APPROVAL};
use siros_presentation::PresentationError;
use siros_transaction_data::{
    Configuration, EntryPosition, Exclusion, Incompatibility, Location, LocationStep, PayloadFault,
    RowValue, SourceKind, TransactionDataError, UnsignedWarning,
};

use crate::host::{holding_absent, label_text};
use crate::verifier::{b64, client_metadata, dc_api_signed, dc_api_unsigned, decrypt_jwe, NONCE};
use crate::wallet::{ready, respond, sd_jwt, Held, Wallet, VCT};

/// The parameters of a DC API request for the `given_name` of each query of `queries`, all
/// required, carrying `transaction_data`.
fn params(queries: &[(&str, &str)], transaction_data: &[String]) -> Value {
    let credentials: Vec<Value> = queries
        .iter()
        .map(|(id, vct)| {
            json!({"id": id, "format": "dc+sd-jwt", "meta": {"vct_values": [vct]},
                   "claims": [{"path": ["given_name"]}]})
        })
        .collect();
    json!({
        "response_type": "vp_token", "response_mode": "dc_api.jwt", "nonce": NONCE,
        "client_metadata": client_metadata(), "transaction_data": transaction_data,
        "dcql_query": {"credentials": credentials}
    })
}

/// The claims of the KB-JWT the response of `input` sends for `pid`.
fn kb_jwt_claims(input: &siros_presentation::PlanInput<'_>) -> Value {
    let payload = decrypt_jwe(respond(input).submission());
    let sent = payload["vp_token"]["pid"][0].as_str().unwrap();
    let body = sent.rsplit('~').next().unwrap().split('.').nth(1).unwrap();
    serde_json::from_slice(&base64url::decode(body).unwrap()).unwrap()
}

#[test]
fn signed_credential_metadata_binds_the_entry_into_the_kb_jwt() {
    let wallet = paso_wallet(json!({APPROVAL: approval()}));
    let approval = entry(APPROVAL, "pid", json!({"what": "Pay 10.00 EUR"}));
    let request = dc_api_signed(&params(&[("pid", VCT)], std::slice::from_ref(&approval)));
    let input = wallet.input(&request);
    let planned = ready(&input).unwrap();
    let card = &planned.view().offers()[0].members()[0].credentials()[0];
    let view = card.transaction().unwrap().view();
    assert_eq!(view.source(), SourceKind::CredentialMetadata);
    assert_eq!(view.unsigned_warning(), UnsignedWarning::NotNeeded);
    let rows: Vec<(String, String)> = view
        .rows()
        .iter()
        .map(|row| match row.value() {
            RowValue::Value(value) => (label_text(row.label()), value.text()),
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(rows, [("What".to_owned(), "Pay 10.00 EUR".to_owned())]);
    assert_eq!(
        view.affirmative_action_label().map(label_text).as_deref(),
        Some("Approve")
    );

    let claims = kb_jwt_claims(&input);
    assert_eq!(
        claims["transaction_data_hashes"],
        json!([b64(&Sha256::digest(approval.as_bytes()))])
    );
    // B.3.3.1: `_alg` only when the entry carries one; the TS12 claims only under a TS12
    // rulebook.
    for absent in ["transaction_data_hashes_alg", "jti", "response_mode", "amr"] {
        assert!(claims.get(absent).is_none(), "{absent}");
    }
}

/// PaSO Core, Annex A.5 through the plan: four offers, each with one of the two payment
/// credentials, which binds the entry naming its query (Section 7.4.2).
#[test]
fn annex_a5_offers_bind_each_credential_its_entry() {
    const CARD: &str = "https://bank.example/sca/card";
    const ACCOUNT: &str = "https://bank.example/sca/account";
    const PID: &str = "https://credentials.example/pid";
    let names = [
        ("given_name", json!("Erika")),
        ("family_name", json!("Mustermann")),
    ];
    let mut wallet = Wallet::new(vec![
        Held::new(1, "dc+sd-jwt", sd_jwt(CARD, &[])),
        Held::new(2, "dc+sd-jwt", sd_jwt(ACCOUNT, &[])),
        Held::new(3, "dc+sd-jwt", sd_jwt(PID, &names)),
    ]);
    let metadata: Value = serde_json::from_str(include_str!(
        "../../../siros-transaction-data/tests/vectors/paso/metadata-a2-payload.json"
    ))
    .unwrap();
    let payment = "urn:paso:sca:global:payment:1";
    let definition = &metadata["credential_metadata"]["transaction_data_types"][payment];
    let configured =
        json!([{"type": payment, "vct_values": [CARD, ACCOUNT], "definition": definition}]);
    wallet.configuration = Configuration::parse(&configured.to_string()).unwrap();
    wallet.metadata = holding_absent(&[CARD, ACCOUNT, PID]);
    let a5: Value = serde_json::from_str(include_str!(
        "../../../siros-transaction-data/tests/vectors/paso/core-a5-request.json"
    ))
    .unwrap();
    let entries: Vec<Value> = serde_json::from_str(include_str!(
        "../../../siros-transaction-data/tests/vectors/paso/core-a5-entries.json"
    ))
    .unwrap();
    let transaction_data: Vec<String> = entries
        .iter()
        .map(|entry| b64(entry.to_string().as_bytes()))
        .collect();
    let request = dc_api_signed(&json!({
        "response_type": "vp_token", "response_mode": "dc_api.jwt", "nonce": NONCE,
        "client_metadata": client_metadata(), "transaction_data": transaction_data,
        "dcql_query": a5["dcql_query"]
    }));
    let planned = ready(&wallet.input(&request)).unwrap();
    let offers: Vec<Vec<(String, Option<usize>)>> = planned
        .view()
        .offers()
        .iter()
        .map(|offer| {
            offer
                .members()
                .iter()
                .map(|member| {
                    let [credential] = member.credentials() else {
                        panic!("one credential per member")
                    };
                    let bound = credential.transaction().map(|t| t.entry().value());
                    (member.query_id().as_str().to_owned(), bound)
                })
                .collect()
        })
        .collect();
    let member = |query: &str, bound: Option<usize>| (query.to_owned(), bound);
    assert_eq!(
        offers,
        [
            vec![member("sca_card", Some(0)), member("pid", None)],
            vec![member("sca_card", Some(0))],
            vec![member("sca_account", Some(1)), member("pid", None)],
            vec![member("sca_account", Some(1))],
        ]
    );
}

/// OpenID4VP 1.0, Section 5.1, under PaSO's first match: an entry of a type no source defines
/// for the credential refuses nothing while the credential takes a later entry.
#[test]
fn a_credential_takes_the_next_entry_of_a_type_it_supports() {
    let wallet = paso_wallet(json!({APPROVAL: approval()}));
    let entries = [
        entry(
            "urn:paso:sca:com.example:approval:2",
            "pid",
            json!({"what": "Pay", "points": 3}),
        ),
        entry(APPROVAL, "pid", json!({"what": "Pay"})),
    ];
    let request = dc_api_signed(&params(&[("pid", VCT)], &entries));
    let planned = ready(&wallet.input(&request)).unwrap();
    let card = &planned.view().offers()[0].members()[0].credentials()[0];
    assert_eq!(card.transaction().unwrap().entry(), EntryPosition::new(1));
}

#[test]
fn each_plan_rule_refuses_the_request() {
    let wallet = paso_wallet(json!({APPROVAL: approval()}));
    let credential = wallet.credentials[0].entry();
    let excluded = |cause| {
        vec![Exclusion {
            credential,
            causes: vec![(EntryPosition::new(0), cause)],
        }]
    };
    let pid = [("pid", VCT)];
    let rows = [
        (
            "a type no source defines for the credential",
            dc_api_signed(&params(
                &pid,
                &[entry("urn:example:unknown", "pid", json!({}))],
            )),
            TransactionDataError::TypeUnknown(
                EntryPosition::new(0),
                excluded(Incompatibility::TypeUndeclared),
            ),
            ErrorCode::InvalidTransactionData,
        ),
        (
            "a payload the only candidate does not conform to",
            dc_api_signed(&params(
                &pid,
                &[entry(APPROVAL, "pid", json!({"what": "Pay", "extra": 1}))],
            )),
            TransactionDataError::NoCompatibleCredential(excluded(Incompatibility::Payload(
                PayloadFault::Uncovered(Location::new(vec![LocationStep::Key("extra".to_owned())])),
            ))),
            ErrorCode::InvalidTransactionData,
        ),
        (
            "an entry for a query no credential answers",
            dc_api_signed(&params(
                &[("pid", VCT), ("card", "https://bank.example/card")],
                &[entry(APPROVAL, "card", json!({"what": "Pay"}))],
            )),
            TransactionDataError::CredentialUnavailable,
            ErrorCode::InvalidTransactionData,
        ),
        (
            "a PaSO type in an unsigned request",
            dc_api_unsigned(&params(
                &pid,
                &[entry(APPROVAL, "pid", json!({"what": "Pay"}))],
            )),
            TransactionDataError::Unsigned(EntryPosition::new(0)),
            ErrorCode::InvalidRequest,
        ),
    ];
    for (case, request, expected, code) in rows {
        let error = ready(&wallet.input(&request)).map(drop).unwrap_err();
        assert_eq!(error.error_code(), code, "{case}");
        assert_eq!(
            error,
            PresentationError::TransactionData(expected),
            "{case}"
        );
    }
}
