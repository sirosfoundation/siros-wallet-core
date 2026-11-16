//! The honest path of an SD-JWT VC over redirects with `direct_post.jwt`, authorizing a TS12
//! payment: the KB-JWT verifies under the holder's key, binds the presentation as sent and the
//! payment, and names the verifier (A6).

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use siros_codec::base64url;
use siros_dcql::QueryId;
use siros_presentation::{OfferIndex, Pick, PresentationError, WalletDisplay};
use siros_transaction_data::{RowValue, UnsignedWarning};
use siros_wallet_state::CredentialId;

use crate::host::{holding, label_text};
use crate::verifier::{
    b64, client_metadata, dc_api_signed, decrypt_jwe, redirect_unsigned, NONCE, NOW, RESPONSE_URI,
    STATE,
};
use crate::wallet::{
    disclosed, holder_signed, ready, respond, respond_to, respond_with, sd_jwt, Held, Wallet, VCT,
};

const PAYMENT: &str = "urn:eudi:sca:payment:1";

/// The payment entry of `transaction_data` naming the query `pid`, as the verifier sends it.
pub fn payment() -> String {
    payment_for("pid")
}

/// The payment entry of `transaction_data` naming the query `query`.
pub fn payment_for(query: &str) -> String {
    payment_naming(&[query])
}

/// The payment entry of `transaction_data` naming the queries `queries`.
pub fn payment_naming(queries: &[&str]) -> String {
    let entry = json!({
        "type": PAYMENT,
        "credential_ids": queries,
        "transaction_data_hashes_alg": ["sha-256"],
        "payload": {
            "transaction_id": "tx-0001",
            "payee": {"name": "Shop AB", "id": "SE1234567890"},
            "currency": "EUR",
            "amount": 49.99
        }
    });
    b64(entry.to_string().as_bytes())
}

/// The SCA Attestation type metadata of [`VCT`], listing the payment type with its labels.
pub fn type_metadata() -> Vec<u8> {
    type_metadata_of(VCT)
}

/// The SCA Attestation type metadata of `vct`, listing the payment type with its labels.
pub fn type_metadata_of(vct: &str) -> Vec<u8> {
    let claim = |path: &[&str], label: &str| {
        let mut full = vec!["payload"];
        full.extend_from_slice(path);
        json!({"path": full, "display": [{"lang": "en", "label": label}]})
    };
    let document = json!({
        "vct": vct,
        "name": "Pay Card",
        "category": "urn:eu:europa:ec:eudi:sua:sca",
        "transaction_data_types": {PAYMENT: {
            "schema_uri": PAYMENT,
            "claims": [
                claim(&["transaction_id"], "Transaction ID"),
                claim(&["payee", "name"], "Payee"),
                claim(&["payee", "id"], "Payee ID"),
                claim(&["currency"], "Currency"),
                claim(&["amount"], "Amount")
            ],
            "ui_labels": {
                "affirmative_action_label": [{"lang": "en", "value": "Confirm Payment"}]
            }
        }}
    });
    document.to_string().into_bytes()
}

#[test]
fn sd_jwt_over_redirect_direct_post_jwt() {
    let given = json!("Erika");
    let family = json!("Mustermann");
    let mut wallet = Wallet::new(vec![Held::new(
        1,
        "dc+sd-jwt",
        sd_jwt(
            VCT,
            &[("given_name", given.clone()), ("family_name", family)],
        ),
    )]);
    wallet.metadata = holding(vec![(VCT, type_metadata())]);
    let request = redirect_unsigned(&json!({
        "response_type": "vp_token",
        "response_mode": "direct_post.jwt",
        "nonce": NONCE,
        "state": STATE,
        "client_metadata": client_metadata(),
        "transaction_data": [payment()],
        "dcql_query": {"credentials": [{"id": "pid", "format": "dc+sd-jwt",
            "meta": {"vct_values": [VCT]}, "claims": [{"path": ["given_name"]}]}]}
    }));
    let input = wallet.input(&request);
    let planned = ready(&input).unwrap();
    let offer = &planned.view().offers()[0];
    let card = &offer.members()[0].credentials()[0];
    let transaction = card.transaction().unwrap();
    assert_eq!(transaction.entry().value(), 0);
    let rows: Vec<(String, String)> = transaction
        .view()
        .rows()
        .iter()
        .map(|row| match row.value() {
            RowValue::Value(value) => (label_text(row.label()), value.text()),
            other => panic!("{other:?}"),
        })
        .collect();
    let expected = [
        ("Transaction ID", "tx-0001"),
        ("Payee", "Shop AB"),
        ("Payee ID", "SE1234567890"),
        ("Currency", "EUR"),
        ("Amount", "49.99"),
    ];
    assert_eq!(
        rows,
        expected.map(|(label, value)| (label.to_owned(), value.to_owned()))
    );
    // An unsigned request of a TS12 type: the UI warns and asks for explicit confirmation.
    assert_eq!(
        transaction.view().unsigned_warning(),
        UnsignedWarning::Required
    );
    assert_eq!(offer.wallet_display(), WalletDisplay::Needed);

    let response = respond(&input);
    let payload = decrypt_jwe(response.submission());
    assert_eq!(payload["state"], STATE);
    let sent = payload["vp_token"]["pid"][0].as_str().unwrap();
    let (presentation, kb_jwt) = sent.rsplit_once('~').unwrap();
    let presentation = format!("{presentation}~");
    let (issuer_jwt, rest) = presentation.split_once('~').unwrap();
    assert!(issuer_jwt.starts_with("eyJ"));
    assert_eq!(rest, format!("{}~", disclosed("given_name", &given)));

    let [header, body, signature] = kb_jwt.split('.').collect::<Vec<_>>()[..] else {
        panic!("a compact KB-JWT")
    };
    let header: Value = serde_json::from_slice(&base64url::decode(header).unwrap()).unwrap();
    assert_eq!(header, json!({"typ": "kb+jwt", "alg": "ES256"}));
    let signing_input = kb_jwt.rsplit_once('.').unwrap().0;
    assert!(holder_signed(
        signing_input.as_bytes(),
        &base64url::decode(signature).unwrap()
    ));
    let claims: Value = serde_json::from_slice(&base64url::decode(body).unwrap()).unwrap();
    assert_eq!(claims["aud"], format!("redirect_uri:{RESPONSE_URI}"));
    assert_eq!(claims["nonce"], NONCE);
    assert_eq!(claims["iat"], NOW);
    assert_eq!(
        claims["sd_hash"],
        b64(&Sha256::digest(presentation.as_bytes()))
    );
    assert_eq!(
        claims["transaction_data_hashes"],
        json!([b64(&Sha256::digest(payment().as_bytes()))])
    );
    assert_eq!(claims["transaction_data_hashes_alg"], "sha-256");
    assert_eq!(claims["response_mode"], "direct_post.jwt");
    assert_eq!(
        claims["amr"],
        json!([{"possession": "key_in_local_native_wscd"}, {"inherence": "fingerprint_device"}])
    );
    assert_eq!(
        base64url::decode(claims["jti"].as_str().unwrap())
            .unwrap()
            .len(),
        16
    );

    let record = serde_json::to_value(response.record()).unwrap();
    assert_eq!(record["usedCredentialIds"], json!([1]));
    assert_eq!(record["audience"], format!("redirect_uri:{RESPONSE_URI}"));
    assert_eq!(record["presentationTimestampSeconds"], NOW);
    let data: Value = serde_json::from_str(record["data"].as_str().unwrap()).unwrap();
    assert_eq!(data, payload["vp_token"]);
}

/// A6: over the DC API the KB-JWT names the calling origin, a signed request included.
#[test]
fn kb_jwt_aud_over_the_dc_api() {
    let wallet = Wallet::new(vec![Held::new(
        1,
        "dc+sd-jwt",
        sd_jwt(VCT, &[("given_name", json!("Erika"))]),
    )]);
    let request = dc_api_signed(&json!({
        "response_type": "vp_token",
        "response_mode": "dc_api.jwt",
        "nonce": NONCE,
        "client_metadata": client_metadata(),
        "dcql_query": {"credentials": [{"id": "pid", "format": "dc+sd-jwt",
            "meta": {"vct_values": [VCT]}, "claims": [{"path": ["given_name"]}]}]}
    }));
    let response = respond(&wallet.input(&request));
    let payload = decrypt_jwe(response.submission());
    let sent = payload["vp_token"]["pid"][0].as_str().unwrap();
    let body = sent.rsplit('~').next().unwrap().split('.').nth(1).unwrap();
    let claims: Value = serde_json::from_slice(&base64url::decode(body).unwrap()).unwrap();
    assert_eq!(claims["aud"], "origin:https://verifier.example");
}

/// T4, A3 and K3: the view names the credential the payment binds to by its `credentialId`;
/// the same ids in any order, in a subset or in picks, give the same response, which binds the
/// payment to that credential; a subset without it is refused.
#[test]
fn a_subset_keeps_the_plans_binding() {
    let mut wallet = Wallet::new(vec![
        Held::new(1, "dc+sd-jwt", sd_jwt(VCT, &[("given_name", json!("One"))])),
        Held::new(2, "dc+sd-jwt", sd_jwt(VCT, &[("given_name", json!("Two"))])),
    ]);
    wallet.metadata = holding(vec![(VCT, type_metadata())]);
    let request = redirect_unsigned(&json!({
        "response_type": "vp_token",
        "response_mode": "direct_post.jwt",
        "nonce": NONCE,
        "state": STATE,
        "client_metadata": client_metadata(),
        "transaction_data": [payment()],
        "dcql_query": {"credentials": [{"id": "pid", "format": "dc+sd-jwt", "multiple": true,
            "meta": {"vct_values": [VCT]}, "claims": [{"path": ["given_name"]}]}]}
    }));
    let input = wallet.input(&request);
    let planned = ready(&input).unwrap();
    let credentials = planned.view().offers()[0].members()[0].credentials();
    let shown: Vec<(CredentialId, Option<usize>)> = credentials
        .iter()
        .map(|c| {
            let entry = c.transaction().map(|t| t.entry().value());
            (c.entry().credential_id(), entry)
        })
        .collect();
    assert_eq!(
        shown,
        [
            (CredentialId::new(1), Some(0)),
            (CredentialId::new(2), None)
        ],
        "the view binds the payment to One"
    );

    let ids = |ids: &[u64]| vec![("pid".to_owned(), ids.to_vec())];
    let response = respond_to(&input, 0, Vec::new(), ids(&[1, 2])).unwrap();
    let reordered = respond_to(&input, 0, Vec::new(), ids(&[2, 1])).unwrap();
    let pick = |id| {
        let query = QueryId::parse("pid").unwrap();
        Pick::new(OfferIndex::new(0), query, CredentialId::new(id))
    };
    let picked = respond_with(&input, |planned| planned.picked(&[pick(2), pick(1)])).unwrap();
    assert_eq!(reordered.submission(), response.submission());
    assert_eq!(picked.submission(), response.submission());
    let payload = decrypt_jwe(response.submission());
    let bound: Vec<(String, bool)> = payload["vp_token"]["pid"]
        .as_array()
        .unwrap()
        .iter()
        .map(|sent| {
            let sent = sent.as_str().unwrap();
            let given = if sent.contains(&disclosed("given_name", &json!("One"))) {
                "One"
            } else {
                "Two"
            };
            let body = sent.rsplit('~').next().unwrap().split('.').nth(1).unwrap();
            let claims: Value = serde_json::from_slice(&base64url::decode(body).unwrap()).unwrap();
            (
                given.to_owned(),
                claims.get("transaction_data_hashes").is_some(),
            )
        })
        .collect();
    assert_eq!(bound, [("One".to_owned(), true), ("Two".to_owned(), false)]);

    let one = &credentials[0];
    assert_eq!(
        respond_to(&input, 0, Vec::new(), ids(&[2])).err(),
        Some(PresentationError::BoundCredentialOmitted {
            entry: one.transaction().unwrap().entry(),
            credential: one.entry(),
        })
    );
}
