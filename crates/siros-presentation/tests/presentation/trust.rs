//! A1's trust rule: a credential whose issuer the query's `trusted_authorities` refuse matches
//! nothing, and a malformed `aki` value makes the request invalid (TR3).

use serde_json::json;
use siros_codec::base64url;
use siros_codec::cbor::Value as Cbor;
use siros_presentation::{Failure, PresentationError, QueryRefusal};
use siros_trust::{AkiError, AuthorityError, Certificate, TrustStore};
use siros_wallet_state::CredentialId;
use siros_zkp_req_nym_auth::testing::Issuer;

use crate::verifier::{redirect_unsigned, NONCE, STATE};
use crate::wallet::{base64, mdoc_by, ready, sd_jwt, sd_jwt_x5c, Held, Wallet, MDL, MDL_NS, VCT};

const LIST: &str = "https://tl.example/eu";

#[test]
fn the_plan_offers_only_the_credentials_whose_issuer_the_query_admits() {
    let root = Issuer::root(0x61, "Admitted root");
    let admitted = root.sign_child(0x62, "Admitted Document Signer");
    let other = Issuer::root(0x63, "Other root").sign_child(0x64, "Other Document Signer");
    let claims = [("given_name", json!("Erika"))];
    let items = [("family_name", Cbor::text("Mustermann"))];
    let mut wallet = Wallet::new(vec![
        Held::new(1, "dc+sd-jwt", sd_jwt_x5c(VCT, &claims, &[&admitted.der])),
        Held::new(2, "dc+sd-jwt", sd_jwt_x5c(VCT, &claims, &[&other.der])),
        Held::new(3, "mso_mdoc", mdoc_by(&admitted, MDL, MDL_NS, &items)),
        Held::new(4, "mso_mdoc", mdoc_by(&other, MDL, MDL_NS, &items)),
    ]);
    wallet.trust = TrustStore::parse(
        &json!([{"type": "etsi_tl", "value": LIST, "certificates": [base64(&root.der)]}])
            .to_string(),
    )
    .unwrap();
    // The `aki` of the admitted Document Signer, as its certificate's builder wrote it.
    let aki = Certificate::parse(&admitted.der)
        .unwrap()
        .authority_key_identifier()
        .map(|key| base64url::encode(key.as_bytes()).into_string())
        .unwrap();
    let request = redirect_unsigned(&json!({
        "response_type": "vp_token", "response_mode": "direct_post", "nonce": NONCE,
        "state": STATE,
        "dcql_query": {"credentials": [
            {"id": "pid", "format": "dc+sd-jwt", "meta": {"vct_values": [VCT]},
                "trusted_authorities": [{"type": "aki", "values": [aki]}],
                "claims": [{"path": ["given_name"]}]},
            {"id": "mdl", "format": "mso_mdoc", "meta": {"doctype_value": MDL},
                "trusted_authorities": [{"type": "etsi_tl", "values": [LIST]}],
                "claims": [{"path": [MDL_NS, "family_name"]}]}
        ]}
    }));
    let planned = ready(&wallet.input(&request)).unwrap();

    let offers: Vec<Vec<(String, Vec<CredentialId>)>> = planned
        .view()
        .offers()
        .iter()
        .map(|offer| {
            offer
                .members()
                .iter()
                .map(|member| {
                    let credentials = member
                        .credentials()
                        .iter()
                        .map(|c| c.entry().credential_id())
                        .collect();
                    (member.query_id().as_str().to_owned(), credentials)
                })
                .collect()
        })
        .collect();
    assert_eq!(
        offers,
        [[
            ("pid".to_owned(), vec![CredentialId::new(1)]),
            ("mdl".to_owned(), vec![CredentialId::new(3)])
        ]]
    );
}

/// One Credential Query with a malformed `aki` value refuses the whole request
/// (`invalid_request`), though another option of its credential set answers.
#[test]
fn a_malformed_aki_value_refuses_the_request() {
    let claims = [("given_name", json!("Erika"))];
    let wallet = Wallet::new(vec![Held::new(1, "dc+sd-jwt", sd_jwt(VCT, &claims))]);
    let request = redirect_unsigned(&json!({
        "response_type": "vp_token", "response_mode": "direct_post", "nonce": NONCE,
        "state": STATE,
        "dcql_query": {
            "credentials": [
                {"id": "bad", "format": "dc+sd-jwt", "meta": {"vct_values": [VCT]},
                    "trusted_authorities": [{"type": "aki", "values": ["!"]}],
                    "claims": [{"path": ["given_name"]}]},
                {"id": "good", "format": "dc+sd-jwt", "meta": {"vct_values": [VCT]},
                    "claims": [{"path": ["given_name"]}]}
            ],
            "credential_sets": [{"options": [["bad"], ["good"]]}]
        }
    }));
    let error = ready(&wallet.input(&request))
        .map(drop)
        .expect_err("an invalid Credential Query refuses the request");
    assert!(
        matches!(
            &error,
            PresentationError::NoOffer(Failure::Refused {
                query,
                refusal: QueryRefusal::Authorities(AuthorityError::Aki {
                    error: AkiError::Base64url(_),
                    ..
                }),
            }) if query == "bad"
        ),
        "{error:?}"
    );
}
