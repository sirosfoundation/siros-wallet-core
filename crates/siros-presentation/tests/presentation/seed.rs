//! The rules of a delivered `secret_seed`: a nym_auth credential whose auxiliary data delivers
//! none answers no `zkp_req` query, excluded with the reason. One row per rule.

use serde_json::{json, Value};
use siros_codec::base64url;
use siros_codec::json::{JsonFault, ReadFault};
use siros_dcql::QueryId;
use siros_presentation::{Exclusion, Failure, NoSeed, PresentationError, Unproven};
use siros_zkp_req_nym_auth::testing::{query, Spec};

use crate::verifier::{b64, client_metadata, redirect_signed, NONCE};
use crate::wallet::{nym_auth, ready, Held, Wallet};

/// A `hash_commitment` entry of `ssc` with the 16-byte `opening` `opening`, edited by `edit`.
fn entry(edit: impl FnOnce(&mut Value)) -> Value {
    let mut entry = json!({"type": "hash_commitment", "alg": "sha-256",
        "path": ["eu.europa.ec.eudi.nym_auth.1", "ssc"], "opening": b64(&[7; 16])});
    edit(&mut entry);
    entry
}

/// Why the nym_auth query has no offer over the attestation whose `auxiliary_data` value is
/// `value`.
fn refusal(value: Value) -> PresentationError {
    let (data, _) = nym_auth(&Spec::default());
    let mut nym = Held::new(1, "mso_mdoc", data);
    nym.metadata = Some(json!([{"type": "auxiliary_data", "value": value}]));
    let wallet = Wallet::new(vec![nym]);
    let request = redirect_signed(&json!({
        "response_type": "vp_token",
        "response_mode": "direct_post.jwt",
        "nonce": NONCE,
        "client_metadata": client_metadata(),
        "dcql_query": {"credentials": [query(Some("18+"), true)]}
    }));
    match ready(&wallet.input(&request)) {
        Ok(_) => panic!("an offer for {value}"),
        Err(refusal) => refusal,
    }
}

#[test]
fn each_rule_of_the_delivered_seed() {
    let mut deep = json!(0);
    for _ in 0..64 {
        deep = json!([deep]);
    }
    let cases = [
        (
            json!([deep]),
            NoSeed::Entries(JsonFault::Read(ReadFault::TooDeep)),
        ),
        (json!({"type": "hash_commitment"}), NoSeed::EntriesNotArray),
        (json!([]), NoSeed::Missing),
        (json!([entry(|_| {}), entry(|_| {})]), NoSeed::Repeated),
        (
            json!([entry(|e| e["alg"] = json!("sha-512"))]),
            NoSeed::Algorithm,
        ),
        (
            json!([entry(|e| e["encoding"] = json!("cbor"))]),
            NoSeed::Encoding,
        ),
        (
            json!([entry(|e| drop(
                e.as_object_mut().unwrap().remove("opening")
            ))]),
            NoSeed::OpeningAbsent,
        ),
        (
            json!([entry(|e| e["opening"] = json!(7))]),
            NoSeed::OpeningNotString,
        ),
        (
            json!([entry(|e| e["opening"] = json!("AA=A"))]),
            NoSeed::OpeningNotBase64url(base64url::decode("AA=A").unwrap_err()),
        ),
        (
            json!([entry(|e| e["opening"] = json!(b64(&[7; 15])))]),
            NoSeed::OpeningLength(15),
        ),
    ];
    for (value, cause) in cases {
        let expected = PresentationError::NoOffer(Failure::Excluded {
            query: QueryId::parse("nym").unwrap(),
            reasons: vec![Exclusion::Unproven(Unproven::Seed(cause))],
        });
        assert_eq!(refusal(value.clone()), expected, "{value}");
    }
}
