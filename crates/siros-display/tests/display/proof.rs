//! The picker's proof statement rows of a nym_auth option, against values written by hand from
//! `proof::rows`' contract: the label, the detail, and the `(unverified request)` marker.

use serde_json::json;
use siros_dcql::CredentialQuery;
use siros_display::proof;
use siros_zkp_req::ZkpReqQuery;

#[test]
fn each_row_of_a_nym_auth_option_ends_in_the_unverified_marker() {
    let query = CredentialQuery::parse(&json!({
        "id": "nym",
        "format": "zkp_req",
        "meta": {"source_format": "mso_mdoc", "doctype_value": "eu.europa.ec.av.1"},
        "_req": [
            {"fn_id": "pseudonym", "return": "nym",
             "params": {"config": "known-offender-matching-ssc", "ver": 1, "prf": "sha-256"}},
            {"fn_id": "age_check", "params": {"range": "18+"}}
        ]
    }))
    .unwrap();
    let query = ZkpReqQuery::parse(&query).unwrap();
    let option = query.options().first().unwrap();
    let rows: Vec<(String, Option<String>)> = proof::rows(&query, option)
        .unwrap()
        .iter()
        .map(|field| {
            (
                field.name().as_str().to_owned(),
                field.value().map(|value| value.as_str().to_owned()),
            )
        })
        .collect();
    assert_eq!(
        rows,
        [
            (
                "Pseudonym".to_owned(),
                Some("config known-offender-matching-ssc (unverified request)".to_owned())
            ),
            (
                "Age check".to_owned(),
                Some("age 18+ (unverified request)".to_owned())
            ),
        ]
    );
}
