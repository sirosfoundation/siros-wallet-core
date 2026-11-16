//! The transaction data validation: the base64url entries, the type
//! allow-list, the credential id references, and the JSON null rejection.

use engine_core::oid4vp::transaction_data::{reject_null, validate_transaction_data};
use engine_core::oid4vp::types::TransactionDataError;

fn base64url_json(value: serde_json::Value) -> String {
    let bytes = serde_json::to_vec(&value).expect("serialize");
    jose_rs::base64url::encode(&bytes)
}
#[test]
fn validates_a_known_type_with_matching_credential_ids() {
    let td = base64url_json(serde_json::json!({
        "type": "owf_payment_initiation",
        "credential_ids": ["cred-1"],
        "payload": { "amount": "100" }
    }));
    let dcql = serde_json::json!({
        "credentials": [{ "id": "cred-1" }]
    });
    let entries = validate_transaction_data(&[td], &Some(dcql)).expect("validate");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].transaction_type, "owf_payment_initiation");
}

#[test]
fn refuses_json_null() {
    assert!(matches!(
        reject_null(&serde_json::Value::Null),
        Err(TransactionDataError::Null)
    ));
}

#[test]
fn refuses_an_unknown_type() {
    let td = base64url_json(serde_json::json!({
        "type": "some_unknown_type",
        "credential_ids": []
    }));
    assert!(matches!(
        validate_transaction_data(&[td], &None),
        Err(TransactionDataError::UnsupportedType { .. })
    ));
}

#[test]
fn refuses_an_invalid_credential_id_reference() {
    let td = base64url_json(serde_json::json!({
        "type": "owf_payment_initiation",
        "credential_ids": ["not-in-query"]
    }));
    let dcql = serde_json::json!({
        "credentials": [{ "id": "cred-1" }]
    });
    assert!(matches!(
        validate_transaction_data(&[td], &Some(dcql)),
        Err(TransactionDataError::InvalidJson { .. })
    ));
}

#[test]
fn refuses_invalid_base64url() {
    assert!(matches!(
        validate_transaction_data(&["not-base64!!!".to_owned()], &None),
        Err(TransactionDataError::InvalidEncoding { .. })
    ));
}
