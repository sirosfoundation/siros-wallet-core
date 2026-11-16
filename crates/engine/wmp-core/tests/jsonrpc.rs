//! JSON-RPC 2.0 framing: notifications, the `params` member, and the strict
//! decoder's version, trailing-data, size and depth checks.

use wmp_core::jsonrpc::{
    decode_batch, decode_message, new_notification, new_request, DecodeError, DecodeOptions,
    Request,
};

#[test]
fn notification_is_detected_by_absent_and_null_id() {
    let notification =
        new_notification("wmp.flow.progress", &serde_json::json!({})).expect("serialize");
    assert!(notification.is_notification());
    let with_null_id =
        serde_json::from_str::<Request>(r#"{"jsonrpc":"2.0","id":null,"method":"m"}"#)
            .expect("parse");
    assert!(with_null_id.is_notification());
    let request = new_request(Some("msg-1"), "m", &serde_json::json!({})).expect("serialize");
    assert!(!request.is_notification());
}

#[test]
fn params_member_is_always_present() {
    let request = new_request(Some("id"), "m", &serde_json::json!({})).expect("serialize");
    let text = serde_json::to_string(&request).expect("serialize");
    assert!(text.contains(r#""params""#));
    let params_none =
        serde_json::from_str::<Request>(r#"{"jsonrpc":"2.0","method":"m"}"#).expect("parse");
    let text = serde_json::to_string(&params_none).expect("serialize");
    assert!(text.contains(r#""params":null"#));
}

#[test]
fn decode_refuses_wrong_version_and_trailing_data() {
    let err = decode_message(
        br#"{"jsonrpc":"1.0","method":"m"}"#,
        DecodeOptions::default(),
    )
    .expect_err("wrong version");
    assert!(matches!(err, DecodeError::UnsupportedVersion(_)));
    let err = decode_message(
        br#"{"jsonrpc":"2.0","method":"m"} trailing"#,
        DecodeOptions::default(),
    )
    .expect_err("trailing data");
    assert!(matches!(err, DecodeError::Trailing));
}

#[test]
fn decode_enforces_size_and_depth_limits() {
    let err = decode_message(
        b"{\"jsonrpc\":\"2.0\",\"method\":\"m\"}",
        DecodeOptions {
            max_size: Some(4),
            max_depth: None,
        },
    )
    .expect_err("too large");
    assert!(matches!(err, DecodeError::TooLarge { max: 4 }));

    let deep = format!(
        "{{\"jsonrpc\":\"2.0\",\"method\":\"m\",\"params\":{}{}{}}}",
        "[".repeat(40),
        r#""x""#,
        "]".repeat(40)
    );
    let err = decode_message(deep.as_bytes(), DecodeOptions::default()).expect_err("too deep");
    assert!(matches!(err, DecodeError::DepthExceeded { max: 32 }));

    let within = format!(
        "{{\"jsonrpc\":\"2.0\",\"method\":\"m\",\"params\":{}{}{}}}",
        "[".repeat(31),
        r#""x""#,
        "]".repeat(31)
    );
    assert!(decode_message(within.as_bytes(), DecodeOptions::default()).is_ok());
}

#[test]
fn batch_returns_none_for_non_arrays_and_checks_members() {
    assert!(
        decode_batch(b" {\"jsonrpc\":\"2.0\"} ", DecodeOptions::default())
            .expect("decode")
            .is_none()
    );
    let batch = decode_batch(
        br#"[{"jsonrpc":"2.0","method":"a"},{"jsonrpc":"2.0","method":"b"}]"#,
        DecodeOptions::default(),
    )
    .expect("decode")
    .expect("batch");
    assert_eq!(batch.len(), 2);
    let err = decode_batch(
        br#"[{"jsonrpc":"2.0","method":"a"},{"jsonrpc":"9.9","method":"b"}]"#,
        DecodeOptions::default(),
    )
    .expect_err("bad member");
    assert!(matches!(err, DecodeError::UnsupportedVersion(_)));
}

#[test]
fn message_kinds_and_views() {
    let msg = decode_message(
        br#"{"jsonrpc":"2.0","id":"m1","method":"wmp.session.create","params":{"wmp":{"version":"0.1"}}}"#,
        DecodeOptions::default(),
    )
    .expect("decode");
    assert!(msg.is_request());
    assert!(!msg.is_response());
    assert_eq!(msg.as_request().method, "wmp.session.create");

    let msg = decode_message(
        br#"{"jsonrpc":"2.0","id":"m1","result":{"wmp":{"version":"0.1","session_id":"ses-1"}}}"#,
        DecodeOptions::default(),
    )
    .expect("decode");
    assert!(msg.is_response());
    assert!(!msg.is_request());
    assert!(msg.as_response().result.is_some());
}
