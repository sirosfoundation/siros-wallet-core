//! The DCQL helpers: the raw query check, the vp_token assembly, the
//! requested types, and the endpoint sanitization.

use engine_core::oid4vp::dcql::{
    build_dcql_vp_token, requested_credential_types, sanitize_endpoint_url, validate_raw_query,
    DcqlError,
};
use engine_ports::VpSelection;
use serde_json::{json, Value};

fn selection(query_id: &str) -> VpSelection {
    VpSelection {
        credential_query_id: query_id.to_owned(),
        credential_id: format!("cred-{query_id}"),
        disclosed_claims: Vec::new(),
    }
}

#[test]
fn the_raw_query_must_be_valid_json() {
    assert!(validate_raw_query("").is_ok());
    assert!(validate_raw_query("{\"credentials\":[]}").is_ok());
    assert_eq!(validate_raw_query("not json"), Err(DcqlError::InvalidJson));
}

#[test]
fn one_token_per_selection_builds_the_object() {
    let vp = build_dcql_vp_token("token-a\ntoken-b", &[selection("pid"), selection("degree")])
        .expect("build");
    let value: Value = serde_json::from_str(&vp).expect("json");
    assert_eq!(value["pid"], json!(["token-a"]));
    assert_eq!(value["degree"], json!(["token-b"]));
}

#[test]
fn a_count_mismatch_refuses() {
    let err = build_dcql_vp_token("token-a", &[selection("pid"), selection("degree")]);
    assert_eq!(
        err,
        Err(DcqlError::TokenCount {
            tokens: 1,
            selected: 2
        })
    );
}

#[test]
fn a_host_object_passes_through() {
    let object = "{\"pid\":[\"token-a\"]}";
    let vp = build_dcql_vp_token(object, &[selection("pid")]).expect("build");
    assert_eq!(vp, object);
}

#[test]
fn two_tokens_for_one_query_collect() {
    let vp = build_dcql_vp_token("token-a\ntoken-b", &[selection("pid"), selection("pid")])
        .expect("build");
    let value: Value = serde_json::from_str(&vp).expect("json");
    assert_eq!(value["pid"], json!(["token-a", "token-b"]));
}

#[test]
fn a_selection_answering_no_query_is_dropped() {
    let vp = build_dcql_vp_token(
        "token-a\ntoken-b",
        &[selection("pid"), VpSelection::default()],
    )
    .expect("build");
    let value: Value = serde_json::from_str(&vp).expect("json");
    assert_eq!(value.as_object().map(|o| o.len()), Some(1));
}

#[test]
fn the_requested_types_name_the_queries() {
    let query = json!({
        "credentials": [
            { "id": "q1", "meta": { "vct_values": ["urn:degree"] } },
            { "id": "q2", "meta": { "doctype_value": "org.iso.pid" } },
            { "id": "q3", "meta": {} }
        ]
    });
    let types = requested_credential_types(Some(&query));
    assert_eq!(types, vec!["urn:degree", "org.iso.pid", "q3"]);
}

#[test]
fn the_requested_types_are_best_effort() {
    assert!(requested_credential_types(None).is_empty());
    // An exotic query yields no names, not an error.
    assert!(requested_credential_types(Some(&json!("anything"))).is_empty());
}

#[test]
fn endpoints_are_sanitized_and_rebuilt() {
    assert_eq!(
        sanitize_endpoint_url("https://verifier.example/response?x=1#frag").expect("clean"),
        "https://verifier.example/response?x=1"
    );
    assert_eq!(
        sanitize_endpoint_url("http://verifier.example/r").expect("clean"),
        "http://verifier.example/r"
    );
}

#[test]
fn non_http_schemes_and_hostless_urls_refuse() {
    assert_eq!(
        sanitize_endpoint_url("file:///etc/passwd"),
        Err(DcqlError::InvalidEndpoint("scheme \"file\"".to_owned()))
    );
    assert_eq!(
        sanitize_endpoint_url("https:///no-host"),
        Err(DcqlError::InvalidEndpoint("no host".to_owned()))
    );
    assert_eq!(
        sanitize_endpoint_url("not-a-url"),
        Err(DcqlError::InvalidEndpoint("no scheme".to_owned()))
    );
}
