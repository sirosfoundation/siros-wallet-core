use engine_core::oid4vci::auth_params::*;
use serde_json::json;
use serde_json::Value;

// ─── same_origin ───────────────────────────────────────────────────

#[test]
fn same_origin_agrees_on_scheme_host_and_effective_port() {
    assert!(same_origin("https://as.example", "https://as.example"));
    assert!(same_origin(
        "https://as.example/v1",
        "https://as.example?x=1"
    ));
    // Different hosts are different origins — that is the
    // cross-origin case the resource indicator covers.
    assert!(!same_origin("https://as.example", "https://issuer.example"));
}

#[test]
fn default_ports_compare_equal() {
    assert!(same_origin("https://as.example", "https://as.example:443"));
    assert!(same_origin("http://as.example", "http://as.example:80"));
}

#[test]
fn different_origins_disagree() {
    assert!(!same_origin(
        "https://as.example",
        "https://issuer.example:8443"
    ));
    assert!(!same_origin("https://as.example", "http://as.example"));
    assert!(!same_origin(
        "https://as.example:8443",
        "https://as.example"
    ));
    assert!(!same_origin("https://as.example", "not-a-url"));
}

#[test]
fn host_and_scheme_compare_case_insensitively() {
    assert!(same_origin("HTTPS://AS.example", "https://as.EXAMPLE"));
}

#[test]
fn userinfo_does_not_change_the_origin() {
    assert!(same_origin(
        "https://user:pass@as.example",
        "https://as.example"
    ));
}

// ─── the parameter assembly ────────────────────────────────────────

fn offer_grants() -> Value {
    json!({
        "authorization_code": { "issuer_state": "session-1" }
    })
}

/// The assembly spec with the fixed client identity and variable
/// credential-naming inputs.
fn spec<'a>(
    scope: Option<&'a str>,
    authorization_details: &'a [Value],
    grants: &'a Value,
    as_issuer: &'a str,
    credential_issuer: &'a str,
) -> AuthorizationRequestSpec<'a> {
    AuthorizationRequestSpec {
        client_id: "client-1",
        redirect_uri: "https://wallet.example/cb",
        state: "state-1",
        scope,
        authorization_details,
        grants,
        as_issuer,
        credential_issuer,
    }
}

#[test]
fn the_resource_indicator_is_sent_cross_origin_only() {
    let params = build_authorization_request_params(&spec(
        Some("openid credential"),
        &[],
        &offer_grants(),
        "https://as.example",
        "https://issuer.example",
    ))
    .expect("build");
    assert_eq!(params.get("resource"), Some("https://issuer.example"));

    let same = build_authorization_request_params(&spec(
        Some("openid credential"),
        &[],
        &offer_grants(),
        "https://as.example",
        "https://as.example:443",
    ))
    .expect("build");
    assert_eq!(same.get("resource"), None);
}

#[test]
fn the_token_request_agrees_with_the_authorization_request() {
    assert_eq!(
        token_request_resource("https://as.example", "https://issuer.example"),
        Some("https://issuer.example".to_owned())
    );
    assert_eq!(
        token_request_resource("https://as.example", "https://as.example:443"),
        None
    );
}

#[test]
fn issuer_state_is_forwarded_from_the_offer_grant() {
    let params = build_authorization_request_params(&spec(
        None,
        &[],
        &offer_grants(),
        "https://as.example",
        "https://as.example",
    ))
    .expect("build");
    assert_eq!(params.get("issuer_state"), Some("session-1"));
}

#[test]
fn nothing_naming_the_credential_refuses() {
    let err = build_authorization_request_params(&spec(
        None,
        &[],
        &json!({}),
        "https://as.example",
        "https://as.example",
    ));
    assert_eq!(err, Err(AuthParamError::NothingNamesCredential));
}

#[test]
fn scope_authorization_details_and_issuer_state_each_satisfy_the_guard() {
    for (scope, details, grants) in [
        (Some("openid"), json!([]), json!({})),
        (
            None,
            json!([{ "credential_configuration_id": "X" }]),
            json!({}),
        ),
        (None, json!([]), offer_grants()),
    ] {
        let params = build_authorization_request_params(&spec(
            scope,
            details.as_array().unwrap_or(&Vec::new()),
            &grants,
            "https://as.example",
            "https://as.example",
        ));
        assert!(params.is_ok(), "the guard must accept each form alone");
    }
}

// ─── the authorization_details projection ─────────────────────────

#[test]
fn the_projection_drops_entries_naming_no_configuration() {
    let projected = project_authorization_details(&[
        json!({ "type": "openid_credential", "credential_identifiers": ["nope"] }),
        json!({ "type": "something", "credential_configuration_id": "Degree", "extra": true }),
    ]);
    assert_eq!(projected.len(), 1);
    assert_eq!(projected[0]["credential_configuration_id"], "Degree");
}

#[test]
fn the_projection_never_forwards_credential_identifiers() {
    let projected = project_authorization_details(&[json!({
        "type": "openid_credential",
        "credential_configuration_id": "Degree",
        "credential_identifiers": ["granted-1", "granted-2"],
    })]);
    assert!(projected[0].get("credential_identifiers").is_none());
}

#[test]
fn the_projection_fixes_the_type() {
    let projected = project_authorization_details(&[json!({
        "type": "not_a_client_choice",
        "credential_configuration_id": "Degree",
    })]);
    assert_eq!(projected[0]["type"], "openid_credential");
}

// ─── the credential identifier substitution ─────────────────────────

#[test]
fn the_granted_identifier_matches_by_configuration_id() {
    let details = json!([
        { "type": "openid_credential", "credential_configuration_id": "PID",
          "credential_identifiers": ["pid-1"] },
        { "type": "openid_credential", "credential_configuration_id": "Degree",
          "credential_identifiers": ["degree-1", "degree-2"] },
    ]);
    assert_eq!(
        granted_credential_identifier(Some(&details), "Degree"),
        Some("degree-1".to_owned())
    );
    // The first identifier only: the rest need their own requests.
}

#[test]
fn a_sole_unlabelled_entry_is_accepted() {
    let details = json!([
        { "credential_identifiers": ["granted-1"] }
    ]);
    assert_eq!(
        granted_credential_identifier(Some(&details), "Degree"),
        Some("granted-1".to_owned())
    );
    assert_eq!(
        granted_credential_identifier(Some(&details), ""),
        Some("granted-1".to_owned())
    );
}

#[test]
fn multiple_unlabelled_entries_are_ambiguous_and_refused() {
    let details = json!([
        { "credential_identifiers": ["a"] },
        { "credential_identifiers": ["b"] }
    ]);
    assert_eq!(
        granted_credential_identifier(Some(&details), "Degree"),
        None
    );
    assert_eq!(granted_credential_identifier(Some(&details), ""), None);
}

#[test]
fn no_granted_identifiers_means_no_substitution() {
    assert_eq!(granted_credential_identifier(None, "Degree"), None);
    assert_eq!(
        granted_credential_identifier(Some(&json!([])), "Degree"),
        None
    );
    // A matching entry that granted no identifiers.
    assert_eq!(
        granted_credential_identifier(
            Some(&json!([{ "credential_configuration_id": "Degree" }])),
            "Degree"
        ),
        None
    );
}
