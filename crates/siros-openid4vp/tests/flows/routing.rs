//! Routing and the request rules a URI request gains: P1, C5, P5, P6 at C5's place, P7, N1, S3,
//! and C7 under the key rule; with the known answers of §8.3's key choice and §5.2's values.

use siros_explain::Explain;
use siros_openid4vp::envelope::Envelope;
use siros_openid4vp::matching::Accepted;
use siros_openid4vp::modes::{DcApi, DirectPost, DirectPostJwt, KeyChoice};
use siros_openid4vp::refusal::{ErrorCode, Refused};
use siros_openid4vp::request::{ClientMetadata, ContentEncryption, Request};
use siros_openid4vp::routing::{Carries, Mode, ModeName, State};
use siros_testkit::fixtures;

use super::{KEY, fetched, link, registry, request_object, uri_payload};

/// The refusals of a URI request with the payload: its parse's, else its acceptance's, each with
/// its rule and code.
fn refusals(payload: &str) -> Vec<(&'static str, ErrorCode)> {
    let uri = link("test%3Averifier", "");
    let object = request_object(payload);
    let received = fetched(&uri, &object).expect("fetched");
    let envelope = Envelope::parse(
        &received,
        siros_testkit::fixtures::routing().expect("the routing registry"),
    )
    .expect("an envelope");
    let refused: Option<Refused> = match Request::parse(&envelope) {
        Err(refused) => Some(refused),
        Ok(request) => Accepted::new(&request, &registry()).err(),
    };
    refused.map_or_else(Vec::new, |refused| {
        refused
            .into_refusals()
            .into_iter()
            .map(|refusal| (refusal.id().as_str(), refusal.code()))
            .collect()
    })
}

/// A payload with a member replaced: `from` as written in [`uri_payload`], and its replacement.
fn with(from: &str, to: &str) -> String {
    let payload = uri_payload("");
    assert!(payload.contains(from), "{from}");
    payload.replacen(from, to, 1)
}

#[test]
fn each_routed_rule_refuses_with_its_code() {
    assert_eq!(refusals(&uri_payload("")), []);
    let p1 = r#""response_type":"vp_token","#;
    let mode = r#""response_mode":"direct_post.jwt""#;
    let cases: [(String, &str, ErrorCode); 13] = [
        // P1: absent, another type.
        (
            with(p1, ""),
            "openid4vp.routing.p1_absent",
            ErrorCode::INVALID_REQUEST,
        ),
        (
            with(p1, r#""response_type":"code","#),
            "openid4vp.routing.p1_other",
            ErrorCode::UNSUPPORTED_RESPONSE_TYPE,
        ),
        // C5: absent; off the channel; direct_post.
        (
            with(&format!("{mode},"), ""),
            "openid4vp.routing.c5_uri",
            ErrorCode::INVALID_REQUEST,
        ),
        (
            with(mode, r#""response_mode":"dc_api.jwt""#),
            "openid4vp.routing.c5_uri",
            ErrorCode::INVALID_REQUEST,
        ),
        (
            with(mode, r#""response_mode":"direct_post""#),
            "openid4vp.routing.c5_uri",
            ErrorCode::INVALID_REQUEST,
        ),
        // P5, P6, P7.
        (
            uri_payload(r#","redirect_uri":"https://verifier.example/cb""#),
            "openid4vp.routing.p5",
            ErrorCode::INVALID_REQUEST,
        ),
        (
            with(r#""state":"eyJhb-6-sVA""#, r#""state":"a b""#),
            "openid4vp.routing.p6",
            ErrorCode::INVALID_REQUEST,
        ),
        (
            with(r#","state":"eyJhb-6-sVA""#, "").replace(
                r#""format":"test""#,
                r#""format":"test","require_cryptographic_holder_binding":false"#,
            ),
            "openid4vp.parameters.p7",
            ErrorCode::INVALID_REQUEST,
        ),
        // N1, S3.
        (
            with("n-0S6_WzA2Mj", "n 0"),
            "openid4vp.parameters.n1",
            ErrorCode::INVALID_REQUEST,
        ),
        (
            uri_payload(r#","scope":"openid""#),
            "openid4vp.parameters.s3",
            ErrorCode::INVALID_SCOPE,
        ),
        // S4: dcql_query beside a scope naming a query (§5.1: "but not both").
        (
            uri_payload(r#","scope":"org.example.test""#),
            "openid4vp.parameters.s4",
            ErrorCode::INVALID_REQUEST,
        ),
        // C7: no key the rule accepts (alg absent), no enc it accepts.
        (
            with(r#","alg":"ECDH-ES""#, ""),
            "openid4vp.modes.c7_key",
            ErrorCode::INVALID_REQUEST,
        ),
        (
            with(
                r#"]}}"#,
                r#"]},"encrypted_response_enc_values_supported":["A128CBC-HS256"]}"#,
            ),
            "openid4vp.modes.c7_enc",
            ErrorCode::INVALID_REQUEST,
        ),
    ];
    for (payload, rule, code) in cases {
        assert_eq!(refusals(&payload), [(rule, code)], "{payload}");
    }
}

#[test]
fn a_mode_c5_refuses_names_its_choice() {
    let routing = |payload: &str| {
        let uri = link("test%3Averifier", "");
        let object = request_object(payload);
        let received = fetched(&uri, &object).expect("fetched");
        let envelope = Envelope::parse(
            &received,
            siros_testkit::fixtures::routing().expect("the routing registry"),
        )
        .expect("an envelope");
        envelope
            .routing()
            .mode()
            .map(|mode| (mode.name(), mode.carries()))
    };
    let mode = r#""response_mode":"direct_post.jwt""#;
    let named = |mode: &dyn Mode, carries| Some((mode.name(), carries));
    assert_eq!(
        routing(&uri_payload("")),
        named(&DirectPostJwt, Carries::Answers)
    );
    assert_eq!(
        routing(&with(mode, r#""response_mode":"direct_post""#)),
        named(&DirectPost, Carries::Errors)
    );
    assert_eq!(
        routing(&with(mode, r#""response_mode":"fragment""#)),
        None::<(ModeName, Carries)>
    );
    // Over the DC API, dc_api and dc_api.jwt; state and redirect_uri are unrecognized (A.2).
    let parameters = fixtures::parameters(
        &super::test_queries(&["q"]),
        r#""state":"a b","redirect_uri":"x""#,
    );
    let received = fixtures::unsigned(&parameters).expect("received");
    let envelope = Envelope::parse(
        &received,
        siros_testkit::fixtures::routing().expect("the routing registry"),
    )
    .expect("an envelope");
    assert_eq!(
        envelope
            .routing()
            .mode()
            .map(|mode| (mode.name(), mode.carries())),
        Some((DcApi.name(), Carries::Answers))
    );
    assert!(envelope.routing().refusals().is_empty());
    assert!(envelope.routing().echo().is_none());
}

#[test]
fn the_key_rule_picks_section_8_3s_key_and_enc() {
    // KA13: §8.3's request, four keys, ["A128GCM", "A128CBC-HS256"]: kid ac, ECDH-ES, A128GCM.
    let metadata = r#"{"jwks":{"keys":[
        {"kty":"EC","kid":"ac","use":"enc","crv":"P-256","alg":"ECDH-ES","x":"YO4epjifD-KWeq1sL2tNmm36BhXnkJ0He-WqMYrp9Fk","y":"Hekpm0zfK7C-YccH5iBjcIXgf6YdUvNUac_0At55Okk"},
        {"kty":"OKP","kid":"jc","use":"enc","crv":"X25519","alg":"ECDH-ES","x":"WPX7wnwq10hFNK9aDSyG1QlLswE_CJY14LdhcFUIVVc"},
        {"kty":"EC","kid":"lc","use":"enc","crv":"P-384","alg":"ECDH-ES","x":"iHytgLNtXjEyYMAIGwfgjINZRmLfObYbmjPhkaPD8OiTkJtRHjegTNdH31Mxg4nV","y":"MizXWSqNB7sSt_SNjg3spvaJnmjB-LpxsPpLUaea33rvINL3Mq-gEaANErRQpbLx"},
        {"kty":"OKP","kid":"bc","use":"enc","crv":"X448","alg":"ECDH-ES","x":"pK5IRpLlX-8XcsRYWHejpzkfsHoDOmAYuBzAC7aTpewWOw_QFHSa64t9p2kuommI8JQQLohS2AIA"}]},
        "encrypted_response_enc_values_supported":["A128GCM","A128CBC-HS256"]}"#;
    let raw = serde_json::value::RawValue::from_string(metadata.to_owned()).expect("JSON");
    let metadata = ClientMetadata::parse(Some(&raw)).expect("metadata");
    let chosen = KeyChoice::of(DirectPostJwt.name(), &metadata).expect("a key and an enc");
    assert_eq!(
        (chosen.kid(), chosen.enc()),
        ("ac", ContentEncryption::A128GCM)
    );
    // A256GCM when listed, after another value.
    let listed = format!(
        r#"{{"jwks":{{"keys":[{KEY}]}},"encrypted_response_enc_values_supported":["A128GCM","A256GCM"]}}"#
    );
    let raw = serde_json::value::RawValue::from_string(listed).expect("JSON");
    let metadata = ClientMetadata::parse(Some(&raw)).expect("metadata");
    assert_eq!(
        KeyChoice::of(DirectPostJwt.name(), &metadata).map(|chosen| chosen.enc()),
        Ok(ContentEncryption::A256GCM)
    );
}

#[test]
fn section_5_2s_nonce_and_state_are_url_safe() {
    // KA17: n-0S6_WzA2Mj and eyJhb...6-sVA, `.` being URL-safe.
    let payload = with(r#""state":"eyJhb-6-sVA""#, r#""state":"eyJhb...6-sVA""#);
    assert_eq!(refusals(&payload), []);
    let uri = link("test%3Averifier", "");
    let object = request_object(&payload);
    let received = fetched(&uri, &object).expect("fetched");
    let envelope = Envelope::parse(
        &received,
        siros_testkit::fixtures::routing().expect("the routing registry"),
    )
    .expect("an envelope");
    let request = Request::parse(&envelope).expect("a request");
    assert_eq!(request.nonce().as_str(), "n-0S6_WzA2Mj");
    assert_eq!(
        envelope
            .routing()
            .state()
            .map(|state| state.as_str().to_owned()),
        Some("eyJhb...6-sVA".to_owned())
    );
    assert!(State::parse("a/b".into()).is_none());
}

#[test]
fn a_registered_scope_value_reads_as_its_dcql_query() {
    // §5.5: the scope value stands for its query; testkit's `TestScope` registers
    // `org.example.test` for the query `scoped`.
    let payload = uri_payload("").replace(
        &format!(r#","dcql_query":{}"#, super::test_queries(&["q"])),
        r#","scope":"org.example.test""#,
    );
    let uri = link("test%3Averifier", "");
    let object = request_object(&payload);
    let received = fetched(&uri, &object).expect("fetched");
    let registry = registry();
    let envelope = Envelope::parse(&received, &registry).expect("an envelope");
    let request = Request::parse(&envelope).expect("a request");
    let ids: Vec<&str> = request
        .queries()
        .iter()
        .map(|query| query.id.as_str())
        .collect();
    assert_eq!(ids, ["scoped"]);
}
