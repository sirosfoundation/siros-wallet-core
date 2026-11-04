//! Routing and the request rules a URI request gains: P1, C5, P5, P6 at C5's place, P7, N1, S3,
//! and C7 under the key rule; with the known answers of §8.3's key choice and §5.2's values.

use siros_openid4vp::envelope::Envelope;
use siros_openid4vp::matching::Accepted;
use siros_openid4vp::refusal::{ErrorCode, Refused};
use siros_openid4vp::request::{ClientMetadata, Encryption, Request, ResponseEnc};
use siros_openid4vp::routing::{DcApiMode, ModeChoice, ResponseMode, State};
use siros_testkit::fixtures;

use super::{KEY, fetched, link, registry, request_object, uri_payload};

/// The refusals of a URI request with the payload: its parse's, else its acceptance's, each with
/// its text and code.
fn refusals(payload: &str) -> Vec<(String, ErrorCode)> {
    let uri = link("test%3Averifier", "");
    let object = request_object(payload);
    let received = fetched(&uri, &object).expect("fetched");
    let envelope = Envelope::parse(&received).expect("an envelope");
    let refused: Option<Refused> = match Request::parse(&envelope) {
        Err(refused) => Some(refused),
        Ok(request) => Accepted::new(&request, &registry()).err(),
    };
    refused.map_or_else(Vec::new, |refused| {
        refused
            .into_refusals()
            .into_iter()
            .map(|refusal| (refusal.text(), refusal.code()))
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
    let cases: [(String, &str, ErrorCode); 12] = [
        // P1: absent, another type.
        (
            with(p1, ""),
            "P1 response_type is absent",
            ErrorCode::INVALID_REQUEST,
        ),
        (
            with(p1, r#""response_type":"code","#),
            "P1 response_type 'code' is not vp_token",
            ErrorCode::UNSUPPORTED_RESPONSE_TYPE,
        ),
        // C5: absent; off the channel; direct_post.
        (
            with(&format!("{mode},"), ""),
            "C5 response_mode None is no mode the wallet answers in by URI",
            ErrorCode::INVALID_REQUEST,
        ),
        (
            with(mode, r#""response_mode":"dc_api.jwt""#),
            "C5 response_mode 'dc_api.jwt' is no mode the wallet answers in by URI",
            ErrorCode::INVALID_REQUEST,
        ),
        (
            with(mode, r#""response_mode":"direct_post""#),
            "C5 response_mode 'direct_post' is no mode the wallet answers in by URI",
            ErrorCode::INVALID_REQUEST,
        ),
        // P5, P6, P7.
        (
            uri_payload(r#","redirect_uri":"https://verifier.example/cb""#),
            "P5 redirect_uri is present with response_mode direct_post.jwt",
            ErrorCode::INVALID_REQUEST,
        ),
        (
            with(r#""state":"eyJhb-6-sVA""#, r#""state":"a b""#),
            "P6 state is not a non-empty string of URL-safe ASCII",
            ErrorCode::INVALID_REQUEST,
        ),
        (
            with(r#","state":"eyJhb-6-sVA""#, "").replace(
                r#""format":"test""#,
                r#""format":"test","require_cryptographic_holder_binding":false"#,
            ),
            "P7 a query waives holder binding and state is absent",
            ErrorCode::INVALID_REQUEST,
        ),
        // N1, S3.
        (
            with("n-0S6_WzA2Mj", "n 0"),
            "N1 nonce is not URL-safe ASCII",
            ErrorCode::INVALID_REQUEST,
        ),
        (
            uri_payload(r#","scope":"openid""#),
            "S3 scope is present; the wallet maps no scope value to a DCQL query",
            ErrorCode::INVALID_SCOPE,
        ),
        // C7: no key the rule accepts (alg absent), no enc it accepts.
        (
            with(r#","alg":"ECDH-ES""#, ""),
            "C7 direct_post.jwt: client_metadata offers no key and content encryption the wallet supports",
            ErrorCode::INVALID_REQUEST,
        ),
        (
            with(
                r#"]}}"#,
                r#"]},"encrypted_response_enc_values_supported":["A128CBC-HS256"]}"#,
            ),
            "C7 direct_post.jwt: client_metadata offers no key and content encryption the wallet supports",
            ErrorCode::INVALID_REQUEST,
        ),
    ];
    for (payload, text, code) in cases {
        let refused = refusals(&payload);
        assert_eq!(refused, [(text.to_owned(), code)], "{payload}");
    }
}

#[test]
fn a_mode_c5_refuses_names_its_choice() {
    let routing = |payload: &str| {
        let uri = link("test%3Averifier", "");
        let object = request_object(payload);
        let received = fetched(&uri, &object).expect("fetched");
        let envelope = Envelope::parse(&received).expect("an envelope");
        envelope.routing().mode()
    };
    let mode = r#""response_mode":"direct_post.jwt""#;
    assert_eq!(
        routing(&uri_payload("")),
        ModeChoice::Answer(ResponseMode::DirectPostJwt)
    );
    assert_eq!(
        routing(&with(mode, r#""response_mode":"direct_post""#)),
        ModeChoice::DirectPost
    );
    assert_eq!(
        routing(&with(mode, r#""response_mode":"fragment""#)),
        ModeChoice::Unsupported
    );
    // Over the DC API, dc_api and dc_api.jwt; state and redirect_uri are unrecognized (A.2).
    let parameters = fixtures::parameters(
        &super::test_queries(&["q"]),
        r#""state":"a b","redirect_uri":"x""#,
    );
    let received = fixtures::unsigned(&parameters).expect("received");
    let envelope = Envelope::parse(&received).expect("an envelope");
    assert_eq!(
        envelope.routing().mode(),
        ModeChoice::Answer(ResponseMode::DcApi(DcApiMode::DcApi))
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
    let chosen = Encryption::choose(&metadata).expect("a key and an enc");
    assert_eq!(
        (
            chosen.key().key().kid(),
            chosen.key().key().alg().map(|alg| alg.as_str()),
            chosen.enc()
        ),
        ("ac", Some("ECDH-ES"), ResponseEnc::A128Gcm)
    );
    // A256GCM when listed, after another value.
    let listed = format!(
        r#"{{"jwks":{{"keys":[{KEY}]}},"encrypted_response_enc_values_supported":["A128GCM","A256GCM"]}}"#
    );
    let raw = serde_json::value::RawValue::from_string(listed).expect("JSON");
    let metadata = ClientMetadata::parse(Some(&raw)).expect("metadata");
    assert_eq!(
        Encryption::choose(&metadata).map(|chosen| chosen.enc()),
        Some(ResponseEnc::A256Gcm)
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
    let envelope = Envelope::parse(&received).expect("an envelope");
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
