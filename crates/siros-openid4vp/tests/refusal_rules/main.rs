//! The request rules: the request's structure, the core's C0-C8 and a format's rules, one
//! fixture each with its OpenID4VP §8.5 error code; DCQL's structure, B.3.3.1's algorithm list,
//! and member names given once at every parse.

#[path = "../common/mod.rs"]
mod common;
mod parsing;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use siros_openid4vp::arrival::Unreadable;
use siros_openid4vp::envelope::Envelope;
use siros_openid4vp::host::{Authentication, AuthenticationNeed, ProfileHost};
use siros_openid4vp::ids::{FormatId, TransactionType};
use siros_openid4vp::matching::Accepted;
use siros_openid4vp::plugins::{
    Answered, Binding, Bound, Exclude, Fault, FetchedRecord, Member, Members, NoCandidate, Profile,
    Registry,
};
use siros_openid4vp::recourse::Failure;
use siros_openid4vp::refusal::{ErrorCode, Refusal, Refused};
use siros_openid4vp::request::{EntryIndex, Request};
use siros_openid4vp::resolve::{Outcome, Prepared};
use siros_openid4vp::rows::{Env, HttpsUrl};
use siros_openid4vp::wallet::Wallet;
use siros_testkit::fixtures;
use siros_testkit::rules::{TestExclusion, TestRule};
use siros_testkit::verifier::ORIGINS;
use siros_testkit::{Binds, Published, TestFormat, TestHost, TestProfile};

use common::{entry, env, registry, test_queries};

/// base64url of a text as written, duplicate member names kept.
fn raw(text: &str) -> String {
    URL_SAFE_NO_PAD.encode(text)
}

/// A refusal as the Verifier receives it: its text and its code.
#[derive(Debug, PartialEq, Eq)]
struct Said {
    text: String,
    code: ErrorCode,
}

impl From<Refusal> for Said {
    fn from(refusal: Refusal) -> Self {
        Self {
            text: refusal.text(),
            code: refusal.code(),
        }
    }
}

/// The refusals of a request, unsigned or signed by the test Verifier: its envelope's, else its
/// parse's, else its acceptance's.
fn refusals(parameters: &str, signed: bool, registry: &Registry<TestHost>) -> Vec<Said> {
    let data = if signed {
        fixtures::signed_data(parameters).expect("signs")
    } else {
        parameters.to_owned()
    };
    // A U rule: its text and its code.
    let unreadable = |cause: Unreadable| {
        vec![Said {
            text: cause.to_string(),
            code: Failure::Unreadable(cause)
                .code()
                .expect("a U rule the parameters break has a code"),
        }]
    };
    let received = match if signed {
        fixtures::signed(&data)
    } else {
        fixtures::unsigned(&data)
    } {
        Ok(received) => received,
        Err(siros_testkit::fixtures::FixtureError::Unreadable(cause)) => return unreadable(cause),
        Err(other) => panic!("the fixture: {other}"),
    };
    let envelope = match Envelope::parse(&received) {
        Ok(envelope) => envelope,
        Err(cause) => return unreadable(cause),
    };
    let refused = match Request::parse(&envelope) {
        Err(refused) => Some(refused),
        Ok(request) => Accepted::new(&request, registry).err(),
    };
    refused.map_or_else(Vec::new, |refused: Refused| {
        refused
            .into_refusals()
            .into_iter()
            .map(Said::from)
            .collect()
    })
}

fn request(mode: &str, metadata: &str, entries: &[String], extra: &str) -> String {
    let data = if entries.is_empty() {
        String::new()
    } else {
        format!(
            r#","transaction_data":[{}]"#,
            entries
                .iter()
                .map(|e| format!("\"{e}\""))
                .collect::<Vec<_>>()
                .join(",")
        )
    };
    format!(
        r#"{{"response_type":"vp_token","response_mode":"{mode}","nonce":"n-0S6_WzA2Mj","client_metadata":{metadata},"dcql_query":{}{data}{extra}}}"#,
        test_queries(&["q", "r"])
    )
}

/// t1 and t2 handled by two profiles.
fn two_profiles() -> Registry<TestHost> {
    let mut builder = Registry::<TestHost>::builder();
    builder.format(TestFormat::new().expect("format"));
    let first = builder.profile(TestProfile::new(Binds::First));
    let second = builder.profile(TestProfile::new(Binds::First));
    builder.exact(TransactionType::parse("t1").expect("type"), first);
    builder.exact(TransactionType::parse("t2").expect("type"), second);
    builder.build().expect("registry")
}

/// A profile refusing once, with the number of entries it judged.
#[derive(Clone)]
struct Counts;

impl Profile for Counts {
    type Finding = ();

    fn refusals(&self, _: &Request<'_>, entries: &[EntryIndex]) -> Vec<Refusal> {
        vec![Refusal::new(TestRule::invalid_transaction_data(format!(
            "{} entries",
            entries.len()
        )))]
    }
    fn members(&self, _: &FormatId<'_>) -> Option<&[Member]> {
        None
    }
    fn bind(&self, _: Binding<'_>, _: &Env) -> Result<Bound, NoCandidate> {
        Err(Exclude::new(TestExclusion::new("binds nothing")).into())
    }
    fn wanted(&self, _: Answered<'_>) -> Result<Vec<HttpsUrl>, Fault> {
        Ok(Vec::new())
    }
    fn informed(&self, _: &[&()]) -> Self {
        Self
    }

    fn authentication(&self, _: Answered<'_>) -> Result<AuthenticationNeed, Fault> {
        Ok(AuthenticationNeed::Presence)
    }
}

impl<H> ProfileHost<H> for Counts {
    fn revalidate(&self, _: FetchedRecord<'_>, _: &H) -> Result<Option<()>, Fault> {
        Ok(None)
    }

    fn respond(&self, _: Answered<'_>, _: &H, _: &Authentication) -> Result<Members, Fault> {
        Ok(Members::none())
    }
}

#[test]
fn a_profile_judges_all_its_entries_at_once() {
    let mut builder = Registry::<TestHost>::builder();
    builder.format(TestFormat::new().expect("format"));
    let profile = builder.profile(Counts);
    builder.exact(TransactionType::parse("t1").expect("type"), profile);
    let registry = builder.build().expect("registry");
    let named = entry(r#"{"type": "t1", "credential_ids": ["q"]}"#);
    let texts: Vec<String> = refusals(
        &request("dc_api", "{}", &[named.clone(), named], ""),
        false,
        &registry,
    )
    .into_iter()
    .map(|refusal| refusal.text)
    .collect();
    assert_eq!(texts, ["2 entries"]);
}

#[test]
fn each_core_rule_refuses_with_its_error_code() {
    let registry = two_profiles();
    let named =
        |kind: &str, ids: &str| entry(&format!(r#"{{"type": "{kind}", "credential_ids": {ids}}}"#));
    let _signed = "eyJ.request.sig";
    let unsigned = request("dc_api", "{}", &[], "");
    let cases: [(&str, String, bool, ErrorCode, &str); 14] = [
        (
            "dcql_query",
            r#"{"response_type":"vp_token","response_mode":"dc_api","nonce":"n-0S6_WzA2Mj"}"#
                .to_owned(),
            false,
            ErrorCode::INVALID_REQUEST,
            "dcql_query is absent",
        ),
        (
            "transaction_data",
            request("dc_api", "{}", &[], r#","transaction_data":[]"#),
            false,
            ErrorCode::INVALID_REQUEST,
            "transaction_data is not a non-empty array of strings",
        ),
        (
            "expected_origins",
            request("dc_api", "{}", &[], r#","expected_origins":5"#),
            true,
            ErrorCode::INVALID_REQUEST,
            "expected_origins is not an array of strings",
        ),
        (
            "nonce",
            unsigned.replace(r#""nonce":"n-0S6_WzA2Mj""#, r#""nonce":5"#),
            false,
            ErrorCode::INVALID_REQUEST,
            "nonce is not a non-empty string",
        ),
        (
            "a format's rules",
            unsigned.replace(
                r#"{"id":"q","format":"test"}"#,
                r#"{"id":"q","format":"test","options":5}"#,
            ),
            false,
            ErrorCode::INVALID_REQUEST,
            "test q: options is not an array of item arrays",
        ),
        (
            "C0",
            request("dc_api", "{}", &["e30=".to_owned()], ""),
            false,
            ErrorCode::INVALID_TRANSACTION_DATA,
            "C0 entry 0: not base64url without padding",
        ),
        (
            "C1",
            request("dc_api", "{}", &[named("t9", r#"["q"]"#)], ""),
            false,
            ErrorCode::INVALID_TRANSACTION_DATA,
            "C1 entry 0: no profile for type t9",
        ),
        (
            "C2",
            request("dc_api", "{}", &[named("t1", r#"["q", "qX"]"#)], ""),
            false,
            ErrorCode::INVALID_TRANSACTION_DATA,
            "C2 entry 0: credential_ids ['q', 'qX'] names no Credential Query of the request",
        ),
        (
            "C3",
            request(
                "dc_api",
                "{}",
                &[named("t1", r#"["q"]"#), named("t1", r#"["r"]"#)],
                "",
            ),
            false,
            ErrorCode::INVALID_TRANSACTION_DATA,
            "C3 two queries transaction data names can be presented together",
        ),
        (
            "C4",
            request(
                "dc_api",
                "{}",
                &[named("t1", r#"["q"]"#), named("t2", r#"["q"]"#)],
                "",
            ),
            false,
            ErrorCode::INVALID_TRANSACTION_DATA,
            "C4 q: entries of two profiles name it",
        ),
        (
            "C5",
            request("direct_post", "{}", &[], ""),
            false,
            ErrorCode::INVALID_REQUEST,
            "C5 response_mode 'direct_post' is no DC API response mode",
        ),
        (
            "C6",
            request("dc_api", "[]", &[], ""),
            false,
            ErrorCode::INVALID_REQUEST,
            "C6 client_metadata: client_metadata is not a JSON object",
        ),
        (
            "C7",
            request("dc_api.jwt", "{}", &[], ""),
            false,
            ErrorCode::INVALID_REQUEST,
            "C7 dc_api.jwt: client_metadata offers no key and content encryption the wallet supports",
        ),
        (
            "C8",
            request("dc_api", "{}", &[], ""),
            true,
            ErrorCode::INVALID_REQUEST,
            "C8 a signed request whose expected_origins [] lack the Origin https://verifier.example",
        ),
    ];
    for (rule, parameters, is_signed, code, text) in cases {
        let refused = refusals(&parameters, is_signed, &registry);
        assert_eq!(
            refused,
            [Said {
                text: text.to_owned(),
                code
            }],
            "{rule}"
        );
    }
}

#[test]
fn malformed_entries_are_refused_by_c0() {
    let registry = registry(Binds::First);
    let cases = [
        (
            raw(r#"{"type": "t1", "credential_ids": ["q"], "a": 1, "a": 2}"#),
            Some("C0 entry 0: an object repeats a member name: a"),
        ),
        (raw("[1]"), Some("C0 entry 0: not a JSON object")),
        (raw(r#"{"a":"#), None),
        (
            "e30=".to_owned(),
            Some("C0 entry 0: not base64url without padding"),
        ),
        (
            "e30+".to_owned(),
            Some("C0 entry 0: not base64url without padding"),
        ),
        (
            raw(r#"{"type": 5, "credential_ids": ["q"]}"#),
            Some("C0 entry 0: type is not a string"),
        ),
        (
            raw(r#"{"type": "t1", "credential_ids": []}"#),
            Some("C0 entry 0: credential_ids is not a non-empty array of strings"),
        ),
    ];
    // base64url's own characters, `-` and `_`, decode.
    let dashed = "eyJ0eXBlIjogInQxIiwgImNyZWRlbnRpYWxfaWRzIjogWyJxIl0sICJ4IjogIj_Dv8O-In0";
    assert_eq!(
        refusals(
            &request("dc_api", "{}", &[dashed.to_owned()], ""),
            false,
            &registry
        ),
        []
    );
    assert_eq!(
        refusals(
            &request("dc_api", "{}", &["e30aa".to_owned()], ""),
            false,
            &registry
        )[0]
        .text,
        "C0 entry 0: not base64url without padding",
        "no base64url text has a length of 1 modulo 4"
    );
    for (entry, want) in cases {
        let refused = refusals(
            &request("dc_api", "{}", std::slice::from_ref(&entry), ""),
            false,
            &registry,
        );
        let [refusal] = refused.as_slice() else {
            panic!("one refusal for {entry}: {refused:?}")
        };
        assert_eq!(refusal.code, ErrorCode::INVALID_TRANSACTION_DATA);
        match want {
            Some(text) => assert_eq!(refusal.text, text),
            // A syntax error's wording is the JSON parser's.
            None => assert!(refusal.text.starts_with("C0 entry 0: "), "{}", refusal.text),
        }
    }
}

#[test]
fn response_mode_and_client_metadata_follow_annex_a_and_section_8_3() {
    let registry = registry(Binds::First);
    let key = r#"{"kty": "EC", "crv": "P-256", "kid": "k", "x": "DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0", "y": "XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc", "alg": "ECDH-ES"}"#;
    let c7 =
        "C7 dc_api.jwt: client_metadata offers no key and content encryption the wallet supports";
    let cases: [(&str, String, &[&str]); 11] = [
        (
            "direct_post",
            "{}".to_owned(),
            &["C5 response_mode 'direct_post' is no DC API response mode"],
        ),
        (
            "dc_api",
            "[]".to_owned(),
            &["C6 client_metadata: client_metadata is not a JSON object"],
        ),
        (
            "dc_api",
            r#"{"vp_formats_supported": []}"#.to_owned(),
            &["C6 client_metadata: vp_formats_supported is not a JSON object"],
        ),
        ("dc_api.jwt", "{}".to_owned(), &[c7]),
        (
            "dc_api.jwt",
            format!(
                r#"{{"jwks": {{"keys": [{}]}}}}"#,
                key.replace("\"EC\"", "\"RSA\"")
            ),
            &[c7],
        ),
        (
            "dc_api.jwt",
            format!(
                r#"{{"jwks": {{"keys": [{key}]}}, "encrypted_response_enc_values_supported": ["XC20P"]}}"#
            ),
            &[c7],
        ),
        // The key rule (§8.3, HAIP §5; reading 25): no key it accepts (`alg` absent, a
        // coordinate of another length, a key wrap), and no `enc` it accepts.
        (
            "dc_api.jwt",
            format!(
                r#"{{"jwks": {{"keys": [{}]}}}}"#,
                key.replace(r#", "alg": "ECDH-ES""#, "")
            ),
            &[c7],
        ),
        (
            "dc_api.jwt",
            format!(
                r#"{{"jwks": {{"keys": [{}]}}}}"#,
                key.replace("XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc", "y")
            ),
            &[c7],
        ),
        (
            "dc_api.jwt",
            format!(
                r#"{{"jwks": {{"keys": [{}]}}}}"#,
                key.replace("ECDH-ES", "ECDH-ES+A128KW")
            ),
            &[c7],
        ),
        (
            "dc_api.jwt",
            format!(
                r#"{{"jwks": {{"keys": [{key}]}}, "encrypted_response_enc_values_supported": ["A128CBC-HS256"]}}"#
            ),
            &[c7],
        ),
        (
            "dc_api.jwt",
            format!(r#"{{"jwks": {{"keys": [{key}]}}}}"#),
            &[],
        ),
    ];
    for (mode, metadata, want) in cases {
        let refused = refusals(&request(mode, &metadata, &[], ""), false, &registry);
        assert_eq!(
            refused.iter().map(|r| r.text.as_str()).collect::<Vec<_>>(),
            want,
            "{mode} {metadata}"
        );
    }
}

#[test]
fn a_signed_request_names_the_origin_in_expected_origins() {
    let registry = registry(Binds::First);
    let other = r#","expected_origins":["https://other.example"]"#;
    let both = format!(
        r#","expected_origins":["https://other.example","{}"]"#,
        ORIGINS[0]
    );
    let lacks = "C8 a signed request whose expected_origins ['https://other.example'] lack the Origin https://verifier.example";
    assert_eq!(
        refusals(&request("dc_api", "{}", &[], other), true, &registry)
            .iter()
            .map(|r| r.text.as_str())
            .collect::<Vec<_>>(),
        [lacks]
    );
    assert_eq!(
        refusals(&request("dc_api", "{}", &[], &both), true, &registry),
        []
    );
    assert_eq!(
        refusals(&request("dc_api", "{}", &[], other), false, &registry),
        [],
        "an unsigned request's expected_origins are ignored"
    );
    assert_eq!(
        refusals(
            &request("dc_api", "{}", &[], r#","expected_origins":5"#),
            false,
            &registry
        ),
        [],
        "ignored whatever their shape"
    );
}

#[test]
fn phase_2_answers_no_request_the_rules_refuse() {
    let registry = registry(Binds::First);
    let text = request("query", "{}", &[], "");
    let received = fixtures::unsigned(&text).expect("received");
    let request = fixtures::request_of(&received).expect("request");
    let outcome = Prepared::prepare(&request, &[], &Wallet::default(), &registry, &env("en"))
        .and_then(|prepared| {
            prepared.respond(
                |resource| Published::default().answer(resource),
                &TestHost::default(),
            )
        });
    assert!(matches!(outcome, Err(Outcome::Refused(_))));
}
