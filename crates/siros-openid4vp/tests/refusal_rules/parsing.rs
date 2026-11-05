//! DCQL's structure, B.3.3.1's algorithm list, and member names given once at every parse.

use siros_openid4vp::plugins::{Registry, RegistryError};
use siros_openid4vp::refusal::ErrorCode;
use siros_openid4vp::resolve::{Outcome, Prepared};
use siros_openid4vp::wallet::Wallet;
use siros_testkit::{Binds, Published, TestFormat, TestHost};

use crate::common::{entry, env, registry, test_queries};

use super::{Said, raw, refusals, request};

#[test]
fn every_parse_refuses_a_member_named_twice() {
    let registry = registry(Binds::First);
    let queries = test_queries(&["q"]);
    // The request's parameters, a member the protocol ignores, its DCQL query, a query's format
    // members at any depth, the client metadata (C6) and an entry (C0).
    let cases: [(String, Option<&str>); 7] = [
        (format!(r#"{{"response_type":"vp_token","response_mode":"dc_api","nonce":"n","x":{{"a":1,"a":2}},"dcql_query":{queries}}}"#), None),
        (
            r#"{"response_type":"vp_token","response_mode":"dc_api","nonce":"n","dcql_query":{"credentials":[{"id":"q","format":"test","meta":{"a":1,"a":2}}]}}"#
                .to_owned(),
            None,
        ),
        (format!(r#"{{"response_type":"vp_token","response_mode":"dc_api","nonce":"a","nonce":"b","dcql_query":{queries}}}"#), None),
        (r#"{"response_type":"vp_token","response_mode":"dc_api","nonce":"n","dcql_query":{"credentials":[{"id":"q","format":"test","id":"r"}]}}"#.to_owned(), None),
        (
            r#"{"response_type":"vp_token","response_mode":"dc_api","nonce":"n","dcql_query":{"credentials":[{"id":"q","format":"test","options":[[0]],"options":[[1]]}]}}"#
                .to_owned(),
            None,
        ),
        (
            format!(r#"{{"response_type":"vp_token","response_mode":"dc_api","nonce":"n","client_metadata":{{"jwks":{{}},"jwks":{{}}}},"dcql_query":{queries}}}"#),
            Some("C6 client_metadata: an object repeats a member name: jwks"),
        ),
        (
            request("dc_api", "{}", &[raw(r#"{"type": "t1", "credential_ids": ["q"], "b": {"x": 1, "x": 2}}"#)], ""),
            Some("C0 entry 0: an object repeats a member name: x"),
        ),
    ];
    for (parameters, text) in cases {
        let refused = refusals(&parameters, false, &registry);
        let [refusal] = refused.as_slice() else {
            panic!("one refusal for {parameters}: {refused:?}")
        };
        if let Some(text) = text {
            assert_eq!(refusal.text, text);
        } else {
            assert_eq!(refusal.code, ErrorCode::INVALID_REQUEST, "{parameters}");
            assert!(
                refusal.text.contains("repeats a member name"),
                "{}",
                refusal.text
            );
        }
    }
    // A returned record.
    let text = request("dc_api", "{}", &[], "");
    let received = siros_testkit::fixtures::unsigned(&text).expect("received");
    let request = siros_testkit::fixtures::request_of(&received).expect("request");
    let returned = r#"["q","c",0,[],{"a":"x","a":"y"},"d"]"#;
    let host = TestHost::default();
    let authenticated = siros_testkit::fixtures::authenticate(request.envelope(), &registry, &host)
        .expect("authentic");
    let ids: &[&str] = &[returned];
    let outcome = Prepared::prepare(
        &authenticated,
        ids,
        &Wallet::default(),
        &registry,
        &env("en"),
    )
    .and_then(|prepared| {
        prepared
            .respond(|resource| Published::default().answer(resource), &host)
            .map(drop)
    });
    assert!(
        matches!(
            outcome,
            Err(Outcome::Rejected(
                siros_openid4vp::resolve::Rejection::NotARecord(_)
            ))
        ),
        "{outcome:?}"
    );
}

#[test]
fn transaction_data_hashes_alg_names_a_hash_the_wallet_computes() {
    let registry = registry(Binds::Every);
    let cases = [
        (
            r#"{"type": "t1", "credential_ids": ["q"], "transaction_data_hashes_alg": ["md5"]}"#,
            "test entry 0: transaction_data_hashes_alg ['md5'] names no hash this wallet computes (B.3.3.1)",
        ),
        (
            r#"{"type": "t1", "credential_ids": ["q"], "transaction_data_hashes_alg": "sha-256"}"#,
            "test entry 0: transaction_data_hashes_alg is not a non-empty array of strings (B.3.3.1)",
        ),
    ];
    for (entry_json, text) in cases {
        let refused = refusals(
            &request("dc_api", "{}", &[entry(entry_json)], ""),
            false,
            &registry,
        );
        assert_eq!(
            refused,
            [Said {
                text: text.to_owned(),
                code: ErrorCode::INVALID_TRANSACTION_DATA
            }]
        );
    }
}

#[test]
fn a_dcql_query_breaking_section_6_is_refused() {
    let registry = registry(Binds::First);
    let query = r#"{"id":"q","format":"test"}"#;
    let cases = [
        r#"{"credentials":[]}"#.to_owned(),
        r#"{"credentials":[5]}"#.to_owned(),
        format!(r#"{{"credentials":[{query},{query}]}}"#),
        r#"{"credentials":[{"id":"a b","format":"test"}]}"#.to_owned(),
        r#"{"credentials":[{"id":"q"}]}"#.to_owned(),
        r#"{"credentials":[{"id":"q","format":"test","multiple":"yes"}]}"#.to_owned(),
        r#"{"credentials":[{"id":"q","format":"test","trusted_authorities":[]}]}"#.to_owned(),
        r#"{"credentials":[{"id":"q","format":"test","trusted_authorities":[{"type":"aki","values":[]}]}]}"#.to_owned(),
        format!(r#"{{"credentials":[{query}],"credential_sets":[]}}"#),
        format!(r#"{{"credentials":[{query}],"credential_sets":[{{"options":[[]]}}]}}"#),
        format!(r#"{{"credentials":[{query}],"credential_sets":[{{"options":[["x"]]}}]}}"#),
        format!(r#"{{"credentials":[{query}],"credential_sets":[{{"options":[["q"]],"required":"no"}}]}}"#),
    ];
    for dcql in &cases {
        let text = format!(
            r#"{{"response_type":"vp_token","response_mode":"dc_api","nonce":"n","dcql_query":{dcql}}}"#
        );
        let refused = refusals(&text, false, &registry);
        let [refusal] = refused.as_slice() else {
            panic!("one refusal for {dcql}: {refused:?}")
        };
        assert!(
            refusal.text.starts_with("dcql_query: ") && refusal.code == ErrorCode::INVALID_REQUEST,
            "{dcql}: {refusal:?}"
        );
    }
    // The sets the factoring computes over hold 64 queries.
    let many = |n: usize| {
        let queries: Vec<String> = (0..n)
            .map(|k| format!(r#"{{"id":"q{k}","format":"test"}}"#))
            .collect();
        format!(
            r#"{{"response_type":"vp_token","response_mode":"dc_api","nonce":"n","dcql_query":{{"credentials":[{}]}}}}"#,
            queries.join(",")
        )
    };
    assert_eq!(refusals(&many(64), false, &registry), []);
    assert_eq!(
        refusals(&many(65), false, &registry)[0].text,
        "dcql_query: more than 64 Credential Queries"
    );
    // Two formats with one identifier make no registry.
    let mut builder = Registry::<TestHost>::builder();
    siros_testkit::fixtures::openid4vp(&mut builder);
    builder.format(TestFormat::new().expect("format"));
    builder.format(TestFormat::new().expect("format"));
    assert!(matches!(
        builder.build(),
        Err(RegistryError::FormatTwice(_))
    ));
}
