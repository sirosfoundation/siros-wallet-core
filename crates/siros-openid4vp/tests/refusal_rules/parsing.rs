//! DCQL's structure, B.3.3.1's algorithm list, and member names given once at every parse.

use siros_openid4vp::plugins::{Registry, RegistryError};
use siros_openid4vp::refusal::ErrorCode;
use siros_openid4vp::resolve::{Outcome, Prepared};
use siros_openid4vp::wallet::Wallet;
use siros_testkit::{Binds, Published, TestFormat, TestHost};

use crate::common::{entry, env, registry, test_queries};

use super::{raw, refusals, request};

#[test]
fn every_parse_refuses_a_member_named_twice() {
    let registry = registry(Binds::First);
    let queries = test_queries(&["q"]);
    // The request's parameters, a member the protocol ignores, its DCQL query, a query's format
    // members at any depth, the client metadata (C6) and an entry (C0).
    let cases: [(String, ErrorCode); 7] = [
        (format!(r#"{{"response_type":"vp_token","response_mode":"dc_api","nonce":"n","x":{{"a":1,"a":2}},"dcql_query":{queries}}}"#), ErrorCode::INVALID_REQUEST),
        (r#"{"response_type":"vp_token","response_mode":"dc_api","nonce":"n","dcql_query":{"credentials":[{"id":"q","format":"test","meta":{"a":1,"a":2}}]}}"#.to_owned(), ErrorCode::INVALID_REQUEST),
        (format!(r#"{{"response_type":"vp_token","response_mode":"dc_api","nonce":"a","nonce":"b","dcql_query":{queries}}}"#), ErrorCode::INVALID_REQUEST),
        (r#"{"response_type":"vp_token","response_mode":"dc_api","nonce":"n","dcql_query":{"credentials":[{"id":"q","format":"test","id":"r"}]}}"#.to_owned(), ErrorCode::INVALID_REQUEST),
        (r#"{"response_type":"vp_token","response_mode":"dc_api","nonce":"n","dcql_query":{"credentials":[{"id":"q","format":"test","options":[[0]],"options":[[1]]}]}}"#.to_owned(), ErrorCode::INVALID_REQUEST),
        (format!(r#"{{"response_type":"vp_token","response_mode":"dc_api","nonce":"n","client_metadata":{{"jwks":{{}},"jwks":{{}}}},"dcql_query":{queries}}}"#), ErrorCode::INVALID_REQUEST),
        (request("dc_api", "{}", &[raw(r#"{"type": "t1", "credential_ids": ["q"], "b": {"x": 1, "x": 2}}"#)], ""), ErrorCode::INVALID_TRANSACTION_DATA),
    ];
    for (parameters, code) in cases {
        let refused = refusals(&parameters, false, &registry);
        let said: Vec<_> = refused.iter().map(|said| (said.cause, said.code)).collect();
        assert_eq!(
            said,
            [("openid4vp.json.duplicate_member", code)],
            "{parameters}"
        );
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
    let app = siros_testkit::render::App::of(&[siros_testkit::render::CrateSource::openid4vp()])
        .expect("the test app");
    let rendering = app.rendering().expect("the rendering");
    let outcome = Prepared::prepare(
        &authenticated,
        ids,
        &Wallet::default(),
        &registry,
        &env("en"),
        &rendering,
        &host,
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
            "openid4vp.hashes_alg.unknown",
        ),
        (
            r#"{"type": "t1", "credential_ids": ["q"], "transaction_data_hashes_alg": "sha-256"}"#,
            "openid4vp.hashes_alg.not_array",
        ),
    ];
    for (entry_json, cause) in cases {
        let refused = refusals(
            &request("dc_api", "{}", &[entry(entry_json)], ""),
            false,
            &registry,
        );
        let said: Vec<_> = refused.iter().map(|said| (said.cause, said.code)).collect();
        assert_eq!(said, [(cause, ErrorCode::INVALID_TRANSACTION_DATA)]);
    }
}

#[test]
fn a_dcql_query_breaking_section_6_is_refused() {
    let registry = registry(Binds::First);
    let query = r#"{"id":"q","format":"test"}"#;
    let cases = [
        (r#"{"credentials":[]}"#.to_owned(), "openid4vp.dcql.credentials"),
        (r#"{"credentials":[5]}"#.to_owned(), "openid4vp.dcql.query_not_object"),
        (format!(r#"{{"credentials":[{query},{query}]}}"#), "openid4vp.dcql.id_twice"),
        (r#"{"credentials":[{"id":"a b","format":"test"}]}"#.to_owned(), "openid4vp.dcql.query_id"),
        (r#"{"credentials":[{"id":"q"}]}"#.to_owned(), "openid4vp.dcql.format"),
        (r#"{"credentials":[{"id":"q","format":"test","multiple":"yes"}]}"#.to_owned(), "openid4vp.dcql.flag"),
        (r#"{"credentials":[{"id":"q","format":"test","trusted_authorities":[]}]}"#.to_owned(), "openid4vp.dcql.trusted_authorities"),
        (r#"{"credentials":[{"id":"q","format":"test","trusted_authorities":[{"type":"aki","values":[]}]}]}"#.to_owned(), "openid4vp.dcql.trusted_authorities"),
        (format!(r#"{{"credentials":[{query}],"credential_sets":[]}}"#), "openid4vp.dcql.sets"),
        (format!(r#"{{"credentials":[{query}],"credential_sets":[{{"options":[[]]}}]}}"#), "openid4vp.dcql.set"),
        (format!(r#"{{"credentials":[{query}],"credential_sets":[{{"options":[["x"]]}}]}}"#), "openid4vp.dcql.set_query"),
        (format!(r#"{{"credentials":[{query}],"credential_sets":[{{"options":[["q"]],"required":"no"}}]}}"#), "openid4vp.dcql.set"),
    ];
    for (dcql, rule) in &cases {
        let text = format!(
            r#"{{"response_type":"vp_token","response_mode":"dc_api","nonce":"n","dcql_query":{dcql}}}"#
        );
        let refused = refusals(&text, false, &registry);
        let said: Vec<_> = refused.iter().map(|said| (said.rule, said.code)).collect();
        assert_eq!(said, [(*rule, ErrorCode::INVALID_REQUEST)], "{dcql}");
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
        refusals(&many(65), false, &registry)[0].rule,
        "openid4vp.dcql.too_many"
    );
    // Two formats with one identifier make no registry.
    let mut builder = Registry::<TestHost>::builder();
    siros_testkit::fixtures::openid4vp(&mut builder);
    builder.format(TestFormat::new().expect("format"));
    builder.format(TestFormat::new().expect("format"));
    assert!(matches!(
        builder.build(),
        Err(RegistryError::FormatTwice { .. })
    ));
}
