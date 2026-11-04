//! Requests by URI: the Authorization Request URI's rules in their order (U3 to U8, U18, U19),
//! the fetch's (U9 to U11), the POST of `wallet_metadata` with a fresh key, and the routes of
//! refused fetches.

use serde_json::Value;
use siros_openid4vp::arrival::{FailedStatus, FetchFailure, Unreadable, UriError};
use siros_openid4vp::jose::{JweError, JwsError};
use siros_openid4vp::json::JsonError;
use siros_openid4vp::recourse::{ErrorTarget, Failure};
use siros_openid4vp::refusal::ErrorCode;
use siros_openid4vp::uri::{Fetch, FetchAnswer, NoFetch, RequestObjectFetch};
use siros_testkit::TestHost;
use siros_testkit::jose::encrypt_to;

use super::{RESPONSE_URI, b64, fetched, link, registry, request_object, uri_payload};

/// The U rule a URI breaks.
fn refused(uri: &str) -> Unreadable {
    match Fetch::of(uri, &registry(), &TestHost::default()) {
        Err(NoFetch::Unreadable(cause)) => cause,
        other => panic!("{uri}: {other:?}"),
    }
}

#[test]
fn an_authorization_request_uri_breaks_its_rules_in_order() {
    let request_uri = "https%3A%2F%2Fverifier.example%2Fr";
    let cases = [
        // U3: fluent-uri's parse refuses an invalid percent-encoding; a URI without a query.
        ("openid4vp://?client_id=%zz", "uri"),
        ("openid4vp://wallet", "query"),
        // U4: an unknown name twice; a name without a value counts as omitted.
        ("openid4vp://?x=1&x=2&client_id=test:v", "repeated"),
        // U5.
        (
            &*format!("openid4vp://?request_uri={request_uri}&client_id="),
            "client_id absent",
        ),
        // U3: `%FF` in `client_id`, read as U+FFFD.
        (
            &*format!("openid4vp://?client_id=test%3A%FF&request_uri={request_uri}"),
            "client_id",
        ),
        // U6, U19, U18.
        (
            &*format!("openid4vp://?client_id=test:v&request=eyJ&request_uri={request_uri}"),
            "both",
        ),
        ("openid4vp://?client_id=test:v&request=eyJ", "by value"),
        ("openid4vp://?client_id=test:v&state=s", "no request_uri"),
        // U7: another scheme, an empty host.
        (
            "openid4vp://?client_id=test:v&request_uri=http%3A%2F%2Fverifier.example%2Fr",
            "request_uri",
        ),
        (
            "openid4vp://?client_id=test:v&request_uri=https%3A%2F%2F%2Fr",
            "request_uri",
        ),
        // U8.
        (
            &*format!(
                "openid4vp://?client_id=test:v&request_uri={request_uri}&request_uri_method=put"
            ),
            "method",
        ),
    ];
    for (uri, rule) in cases {
        let cause = refused(uri);
        let holds = match (rule, &cause) {
            ("uri", Unreadable::Uri(UriError::Syntax(_)))
            | ("query", Unreadable::Uri(UriError::Query))
            | ("client_id absent", Unreadable::ClientIdAbsent)
            | ("both", Unreadable::RequestAndRequestUri)
            | ("by value", Unreadable::RequestByValue)
            | ("no request_uri", Unreadable::ParametersInUri) => true,
            ("repeated", Unreadable::Repeated(name)) => name == "x",
            ("client_id", Unreadable::ClientId(id)) => id == "test:\u{fffd}",
            ("request_uri", Unreadable::RequestUri(uri)) => uri.ends_with("/r"),
            ("method", Unreadable::RequestUriMethod(method)) => method == "put",
            _ => false,
        };
        assert!(holds, "{rule}: {uri}: {cause:?}");
    }
    // The codes: invalid_request_uri, invalid_request_uri_method, request_not_supported.
    let code = |uri: &str| Failure::Unreadable(refused(uri)).code();
    assert_eq!(code(cases[8].0), Some(ErrorCode::INVALID_REQUEST_URI));
    assert_eq!(
        code(cases[10].0),
        Some(ErrorCode::INVALID_REQUEST_URI_METHOD)
    );
    assert_eq!(code(cases[6].0), Some(ErrorCode::REQUEST_NOT_SUPPORTED));
}

#[test]
fn a_fetch_that_fails_terminates_and_a_body_is_an_es256_jws() {
    let uri = link("test%3Averifier", "");
    // U9: terminating, no route.
    let host = TestHost::default();
    let registry = registry();
    let fetch = Fetch::of(&uri, &registry, &host).expect("a fetch");
    let failure = FetchFailure::Status(FailedStatus::new(404).expect("a status"));
    let rejected = fetch
        .resume(FetchAnswer::Failed(failure), &registry, &host)
        .expect_err("U9");
    assert!(
        matches!(rejected.failure(), Failure::Unreadable(Unreadable::Fetch(f)) if *f == failure)
    );
    assert_eq!(rejected.failure().code(), None);
    assert!(rejected.route().is_none());
    // U10: a JWS whose alg is no ES256, its payload naming the Response URI: an unverified route.
    let payload = uri_payload("");
    let none = format!(
        "{}.{}.{}",
        b64(r#"{"alg":"none"}"#),
        b64(&payload),
        b64("x")
    );
    let rejected = fetched(&uri, &none).expect_err("U10");
    assert!(matches!(
        rejected.failure(),
        Failure::Unreadable(Unreadable::Jws(JwsError::Algorithm(Some(alg)))) if alg == "none"
    ));
    let route = rejected.route().expect("an unverified route");
    assert!(matches!(route.target(), ErrorTarget::Unverified(at) if at.as_str() == RESPONSE_URI));
    assert_eq!(route.echo().map(|echo| echo.as_str()), Some("eyJhb-6-sVA"));
    // U10 whose payload does not decode: the End-User alone.
    let rejected = fetched(&uri, "a.b").expect_err("U10");
    assert!(matches!(
        rejected.failure(),
        Failure::Unreadable(Unreadable::Jws(JwsError::Structure))
    ));
    assert!(rejected.route().is_none());
    // The body as signed reads.
    let object = request_object(&payload);
    assert!(fetched(&uri, &object).is_ok());
}

#[test]
fn a_post_carries_wallet_metadata_and_a_jwe_decrypts_under_its_key_alone() {
    let uri = link("test%3Averifier", "&request_uri_method=post");
    let host = TestHost::default();
    let registry = registry();
    let fetch = Fetch::of(&uri, &registry, &host).expect("a fetch");
    let RequestObjectFetch::Post { uri: target, body } = fetch.request() else {
        panic!("a POST")
    };
    assert_eq!(target.as_str(), super::REQUEST_URI);
    // §5.10: wallet_metadata alone, a JSON string, its members what §5.10, §10.1 and CS-12 ask,
    // and no more.
    let form: Vec<(String, String)> = serde_urlencoded::from_str(body.as_str()).expect("a form");
    let [(name, metadata)] = form.as_slice() else {
        panic!("one member: {form:?}")
    };
    assert_eq!(name, "wallet_metadata");
    let metadata: Value = serde_json::from_str(metadata).expect("JSON");
    let mut names: Vec<&str> = metadata
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "authorization_encryption_alg_values_supported",
            "authorization_encryption_enc_values_supported",
            "client_id_prefixes_supported",
            "jwks",
            "request_object_signing_alg_values_supported",
            "vp_formats_supported",
        ]
    );
    // §10.1: the prefixes the build registers.
    assert_eq!(
        metadata["client_id_prefixes_supported"],
        serde_json::json!(["test"])
    );
    assert_eq!(
        metadata["request_object_signing_alg_values_supported"],
        serde_json::json!(["ES256"])
    );
    assert_eq!(
        metadata["authorization_encryption_alg_values_supported"],
        serde_json::json!(["ECDH-ES"])
    );
    // The key rule's encryptions the module's `agreements` state, in the module's order.
    assert_eq!(
        metadata["authorization_encryption_enc_values_supported"],
        serde_json::json!(["A256GCM", "A128GCM"])
    );
    assert!(metadata["vp_formats_supported"].get("test").is_some());
    let key = &metadata["jwks"]["keys"][0];
    assert_eq!(
        (&key["kty"], &key["crv"], &key["use"]),
        (
            &serde_json::json!("EC"),
            &serde_json::json!("P-256"),
            &serde_json::json!("enc")
        )
    );
    let jwk = siros_openid4vp::json::Node::parse(&key.to_string())
        .expect("a JWK")
        .into_owned();
    // A signed Request Object encrypted to the posted key, compressed with DEF.
    let payload = uri_payload("");
    let object = request_object(&payload);
    let jwe = encrypt_to(&jwk, "A128GCM", true, object.as_bytes()).expect("encrypts");
    let received = fetch
        .resume(FetchAnswer::Body(&jwe), &registry, &host)
        .expect("decrypts");
    assert_eq!(
        super::envelope(&received).parameters().text("nonce"),
        Some(Some("n-0S6_WzA2Mj".into()))
    );
    // U11 tamper: a JWE to another key.
    let other = siros_testkit::jose::scalar_jwk(9).expect("a JWK");
    let jwe = encrypt_to(&other, "A128GCM", false, object.as_bytes()).expect("encrypts");
    let fetch = Fetch::of(&uri, &registry, &host).expect("a fetch");
    let rejected = fetch
        .resume(FetchAnswer::Body(&jwe), &registry, &host)
        .expect_err("U11");
    assert!(matches!(
        rejected.failure(),
        Failure::Unreadable(Unreadable::Undecryptable)
    ));
    // U11: a JWE whose alg is other than ECDH-ES.
    let parts: Vec<&str> = jwe.split('.').collect();
    let header = b64(r#"{"alg":"RSA-OAEP","enc":"A128GCM"}"#);
    let wrapped = format!(
        "{header}.{}.{}.{}.{}",
        parts[1], parts[2], parts[3], parts[4]
    );
    let fetch = Fetch::of(&uri, &registry, &host).expect("a fetch");
    let rejected = fetch
        .resume(FetchAnswer::Body(&wrapped), &registry, &host)
        .expect_err("U11");
    assert!(matches!(
        rejected.failure(),
        Failure::Unreadable(Unreadable::Jwe(JweError::Algorithm(Some(alg)))) if alg == "RSA-OAEP"
    ));
    // U11: a JWE after a GET, which posted no key.
    let get = link("test%3Averifier", "");
    let rejected = super::fetched(&get, &jwe).expect_err("U11");
    assert!(matches!(
        rejected.failure(),
        Failure::Unreadable(Unreadable::Encrypted)
    ));
    assert_eq!(
        rejected.failure().code(),
        Some(ErrorCode::INVALID_REQUEST_OBJECT)
    );
    // A JWE header member twice is the json module's refusal.
    let twice = format!(
        "{}.{}.{}.{}.{}",
        b64(r#"{"alg":"ECDH-ES","alg":"ECDH-ES","enc":"A128GCM"}"#),
        parts[1],
        parts[2],
        parts[3],
        parts[4]
    );
    let fetch = Fetch::of(&uri, &registry, &host).expect("a fetch");
    let rejected = fetch
        .resume(FetchAnswer::Body(&twice), &registry, &host)
        .expect_err("U11");
    assert!(matches!(
        rejected.failure(),
        Failure::Unreadable(Unreadable::Jwe(JweError::Json(JsonError::DuplicateMember(m)))) if m == "alg"
    ));
}

#[test]
fn the_by_reference_example_of_section_8_2_terminates_by_u14() {
    // KA12: the outer client_id https://client.example.org/cb, the Request Object's
    // redirect_uri:https://client.example.org/post (§8.2, §5.10.1).
    let uri = "https://wallet.example.com?client_id=https%3A%2F%2Fclient.example.org%2Fcb&request_uri=https%3A%2F%2Fclient.example.org%2F567545564";
    let payload = format!(
        r#"{{"client_id":"redirect_uri:https://client.example.org/post","response_uri":"https://client.example.org/post","response_type":"vp_token","response_mode":"direct_post","dcql_query":{},"nonce":"n-0S6_WzA2Mj","state":"eyJhb...6-sVA"}}"#,
        super::test_queries(&["q"])
    );
    let object = request_object(&payload);
    let received = fetched(uri, &object).expect("fetched");
    let cause = siros_openid4vp::envelope::Envelope::parse(
        &received,
        siros_testkit::fixtures::routing().expect("the routing registry"),
    )
    .map(drop)
    .expect_err("U14");
    assert_eq!(
        cause,
        Unreadable::ClientIdMismatch {
            outer: "https://client.example.org/cb".to_owned(),
            inner: Some("redirect_uri:https://client.example.org/post".to_owned()),
        }
    );
    // U14 terminates: no code, no route.
    let rejected = siros_openid4vp::recourse::Rejected::unreadable(&received, cause);
    assert_eq!(rejected.failure().code(), None);
    assert!(rejected.route().is_none());
}

#[test]
fn a_post_carries_each_contribution_by_the_names_it_declared() {
    use siros_openid4vp::json::Node;
    use siros_openid4vp::plugins::Registry;
    use siros_openid4vp::wallet_metadata::{
        MetadataMember, MetadataRefused, ParameterName, PostContent, PostParameter,
    };
    use siros_testkit::{TestFormat, TestPostContribution, TestPrefix};
    const MEMBER: ParameterName = siros_explain::checked!(ParameterName, "test_member");
    const PARAMETER: ParameterName = siros_explain::checked!(ParameterName, "test_parameter");
    const OTHER: ParameterName = siros_explain::checked!(ParameterName, "other_member");
    let build = |format: TestFormat, content: PostContent| {
        let mut builder = Registry::<TestHost>::builder();
        siros_testkit::fixtures::openid4vp(&mut builder);
        builder.format(format);
        builder.client_prefix(TestPrefix::Request);
        builder.post_contribution(TestPostContribution {
            members: &[MEMBER],
            parameters: &[PARAMETER],
            content,
        });
        builder.build().expect("registry")
    };
    let format = || TestFormat::new().expect("format");
    let uri = link("test%3Averifier", "&request_uri_method=post");
    let host = TestHost::default();
    // §10.1, §5.10: a contribution's member in wallet_metadata, its parameter beside it.
    let content = PostContent {
        members: vec![MetadataMember::new(MEMBER, Node::Bool(true))],
        parameters: vec![PostParameter::new(PARAMETER, "x y".to_owned())],
    };
    let registry = build(format(), content);
    let fetch = Fetch::of(&uri, &registry, &host).expect("a fetch");
    let RequestObjectFetch::Post { body, .. } = fetch.request() else {
        panic!("a POST")
    };
    let mut form: Vec<(String, String)> =
        serde_urlencoded::from_str(body.as_str()).expect("a form");
    form.sort();
    let [(parameter, value), (metadata_name, metadata)] = form.as_slice() else {
        panic!("two members: {form:?}")
    };
    assert_eq!(
        (parameter.as_str(), value.as_str(), metadata_name.as_str()),
        ("test_parameter", "x y", "wallet_metadata")
    );
    let metadata: Value = serde_json::from_str(metadata).expect("JSON");
    assert_eq!(metadata["test_member"], serde_json::json!(true));
    // A member or a parameter of a name the contribution did not declare.
    let undeclared = [
        PostContent {
            members: vec![MetadataMember::new(OTHER, Node::Bool(true))],
            parameters: Vec::new(),
        },
        PostContent {
            members: Vec::new(),
            parameters: vec![PostParameter::new(OTHER, String::new())],
        },
    ];
    for content in undeclared {
        let registry = build(format(), content);
        assert!(matches!(
            Fetch::of(&uri, &registry, &host),
            Err(NoFetch::Metadata(MetadataRefused::Undeclared(name))) if name == OTHER
        ));
    }
    // §10.1: a format's vp_formats_supported value is an object.
    let registry = build(format().stating(Node::Bool(true)), PostContent::default());
    assert!(matches!(
        Fetch::of(&uri, &registry, &host),
        Err(NoFetch::Metadata(MetadataRefused::NotObject(member))) if member == "vp_formats_supported.test"
    ));
}

#[test]
fn a_response_uri_answer_is_a_json_object_and_redirects_to_a_uri() {
    use siros_openid4vp::uri::{AnswerError, ResponseUriAnswer};
    let registry = registry();
    // §8.2: a JSON object, its redirect_uri a URI with a scheme, a fragment allowed (reading 23).
    let answer = ResponseUriAnswer::parse(
        r#"{"redirect_uri": "https://verifier.example/cb#s", "other": 1}"#,
        &registry,
    )
    .expect("an answer");
    assert_eq!(
        answer.redirect().map(|uri| uri.as_str()),
        Some("https://verifier.example/cb#s")
    );
    for (body, want) in [
        ("[]", "object"),
        ("no JSON", "object"),
        (
            r#"{"redirect_uri": "https://a.example", "redirect_uri": "https://b.example"}"#,
            "object",
        ),
        (r#"{"redirect_uri": "/cb"}"#, "redirect"),
        (r#"{"redirect_uri": 1}"#, "redirect"),
    ] {
        let got = ResponseUriAnswer::parse(body, &registry).map(drop);
        let holds = matches!(
            (&got, want),
            (Err(AnswerError::NotObject), "object") | (Err(AnswerError::RedirectUri), "redirect")
        );
        assert!(holds, "{body}: {got:?}");
    }
}
