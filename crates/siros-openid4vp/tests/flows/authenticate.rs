//! Verifier authentication: the classification (A1, A2), the signed request's Client Identifier
//! (A3), the decision (A6), the signature, validity and audience (A8 to A10), multisigned requests
//! (A11), the endpoint (A12, A13), each refusal's route; the registry's and the configuration's
//! rules; and the tamper cases, each failing for its rule with no `Authenticated` built.

use siros_explain::{Explain, Text};
use siros_openid4vp::arrival::{DcApiProtocols, Received};
use siros_openid4vp::authenticate::{
    BoundEndpoint, EndpointBasis, OriginPolicy, PrefixName, TrustConfig, Unauthenticated,
    VerifierId,
};
use siros_openid4vp::effects::Verdict;
use siros_openid4vp::envelope::Envelope;
use siros_openid4vp::host::Seconds;
use siros_openid4vp::ids::Origin;
use siros_openid4vp::jose::{Skew, SkewTooLarge, TimeError};
use siros_openid4vp::matching::Accepted;
use siros_openid4vp::plugins::{Registry, RegistryError};
use siros_openid4vp::recourse::{ErrorTarget, Failure, Rejected};
use siros_openid4vp::refusal::ErrorCode;
use siros_openid4vp::request::Request;
use siros_testkit::fixtures;
use siros_testkit::fixtures::REQUEST_OBJECT_HEADER;
use siros_testkit::jose::{VERIFIER_SECRET, compact_jws};
use siros_testkit::{TestFormat, TestHost, TestPrefix, TestTrust};

use super::{
    RESPONSE_URI, authenticated, config, envelope, fetched, link, registry, registry_with,
    request_object, uri_payload,
};

/// The refusal of a URI request whose payload is given, under the prefix and the trust service.
fn refused(
    payload: &str,
    prefix: TestPrefix,
    trust: &TestTrust,
    config: &TrustConfig,
) -> Box<Rejected<'static>> {
    let uri: &'static str = Box::leak(link("test%3Averifier", "").into_boxed_str());
    let object: &'static str = Box::leak(request_object(payload).into_boxed_str());
    let received: &'static Received<'static> =
        Box::leak(Box::new(fetched(uri, object).expect("fetched")));
    let envelope: &'static Envelope<'static> = Box::leak(Box::new(envelope(received)));
    let registry: &'static Registry<TestHost> = Box::leak(Box::new(registry_with(prefix)));
    match authenticated(envelope, registry, trust, config) {
        Ok(_) => panic!("authenticated: {payload}"),
        Err(rejected) => rejected,
    }
}

fn cause<'a>(rejected: &'a Rejected<'_>) -> &'a Unauthenticated {
    match rejected.failure() {
        Failure::Unauthenticated(cause) => cause,
        Failure::Unreadable(other) => panic!("an unreadable request: {other:?}"),
    }
}

fn target(rejected: &Rejected<'_>) -> Option<ErrorTarget> {
    rejected.route().map(|route| route.target().clone())
}

fn unverified() -> Option<ErrorTarget> {
    Some(ErrorTarget::Unverified(
        siros_openid4vp::uri::ResponseUri::parse(RESPONSE_URI.to_owned()).expect("an https URI"),
    ))
}

#[test]
fn a_uri_request_authenticates_under_its_prefix() {
    let uri = link("test%3Averifier", "");
    let object = request_object(&uri_payload(""));
    let received = fetched(&uri, &object).expect("fetched");
    let envelope = envelope(&received);
    let registry = registry();
    let trust = TestTrust {
        name: Some("Example Verifier".to_owned()),
        ..TestTrust::default()
    };
    let pending = envelope
        .questions(&registry, &config(), &TestHost::default())
        .expect("questions");
    assert_eq!(pending.questions().count(), 1);
    let authenticated = pending
        .authenticate(
            |evaluation| trust.decide(evaluation),
            &config(),
            &TestHost::default(),
        )
        .expect("authenticated");
    let verifier = authenticated.verifier();
    assert!(matches!(verifier.id(), VerifierId::Client(id) if id.as_str() == "test:verifier"));
    assert_eq!(
        verifier.name(),
        Some(&Text::Raw("Example Verifier".to_owned()))
    );
    assert!(matches!(
        verifier.endpoint(),
        BoundEndpoint::ResponseUri { uri, basis: EndpointBasis::Request } if uri.as_str() == RESPONSE_URI
    ));
    assert!(verifier.metadata().is_some());
}

#[test]
fn a_registered_object_rule_refuses_the_claims_it_reads_as_a14() {
    // A14: after A10, each registered rule reads the payload's claims; its refusal carries its
    // own code, and no Authenticated is built.
    let mut builder = Registry::<TestHost>::builder();
    siros_testkit::fixtures::openid4vp(&mut builder);
    builder.format(TestFormat::new().expect("format"));
    builder.client_prefix(siros_testkit::TestPrefix::Request);
    builder.object_rule(siros_testkit::rules::TestObjectRule("jti"));
    let registry = builder.build().expect("registry");
    let uri = link("test%3Averifier", "");
    let trust = TestTrust::default();
    let without = request_object(&uri_payload(""));
    let received = fetched(&uri, &without).expect("fetched");
    let refused = envelope(&received);
    let rejected = authenticated(&refused, &registry, &trust, &config())
        .map(drop)
        .expect_err("A14");
    assert!(matches!(
        rejected.failure(),
        Failure::Unauthenticated(Unauthenticated::Object(_))
    ));
    assert_eq!(
        rejected.failure().code(),
        Some(ErrorCode::INVALID_REQUEST_OBJECT)
    );
    let with = request_object(&uri_payload(r#","jti":"j""#));
    let received = fetched(&uri, &with).expect("fetched");
    let accepted = envelope(&received);
    assert!(authenticated(&accepted, &registry, &trust, &config()).is_ok());
}

#[test]
fn each_a_rule_refuses_with_its_code_and_route() {
    let trust = TestTrust::default();
    let checked = config();
    // A1, A2 (an unregistered prefix; none, a pre-registered client).
    let client = |id: &str| uri_payload("").replace("test:verifier", id);
    let classify = |id: &str| {
        let uri: &'static str = Box::leak(link(&id.replace(':', "%3A"), "").into_boxed_str());
        let object: &'static str = Box::leak(request_object(&client(id)).into_boxed_str());
        let received: &'static Received<'static> =
            Box::leak(Box::new(fetched(uri, object).expect("fetched")));
        let envelope: &'static Envelope<'static> = Box::leak(Box::new(envelope(received)));
        let registry: &'static Registry<TestHost> = Box::leak(Box::new(registry()));
        envelope
            .questions(registry, &checked, &TestHost::default())
            .map(drop)
            .expect_err(id)
    };
    for (id, want) in [
        ("origin:https://verifier.example", "A1"),
        ("x509_hash:abc", "A2"),
        ("verifier", "A2"),
    ] {
        let rejected = classify(id);
        let holds = match cause(&rejected) {
            Unauthenticated::Origin => want == "A1",
            Unauthenticated::UnknownPrefix(named) => want == "A2" && named == id,
            _ => false,
        };
        assert!(holds, "{id}: {rejected:?}");
        assert_eq!(target(&rejected), unverified(), "{id}: unverified");
        assert_eq!(rejected.failure().code(), Some(ErrorCode::INVALID_REQUEST));
    }
    // A7: an alg the verifying module does not state (RFC 8725 §3.1), refused before the
    // trust service is asked.
    let header = REQUEST_OBJECT_HEADER.replace("ES256", "ES384");
    let uri: &'static str = Box::leak(link("test%3Averifier", "").into_boxed_str());
    let object: &'static str = Box::leak(
        compact_jws(&VERIFIER_SECRET, &header, &uri_payload(""))
            .expect("signs")
            .into_boxed_str(),
    );
    let received: &'static Received<'static> =
        Box::leak(Box::new(fetched(uri, object).expect("fetched")));
    let read: &'static Envelope<'static> = Box::leak(Box::new(envelope(received)));
    let prefixes: &'static Registry<TestHost> = Box::leak(Box::new(registry()));
    let rejected = read
        .questions(prefixes, &checked, &TestHost::default())
        .map(drop)
        .expect_err("A7");
    assert!(matches!(cause(&rejected), Unauthenticated::Algorithm(alg) if alg == "ES384"));
    assert_eq!(target(&rejected), unverified());
    assert_eq!(
        rejected.failure().code(),
        Some(ErrorCode::INVALID_REQUEST_OBJECT)
    );
    // A6: the trust service denies.
    let denied = TestTrust {
        verdict: Verdict::Deny,
        ..TestTrust::default()
    };
    let rejected = refused(&uri_payload(""), TestPrefix::Request, &denied, &checked);
    assert!(matches!(cause(&rejected), Unauthenticated::Untrusted(id) if id == "test:verifier"));
    assert_eq!(target(&rejected), unverified());
    // A9: expired, not yet valid.
    let now = 1_785_000_000_i64;
    for (extra, why) in [
        (format!(r#","exp":{}"#, now - 61), "expired"),
        (format!(r#","nbf":{}"#, now + 61), "not yet valid"),
    ] {
        let rejected = refused(&uri_payload(&extra), TestPrefix::Request, &trust, &checked);
        let holds = matches!(
            (cause(&rejected), why),
            (Unauthenticated::Validity(TimeError::Expired), "expired")
                | (
                    Unauthenticated::Validity(TimeError::NotYetValid),
                    "not yet valid"
                )
        );
        assert!(holds, "{why}: {rejected:?}");
        assert_eq!(
            rejected.failure().code(),
            Some(ErrorCode::INVALID_REQUEST_OBJECT)
        );
    }
    // Within the skew both stand.
    let within = format!(r#","exp":{},"nbf":{}"#, now - 59, now + 59);
    let uri = link("test%3Averifier", "");
    let object = request_object(&uri_payload(&within));
    let received = fetched(&uri, &object).expect("fetched");
    let envelope = envelope(&received);
    let registry = registry();
    assert!(authenticated(&envelope, &registry, &trust, &checked).is_ok());
    // A10: another recipient (tamper).
    let rejected = refused(
        &uri_payload(r#","aud":"https://wallet.example""#),
        TestPrefix::Request,
        &trust,
        &checked,
    );
    assert!(
        matches!(cause(&rejected), Unauthenticated::Audience(aud) if aud == "https://wallet.example")
    );
    let uri = link("test%3Averifier", "");
    let object = request_object(&uri_payload(r#","aud":"https://self-issued.me/v2""#));
    let received = fetched(&uri, &object).expect("fetched");
    let envelope = super::envelope(&received);
    assert!(authenticated(&envelope, &registry, &trust, &checked).is_ok());
    // A12: no response_uri; tamper: one outside the decision's endpoints; and off the host the
    // identifier names, without endpoints.
    let without = uri_payload("").replace(&format!(r#""response_uri":"{RESPONSE_URI}","#), "");
    let rejected = refused(&without, TestPrefix::Request, &trust, &checked);
    assert!(matches!(cause(&rejected), Unauthenticated::Endpoint(None)));
    assert!(target(&rejected).is_none(), "no response_uri, no route");
    let listing = TestTrust {
        endpoints: Some(vec!["https://verifier.example/other".to_owned()]),
        ..TestTrust::default()
    };
    let rejected = refused(&uri_payload(""), TestPrefix::Request, &listing, &checked);
    assert!(matches!(cause(&rejected), Unauthenticated::Endpoint(Some(at)) if at == RESPONSE_URI));
    assert_eq!(target(&rejected), unverified());
    let rejected = refused(
        &uri_payload(""),
        TestPrefix::Framework("elsewhere.example".to_owned()),
        &trust,
        &checked,
    );
    assert!(matches!(
        cause(&rejected),
        Unauthenticated::Endpoint(Some(_))
    ));
    // A13 tamper: a response_uri by http, refused when the questions are asked, without a route.
    let http = uri_payload("").replace(RESPONSE_URI, "http://verifier.example/post");
    let uri = link("test%3Averifier", "");
    let object = request_object(&http);
    let received = fetched(&uri, &object).expect("fetched");
    let envelope = super::envelope(&received);
    let rejected = envelope
        .questions(&registry, &checked, &TestHost::default())
        .map(drop)
        .expect_err("A13");
    assert!(matches!(
        cause(&rejected),
        Unauthenticated::EndpointScheme(_)
    ));
    assert!(target(&rejected).is_none());
}

#[test]
fn a_signature_over_altered_parameters_fails_by_a8_on_its_route() {
    let trust = TestTrust::default();
    let checked = config();
    // Tamper: the payload altered after the Verifier signed it.
    let object = request_object(&uri_payload(""));
    let parts: Vec<&str> = object.split('.').collect();
    let altered = format!(
        "{}.{}.{}",
        parts[0],
        super::b64(&uri_payload("").replace("n-0S6_WzA2Mj", "n-tampered")),
        parts[2]
    );
    let uri = link("test%3Averifier", "");
    let received = fetched(&uri, &altered).expect("fetched");
    let envelope = super::envelope(&received);
    let registry = registry();
    let rejected = authenticated(&envelope, &registry, &trust, &checked)
        .map(drop)
        .expect_err("A8");
    assert!(matches!(cause(&rejected), Unauthenticated::Signature));
    assert_eq!(
        rejected.failure().code(),
        Some(ErrorCode::INVALID_REQUEST_OBJECT)
    );
    // Under a Request binding the route is unverified; under a Framework one it is listed.
    assert_eq!(target(&rejected), unverified());
    let listing = TestTrust {
        endpoints: Some(vec![RESPONSE_URI.to_owned()]),
        ..TestTrust::default()
    };
    let rejected = authenticated(&envelope, &registry, &listing, &checked)
        .map(drop)
        .expect_err("A8");
    assert!(matches!(cause(&rejected), Unauthenticated::Signature));
    assert!(
        matches!(target(&rejected), Some(ErrorTarget::Listed(at)) if at.as_str() == RESPONSE_URI)
    );
    assert_eq!(
        rejected
            .route()
            .and_then(|route| route.echo())
            .map(|echo| echo.as_str()),
        Some("eyJhb-6-sVA")
    );
}

#[test]
fn a_signed_dc_api_request_names_its_client_and_an_origin_it_expects() {
    let trust = TestTrust::default();
    let checked = config();
    let registry = registry();
    // A3: a signed DC API request without client_id.
    let parameters = fixtures::parameters(
        &super::test_queries(&["q"]),
        r#""expected_origins":["https://verifier.example"]"#,
    );
    let jws = compact_jws(
        &VERIFIER_SECRET,
        fixtures::REQUEST_OBJECT_HEADER,
        &parameters,
    )
    .expect("signs");
    let data = format!(r#"{{"request":"{jws}"}}"#);
    let received = fixtures::signed(&data).expect("received");
    let envelope = Envelope::parse(
        &received,
        siros_testkit::fixtures::routing().expect("the routing registry"),
    )
    .expect("an envelope");
    let rejected = envelope
        .questions(&registry, &checked, &TestHost::default())
        .map(drop)
        .expect_err("A3");
    assert!(matches!(cause(&rejected), Unauthenticated::ClientIdAbsent));
    assert_eq!(target(&rejected), Some(ErrorTarget::DcApi));
    // Signed by the test Verifier: authenticated, endpoint the platform's.
    let data = fixtures::signed_data(&parameters).expect("signs");
    let received = fixtures::signed(&data).expect("received");
    let envelope = Envelope::parse(
        &received,
        siros_testkit::fixtures::routing().expect("the routing registry"),
    )
    .expect("an envelope");
    let done = authenticated(&envelope, &registry, &trust, &checked).expect("authenticated");
    assert_eq!(done.verifier().endpoint(), &BoundEndpoint::DcApi);
    // Tamper: verified expected_origins that lack the Origin is C8.
    let elsewhere = fixtures::parameters(
        &super::test_queries(&["q"]),
        r#""expected_origins":["https://elsewhere.example"]"#,
    );
    let data = fixtures::signed_data(&elsewhere).expect("signs");
    let received = fixtures::signed(&data).expect("received");
    let envelope = Envelope::parse(
        &received,
        siros_testkit::fixtures::routing().expect("the routing registry"),
    )
    .expect("an envelope");
    assert!(authenticated(&envelope, &registry, &trust, &checked).is_ok());
    let request = Request::parse(&envelope).expect("a request");
    let refused = Accepted::new(&request, &registry)
        .map(drop)
        .expect_err("C8");
    assert_eq!(
        refused
            .refusals()
            .iter()
            .map(|refusal| refusal.id().as_str())
            .collect::<Vec<_>>(),
        ["openid4vp.rules.c8"]
    );
    // An unsigned request under OriginPolicy::Evaluate: the Origin's evaluation, A6 on a Deny.
    let parameters = fixtures::parameters(&super::test_queries(&["q"]), "");
    let received = fixtures::unsigned(&parameters).expect("received");
    let envelope = Envelope::parse(
        &received,
        siros_testkit::fixtures::routing().expect("the routing registry"),
    )
    .expect("an envelope");
    let evaluate = TrustConfig {
        origins: OriginPolicy::Evaluate,
        ..checked
    };
    let denied = TestTrust {
        verdict: Verdict::Deny,
        ..TestTrust::default()
    };
    let rejected = authenticated(&envelope, &registry, &denied, &evaluate)
        .map(drop)
        .expect_err("A6");
    assert!(
        matches!(cause(&rejected), Unauthenticated::Untrusted(origin) if origin == "https://verifier.example")
    );
    let accepted =
        authenticated(&envelope, &registry, &denied, &checked).expect("OriginPolicy::Accept");
    assert!(matches!(accepted.verifier().id(), VerifierId::Origin(_)));
}

#[test]
fn a_multisigned_request_authenticates_by_its_first_good_signature_or_lists_each_reason() {
    let checked = config();
    let registry = registry();
    let parameters = fixtures::parameters(
        &super::test_queries(&["q"]),
        r#""expected_origins":["https://verifier.example"]"#,
    );
    let payload = super::b64(&parameters);
    let signature = |client_id: &str, key: &[u8; 32]| {
        let protected = super::b64(&format!(
            r#"{{"alg":"ES256","typ":"oauth-authz-req+jwt","client_id":"{client_id}"}}"#
        ));
        let signed =
            siros_testkit::jose::sign(key, &format!("{protected}.{payload}")).expect("signs");
        format!(r#"{{"protected":"{protected}","signature":"{signed}"}}"#)
    };
    let other = [7u8; 32];
    let jws = |signatures: &[String]| {
        format!(
            r#"{{"payload":"{payload}","signatures":[{}]}}"#,
            signatures.join(",")
        )
    };
    let origin = || Origin::parse("https://verifier.example").expect("origin");
    // The second signature, by the test Verifier, authenticates.
    let data = jws(&[
        signature("x509_hash:abc", &VERIFIER_SECRET),
        signature("test:verifier", &VERIFIER_SECRET),
    ]);
    let received = Received::dc_api(
        "openid4vp-v1-multisigned",
        &data,
        origin(),
        &DcApiProtocols::ALL,
    )
    .expect("received");
    let envelope = Envelope::parse(
        &received,
        siros_testkit::fixtures::routing().expect("the routing registry"),
    )
    .expect("an envelope");
    let done = authenticated(&envelope, &registry, &TestTrust::default(), &checked)
        .expect("authenticated");
    assert!(
        matches!(done.verifier().id(), VerifierId::Client(id) if id.as_str() == "test:verifier")
    );
    // A11: none does; each reason listed.
    let data = jws(&[
        signature("x509_hash:abc", &VERIFIER_SECRET),
        signature("test:verifier", &other),
    ]);
    let received = Received::dc_api(
        "openid4vp-v1-multisigned",
        &data,
        origin(),
        &DcApiProtocols::ALL,
    )
    .expect("received");
    let envelope = Envelope::parse(
        &received,
        siros_testkit::fixtures::routing().expect("the routing registry"),
    )
    .expect("an envelope");
    let rejected = authenticated(&envelope, &registry, &TestTrust::default(), &checked)
        .map(drop)
        .expect_err("A11");
    let Unauthenticated::NoSignature(reasons) = cause(&rejected) else {
        panic!("A11: {rejected:?}")
    };
    assert!(matches!(
        reasons.items(),
        [
            Unauthenticated::UnknownPrefix(_),
            Unauthenticated::Signature
        ]
    ));
    assert_eq!(target(&rejected), Some(ErrorTarget::DcApi));
    assert_eq!(
        rejected.failure().code(),
        Some(ErrorCode::INVALID_REQUEST_OBJECT)
    );
}

#[test]
fn the_registry_and_the_configuration_refuse_what_their_rule_excludes() {
    // A prefix registered twice; `origin` is no prefix name.
    let mut builder = Registry::<TestHost>::builder();
    siros_testkit::fixtures::openid4vp(&mut builder);
    builder.client_prefix(TestPrefix::Request);
    builder.client_prefix(TestPrefix::Framework("verifier.example".to_owned()));
    assert!(matches!(builder.build(), Err(RegistryError::PrefixTwice(name)) if name == "test"));
    assert_eq!(PrefixName::new("origin"), None);
    assert_eq!(
        PrefixName::new("x509_hash").map(|name| name.as_str()),
        Some("x509_hash")
    );
    // A skew past 300 s.
    assert_eq!(Skew::new(Seconds(301)), Err(SkewTooLarge(301)));
    assert!(Skew::new(Seconds(300)).is_ok());
}
