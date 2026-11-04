//! The flows' request side: requests by URI and their fetch (U3 to U11, U18, U19), the envelope
//! (U12 to U14, U16, U17), routing (P1, C5, P5, P6, P7, N1, S3, C7), Verifier authentication
//! (A1 to A13) and the routes of refused requests; one fixture per rule, each asserting the rule's
//! variant or code, the tamper cases with why each fails, and the known answers of OpenID4VP's
//! examples.

mod authenticate;
#[path = "../common/mod.rs"]
mod common;
mod envelope;
mod routing;
mod uri;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use siros_openid4vp::arrival::Received;
use siros_openid4vp::authenticate::{Authenticated, OriginPolicy, Pending, TrustConfig};
use siros_openid4vp::envelope::Envelope;
use siros_openid4vp::host::Seconds;
use siros_openid4vp::jose::Skew;
use siros_openid4vp::plugins::Registry;
use siros_openid4vp::recourse::Rejected;
use siros_openid4vp::uri::{Fetch, FetchAnswer, RequestObjectFetch};
use siros_testkit::fixtures::REQUEST_OBJECT_HEADER;
use siros_testkit::jose::{VERIFIER_SECRET, compact_jws};
use siros_testkit::{Binds, TestFormat, TestHost, TestPrefix, TestProfile, TestTrust};

use common::test_queries;

/// The test Verifier's endpoints.
const REQUEST_URI: &str = "https://verifier.example/request/1";
const RESPONSE_URI: &str = "https://verifier.example/post";
/// A P-256 key the key rule accepts: B.2.6's.
const KEY: &str = r#"{"kty":"EC","crv":"P-256","kid":"1","use":"enc","alg":"ECDH-ES","x":"DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0","y":"XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc"}"#;

fn b64(text: &str) -> String {
    URL_SAFE_NO_PAD.encode(text)
}

/// A link holding `client_id` and `request_uri`, and `extra` query members.
fn link(client_id: &str, extra: &str) -> String {
    format!(
        "openid4vp://?client_id={client_id}&request_uri={}{extra}",
        REQUEST_URI.replace(':', "%3A").replace('/', "%2F")
    )
}

/// A Request Object's payload by URI: the test Verifier's `client_id`, `direct_post.jwt` to its
/// Response URI, `state`, a key the key rule accepts, one `test` query; then `extra` members.
fn uri_payload(extra: &str) -> String {
    format!(
        r#"{{"client_id":"test:verifier","response_type":"vp_token","response_mode":"direct_post.jwt","response_uri":"{RESPONSE_URI}","nonce":"n-0S6_WzA2Mj","state":"eyJhb-6-sVA","client_metadata":{{"jwks":{{"keys":[{KEY}]}}}},"dcql_query":{}{extra}}}"#,
        test_queries(&["q"])
    )
}

/// The test Verifier's Request Object: a compact JWS of the payload.
fn request_object(payload: &str) -> String {
    compact_jws(&VERIFIER_SECRET, REQUEST_OBJECT_HEADER, payload).expect("signs")
}

/// The test format and profile, and the `test` prefix vouching by the request.
fn registry() -> Registry<TestHost> {
    registry_with(TestPrefix::Request)
}

fn registry_with(prefix: TestPrefix) -> Registry<TestHost> {
    let mut builder = Registry::<TestHost>::builder();
    siros_testkit::fixtures::openid4vp(&mut builder);
    builder.format(TestFormat::new().expect("format"));
    let profile = builder.profile(TestProfile::new(Binds::First));
    builder.exact(
        siros_openid4vp::ids::TransactionType::parse("t1").expect("type"),
        profile,
    );
    builder.client_prefix(prefix);
    builder.build().expect("registry")
}

/// HAIP's width: a skew of 60 s, unsigned DC API requests accepted, `exp` and `aud` checked
/// when present.
fn config() -> TrustConfig {
    TrustConfig {
        skew: Skew::new(Seconds(60)).expect("a skew"),
        origins: OriginPolicy::Accept,
    }
}

/// A URI request fetched by GET: the body the caller fetched, resumed.
fn fetched<'a>(uri: &'a str, body: &'a str) -> Result<Received<'a>, Box<Rejected<'a>>> {
    let host = TestHost::default();
    let registry = registry();
    let fetch = Fetch::of(uri, &registry, &host).expect("a fetch");
    assert!(matches!(fetch.request(), RequestObjectFetch::Get(_)));
    fetch.resume(FetchAnswer::Body(body), &registry, &host)
}

/// The envelope's questions answered by the trust service, and the checks under the bound key.
fn authenticated<'e>(
    envelope: &'e Envelope<'e>,
    registry: &'e Registry<TestHost>,
    trust: &TestTrust,
    config: &TrustConfig,
) -> Result<Authenticated<'e>, Box<Rejected<'e>>> {
    let pending: Pending<'_, TestHost> =
        envelope.questions(registry, config, &TestHost::default())?;
    pending.authenticate(
        |evaluation| trust.decide(evaluation),
        config,
        &TestHost::default(),
    )
}

/// The envelope of a URI request in the test host's modes.
fn envelope<'r>(received: &'r Received<'r>) -> Envelope<'r> {
    Envelope::parse(
        received,
        siros_testkit::fixtures::routing().expect("the routing registry"),
    )
    .expect("an envelope")
}

/// I4: two received forms never share a digest. The forms are drawn so that their parts coincide
/// across forms: the same parameters unsigned, signed and by URI, the same text as an Origin and
/// as a URI, and parts that shift a byte between neighbours.
#[test]
fn received_forms_never_share_a_digest() {
    use siros_openid4vp::arrival::DcApiProtocols;
    use siros_openid4vp::ids::Origin;
    use siros_testkit::fixtures;

    let mut owned: Vec<(String, String, &str)> = Vec::new();
    for k in 0..40 {
        let nonce = format!("n{k}");
        let parameters =
            fixtures::parameters(&test_queries(&["q"]), &format!(r#""state":"{nonce}""#));
        let origin = if k % 2 == 0 {
            "https://verifier.example"
        } else {
            "https://verifier.example/"
        };
        owned.push((
            origin.to_owned(),
            parameters.clone(),
            "openid4vp-v1-unsigned",
        ));
        owned.push((
            origin.to_owned(),
            fixtures::signed_data(&parameters).expect("signs"),
            "openid4vp-v1-signed",
        ));
    }
    let mut digests: Vec<String> = owned
        .iter()
        .map(|(origin, data, protocol)| {
            Received::dc_api(
                protocol,
                data,
                Origin::parse(origin.as_str()).expect("origin"),
                &DcApiProtocols::ALL,
            )
            .expect("received")
            .digest()
            .as_str()
            .to_owned()
        })
        .collect();
    let objects: Vec<(String, String)> = (0..40)
        .map(|k| {
            let payload = uri_payload(&format!(r#","x":{k}"#));
            (
                link("test%3Averifier", &format!("&k={k}")),
                request_object(&payload),
            )
        })
        .collect();
    for (uri, object) in &objects {
        digests.push(
            fetched(uri, object)
                .expect("fetched")
                .digest()
                .as_str()
                .to_owned(),
        );
    }
    let count = digests.len();
    digests.sort();
    digests.dedup();
    assert_eq!(
        digests.len(),
        count,
        "collisions: {}",
        count - digests.len()
    );
}
