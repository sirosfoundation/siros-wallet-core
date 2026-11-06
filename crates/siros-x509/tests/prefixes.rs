//! `x509_hash` and `x509_san_dns` (§5.9.3): one A5 fixture per rule, each asserting its
//! `X509Refusal`; the endpoint rules; the known answers of §5.9.3's and A.3.2.1's examples.

use std::borrow::Cow;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use siros_openid4vp::arrival::{DcApiProtocols, Received};
use siros_openid4vp::authenticate::{
    Authenticated, BoundEndpoint, EndpointBasis, OriginPolicy, TrustConfig, Unauthenticated,
    VerifierId,
};
use siros_openid4vp::effects::{Decision, Evaluation, Verdict};
use siros_openid4vp::envelope::Envelope;
use siros_openid4vp::host::Seconds;
use siros_openid4vp::ids::Origin;
use siros_openid4vp::jose::Skew;
use siros_openid4vp::json::{Member, Node, Object};
use siros_openid4vp::plugins::Registry;
use siros_openid4vp::recourse::{Failure, Rejected};
use siros_openid4vp::uri::{Fetch, FetchAnswer};
use siros_testkit::jose::{VERIFIER_SECRET, compact_jws};
use siros_testkit::{TestFormat, TestHost, TestTrust};
use siros_x509::test_util::{Leaf, certificate, header, point, x5c, x509_hash};
use siros_x509::{LeafHash, X509Hash, X509Refusal, X509SanDns};

const ORIGIN: &str = "https://verifier.example";
const RESPONSE_URI: &str = "https://rp.example.com/post";

fn registry() -> Registry<TestHost> {
    let mut builder = Registry::<TestHost>::builder();
    siros_testkit::fixtures::openid4vp(&mut builder);
    builder.format(TestFormat::new().expect("format"));
    builder.client_prefix(X509Hash);
    builder.client_prefix(X509SanDns);
    builder.build().expect("registry")
}

fn config() -> TrustConfig {
    TrustConfig {
        skew: Skew::new(Seconds(60)).expect("skew"),
        origins: OriginPolicy::Accept,
    }
}

/// The test Verifier's leaf naming the DNS names.
fn leaf(dns: &[&str]) -> Vec<u8> {
    certificate(&Leaf {
        subject: "rp.example.com",
        point: point(&VERIFIER_SECRET),
        dns,
    })
}

/// A.3.2.1's payload: a signed DC API request's parameters under the Client Identifier.
fn payload(client_id: &str) -> String {
    format!(
        r#"{{"expected_origins":["https://origin1.example.com","https://origin2.example.com"],"client_id":"{client_id}","client_metadata":{{"jwks":{{"keys":[{{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","use":"enc","kid":"1"}}]}}}},"response_type":"vp_token","response_mode":"dc_api","nonce":"n-0S6_WzA2Mj","dcql_query":{{"credentials":[{{"id":"q","format":"test"}}]}}}}"#
    )
}

/// The `data` of a signed DC API request whose protected header is given.
fn data(header: &str, payload: &str) -> String {
    let jws = compact_jws(&VERIFIER_SECRET, header, payload).expect("signs");
    format!(r#"{{"request":"{jws}"}}"#)
}

/// The outcome of authenticating a signed DC API request.
fn outcome<'e>(
    envelope: &'e Envelope<'e>,
    registry: &'e Registry<TestHost>,
) -> Result<Authenticated<'e>, Box<Rejected<'e>>> {
    let trust = TestTrust::default();
    envelope
        .questions(registry, &config(), &TestHost::default())?
        .authenticate(
            |evaluation| trust.decide(evaluation),
            &config(),
            &TestHost::default(),
        )
}

/// The X.509 rule a signed DC API request breaks.
fn refusal(header: &str, client_id: &str) -> X509Refusal {
    let data = data(header, &payload(client_id));
    let origin = Origin::parse(ORIGIN).expect("origin");
    let received = Received::dc_api("openid4vp-v1-signed", &data, origin, &DcApiProtocols::ALL)
        .expect("received");
    let envelope = Envelope::parse(
        &received,
        siros_testkit::fixtures::routing().expect("the routing registry"),
    )
    .expect("an envelope");
    let registry = registry();
    let rejected = outcome(&envelope, &registry)
        .map(drop)
        .expect_err(client_id);
    let Failure::Unauthenticated(Unauthenticated::Prefix(refusal)) = rejected.failure() else {
        panic!("A5: {rejected:?}")
    };
    assert_eq!(
        rejected.failure().code().map(|code| code.as_str()),
        Some("invalid_request")
    );
    let rule: &dyn std::error::Error = refusal.rule();
    rule.downcast_ref::<X509Refusal>()
        .cloned()
        .unwrap_or_else(|| panic!("an X509Refusal: {rule}"))
}

#[test]
fn each_x509_rule_refuses_its_claim() {
    let good = leaf(&["rp.example.com"]);
    let san = "x509_san_dns:rp.example.com";
    let hash = x509_hash(&good);
    assert_eq!(
        refusal(&header(&x5c(&good)), "x509_hash:abc"),
        X509Refusal::HashSyntax("abc".to_owned())
    );
    // The tamper case: another leaf than the identifier's.
    let other = x509_hash(&leaf(&["other.example.com"]));
    assert_eq!(
        refusal(&header(&x5c(&good)), &other),
        X509Refusal::Hash(other.trim_start_matches("x509_hash:").to_owned())
    );
    assert_eq!(
        refusal(&header(&x5c(&good)), "x509_san_dns:rp_example"),
        X509Refusal::SanSyntax("rp_example".to_owned())
    );
    // The tamper case: the leaf names another DNS name.
    let elsewhere = leaf(&["elsewhere.example.com"]);
    assert_eq!(
        refusal(&header(&x5c(&elsewhere)), san),
        X509Refusal::San("rp.example.com".to_owned())
    );
    assert_eq!(
        refusal(r#"{"alg":"ES256","typ":"oauth-authz-req+jwt"}"#, &hash),
        X509Refusal::X5cAbsent
    );
    assert_eq!(
        refusal(
            r#"{"alg":"ES256","typ":"oauth-authz-req+jwt","x5c":"MA"}"#,
            &hash
        ),
        X509Refusal::X5cNotArray
    );
    assert_eq!(refusal(&header(&[]), &hash), X509Refusal::X5cEmpty);
    assert_eq!(
        refusal(&header(&["*".to_owned()]), &hash),
        X509Refusal::Base64(0)
    );
    assert!(matches!(
        refusal(
            &header(&[STANDARD.encode([0x30, 0x03, 0x02, 0x01, 0x01])]),
            &hash
        ),
        X509Refusal::Certificate { item: 0, .. }
    ));
    // A compressed point (RFC 5480 §2.2 reads the uncompressed form).
    let mut compressed = point(&VERIFIER_SECRET);
    compressed.truncate(33);
    compressed[0] = 0x02;
    let weak = certificate(&Leaf {
        subject: "rp.example.com",
        point: compressed,
        dns: &["rp.example.com"],
    });
    assert_eq!(refusal(&header(&x5c(&weak)), san), X509Refusal::Key);
    // The entry's tag [2], dNSName, turned into [15], which GeneralName (RFC 5280 §4.2.1.6) lacks.
    let entry = [&[0x82, 14][..], b"rp.example.com"].concat();
    let at = good
        .windows(entry.len())
        .position(|window| window == entry)
        .expect("the dNSName entry");
    let mut unreadable = good.clone();
    unreadable[at] = 0x8f;
    assert!(matches!(
        refusal(&header(&x5c(&unreadable)), san),
        X509Refusal::SubjectAltName(_)
    ));
}

#[test]
fn a_dc_api_request_authenticates_under_either_prefix() {
    // KA14: A.3.2.1's payload as data.request; the classification names x509_san_dns.
    let good = leaf(&["rp.example.com"]);
    let san = "x509_san_dns:rp.example.com";
    let data = data(&header(&x5c(&good)), &payload(san));
    let origin = Origin::parse("https://origin1.example.com").expect("origin");
    let received = Received::dc_api("openid4vp-v1-signed", &data, origin, &DcApiProtocols::ALL)
        .expect("received");
    let envelope = Envelope::parse(
        &received,
        siros_testkit::fixtures::routing().expect("the routing registry"),
    )
    .expect("an envelope");
    assert_eq!(envelope.client_id().map(|id| id.as_str()), Some(san));
    let registry = registry();
    let done = outcome(&envelope, &registry).expect("authenticated");
    assert!(matches!(done.verifier().id(), VerifierId::Client(id) if id.as_str() == san));
    assert_eq!(done.verifier().endpoint(), &BoundEndpoint::DcApi);
    // x509_hash over the same leaf.
    let hash = x509_hash(&good);
    let data =
        siros_testkit::jose::compact_jws(&VERIFIER_SECRET, &header(&x5c(&good)), &payload(&hash))
            .map(|jws| format!(r#"{{"request":"{jws}"}}"#))
            .expect("signs");
    let origin = Origin::parse(ORIGIN).expect("origin");
    let received = Received::dc_api("openid4vp-v1-signed", &data, origin, &DcApiProtocols::ALL)
        .expect("received");
    let envelope = Envelope::parse(
        &received,
        siros_testkit::fixtures::routing().expect("the routing registry"),
    )
    .expect("an envelope");
    assert!(outcome(&envelope, &registry).is_ok());
}

/// A12 or A6, with what the refusal names.
#[derive(Debug, PartialEq, Eq)]
enum Refused {
    Endpoint(Option<String>),
    Untrusted(String),
}

#[test]
fn a_uri_request_binds_its_endpoint_as_the_prefix_says() {
    let good = leaf(&["rp.example.com"]);
    let registry = registry();
    let host = TestHost::default();
    let run = |client_id: &str,
               response_uri: &str,
               decide: &dyn Fn(&Evaluation) -> Decision|
     -> Result<EndpointBasis, Refused> {
        let payload = format!(
            r#"{{"client_id":"{client_id}","response_type":"vp_token","response_mode":"direct_post.jwt","response_uri":"{response_uri}","nonce":"n-0S6_WzA2Mj","state":"s","dcql_query":{{"credentials":[{{"id":"q","format":"test"}}]}}}}"#
        );
        let object = compact_jws(&VERIFIER_SECRET, &header(&x5c(&good)), &payload).expect("signs");
        let uri = format!(
            "openid4vp://?client_id={}&request_uri=https%3A%2F%2Frp.example.com%2Fr",
            client_id.replace(':', "%3A")
        );
        let fetch = Fetch::of(&uri, &registry, &host).expect("a fetch");
        let received = fetch
            .resume(FetchAnswer::Body(&object), &registry, &host)
            .expect("received");
        let envelope = Envelope::parse(
            &received,
            siros_testkit::fixtures::routing().expect("the routing registry"),
        )
        .expect("an envelope");
        let config = config();
        let outcome = envelope
            .questions(&registry, &config, &host)
            .and_then(|pending| pending.authenticate(decide, &config, &host));
        match outcome {
            Ok(done) => match done.verifier().endpoint() {
                BoundEndpoint::ResponseUri { basis, .. } => Ok(*basis),
                BoundEndpoint::DcApi => panic!("a URI request bound to the DC API"),
            },
            Err(rejected) => match rejected.failure() {
                Failure::Unauthenticated(Unauthenticated::Endpoint(at)) => {
                    Err(Refused::Endpoint(at.clone()))
                }
                Failure::Unauthenticated(Unauthenticated::Untrusted(id)) => {
                    Err(Refused::Untrusted(id.clone()))
                }
                other => panic!("{other:?}"),
            },
        }
    };
    let plain = |evaluation: &Evaluation| TestTrust::default().decide(evaluation);
    let listing = |evaluation: &Evaluation| {
        TestTrust {
            endpoints: Some(vec![RESPONSE_URI.to_owned()]),
            ..TestTrust::default()
        }
        .decide(evaluation)
    };
    let hash = x509_hash(&good);
    let san = "x509_san_dns:rp.example.com";
    // The decision's endpoints vouch for a response_uri they list, for both prefixes.
    assert_eq!(
        run(&hash, RESPONSE_URI, &listing),
        Ok(EndpointBasis::Framework)
    );
    assert_eq!(
        run(san, RESPONSE_URI, &listing),
        Ok(EndpointBasis::Framework)
    );
    assert!(
        matches!(
            run(&hash, "https://other.example.com/post", &listing),
            Err(Refused::Endpoint(Some(_)))
        ),
        "A12: off the list"
    );
    // Without endpoints: x509_hash by the request; x509_san_dns on the DNS name's host alone,
    // compared after ASCII lowercasing (A12 otherwise).
    assert_eq!(
        run(&hash, "https://anywhere.example/post", &plain),
        Ok(EndpointBasis::Request)
    );
    assert_eq!(
        run(san, "https://RP.example.com/post", &plain),
        Ok(EndpointBasis::Framework)
    );
    assert!(matches!(
        run(san, "https://other.example.com/post", &plain),
        Err(Refused::Endpoint(Some(_)))
    ));
    // A permit whose `endpoints` is no array of URIs binds nothing (A6).
    let broken = |_: &Evaluation| Decision {
        verdict: Verdict::Permit,
        context: Some(
            Object::new(vec![Member {
                name: Cow::Borrowed("endpoints"),
                value: Node::String(Cow::Borrowed(RESPONSE_URI)),
            }])
            .expect("a context"),
        ),
    };
    assert_eq!(
        run(&hash, RESPONSE_URI, &broken),
        Err(Refused::Untrusted(hash.clone()))
    );
}

#[test]
fn section_5_9_3s_x509_hash_is_a_base64url_sha_256() {
    // KA20: §5.9.3's example identifier is base64url without padding of 32 octets.
    let original = "Uvo3HtuIxuhC92rShpgqcT3YXwrqRxWEviRiA0OZszk";
    let hash = LeafHash::parse(original).expect("32 octets");
    assert_eq!(URL_SAFE_NO_PAD.encode(hash.octets()), original);
    assert_eq!(hash.text(), original);
}

#[test]
fn an_ed25519_key_reads_as_the_okp_jwk_of_rfc_8410_and_rfc_8037() {
    use der::Decode;
    use siros_x509::SpkiKey;
    use spki::SubjectPublicKeyInfoOwned;

    // RFC 8410 §10.1's public key, and its JWK per RFC 8037 §2.
    let der = STANDARD
        .decode("MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=")
        .expect("base64");
    let spki = SubjectPublicKeyInfoOwned::from_der(&der).expect("SubjectPublicKeyInfo");
    let key = spki.key().expect("a key");
    let jwk = key.jwk();
    let text = |name: &str| jwk.member(name).and_then(Node::as_str);
    assert_eq!(
        (text("kty"), text("crv"), text("x"), text("y")),
        (
            Some("OKP"),
            Some("Ed25519"),
            Some("Gb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE"),
            None
        )
    );
}
