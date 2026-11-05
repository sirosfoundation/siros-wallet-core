//! I3 over URI arrivals: each dressed case's request sent by URI, its Request Object fetched by
//! GET or by POST (a JWE to the posted key), authenticated, then phase 1; phase 2 prepares the
//! selection phase 1 derived, and falls back on each record of the same selection as the DC API
//! request derived it: a record commits to the request as received.

use serde_json::{Value, json};
use siros_openid4vp::authenticate::{OriginPolicy, TrustConfig};
use siros_openid4vp::envelope::Envelope;
use siros_openid4vp::host::Seconds;
use siros_openid4vp::jose::Skew;
use siros_openid4vp::json::Node;
use siros_openid4vp::request::Request;
use siros_openid4vp::resolve::{Finding, Outcome, Prepared};
use siros_openid4vp::uri::{Fetch, FetchAnswer, RequestObjectFetch};
use siros_openid4vp::wallet::Wallet;
use siros_testkit::TestTrust;
use siros_testkit::fixtures::{self, REQUEST_OBJECT_HEADER, first_selection};
use siros_testkit::jose::{VERIFIER_SECRET, compact_jws, encrypt_to};

use crate::common::{HaipHost, registry};
use crate::generate::{Dressed, ENC_KEY};
use crate::tally::Tally;

const RESPONSE_URI: &str = "https://verifier.example/post";

/// The dressed request's parameters as a Request Object by URI: the test Verifier's `client_id`,
/// `direct_post.jwt` to its Response URI with `state`, the key the key rule accepts first.
fn payload(dressed: &Dressed, k: usize) -> String {
    let mut parameters: Value = serde_json::from_str(&dressed.parameters).expect("JSON");
    let object = parameters.as_object_mut().expect("an object");
    object.retain(|name, _| name != "expected_origins");
    let mut key: Value = serde_json::from_str(ENC_KEY).expect("the key");
    key["kid"] = json!("verifier-enc");
    let metadata = object.entry("client_metadata").or_insert_with(|| json!({}));
    let mut keys = metadata["jwks"]["keys"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    keys.insert(0, key);
    metadata["jwks"] = json!({"keys": keys});
    object.extend([
        ("client_id".to_owned(), json!("test:verifier")),
        ("response_mode".to_owned(), json!("direct_post.jwt")),
        ("response_uri".to_owned(), json!(RESPONSE_URI)),
        ("state".to_owned(), json!(format!("s-{k}"))),
    ]);
    parameters.to_string()
}

/// Checks the dressed case by URI, by POST when `post`.
pub fn check(dressed: &Dressed, k: usize, tally: &mut Tally) {
    let post = k % 2 == 1;
    let registry = registry().expect("the real registry");
    let host = HaipHost::default();
    let method = if post { "&request_uri_method=post" } else { "" };
    let uri = format!(
        "openid4vp://?client_id=test%3Averifier&request_uri=https%3A%2F%2Fverifier.example%2Fr%2F{k}{method}"
    );
    let fetch = Fetch::of(&uri, &registry, &host).expect("R-uri: a fetch");
    let object = compact_jws(
        &VERIFIER_SECRET,
        REQUEST_OBJECT_HEADER,
        &payload(dressed, k),
    )
    .expect("signs");
    let body = match fetch.request() {
        RequestObjectFetch::Get(_) => {
            assert!(!post, "R-uri: a GET for request_uri_method get");
            tally.add("URI requests by GET");
            object
        }
        RequestObjectFetch::Post { body, .. } => {
            assert!(post, "R-uri: a POST for request_uri_method post");
            tally.add("URI requests by POST");
            let form: Vec<(String, String)> =
                serde_urlencoded::from_str(body.as_str()).expect("a form");
            let metadata: Value = serde_json::from_str(&form[0].1).expect("wallet_metadata");
            let jwk = Node::parse(&metadata["jwks"]["keys"][0].to_string())
                .expect("a JWK")
                .into_owned();
            encrypt_to(&jwk, "A256GCM", k % 4 == 1, object.as_bytes()).expect("encrypts")
        }
    };
    let received = fetch
        .resume(FetchAnswer::Body(&body), &registry, &host)
        .expect("R-uri: the Request Object reads");
    let envelope = Envelope::parse(
        &received,
        siros_testkit::fixtures::routing().expect("the routing registry"),
    )
    .expect("R-uri: an envelope");
    let config = TrustConfig {
        skew: Skew::new(Seconds(60)).expect("a skew"),
        origins: OriginPolicy::Accept,
    };
    let trust = TestTrust::default();
    let pending = envelope
        .questions(&registry, &config, &host)
        .expect("R-uri: the questions");
    let authenticated = pending
        .authenticate(|evaluation| trust.decide(evaluation), &config, &host)
        .expect("R-uri: authenticated");
    assert!(
        authenticated.verifier().metadata().is_some(),
        "R-uri: the metadata the request names"
    );
    let request = Request::parse(&envelope).expect("R-uri: a request");
    let wallet = Wallet::new(
        dressed
            .credentials
            .iter()
            .map(|held| held.credential().expect("a credential"))
            .collect(),
    )
    .expect("a wallet");
    let Ok(ids) = first_selection(&request, &wallet, &registry, &dressed.env) else {
        tally.add("URI requests refused or unmet");
        return;
    };
    let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
    match Prepared::prepare(&authenticated, &ids, &wallet, &registry, &dressed.env) {
        Ok(prepared) => {
            drop(prepared);
            tally.add("URI selections prepared");
        }
        Err(Outcome::Fallback(findings)) => {
            assert!(
                !findings
                    .items()
                    .iter()
                    .any(|f| matches!(f, Finding::Diverged { .. })),
                "R-records: phase 2 derives every record phase 1 derived by URI"
            );
            tally.add("URI selections prepared");
        }
        Err(other) => panic!("R-records: {other}"),
    }
    // The same selection as the DC API request derived it: records of another request.
    let dc_api = dressed.received();
    let dc_api = fixtures::request_of(&dc_api).expect("the DC API request");
    let Ok(foreign) = first_selection(&dc_api, &wallet, &registry, &dressed.env) else {
        return;
    };
    let foreign: Vec<&str> = foreign.iter().map(String::as_str).collect();
    // An empty selection names no record (an optional set's "none").
    if foreign.is_empty() {
        return;
    }
    match Prepared::prepare(&authenticated, &foreign, &wallet, &registry, &dressed.env) {
        Err(Outcome::Fallback(findings)) => {
            assert_eq!(
                findings.items().len(),
                foreign.len(),
                "R-records: every foreign record diverges"
            );
            assert!(
                findings
                    .items()
                    .iter()
                    .all(|f| matches!(f, Finding::Diverged { .. }))
            );
            tally.add("URI foreign records falling back");
        }
        other => panic!(
            "R-records: a record of another request answered: {:?}",
            other.map(drop)
        ),
    }
}
