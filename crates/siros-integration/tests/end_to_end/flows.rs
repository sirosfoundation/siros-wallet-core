//! The design's section 5.4: every flow, F1 to F13, to its `Delivery` or its `Reply`, one honest
//! path each, through the core with the real plug-ins over the test doubles' host. Each request
//! is the test Verifier's, signed where the flow signs, its expected values the specifications':
//! the delivery's channel and endpoint (§8.2, §8.3.1, A.2, A.4), the JWE's key and `enc` (§8.3,
//! HAIP §5), `state` (§5.2) and the Key Binding JWT's `aud` and `nonce` (Annex A, B.3.6).

use std::num::NonZeroU32;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use sha2::Digest;
use siros_explain::AllOf;
use siros_openid4vp::arrival::{DcApiProtocols, Received};
use siros_openid4vp::authenticate::{Authenticated, OriginPolicy, TrustConfig};
use siros_openid4vp::envelope::Envelope;
use siros_openid4vp::host::{
    Authentication, AuthenticationNeed, Factor, Knowledge, Seconds, Timestamp,
};
use siros_openid4vp::ids::Origin;
use siros_openid4vp::jose::Skew;
use siros_openid4vp::json::Node;
use siros_openid4vp::plugins::{Registry, RegistryBuilder};
use siros_openid4vp::recourse::{DcApiErrors, ErrorTarget, Reply};
use siros_openid4vp::request::Request;
use siros_openid4vp::resolve::{Delivery, Outcome, Prepared, Route};
use siros_openid4vp::routing::{ChannelKind, ModeName};
use siros_openid4vp::uri::{Fetch, FetchAnswer, RequestObjectFetch, ResponseUriAnswer};
use siros_openid4vp::wallet::Wallet;
use siros_testkit::fixtures::{self, B26_KEY, Held, first_selection};
use siros_testkit::jose::{VERIFIER_SECRET, compact_jws, encrypt_to, sign};
use siros_testkit::prefix::Registration;
use siros_testkit::{Published, TestChoice, TestMode, TestTrust};
use siros_x509::test_util::{Leaf, certificate, header, point, x5c, x509_hash};

use crate::common::{HaipHost, registry};

use super::{NOW, english, read_sd_jwt};

/// The Origin of the DC API flows.
const ORIGIN: &str = "https://verifier.example";
/// The test Verifier's DNS name, its Response URI and Request URI (B.3.6's Client Identifier).
const DNS: &str = "client.example.org";
const RESPONSE_URI: &str = "https://client.example.org/post";
const REQUEST_URI: &str = "https%3A%2F%2Fclient.example.org%2Frequest%2F1";
/// B.3.6's Client Identifier (KA18).
const SAN: &str = "x509_san_dns:client.example.org";
/// The `state` of the URI flows (§5.2).
const STATE: &str = "eyJhb-6-sVA";
/// The `nonce` of every flow (§5.2's example).
const NONCE: &str = "n-0S6_WzA2Mj";

/// One SD-JWT VC query of the PID's given name.
const PID_QUERY: &str = r#"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"path":["given_name"]}]}]}"#;

/// The wallet's PID, an SD-JWT VC bound to an ES256 key.
fn pid() -> Held {
    Held::new(
        "pid",
        "dc+sd-jwt",
        r#"{"type": "urn:eudi:pid:1", "metadata": {}, "values": {"given_name": "Erika"}, "alg": "ES256", "curve": "P-256", "key_alg": "ES256", "key_curve": "P-256"}"#,
    )
    .with_issued()
    .expect("the issued SD-JWT")
}

/// HAIP's width: a skew of 60 s, unsigned DC API requests accepted.
fn config() -> TrustConfig {
    TrustConfig {
        skew: Skew::new(Seconds(60)).expect("a skew"),
        origins: OriginPolicy::Accept,
    }
}

/// The test Verifier's leaf, naming its DNS name.
fn leaf() -> Vec<u8> {
    certificate(&Leaf {
        subject: DNS,
        point: point(&VERIFIER_SECRET),
        dns: &[DNS],
    })
}

/// A request's parameters: its mode, `client_metadata` with B.2.6's key, the PID query, then
/// `extra` members.
fn parameters(mode: &str, extra: &str) -> String {
    format!(
        r#"{{"response_type":"vp_token","response_mode":"{mode}","nonce":"{NONCE}","client_metadata":{{"jwks":{{"keys":[{B26_KEY}]}}}},"dcql_query":{PID_QUERY}{extra}}}"#
    )
}

/// A Request Object's payload by URI: the Client Identifier, the mode to the Response URI with
/// `state`, then `extra` members.
fn uri_payload(client_id: &str, mode: &str, extra: &str) -> String {
    parameters(
        mode,
        &format!(
            r#","client_id":"{client_id}","response_uri":"{RESPONSE_URI}","state":"{STATE}"{extra}"#
        ),
    )
}

/// The registry of every real plug-in with `more` registered after them.
fn registry_with(more: impl FnOnce(&mut RegistryBuilder<HaipHost>)) -> Registry<HaipHost> {
    let mut builder = Registry::<HaipHost>::builder();
    fixtures::openid4vp(&mut builder);
    builder.format(siros_sdjwt::SdJwtVc::new().expect("the SD-JWT VC format"));
    builder.format(siros_mdoc::Mdoc::new().expect("the mdoc format"));
    siros_paso::PasoProfile::default()
        .register(&mut builder)
        .expect("PaSO registers");
    builder.client_prefix(siros_testkit::TestPrefix::Request);
    builder.client_prefix(siros_x509::X509Hash);
    builder.client_prefix(siros_x509::X509SanDns);
    more(&mut builder);
    builder.build().expect("the registry")
}

/// An envelope authenticated under the trust service's decisions.
fn authentic<'e>(
    envelope: &'e Envelope<'e>,
    registry: &'e Registry<HaipHost>,
    trust: &TestTrust,
    host: &HaipHost,
) -> Authenticated<'e> {
    envelope
        .questions(registry, &config(), host)
        .and_then(|pending| {
            pending.authenticate(|evaluation| trust.decide(evaluation), &config(), host)
        })
        .unwrap_or_else(|rejected| panic!("authenticated: {:?}", rejected.failure()))
}

/// Phase 1's first selection and phase 2's delivery of it, phase 2's fetches answered from
/// `published`.
fn delivered(
    authenticated: &Authenticated<'_>,
    held: &[Held],
    registry: &Registry<HaipHost>,
    published: &Published,
    host: &HaipHost,
) -> Delivery {
    responded(authenticated, held, registry, published, host)
        .unwrap_or_else(|outcome| panic!("phase 2: {outcome}"))
}

/// Phase 1's first selection and phase 2's outcome for it, phase 2's fetches answered from
/// `published`.
fn responded(
    authenticated: &Authenticated<'_>,
    held: &[Held],
    registry: &Registry<HaipHost>,
    published: &Published,
    host: &HaipHost,
) -> Result<Delivery, Outcome> {
    let env = english();
    let wallet = Wallet::new(
        held.iter()
            .map(|h| h.credential().expect("a credential"))
            .collect(),
    )
    .expect("a wallet");
    let request = Request::parse(authenticated.envelope()).expect("the request");
    let app = crate::common::wallet_app(&wallet, &request, &env, host);
    let rendering = app.rendering().expect("the rendering");
    let ids = first_selection(&request, &wallet, registry, &env, &rendering).expect("a selection");
    let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
    Prepared::prepare(
        authenticated,
        &ids,
        &wallet,
        registry,
        &env,
        &rendering,
        host,
    )
    .and_then(|prepared| prepared.respond(|resource| published.answer(resource), host))
    .map(|built| built.delivery().clone())
}

/// A DC API arrival from the Origin.
fn dc_api<'a>(protocol: &'a str, data: &'a str) -> Received<'a> {
    Received::dc_api(
        protocol,
        data,
        Origin::parse(ORIGIN).expect("the Origin"),
        &DcApiProtocols::ALL,
    )
    .expect("the DC API request arrives")
}

/// The JSON of a DC API delivery.
fn dc_api_data(delivery: &Delivery) -> Value {
    let Delivery::DcApi(data) = delivery else {
        panic!("A.2: a DC API delivery, got {delivery:?}")
    };
    serde_json::from_str(data.as_str()).expect("JSON")
}

/// The form a URI delivery POSTs to the bound Response URI.
fn posted(delivery: &Delivery) -> Vec<(String, String)> {
    let Delivery::Post { endpoint, body } = delivery else {
        panic!("§8.2: a POST, got {delivery:?}")
    };
    assert_eq!(endpoint.as_str(), RESPONSE_URI, "the bound Response URI");
    assert!(body.media_type().is_form(), "{}", body.media_type());
    serde_urlencoded::from_bytes(body.bytes()).expect("a form")
}

/// The header and the plaintext of the test `Haip`'s JWE, which keeps its plaintext readable.
fn opened(jwe: &str) -> (Value, Value) {
    let parts: Vec<&str> = jwe.split('.').collect();
    let [header, "", "", plaintext, ""] = parts.as_slice() else {
        panic!("a compact JWE: {jwe}")
    };
    let read = |part: &str| -> Value {
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).expect("base64url")).expect("JSON")
    };
    (read(header), read(plaintext))
}

/// The Authorization Response a `response=<JWE>` form carries, sealed to B.2.6's key (`kid` 1)
/// with A128GCM, the Verifier listing no `enc` (§5.1).
fn sealed_form(delivery: &Delivery) -> Value {
    let form = posted(delivery);
    let [(name, jwe)] = form.as_slice() else {
        panic!("§8.3.1: response alone, got {form:?}")
    };
    assert_eq!(name, "response");
    let (header, response) = opened(jwe);
    assert_eq!(
        (&header["kid"], &header["enc"]),
        (&json!("1"), &json!("A128GCM"))
    );
    response
}

/// The Key Binding JWT's payload of the PID's presentation in a VP Token.
fn key_binding(vp_token: &Value) -> Value {
    read_sd_jwt(&vp_token["pid"][0])["kb_jwt"]["payload"].clone()
}

/// The DC API flows' Key Binding JWT: the Origin as audience, even for a signed request (A.4,
/// B.3.6), the request's nonce.
fn assert_dc_api_binding(vp_token: &Value) {
    let payload = key_binding(vp_token);
    assert_eq!(payload["aud"], json!(format!("origin:{ORIGIN}")));
    assert_eq!(payload["nonce"], json!(NONCE));
}

/// F1, F2: an unsigned DC API request, `dc_api` in the clear, `dc_api.jwt` sealed by the core.
#[test]
fn f1_f2_an_unsigned_dc_api_request_answers_in_its_mode() {
    let registry = registry().expect("the real registry");
    let host = HaipHost::at(Timestamp(NOW));
    for mode in ["dc_api", "dc_api.jwt"] {
        let data = parameters(mode, "");
        let received = dc_api("openid4vp-v1-unsigned", &data);
        let envelope = Envelope::parse(&received, &registry).expect("an envelope");
        let authenticated = authentic(&envelope, &registry, &TestTrust::default(), &host);
        let delivery = delivered(
            &authenticated,
            &[pid()],
            &registry,
            &Published::default(),
            &host,
        );
        let data = dc_api_data(&delivery);
        let response = match mode {
            // F1: the Authorization Response itself (A.2).
            "dc_api" => data,
            // F2: {"response": JWE}, the JWE the core sealed to B.2.6's key (A.2, §8.3).
            _ => {
                let jwe = data["response"].as_str().expect("A.2: response");
                let (header, response) = opened(jwe);
                assert_eq!(
                    (&header["kid"], &header["enc"]),
                    (&json!("1"), &json!("A128GCM"))
                );
                response
            }
        };
        assert!(
            response.get("state").is_none(),
            "A.2: no state over the DC API"
        );
        assert_dc_api_binding(&response["vp_token"]);
    }
}

/// F3, F4: a signed and a multisigned DC API request under siros-x509's prefixes, its
/// `expected_origins` naming the Origin (C8).
#[test]
fn f3_f4_a_signed_dc_api_request_answers_its_origin() {
    let registry = registry().expect("the real registry");
    let host = HaipHost::at(Timestamp(NOW));
    let leaf = leaf();
    let origins = format!(r#","expected_origins":["{ORIGIN}"]"#);
    // F3: x509_san_dns, dc_api.jwt; x509_hash, dc_api.
    for (client_id, mode) in [(SAN.to_owned(), "dc_api.jwt"), (x509_hash(&leaf), "dc_api")] {
        let payload = parameters(mode, &format!(r#","client_id":"{client_id}"{origins}"#));
        let jws = compact_jws(&VERIFIER_SECRET, &header(&x5c(&leaf)), &payload).expect("signs");
        let data = format!(r#"{{"request":"{jws}"}}"#);
        let received = dc_api("openid4vp-v1-signed", &data);
        let envelope = Envelope::parse(&received, &registry).expect("an envelope");
        let authenticated = authentic(&envelope, &registry, &TestTrust::default(), &host);
        let delivery = delivered(
            &authenticated,
            &[pid()],
            &registry,
            &Published::default(),
            &host,
        );
        let data = dc_api_data(&delivery);
        let response = if mode == "dc_api" {
            data
        } else {
            opened(data["response"].as_str().expect("response")).1
        };
        assert_dc_api_binding(&response["vp_token"]);
    }
    // F4: two signatures, each with its client_id in its protected header (A.3.2.2, U17); the
    // first, under an unknown prefix, fails, and the second authenticates (A11).
    let payload = URL_SAFE_NO_PAD.encode(parameters("dc_api.jwt", &origins));
    let x5c: Vec<String> = x5c(&leaf);
    let signature = |client_id: &str| {
        let protected = URL_SAFE_NO_PAD.encode(format!(
            r#"{{"alg":"ES256","typ":"oauth-authz-req+jwt","client_id":"{client_id}","x5c":{}}}"#,
            serde_json::to_string(&x5c).expect("x5c")
        ));
        let signed = sign(&VERIFIER_SECRET, &format!("{protected}.{payload}")).expect("signs");
        format!(r#"{{"protected":"{protected}","signature":"{signed}"}}"#)
    };
    let data = format!(
        r#"{{"payload":"{payload}","signatures":[{},{}]}}"#,
        signature("unknown:verifier"),
        signature(SAN)
    );
    let received = dc_api("openid4vp-v1-multisigned", &data);
    let envelope = Envelope::parse(&received, &registry).expect("an envelope");
    let authenticated = authentic(&envelope, &registry, &TestTrust::default(), &host);
    let delivery = delivered(
        &authenticated,
        &[pid()],
        &registry,
        &Published::default(),
        &host,
    );
    let response = opened(
        dc_api_data(&delivery)["response"]
            .as_str()
            .expect("response"),
    )
    .1;
    assert_dc_api_binding(&response["vp_token"]);
}

/// A URI flow's arrival: the link the OS hands over or the QR code holds, its Request Object
/// fetched as `fetch` asks and answered by `object`.
fn by_uri<'a>(
    uri: &'a str,
    registry: &'a Registry<HaipHost>,
    host: &HaipHost,
    object: impl FnOnce(RequestObjectFetch<'_>) -> String,
    body: &'a mut String,
) -> Received<'a> {
    let fetch = Fetch::of(uri, registry, host).expect("a fetch");
    *body = object(fetch.request());
    fetch
        .resume(FetchAnswer::Body(body), registry, host)
        .unwrap_or_else(|rejected| panic!("the Request Object reads: {:?}", rejected.failure()))
}

/// The link of the test Verifier's request by URI, the Request Object fetched by `method`.
fn link(client_id: &str, method: &str) -> String {
    format!(
        "openid4vp://?client_id={}&request_uri={REQUEST_URI}{method}",
        client_id.replace(':', "%3A")
    )
}

/// The Request Object of the payload, signed with the leaf in `x5c`.
fn signed_object(payload: &str) -> String {
    compact_jws(&VERIFIER_SECRET, &header(&x5c(&leaf())), payload).expect("signs")
}

/// The URI flows' Authorization Response: `state` as received, the Key Binding JWT's `aud` the
/// full Client Identifier (B.3.6; KA18 for `x509_san_dns:client.example.org`) and the nonce.
fn assert_uri_response(response: &Value, client_id: &str) {
    assert_eq!(response["state"], json!(STATE));
    let payload = key_binding(&response["vp_token"]);
    assert_eq!(payload["aud"], json!(client_id));
    assert_eq!(payload["nonce"], json!(NONCE));
}

/// F5, F6: a link (same device) or a QR code (cross device), `request_uri` by GET, siros-x509's
/// prefixes, `direct_post.jwt`: the core seals, the mode POSTs `response=<JWE>` to the bound
/// Response URI; the Response URI's answer sends the user agent on, or ends the flow (§8.2).
#[test]
fn f5_f6_a_request_by_uri_posts_its_sealed_answer_and_reads_the_response_uris_answer() {
    let registry = registry().expect("the real registry");
    let host = HaipHost::at(Timestamp(NOW));
    let leaf = leaf();
    for client_id in [SAN.to_owned(), x509_hash(&leaf)] {
        let uri = link(&client_id, "");
        let mut body = String::new();
        let received = by_uri(
            &uri,
            &registry,
            &host,
            |fetch| {
                assert!(matches!(fetch, RequestObjectFetch::Get(_)), "U8: a GET");
                signed_object(&uri_payload(&client_id, "direct_post.jwt", ""))
            },
            &mut body,
        );
        let envelope = Envelope::parse(&received, &registry).expect("an envelope");
        let authenticated = authentic(&envelope, &registry, &TestTrust::default(), &host);
        let delivery = delivered(
            &authenticated,
            &[pid()],
            &registry,
            &Published::default(),
            &host,
        );
        assert_uri_response(&sealed_form(&delivery), &client_id);
    }
    // F5 sends the user agent to the answer's redirect_uri (HAIP §5.1); F6's answer holds none,
    // which ends the flow (§8.2).
    let answer = ResponseUriAnswer::parse(
        r#"{"redirect_uri":"https://client.example.org/cb#response_code=091535f699ea575c7937fa5f0f454aee"}"#,
        &registry,
    )
    .expect("F5: the answer");
    assert_eq!(
        answer.redirect().map(|target| target.as_str()),
        Some("https://client.example.org/cb#response_code=091535f699ea575c7937fa5f0f454aee")
    );
    let answer = ResponseUriAnswer::parse("{}", &registry).expect("F6: the answer");
    assert!(answer.redirect().is_none());
}

/// The Request Object a POST of `wallet_metadata` asks for: encrypted to the posted key with the
/// first `enc` the wallet lists when it posts one (§5.10, reading 21), else signed alone.
fn posted_object(fetch: RequestObjectFetch<'_>, payload: &str) -> String {
    let RequestObjectFetch::Post { body, .. } = fetch else {
        panic!("U8: a POST for request_uri_method post")
    };
    let form: Vec<(String, String)> =
        serde_urlencoded::from_str(body.as_str()).expect("the POST's form");
    let metadata: Value = serde_json::from_str(&form[0].1).expect("wallet_metadata");
    let object = signed_object(payload);
    let jwk = Node::parse(&metadata["jwks"]["keys"][0].to_string())
        .expect("the posted key")
        .into_owned();
    let enc = metadata["authorization_encryption_enc_values_supported"][0]
        .as_str()
        .expect("an enc the wallet lists");
    encrypt_to(&jwk, enc, false, object.as_bytes()).expect("encrypts")
}

/// F7: `request_uri_method` `post`: `wallet_metadata` POSTed with a fresh key, the Request Object
/// encrypted to it and decrypted by the host's `RequestDecryption`.
#[test]
fn f7_a_posted_request_uri_answers_by_uri() {
    let registry = registry().expect("the real registry");
    let host = HaipHost::at(Timestamp(NOW));
    let uri = link(SAN, "&request_uri_method=post");
    let mut body = String::new();
    let received = by_uri(
        &uri,
        &registry,
        &host,
        |fetch| posted_object(fetch, &uri_payload(SAN, "direct_post.jwt", "")),
        &mut body,
    );
    let envelope = Envelope::parse(&received, &registry).expect("an envelope");
    let authenticated = authentic(&envelope, &registry, &TestTrust::default(), &host);
    let delivery = delivered(
        &authenticated,
        &[pid()],
        &registry,
        &Published::default(),
        &host,
    );
    assert_uri_response(&sealed_form(&delivery), SAN);
}

/// F8: a URI request refused after authentication: its route's error mode writes the error to
/// the bound Response URI, sealed by the core to the route's key (`direct_post.jwt`), or plain
/// (`direct_post`, which carries errors alone: C5, reading 24).
#[test]
fn f8_a_request_refused_after_authentication_answers_on_its_route() {
    let registry = registry().expect("the real registry");
    let host = HaipHost::at(Timestamp(NOW));
    for mode in ["direct_post.jwt", "direct_post"] {
        // S3: a scope value the wallet registers no query for, beside the PID query.
        let payload = uri_payload(SAN, mode, r#","scope":"org.example.unknown""#);
        let uri = link(SAN, "");
        let mut body = String::new();
        let received = by_uri(
            &uri,
            &registry,
            &host,
            |_| signed_object(&payload),
            &mut body,
        );
        let envelope = Envelope::parse(&received, &registry).expect("an envelope");
        let authenticated = authentic(&envelope, &registry, &TestTrust::default(), &host);
        let refused = match Request::parse(authenticated.envelope()) {
            Err(refused) => refused,
            Ok(request) => match siros_openid4vp::matching::Accepted::new(&request, &registry) {
                Err(refused) => refused,
                Ok(_) => panic!("{mode}: a refused request"),
            },
        };
        let route = Route::new(&authenticated, &registry, &host).expect("a route");
        let Ok(Reply::Deliver(delivery)) = route.refusal(&refused, DcApiErrors::Cancel, &host)
        else {
            panic!("{mode}: an error by URI is delivered")
        };
        let error = match mode {
            "direct_post.jwt" => sealed_form(&delivery),
            _ => {
                let form = posted(&delivery);
                form.into_iter()
                    .map(|(name, value)| (name, Value::String(value)))
                    .collect()
            }
        };
        assert_eq!(error["error"], json!("invalid_scope"), "{mode}: S3's code");
        assert_eq!(error["state"], json!(STATE), "{mode}");
        assert!(error["error_description"].is_string(), "{mode}");
    }
}

/// F9: a URI request refused before authentication: a Framework binding's listed Response URI
/// receives A8's error plain (`Listed`); the Response URI an unauthenticated payload names
/// receives it on the End-User's choice (`Unverified`).
#[test]
fn f9_a_request_refused_before_authentication_replies_plain_on_its_route() {
    let registry = registry().expect("the real registry");
    let host = HaipHost::at(Timestamp(NOW));
    // A8 after the decision listed the Response URI: the signature by another key.
    let payload = uri_payload(SAN, "direct_post.jwt", "");
    let forged = compact_jws(&[7u8; 32], &header(&x5c(&leaf())), &payload).expect("signs");
    let uri = link(SAN, "");
    let mut body = String::new();
    let received = by_uri(&uri, &registry, &host, |_| forged, &mut body);
    let envelope = Envelope::parse(&received, &registry).expect("an envelope");
    let listing = TestTrust {
        endpoints: Some(vec![RESPONSE_URI.to_owned()]),
        ..TestTrust::default()
    };
    let rejected = envelope
        .questions(&registry, &config(), &host)
        .and_then(|pending| {
            pending.authenticate(|evaluation| listing.decide(evaluation), &config(), &host)
        })
        .map(drop)
        .expect_err("A8");
    assert!(matches!(
        rejected.route().map(|route| route.target()),
        Some(ErrorTarget::Listed(_))
    ));
    let Ok(Reply::Deliver(delivery)) = rejected.reply(DcApiErrors::Cancel) else {
        panic!("A8: the plain error to the listed Response URI")
    };
    let form = posted(&delivery);
    let names: Vec<&str> = form.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names, ["error", "error_description", "state"]);
    assert_eq!(form[0].1, "invalid_request_object");
    // U12 (a Request Object's typ): the payload's https response_uri, unverified.
    let wrong_typ =
        compact_jws(&VERIFIER_SECRET, r#"{"alg":"ES256","typ":"JWT"}"#, &payload).expect("signs");
    let fetch = Fetch::of(&uri, &registry, &host).expect("a fetch");
    let received = fetch
        .resume(FetchAnswer::Body(&wrong_typ), &registry, &host)
        .expect("the JWS reads");
    let cause = Envelope::parse(&received, &registry)
        .map(drop)
        .expect_err("U12");
    let rejected = siros_openid4vp::recourse::Rejected::unreadable(&received, cause);
    assert!(matches!(
        rejected.route().map(|route| route.target()),
        Some(ErrorTarget::Unverified(_))
    ));
    let Ok(Reply::Deliver(delivery)) = rejected.reply(DcApiErrors::Cancel) else {
        panic!("U12: the plain error to the unverified Response URI")
    };
    assert_eq!(posted(&delivery)[0].1, "invalid_request_object");
}

/// F10: a link or QR code under the WE BUILD build: `x509_hash`, `verifier_info` to the trust
/// service, which requires its registration certificate, CS-02 §8.2's `exp` and `aud`
/// (siros-webuild's `Cs02Claims`), an encrypted Request Object; the Verifier's error answer read
/// by siros-webuild's `Cs02ErrorAnswer` (CS-02 §8.3).
#[test]
fn f10_a_we_build_request_by_uri_answers_and_reads_the_verifiers_error() {
    let registry = registry_with(|builder| {
        builder.object_rule(siros_webuild::Cs02Claims);
        builder.answer_reader(siros_webuild::Cs02ErrorAnswer);
    });
    let host = HaipHost::at(Timestamp(NOW));
    let client_id = x509_hash(&leaf());
    let payload = uri_payload(
        &client_id,
        "direct_post.jwt",
        &format!(
            r#","exp":{},"aud":"https://self-issued.me/v2","verifier_info":[{{"format":"registration_cert","data":"eyJ0eXAiOiJyYy13cnArand0In0.e30.c2ln"}}]"#,
            NOW + 300
        ),
    );
    let uri = link(&client_id, "&request_uri_method=post");
    let mut body = String::new();
    let received = by_uri(
        &uri,
        &registry,
        &host,
        |fetch| posted_object(fetch, &payload),
        &mut body,
    );
    let envelope = Envelope::parse(&received, &registry).expect("an envelope");
    let trust = TestTrust {
        registration: Registration::Required,
        ..TestTrust::default()
    };
    let authenticated = authentic(&envelope, &registry, &trust, &host);
    let delivery = delivered(
        &authenticated,
        &[pid()],
        &registry,
        &Published::default(),
        &host,
    );
    assert_uri_response(&sealed_form(&delivery), &client_id);
    let answer = ResponseUriAnswer::parse(
        r#"{"error":"invalid_request","error_description":"the presentation is expired","redirect_uri":"https://client.example.org/failed"}"#,
        &registry,
    )
    .expect("CS-02 §8.3: the error answer");
    assert_eq!(answer.outcomes().len(), 1, "the Verifier's error, shown");
    assert!(answer.redirect().is_some());
}

/// F11, F12: an SCA transaction under the WE BUILD build, by URI (`direct_post.jwt`) and over the
/// DC API (signed, `dc_api.jwt`): PaSO Core A.1's payment, strongly authenticated (PSD2 Art.
/// 4(30): factors of two categories), its Key Binding JWT holding the transaction's hash (PaSO
/// Core §6.1), its `aud` the full Client Identifier by URI and the Origin over the DC API
/// (B.3.6), and the request's nonce.
#[test]
fn f11_f12_an_sca_payment_answers_by_uri_and_over_the_dc_api() {
    let registry = registry().expect("the real registry");
    let host = super::authenticated_as_a2();
    let core = super::annex("paso-core.md", "A.1");
    let entry = siros_testkit::verifier::encode(&core[1]).expect("Core A.1's entry");
    let dcql = super::member(&core[0], "dcql_query");
    let document = siros_testkit::verifier::paso_document(
        "https://bank.example/sca/card",
        "dc+sd-jwt",
        &super::payment_metadata(),
        None,
        siros_testkit::verifier::ISSUER,
    )
    .expect("the card's PaSO document");
    let mut card = Held::new(
        "card",
        "dc+sd-jwt",
        r#"{"type": "https://bank.example/sca/card", "metadata": {}, "values": {"pan_last_four": "1234", "scheme": "visa"},
            "alg": "ES256", "curve": "P-256", "key_alg": "ES256", "key_curve": "P-256"}"#,
    );
    card = card.with_issued().expect("the issued SD-JWT");
    card.documents
        .push(("paso".to_owned(), document.into_bytes()));
    let held = [card];
    let hashed = json!(URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(entry.as_bytes())));
    let binding = |vp_token: &Value, aud: &str| {
        let payload = read_sd_jwt(&vp_token["sca_card"][0])["kb_jwt"]["payload"].clone();
        assert_eq!(payload["aud"], json!(aud));
        assert_eq!(payload["nonce"], json!(NONCE));
        payload["transaction_data_hash"].clone()
    };
    let body_of = |mode: &str, extra: &str| {
        format!(
            r#"{{"response_type":"vp_token","response_mode":"{mode}","nonce":"{NONCE}","client_metadata":{{"jwks":{{"keys":[{B26_KEY}]}}}},"dcql_query":{dcql},"transaction_data":["{entry}"]{extra}}}"#
        )
    };
    // F11 by URI.
    let payload = body_of(
        "direct_post.jwt",
        &format!(r#","client_id":"{SAN}","response_uri":"{RESPONSE_URI}","state":"{STATE}""#),
    );
    let uri = link(SAN, "");
    let mut body = String::new();
    let received = by_uri(
        &uri,
        &registry,
        &host,
        |_| signed_object(&payload),
        &mut body,
    );
    let envelope = Envelope::parse(&received, &registry).expect("an envelope");
    let authenticated = authentic(&envelope, &registry, &TestTrust::default(), &host);
    let delivery = delivered(
        &authenticated,
        &held,
        &registry,
        &Published::default(),
        &host,
    );
    let response = sealed_form(&delivery);
    assert_eq!(response["state"], json!(STATE));
    assert_eq!(binding(&response["vp_token"], SAN), hashed);
    // A PIN alone covers one category: the payment's Strong need refuses it.
    let mut weak = super::authenticated_as_a2();
    weak.platform.authentication = Some(Authentication::new(
        Timestamp(NOW - 5),
        AllOf::one(Factor::Knowledge(Knowledge::Pin(NonZeroU32::new(6)))),
    ));
    match responded(
        &authenticated,
        &held,
        &registry,
        &Published::default(),
        &weak,
    ) {
        Err(Outcome::AuthenticationTooWeak { need, .. }) => {
            assert_eq!(need, AuthenticationNeed::Strong);
        }
        other => panic!("a PIN alone: {other:?}"),
    }
    // F12 over the DC API, signed, dc_api.jwt.
    let payload = body_of(
        "dc_api.jwt",
        &format!(r#","client_id":"{SAN}","expected_origins":["{ORIGIN}"]"#),
    );
    let jws = signed_object(&payload);
    let data = format!(r#"{{"request":"{jws}"}}"#);
    let received = dc_api("openid4vp-v1-signed", &data);
    let envelope = Envelope::parse(&received, &registry).expect("an envelope");
    let authenticated = authentic(&envelope, &registry, &TestTrust::default(), &host);
    let delivery = delivered(
        &authenticated,
        &held,
        &registry,
        &Published::default(),
        &host,
    );
    let response = opened(
        dc_api_data(&delivery)["response"]
            .as_str()
            .expect("response"),
    )
    .1;
    assert_eq!(
        binding(&response["vp_token"], &format!("origin:{ORIGIN}")),
        hashed
    );
}

/// F13: an extension's mode by URI (siros-testkit's `TestMode`), registered for answers and for
/// errors: the core seals to the key it chose among the Verifier's, checked, and its body goes
/// to the bound Response URI.
#[test]
fn f13_an_extension_mode_answers_by_uri_through_the_core() {
    const NAME: ModeName = siros_explain::checked!(ModeName, "post.test");
    let mode = TestMode {
        choice: TestChoice::Key {
            place: 0,
            enc: siros_openid4vp::request::ContentEncryption::A128GCM,
        },
        ..TestMode::new(NAME, ChannelKind::Uri)
    };
    let registry = registry_with(|builder| {
        builder.jwe_mode(mode.clone());
        builder.error_mode(mode);
    });
    let host = HaipHost::at(Timestamp(NOW));
    let uri = link(SAN, "");
    let mut body = String::new();
    let received = by_uri(
        &uri,
        &registry,
        &host,
        |_| signed_object(&uri_payload(SAN, "post.test", "")),
        &mut body,
    );
    let envelope = Envelope::parse(&received, &registry).expect("an envelope");
    let authenticated = authentic(&envelope, &registry, &TestTrust::default(), &host);
    let delivery = delivered(
        &authenticated,
        &[pid()],
        &registry,
        &Published::default(),
        &host,
    );
    assert_uri_response(&sealed_form(&delivery), SAN);
}
