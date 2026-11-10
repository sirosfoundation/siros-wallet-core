//! I19: the WE BUILD build (section 4.10.4) over F11 and F12: a POST of `wallet_metadata`, a JWE
//! Request Object encrypted with the first values of its `authorization_encryption_*` lists
//! (reading 21), `verifier_info` to the trust service, CS-12 §8.1's payment, the Key Binding JWT's
//! TS12 claims (TS12 §3.6) and the Verifier's error read by `Cs02ErrorAnswer` (CS-02 §8.3). The HAIP
//! build's path is `flows`' F5. Beside them, CS-12 §7.3 item 7's one SCA attestation per request
//! and phase 2's https logo (PaSO View §3).

use std::num::NonZeroU32;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use siros_openid4vp::arrival::{DcApiProtocols, Received};
use siros_openid4vp::authenticate::Unauthenticated;
use siros_openid4vp::envelope::Envelope;
use siros_openid4vp::host::{
    AttackDetection, Authentication, AuthenticationNeed, Factor, FalseAcceptRate, Inherence,
    Isolation, Knowledge, Modality, Possession, Sensor, Timestamp,
};
use siros_openid4vp::ids::Origin;
use siros_openid4vp::json::Node;
use siros_openid4vp::matching::{Accepted, ExcludedBy, Match, ReservedCredential};
use siros_openid4vp::media::MediaType;
use siros_openid4vp::plugins::Registry;
use siros_openid4vp::recourse::Failure;
use siros_openid4vp::request::Request;
use siros_openid4vp::resolve::{Delivery, Finding, Outcome};
use siros_openid4vp::rows::HttpsUrl;
use siros_openid4vp::uri::{Fetch, FetchAnswer, RequestObjectFetch, ResponseUriAnswer};
use siros_openid4vp::wallet::Wallet;
use siros_paso::image::ImageFailure;
use siros_syntax::{AllOf, Keyed};
use siros_testkit::fixtures::{B26_KEY, Held};
use siros_testkit::jose::{VERIFIER_SECRET, Zip, compact_jws, encrypt_to};
use siros_testkit::prefix::Registration;
use siros_testkit::x509::{header, x5c, x509_hash};
use siros_testkit::{Published, PublishedResource, TestPlatform, TestTrust};
use siros_ts12::{Ts12Document, Ts12Finding};
use siros_webuild::VerifierError;

use crate::common::{WeBuildHost, own_modules, sri, we_build_app, we_build_registry};

use super::flows::{
    NONCE, ORIGIN, RESPONSE_URI, STATE, authentic, built_by, by_uri, config, dc_api_data, leaf,
    link, sealed_form,
};
use super::{AMOUNTS, NOW, english, read_sd_jwt};

/// CS-12 §8.1's DCQL query for an `sca-iban` presentation.
const DCQL: &str = r#"{"credentials":[{"id":"sca_iban","format":"dc+sd-jwt","meta":{"vct_values":["https://webuildconsortium.eu/sca/sca-iban/1.0"]}}]}"#;

/// CS-12 §8.1's payment; `transaction_data_hashes_alg` as B.3.3.1's array (reading 27).
const PAYMENT: &str = r#"{"type":"urn:eudi:sca:payment:1","credential_ids":["sca_iban"],"transaction_data_hashes_alg":["sha-256"],"payload":{"transaction_id":"9c3b1e2a-6f21-4e2a-9a71-2b7e6a5d1234","payee":{"name":"Example Merchant B.V.","id":"NL-KVK-12345678"},"currency":"EUR","amount":129.95}}"#;

/// CS-13 §7.2's `verifier_info`, which section 4.10.4's trust service requires.
const VERIFIER_INFO: &str = r#","verifier_info":[{"format":"registration_cert","data":"eyJ0eXAiOiJyYy13cnArand0In0.e30.c2ln"}]"#;

/// The host at `NOW`, the End-User's authentication factors of three categories.
fn host() -> WeBuildHost {
    let mut host = WeBuildHost {
        platform: TestPlatform::at(Timestamp(NOW)),
        paso: siros_paso::TestPaso::at(Timestamp(NOW)),
        ..WeBuildHost::default()
    };
    host.platform.authentication = Some(Authentication::new(
        Timestamp(NOW - 5),
        AllOf::one(Factor::Knowledge(Knowledge::Pin(NonZeroU32::new(6))))
            .and(AllOf::one(Factor::Possession(Possession::LocalNativeWscd)))
            .and(AllOf::one(Factor::Inherence(Inherence {
                modality: Modality::Face,
                sensor: Sensor::Device,
                isolation: Isolation::Hardware,
                false_accepts: NonZeroU32::new(50_000).map(FalseAcceptRate::one_in),
                attack_detection: AttackDetection::Present,
            }))),
    ));
    host
}

/// CS-12 §7.2's metadata of the wallet's attestation.
const METADATA: &str = include_str!("../../../siros-ts12/tests/data/cs12-sca-iban.json");

/// The wallet's SCA attestation: a bank's type extending WE BUILD's `sca-iban` (CS-12 §7.2), its
/// registration document composed from that metadata.
fn held_under(metadata: &str) -> Held {
    let own = Node::parse(metadata).expect("the metadata");
    let document = Ts12Document::compose(&own, &Keyed::empty()).expect("composes");
    let mut card = Held::new(
        "card",
        "dc+sd-jwt",
        r#"{"extends": ["https://webuildconsortium.eu/sca/sca-iban/1.0"], "type": "https://issuer.bank.example/credentials/sca/iban/1.0", "metadata": {}, "values": {"iban": "NL91ABNA0417164300"}, "alg": "ES256", "curve": "P-256", "key_alg": "ES256", "key_curve": "P-256"}"#,
    )
    .with_issued()
    .expect("the issued SD-JWT");
    card.documents.push((
        siros_ts12::DOCUMENT.as_str().to_owned(),
        document.content().as_bytes().to_vec(),
    ));
    card
}

fn held() -> Held {
    held_under(METADATA)
}

fn payload_of(client_id: &str, mode: &str, extra: &str) -> String {
    payload_over(PAYMENT, client_id, mode, extra)
}

fn payload_over(payment: &str, client_id: &str, mode: &str, extra: &str) -> String {
    let entry = siros_testkit::verifier::encode(payment).expect("the entry");
    format!(
        r#"{{"client_id":"{client_id}","response_type":"vp_token","response_mode":"{mode}","nonce":"{NONCE}","client_metadata":{{"jwks":{{"keys":[{B26_KEY}]}}}},"dcql_query":{DCQL},"transaction_data":["{entry}"],"exp":{exp},"aud":"https://self-issued.me/v2"{extra}}}"#,
        exp = NOW + 300,
    )
}

/// F11's Request Object: `verifier_info` for the trust service and the Response URI.
fn uri_payload(client_id: &str) -> String {
    payload_of(
        client_id,
        "direct_post.jwt",
        &format!(r#","response_uri":"{RESPONSE_URI}","state":"{STATE}"{VERIFIER_INFO}"#),
    )
}

/// A signed DC API Request Object's payload: `verifier_info` and the Origin.
fn dc_api_payload(payment: &str, client_id: &str) -> String {
    payload_over(
        payment,
        client_id,
        "dc_api.jwt",
        &format!(r#","expected_origins":["{ORIGIN}"]{VERIFIER_INFO}"#),
    )
}

/// The trust service section 4.10.4 requires: it refuses a request without `verifier_info`.
fn requiring_registration() -> TestTrust {
    TestTrust {
        registration: Registration::Required,
        ..TestTrust::default()
    }
}

fn signed(payload: &str) -> String {
    compact_jws(
        &VERIFIER_SECRET,
        &header(&x5c(&leaf()).expect("the chain")),
        payload,
    )
    .expect("signs")
}

/// Answers a POST with the Request Object as a JWE under the first values of the wallet's lists.
fn encrypted_with_first_values(fetch: RequestObjectFetch<'_>, payload: &str) -> String {
    let RequestObjectFetch::Post { body, .. } = fetch else {
        panic!("U8: a POST for request_uri_method post")
    };
    let form: Vec<(String, String)> =
        serde_urlencoded::from_str(body.as_str()).expect("the POST's form");
    let metadata: Value = serde_json::from_str(&form[0].1).expect("wallet_metadata");
    assert_eq!(
        metadata["authorization_encryption_alg_values_supported"][0],
        json!("ECDH-ES"),
        "reading 21: the first alg of the posted list"
    );
    let enc = metadata["authorization_encryption_enc_values_supported"][0]
        .as_str()
        .expect("an enc the wallet lists");
    let jwk = Node::parse(&metadata["jwks"]["keys"][0].to_string())
        .expect("the posted key")
        .into_owned();
    encrypt_to(&jwk, enc, Zip::None, signed(payload).as_bytes()).expect("encrypts")
}

/// What phase 2 answers for the attestation.
fn responded(
    authenticated: &siros_openid4vp::authenticate::Authenticated<'_>,
    registry: &Registry<WeBuildHost>,
    host: &WeBuildHost,
) -> Result<Delivery, Outcome> {
    answered_from(
        authenticated,
        &held(),
        &Published::default(),
        registry,
        host,
    )
}

/// What phase 2 answers for an attestation, its fetches answered from `published`.
fn answered_from(
    authenticated: &siros_openid4vp::authenticate::Authenticated<'_>,
    card: &Held,
    published: &Published,
    registry: &Registry<WeBuildHost>,
    host: &WeBuildHost,
) -> Result<Delivery, Outcome> {
    built_by(
        authenticated,
        std::slice::from_ref(card),
        registry,
        published,
        host,
        |wallet, _, env| we_build_app(wallet, env, AMOUNTS),
        |built| built.delivery().clone(),
    )
}

/// Phase 1 over a signed request of the attestation: `read` takes what the matcher found.
fn matched_by<T>(
    payload: &str,
    card: &Held,
    registry: &Registry<WeBuildHost>,
    host: &WeBuildHost,
    read: impl FnOnce(&Match<'_>, &Request<'_>) -> T,
) -> T {
    let data = format!(r#"{{"request":"{}"}}"#, signed(payload));
    let received = dc_api_received(&data);
    let envelope = Envelope::parse(&received, registry).expect("an envelope");
    let authenticated = authentic(&envelope, registry, &requiring_registration(), host);
    let credential = card.credential().expect("a credential");
    let wallet = Wallet::new(vec![credential]).expect("a wallet");
    let env = english();
    let request = Request::parse(authenticated.envelope()).expect("the request");
    let context = we_build_app(&wallet, &env, AMOUNTS);
    let accepted = Accepted::new(&request, registry).expect("accepted");
    let matched = Match::run(&accepted, &wallet, &env, &context).expect("phase 1");
    read(&matched, &request)
}

/// The signed DC API request as the build's protocols receive it.
fn dc_api_received(data: &str) -> Received<'_> {
    Received::dc_api(
        "openid4vp-v1-signed",
        data,
        Origin::parse(ORIGIN).expect("the Origin"),
        &DcApiProtocols::SIGNED,
    )
    .expect("the signed protocol arrives")
}

/// TS12 §3.6's claims: `jti` a version 4 UUID (RFC 9562 §5.4), `response_mode` as the request names
/// it, `amr` one object per factor in the order applied, the entry's SHA-256 as received (B.3.3.1).
fn assert_ts12_claims(vp_token: &Value, mode: &str, aud: &str) {
    let payload = read_sd_jwt(&vp_token["sca_iban"][0])["kb_jwt"]["payload"].clone();
    let entry = siros_testkit::verifier::encode(PAYMENT).expect("the entry");
    assert_eq!(payload["aud"], json!(aud));
    assert_eq!(payload["nonce"], json!(NONCE));
    assert_eq!(payload["response_mode"], json!(mode));
    assert_eq!(
        payload["amr"],
        json!([
            {"knowledge": "pin_6_or_more_digits"},
            {"possession": "key_in_local_native_wscd"},
            {"inherence": "face_device"}
        ])
    );
    assert_eq!(
        payload["transaction_data_hashes"],
        json!([URL_SAFE_NO_PAD.encode(Sha256::digest(entry.as_bytes()))])
    );
    assert_eq!(payload["transaction_data_hashes_alg"], json!("sha-256"));
    let jti = payload["jti"].as_str().expect("a jti");
    assert_eq!(
        (jti.len(), jti.as_bytes()[14], jti.as_bytes()[8]),
        (36, b'4', b'-'),
        "{jti}"
    );
}

#[test]
fn f11_a_ts12_payment_answers_by_uri_under_the_we_build_build() {
    let registry = we_build_registry().expect("the WE BUILD build");
    let host = host();
    let client_id = x509_hash(&leaf());
    let payload = uri_payload(&client_id);
    let uri = link(&client_id, "&request_uri_method=post");
    let mut body = String::new();
    let received = by_uri(
        &uri,
        &registry,
        &host,
        |fetch| encrypted_with_first_values(fetch, &payload),
        &mut body,
    );
    let envelope = Envelope::parse(&received, &registry).expect("an envelope");
    let authenticated = authentic(&envelope, &registry, &requiring_registration(), &host);
    let delivery = responded(&authenticated, &registry, &host).expect("phase 2");
    let response = sealed_form(&delivery);
    assert_eq!(response["state"], json!(STATE));
    assert_ts12_claims(&response["vp_token"], "direct_post.jwt", &client_id);

    // CS-02 §8.3: the Verifier's error answer.
    let answer = ResponseUriAnswer::parse(
        r#"{"error":"invalid_request","error_description":"the presentation is expired"}"#,
        &registry,
    )
    .expect("the error answer");
    let [outcome] = answer.outcomes() else {
        panic!("one outcome: the Verifier's error")
    };
    let error = (outcome.as_ref() as &dyn std::error::Error)
        .downcast_ref::<VerifierError>()
        .expect("the Verifier's error");
    assert_eq!(
        (
            error.code().as_str(),
            error.description().map(|description| description.as_str())
        ),
        ("invalid_request", Some("the presentation is expired"))
    );

    // TS12 §3.6: `amr` holds two categories; one factor is too weak.
    let mut weak = host.clone();
    weak.platform.authentication = Some(Authentication::new(
        Timestamp(NOW - 5),
        AllOf::one(Factor::Knowledge(Knowledge::Pin(NonZeroU32::new(6)))),
    ));
    match responded(&authenticated, &registry, &weak) {
        Err(Outcome::AuthenticationTooWeak { need, .. }) => {
            assert_eq!(need, AuthenticationNeed::Strong);
        }
        other => panic!("a PIN alone: {other:?}"),
    }
}

#[test]
fn f12_a_ts12_payment_answers_over_the_dc_api_under_the_we_build_build() {
    let registry = we_build_registry().expect("the WE BUILD build");
    let host = host();
    let client_id = x509_hash(&leaf());
    let payload = dc_api_payload(PAYMENT, &client_id);
    let data = format!(r#"{{"request":"{}"}}"#, signed(&payload));
    let received = dc_api_received(&data);
    let envelope = Envelope::parse(&received, &registry).expect("an envelope");
    let authenticated = authentic(&envelope, &registry, &requiring_registration(), &host);
    let delivery = responded(&authenticated, &registry, &host).expect("phase 2");
    let sealed = dc_api_data(&delivery);
    let (_, response) = super::flows::opened(sealed["response"].as_str().expect("the JWE"));
    assert_ts12_claims(
        &response["vp_token"],
        "dc_api.jwt",
        &format!("origin:{ORIGIN}"),
    );
}

/// CS-12 §7.3 item 7; rb-sca-iban §9: an SCA attestation answers only the query a TS12 entry names.
#[test]
fn an_sca_attestation_answers_only_the_query_its_transaction_names() {
    let registry = we_build_registry().expect("the WE BUILD build");
    let host = host();
    let client_id = x509_hash(&leaf());
    let two_queries = r#"{"credentials":[{"id":"sca_iban","format":"dc+sd-jwt","meta":{"vct_values":["https://webuildconsortium.eu/sca/sca-iban/1.0"]}},{"id":"other","format":"dc+sd-jwt","meta":{"vct_values":["https://webuildconsortium.eu/sca/sca-iban/1.0"]}}]}"#;
    let payload = dc_api_payload(PAYMENT, &client_id).replace(DCQL, two_queries);
    matched_by(&payload, &held(), &registry, &host, |matched, request| {
        let of = |id: &str| {
            let query = request
                .indexed_queries()
                .find(|(_, query)| query.id().as_str() == id)
                .expect("the query")
                .0;
            matched
                .candidates(query)
                .iter()
                .map(|candidate| candidate.credential.id.to_string())
                .collect::<Vec<_>>()
        };
        assert_eq!(of("sca_iban"), ["card"]);
        assert!(of("other").is_empty());
        let [excluded] = matched.excluded() else {
            panic!("one exclusion: {:?}", matched.excluded())
        };
        assert_eq!(excluded.by, ExcludedBy::Profile);
        assert!(
            (excluded.exclude.rule() as &dyn std::error::Error)
                .downcast_ref::<ReservedCredential>()
                .is_some()
        );
    });
}

/// PaSO View §3 through TS12's `payee.logo`: phase 2 fetches a displayed https logo, whose content
/// must meet its `payee.logo#integrity`; a logo failing it falls back, and the profile informed of
/// it offers the credential no more. A 1x1 PNG (ISO/IEC 15948).
#[test]
fn a_displayed_https_logo_meets_its_integrity_in_phase_2() {
    const URL: &str = "https://payee.example/logo.png";
    let logo = STANDARD
        .decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==")
        .expect("base64");
    let registry = we_build_registry().expect("the WE BUILD build");
    let host = host();
    let client_id = x509_hash(&leaf());
    let payment = PAYMENT.replace(
        r#""id":"NL-KVK-12345678""#,
        &format!(
            r#""id":"NL-KVK-12345678","logo":"{URL}","logo#integrity":"{}""#,
            sri(&logo)
        ),
    );
    let metadata = METADATA.replacen(
        r#""claims": ["#,
        r#""claims": [{"path": ["payload", "payee", "logo"], "display": [{"lang": "en", "label": "Logo"}]},"#,
        1,
    );
    let card = held_under(&metadata);
    let payload = dc_api_payload(&payment, &client_id);
    let data = format!(r#"{{"request":"{}"}}"#, signed(&payload));
    let received = dc_api_received(&data);
    let envelope = Envelope::parse(&received, &registry).expect("an envelope");
    let authenticated = authentic(&envelope, &registry, &requiring_registration(), &host);
    let serving = |content: Vec<u8>| {
        Published::new(vec![PublishedResource {
            url: HttpsUrl::parse(URL).expect("the URL"),
            content,
            media: MediaType::parse("image/png").expect("the media type"),
        }])
    };
    assert!(
        answered_from(
            &authenticated,
            &card,
            &serving(logo.clone()),
            &registry,
            &host
        )
        .is_ok()
    );
    let mut other = logo;
    other.push(0);
    let answer = answered_from(&authenticated, &card, &serving(other), &registry, &host);
    let Err(Outcome::Fallback(findings)) = answer else {
        panic!("phase 2 falls back: {answer:?}")
    };
    let [Finding::Revalidation { finding, .. }] = findings.items() else {
        panic!("{findings:?}")
    };
    let failed = finding.data::<Ts12Finding>().expect("TS12's finding");
    assert_eq!(
        (failed.url.ascii(), &failed.failure),
        (URL, &ImageFailure::IntegrityMismatch)
    );
    let informed = registry.informed(&[finding]).expect("informed");
    matched_by(&payload, &card, &informed, &host, |matched, request| {
        let (query, _) = request.indexed_queries().next().expect("the query");
        assert!(matched.candidates(query).is_empty());
    });
}

/// View §3: phase 2 fetches a displayed logo alone, so a logo at TS12 §3.3.1's level 4 sends nothing
/// to the payee's host; here its host answers nothing.
#[test]
fn a_hidden_https_logo_is_not_fetched() {
    let registry = we_build_registry().expect("the WE BUILD build");
    let host = host();
    let client_id = x509_hash(&leaf());
    let payment = PAYMENT.replace(
        r#""id":"NL-KVK-12345678""#,
        r#""id":"NL-KVK-12345678","logo":"https://payee.example/logo.png","logo#integrity":"sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=""#,
    );
    let card = held_under(&METADATA.replacen(
        r#""claims": ["#,
        r#""claims": [{"path": ["payload", "payee", "logo"], "visualisation": 4},"#,
        1,
    ));
    let payload = dc_api_payload(&payment, &client_id);
    let data = format!(r#"{{"request":"{}"}}"#, signed(&payload));
    let received = dc_api_received(&data);
    let envelope = Envelope::parse(&received, &registry).expect("an envelope");
    let authenticated = authentic(&envelope, &registry, &requiring_registration(), &host);
    let answer = answered_from(
        &authenticated,
        &card,
        &Published::default(),
        &registry,
        &host,
    );
    assert!(answer.is_ok(), "{answer:?}");
}

/// Section 8.2's tamper: a TS12 entry altered after the Request Object was signed fails A8.
#[test]
fn a_ts12_entry_altered_after_signing_fails_the_signature() {
    let registry = we_build_registry().expect("the WE BUILD build");
    let host = host();
    let client_id = x509_hash(&leaf());
    let payload = uri_payload(&client_id);
    let jws = signed(&payload);
    let parts: Vec<&str> = jws.split('.').collect();
    let [protected, _, signature] = parts.as_slice() else {
        panic!("a compact JWS")
    };
    let entry = siros_testkit::verifier::encode(PAYMENT).expect("the entry");
    let altered = siros_testkit::verifier::encode(&PAYMENT.replace("129.95", "12995"))
        .expect("the altered entry");
    let tampered = format!(
        "{protected}.{}.{signature}",
        URL_SAFE_NO_PAD.encode(payload.replace(&entry, &altered))
    );
    let uri = link(&client_id, "");
    let fetch = Fetch::of(&uri, &registry, &host).expect("a fetch");
    let received = fetch
        .resume(FetchAnswer::Body(&tampered), &registry, &host)
        .unwrap_or_else(|rejected| panic!("the Request Object reads: {:?}", rejected.failure()));
    let envelope = Envelope::parse(&received, &registry).expect("an envelope");
    let refused = envelope
        .questions(&registry, &config(), &host)
        .and_then(|pending| {
            pending.authenticate(
                |evaluation| TestTrust::default().decide(evaluation),
                &config(),
                own_modules(&english(), AMOUNTS),
                &host,
            )
        })
        .err()
        .expect("the altered entry is refused");
    assert!(
        matches!(
            refused.failure(),
            Failure::Unauthenticated(Unauthenticated::Signature)
        ),
        "A8: {:?}",
        refused.failure()
    );
}
