//! I19: the WE BUILD build (section 4.10.4) over F11 and F12: a POST of `wallet_metadata`, a JWE
//! Request Object encrypted with the first values of its `authorization_encryption_*` lists
//! (reading 21), `verifier_info` to the trust service, CS-12 §8.1's payment, the Key Binding JWT's
//! TS12 claims (TS12 §3.6) and the Verifier's error read by `Cs02ErrorAnswer` (CS-02 §8.3). The HAIP
//! build's path is `flows`' F5.

use std::num::NonZeroU32;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use siros_explain::AllOf;
use siros_openid4vp::arrival::{DcApiProtocols, Received};
use siros_openid4vp::authenticate::Unauthenticated;
use siros_openid4vp::envelope::Envelope;
use siros_openid4vp::host::{
    AttackDetection, Authentication, AuthenticationNeed, Factor, FalseAcceptRate, Inherence,
    Isolation, Knowledge, Modality, Possession, Sensor, Timestamp,
};
use siros_openid4vp::ids::Origin;
use siros_openid4vp::json::Node;
use siros_openid4vp::plugins::Registry;
use siros_openid4vp::recourse::Failure;
use siros_openid4vp::resolve::{Delivery, Outcome};
use siros_openid4vp::uri::{Fetch, FetchAnswer, RequestObjectFetch, ResponseUriAnswer};
use siros_testkit::fixtures::{B26_KEY, Held};
use siros_testkit::jose::{VERIFIER_SECRET, Zip, compact_jws, encrypt_to};
use siros_testkit::prefix::Registration;
use siros_testkit::{Published, TestPlatform, TestTrust};
use siros_ts12::Ts12Document;
use siros_x509::test_util::{header, x5c, x509_hash};

use crate::common::{WeBuildHost, we_build_app, we_build_registry};

use super::flows::{
    NONCE, ORIGIN, RESPONSE_URI, STATE, authentic, built_by, by_uri, config, dc_api_data, leaf,
    link, sealed_form,
};
use super::{NOW, read_sd_jwt};

/// CS-12 §8.1's DCQL query for an `sca-iban` presentation.
const DCQL: &str = r#"{"credentials":[{"id":"sca_iban","format":"dc+sd-jwt","meta":{"vct_values":["https://webuildconsortium.eu/sca/sca-iban/1.0"]}}]}"#;

/// CS-12 §8.1's payment; `transaction_data_hashes_alg` as B.3.3.1's array (reading 27).
const PAYMENT: &str = r#"{"type":"urn:eudi:sca:payment:1","credential_ids":["sca_iban"],"transaction_data_hashes_alg":["sha-256"],"payload":{"transaction_id":"9c3b1e2a-6f21-4e2a-9a71-2b7e6a5d1234","payee":{"name":"Example Merchant B.V.","id":"NL-KVK-12345678"},"currency":"EUR","amount":129.95}}"#;

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

/// The wallet's SCA attestation: a bank's type extending WE BUILD's `sca-iban` (CS-12 §7.2), its
/// registration document composed from that metadata.
fn held() -> Held {
    let metadata = include_str!("../../../siros-ts12/tests/data/cs12-sca-iban.json");
    let own = Node::parse(metadata).expect("CS-12's metadata");
    let document = Ts12Document::compose(&own, &siros_explain::Keyed::empty()).expect("composes");
    let mut card = Held::new(
        "card",
        "dc+sd-jwt",
        r#"{"extends": ["https://webuildconsortium.eu/sca/sca-iban/1.0"], "type": "https://issuer.bank.example/credentials/sca/iban/1.0", "metadata": {}, "values": {"iban": "NL91ABNA0417164300"}, "alg": "ES256", "curve": "P-256", "key_alg": "ES256", "key_curve": "P-256"}"#,
    )
    .with_issued()
    .expect("the issued SD-JWT");
    card.documents
        .push((siros_ts12::DOCUMENT.to_owned(), document));
    card
}

fn payload_of(client_id: &str, mode: &str, extra: &str) -> String {
    let entry = siros_testkit::verifier::encode(PAYMENT).expect("the entry");
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
        &format!(
            r#","response_uri":"{RESPONSE_URI}","state":"{STATE}","verifier_info":[{{"format":"registration_cert","data":"eyJ0eXAiOiJyYy13cnArand0In0.e30.c2ln"}}]"#
        ),
    )
}

fn signed(payload: &str) -> String {
    compact_jws(&VERIFIER_SECRET, &header(&x5c(&leaf())), payload).expect("signs")
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
    built_by(
        authenticated,
        &[held()],
        registry,
        &Published::default(),
        host,
        |wallet, _, env| we_build_app(wallet, env),
        |built| built.delivery().clone(),
    )
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
    let trust = TestTrust {
        registration: Registration::Required,
        ..TestTrust::default()
    };
    let authenticated = authentic(&envelope, &registry, &trust, &host);
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
    assert_eq!(answer.outcomes().len(), 1, "the Verifier's error, shown");

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
    let payload = payload_of(
        &client_id,
        "dc_api.jwt",
        &format!(r#","expected_origins":["{ORIGIN}"]"#),
    );
    let data = format!(r#"{{"request":"{}"}}"#, signed(&payload));
    let received = Received::dc_api(
        "openid4vp-v1-signed",
        &data,
        Origin::parse(ORIGIN).expect("the Origin"),
        &DcApiProtocols::SIGNED,
    )
    .expect("the signed protocol arrives");
    let envelope = Envelope::parse(&received, &registry).expect("an envelope");
    let authenticated = authentic(&envelope, &registry, &TestTrust::default(), &host);
    let delivery = responded(&authenticated, &registry, &host).expect("phase 2");
    let sealed = dc_api_data(&delivery);
    let (_, response) = super::flows::opened(sealed["response"].as_str().expect("the JWE"));
    assert_ts12_claims(
        &response["vp_token"],
        "dc_api.jwt",
        &format!("origin:{ORIGIN}"),
    );
    // CS-07 WU-DC-01: the build refuses the unsigned protocol.
    assert!(
        Received::dc_api(
            "openid4vp-v1-unsigned",
            "{}",
            Origin::parse(ORIGIN).expect("the Origin"),
            &DcApiProtocols::SIGNED,
        )
        .is_err()
    );
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
