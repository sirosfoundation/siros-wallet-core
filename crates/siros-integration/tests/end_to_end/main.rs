//! One path per configuration and one per flow of the design (`flows`) through the core with
//! every real plug-in, each built from a specification's own example: the request parsed,
//! matched, offered, its first selection shown and answered. Each expected value is the specification's text, or a value it defines computed
//! here from the example's bytes.

#[path = "../common/mod.rs"]
mod common;
mod csc;
mod flows;

use crate::common::HaipHost;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use siros_openid4vp::consent::{ConsentEntry, Header};
use std::num::NonZeroU32;

use siros_explain::{AllOf, Text};
use siros_openid4vp::host::{
    AttackDetection, Authentication, Factor, FalseAcceptRate, Inherence, Isolation, Knowledge,
    Modality, Possession, Sensor, Timestamp,
};
use siros_openid4vp::ids::LocaleTag;
use siros_openid4vp::json::Node;
use siros_openid4vp::matching::{Accepted, Consent, Match, Views, display, offer};
use siros_openid4vp::request::Request;
use siros_openid4vp::resolve::{Delivery, Prepared};
use siros_openid4vp::rows::{Amounts, Choice, Env, RenderOptions};
use siros_openid4vp::wallet::Wallet;
use siros_testkit::Published;
use siros_testkit::fixtures::{Held, NONCE, OPTIONS, ORIGIN, parameters};
use siros_testkit::reading::model_shape;
use siros_testkit::verifier::{self, ISSUER};

use common::{paso_app, registry, sri};

const PAY: &str = "urn:paso:sca:global:payment:1";
const RESPONSE_MODE: &str = "urn:paso:risk:global:response_mode:1";
const AMR: &str = "urn:paso:risk:global:amr:1";
const NOW: u64 = 1_785_000_000;

/// A PaSO Annex section, from its heading to the next, as the specification file writes it.
fn annex_section(file: &str, section: &str) -> String {
    let path = format!(
        "{}/../siros-paso/tests/data/paso-d2/{file}",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(path).expect("the specification file");
    let start = text.find(&format!("### {section} ")).expect("the section");
    let body = &text[start + 4..];
    body[..body.find("\n### ").unwrap_or(body.len())].to_owned()
}

/// The ```json blocks of a PaSO Annex section.
fn annex(file: &str, section: &str) -> Vec<String> {
    annex_section(file, section)
        .split("```json\n")
        .skip(1)
        .map(|block| block[..block.find("```").expect("a closing fence")].to_owned())
        .collect()
}

/// A CSC example the QES tests hold, as check_qes.py reads it from the specification.
fn csc(name: &str) -> String {
    let path = format!(
        "{}/../siros-qes/tests/data/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(path).expect("the CSC example")
}

/// A member of a JSON object text, written back with its members in their order.
fn member(json: &str, name: &str) -> String {
    Node::parse(json)
        .expect("JSON")
        .get(name)
        .expect("the member")
        .python_text()
        .to_string()
}

/// An English wallet showing amounts as written.
fn english() -> Env {
    Env::new(
        vec![LocaleTag::parse("en").expect("en")],
        Vec::new(),
        RenderOptions {
            amounts: Amounts::Written,
            ..OPTIONS
        },
        Vec::new(),
        Choice::First,
    )
    .expect("the configuration")
}

/// What the user saw and what the wallet answered for the first selection the consent offers:
/// each slot's default.
struct Answered {
    header: Header,
    entry: ConsentEntry,
    vp_token: String,
    delivery: Delivery,
}

/// The request answered through the core with every real plug-in, for an English wallet holding
/// the credentials, phase 2's fetches answered from `published`.
fn answer(
    request: &Request<'_>,
    held: &[Held],
    published: &Published,
    host: &HaipHost,
) -> Answered {
    let env = english();
    let registry = registry().expect("the real registry");
    let wallet = Wallet::new(
        held.iter()
            .map(|h| h.credential().expect("a credential"))
            .collect(),
    )
    .expect("a wallet");
    let accepted = Accepted::new(request, &registry).expect("the request keeps every rule");
    let matched = Match::run(&accepted, &wallet, &env).expect("no fault");
    let consent = Consent::of(&matched).expect("the wallet meets the request");
    let views = Views::of(&matched, &env).expect("no fault");
    let sets = offer(&matched, &consent, Choice::First);
    let shown = display(&sets, &views, &[]).expect("no fault");
    let ids: Vec<&str> = shown.sets()[0].iter().map(|slot| slot[0].id()).collect();
    let selection = shown.select(0, &ids).expect("the defaults are a selection");
    let header = selection.header();
    let chosen = selection.ids();
    let entry = views
        .by_id(chosen[0])
        .expect("the chosen entry")
        .entry
        .clone();
    let authenticated = siros_testkit::fixtures::authenticate(request.envelope(), &registry, host)
        .expect("authentic");
    let built = Prepared::prepare(&authenticated, &chosen, &wallet, &registry, &env)
        .and_then(|prepared| prepared.respond(|resource| published.answer(resource), host))
        .expect("the wallet answers");
    Answered {
        header,
        entry,
        vp_token: built.response().vp_token().json(),
        delivery: built.delivery().clone(),
    }
}

/// The one presentation of a query in `vp_token`.
fn presentation(answered: &Answered, query: &str) -> Value {
    let token: Value = serde_json::from_str(&answered.vp_token).expect("vp_token");
    let Delivery::DcApi(data) = &answered.delivery else {
        panic!("dc_api answers on the DC API");
    };
    // OpenID4VP Annex A: dc_api's data is {"vp_token": ...}.
    let data: Value = serde_json::from_str(data.as_str()).expect("data");
    assert_eq!(data, json!({"vp_token": token}));
    let [presentation] = token[query]
        .as_array()
        .expect("the query's presentations")
        .as_slice()
    else {
        panic!("one presentation for {query}");
    };
    presentation.clone()
}

/// An mdoc presentation as a Verifier reads it, in the reference model's JSON shape.
fn read_mdoc(presentation: &Value) -> Value {
    let text = presentation.to_string();
    let written = Node::parse(&text).expect("JSON");
    let read = model_shape(&written, None).expect("a DeviceResponse");
    serde_json::from_str(&read.python_compact().to_string()).expect("JSON")
}

fn b64url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The time of an instant as Risk Signals §2.3 writes `collected_at`, the days counted with
/// Howard Hinnant's civil-from-days.
fn stamp(seconds: u64) -> String {
    let days = i64::try_from(seconds / 86_400).expect("days") + 719_468;
    let era = days.div_euclid(146_097);
    let doe = days.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let rest = seconds % 86_400;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        rest / 60 % 60,
        rest % 60
    )
}

/// Core A.1's transaction shown with Payment A.1's metadata, its title left to the wallet as
/// Core A.4 shows it, under the risk profile Core A.2 assumes: the response mode and the
/// authentication methods required.
fn payment_metadata() -> String {
    let mut meta: Value =
        serde_json::from_str(&member(&annex("Payment.md", "A.1")[1], PAY)).expect("metadata");
    drop(
        meta["ui_labels"]
            .as_object_mut()
            .expect("ui_labels")
            .remove("transaction_title"),
    );
    meta["risk_signals"] = json!([
        {"type": RESPONSE_MODE, "required": true},
        {"type": AMR, "required": true}
    ]);
    json!({ PAY: meta }).to_string()
}

/// The host whose End-User completed, five seconds ago, the authentication Core A.2's `amr`
/// reports: a PIN, a key in the device's WSCD and a strong face biometric (Risk Signal Registry
/// §2.8).
fn authenticated_as_a2() -> HaipHost {
    let mut host = HaipHost::at(Timestamp(NOW));
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

/// Core A.2's envelopes, in order: the response mode the request's (Risk Signal Registry §2.7),
/// read at signing; the authentication methods as the End-User completed them.
fn a2_envelopes(a2: &Value) -> Value {
    a2["risk_signals"]
        .as_array()
        .expect("risk_signals")
        .iter()
        .map(|e| {
            let (value, collected) = if e["type"] == RESPONSE_MODE {
                (json!("dc_api"), NOW)
            } else {
                (e["value"].clone(), NOW - 5)
            };
            json!({"type": e["type"], "collected_at": stamp(collected), "status": e["status"], "value": value})
        })
        .collect()
}

/// A text of Payment A.1's type as the test app renders it for the English wallet.
fn english_text(text: &Text) -> String {
    let types = payment_metadata();
    let given = Node::parse(&types).expect("the types");
    let given = given.get(PAY).expect("Payment A.1's metadata");
    let english = english();
    let app = paso_app(
        PAY,
        &given.python_compact().to_string(),
        english.priority(),
        &english.priority()[0],
    );
    app.plain(&english, text).expect("the text renders")
}

/// Core A.4: the payment screen of A.1's transaction in English.
fn assert_core_a4(answered: &Answered) {
    let header = &answered.header;
    assert_eq!(
        [&header.title, &header.confirm, &header.cancel].map(english_text),
        ["Payment Confirmation", "Pay", "Cancel"]
    );
    let payment = answered
        .entry
        .overlay()
        .and_then(|overlay| overlay.header.as_ref())
        .expect("a payment's transaction header");
    assert_eq!(
        [&payment.counterparty, &payment.amount].map(english_text),
        ["Shop Inc.", "49.99 EUR"]
    );
}

#[test]
fn paso_core_a1_through_an_sd_jwt_card_answers_with_core_a2s_key_binding_jwt() {
    let core = annex("paso-core.md", "A.1");
    let a2: Value = serde_json::from_str(&annex("paso-core.md", "A.2")[0]).expect("A.2");
    let entry = verifier::encode(&core[1]).expect("Core A.1's entry");
    // Core §3: a PaSO request is signed, its expected_origins naming the Origin (Annex A).
    let text = parameters(
        &member(&core[0], "dcql_query"),
        &format!(r#""transaction_data":["{entry}"],"expected_origins":["{ORIGIN}"]"#),
    );
    siros_testkit::signed_request!(let request = &text);
    let document = verifier::paso_document(
        "https://bank.example/sca/card",
        "dc+sd-jwt",
        &payment_metadata(),
        None,
        ISSUER,
    )
    .expect("the card's PaSO document");
    let integrity =
        serde_json::from_str::<Value>(&document).expect("document")["integrity"].clone();
    let mut card = Held::new(
        "card",
        "dc+sd-jwt",
        r#"{"type": "https://bank.example/sca/card", "metadata": {}, "values": {"pan_last_four": "1234", "scheme": "visa"},
            "jwt": "eyJhbGciOiJFUzI1NiJ9.card.sig", "alg": "ES256", "curve": "P-256", "key_alg": "ES256", "key_curve": "P-256"}"#,
    );
    card.documents = vec![("paso".to_owned(), document.into_bytes())];
    let host = authenticated_as_a2();
    let answered = answer(&request, &[card], &Published::default(), &host);
    assert_core_a4(&answered);
    let presentation = presentation(&answered, "sca_card");
    // OpenID4VP B.3.6, RFC 9901 §4: the SD-JWT with a disclosure per requested claim, then the
    // Key Binding JWT of the card's key.
    let sd_jwt = presentation["sd_jwt"].as_str().expect("sd_jwt");
    let parts: Vec<&str> = sd_jwt.split('~').collect();
    assert_eq!(parts.first(), Some(&"eyJhbGciOiJFUzI1NiJ9.card.sig"));
    assert_eq!(parts.last(), Some(&""), "an SD-JWT ends with ~");
    let disclosed: Vec<(Value, Value)> = parts[1..parts.len() - 1]
        .iter()
        .map(|d| {
            let array: Value =
                serde_json::from_slice(&URL_SAFE_NO_PAD.decode(d).expect("base64url"))
                    .expect("a disclosure");
            (array[1].clone(), array[2].clone())
        })
        .collect();
    assert_eq!(
        disclosed,
        [
            (json!("pan_last_four"), json!("1234")),
            (json!("scheme"), json!("visa"))
        ]
    );
    let kb = &presentation["kb_jwt"];
    assert_eq!(kb["header"], json!({"typ": "kb+jwt", "alg": "ES256"}));
    let payload = kb["payload"].as_object().expect("the payload");
    // Core A.2: the payload holds exactly the example's claims.
    let mut names: Vec<&String> = payload.keys().collect();
    let mut want: Vec<&String> = a2.as_object().expect("A.2").keys().collect();
    names.sort();
    want.sort();
    assert_eq!(names, want);
    // Annex A and B.3.6: the Origin as audience, the request's nonce, sd_hash over the SD-JWT.
    assert_eq!(payload["aud"], json!(format!("origin:{ORIGIN}")));
    assert_eq!(payload["nonce"], json!(NONCE));
    assert_eq!(payload["iat"], json!(NOW));
    assert_eq!(
        payload["sd_hash"],
        json!(b64url(&Sha256::digest(sd_jwt.as_bytes())))
    );
    // Core §6.1-6.2: the SCA claims.
    assert_eq!(
        payload["transaction_data_hash"],
        json!(b64url(&Sha256::digest(entry.as_bytes())))
    );
    assert_eq!(payload["transaction_data_hash_alg"], json!("sha-256"));
    assert_eq!(payload["display_locale"], json!("en"));
    assert_eq!(payload["metadata_integrity"], integrity);
    assert_eq!(
        payload["request_integrity"],
        json!(sri(request.request_object().expect("signed").as_bytes()))
    );
    assert_eq!(payload["wallet_instance_version"], json!(host.paso.version));
    // Core §6.1: a fresh jti, the host's first identifier.
    assert_eq!(
        payload["jti"],
        json!("00000000-0000-4000-8000-000000000001")
    );
    assert_eq!(payload["risk_signals"], a2_envelopes(&a2));
}

#[test]
fn paso_core_a1_through_an_mdoc_card_answers_with_core_a3s_device_signed_name_space() {
    let core = annex("paso-core.md", "A.1");
    let a2: Value = serde_json::from_str(&annex("paso-core.md", "A.2")[0]).expect("A.2");
    // Core A.3's element names, from its CBOR diagnostic notation.
    let mut a3: Vec<String> = annex_section("paso-core.md", "A.3")
        .lines()
        .filter_map(|line| {
            line.strip_prefix("  \"")
                .and_then(|rest| rest.split_once("\" :"))
                .map(|(name, _)| name.to_owned())
        })
        .collect();
    let entry = verifier::encode(&core[1]).expect("Core A.1's entry");
    // Core A.1's query, for an mdoc of the card.
    let dcql = r#"{"credentials": [{"id": "sca_card", "format": "mso_mdoc", "meta": {"doctype_value": "com.bank.example.sca.card"},
        "claims": [{"path": ["com.bank.example.sca", "pan_last_four"]}, {"path": ["com.bank.example.sca", "scheme"]}]}]}"#;
    let text = parameters(
        dcql,
        &format!(r#""transaction_data":["{entry}"],"expected_origins":["{ORIGIN}"]"#),
    );
    siros_testkit::signed_request!(let request = &text);
    let document = verifier::paso_document(
        "com.bank.example.sca.card",
        "mso_mdoc",
        &payment_metadata(),
        None,
        ISSUER,
    )
    .expect("the card's PaSO document");
    let integrity =
        serde_json::from_str::<Value>(&document).expect("document")["integrity"].clone();
    // ISO/IEC 18013-5 §9.1.2.4: the MSO authorizes the device to sign PaSO's name space.
    let mut card = Held::new(
        "card",
        "mso_mdoc",
        r#"{"type": "com.bank.example.sca.card", "metadata": {}, "values": {"com.bank.example.sca": {"pan_last_four": "1234", "scheme": "visa"}},
            "key_authorizations": {"namespaces": ["urn:paso:sca:1"]},
            "issuer_alg": -7, "issuer_curve": "P-256", "device_alg": -7, "device_curve": "P-256"}"#,
    )
    .with_issued()
    .expect("the card's IssuerSigned");
    card.documents
        .push(("paso".to_owned(), document.into_bytes()));
    let host = authenticated_as_a2();
    let answered = answer(&request, &[card], &Published::default(), &host);
    assert_core_a4(&answered);
    let response = read_mdoc(&presentation(&answered, "sca_card"));
    // OpenID4VP B.2.5: a DeviceResponse of one document, the requested elements issuer-signed.
    assert_eq!(
        (&response["version"], &response["status"]),
        (&json!("1.0"), &json!(0))
    );
    let [document] = response["documents"]
        .as_array()
        .expect("documents")
        .as_slice()
    else {
        panic!("one document");
    };
    assert_eq!(document["docType"], json!("com.bank.example.sca.card"));
    assert_eq!(
        document["issuerSigned"]["nameSpaces"],
        json!({"com.bank.example.sca": {"pan_last_four": "1234", "scheme": "visa"}})
    );
    let device = &document["deviceSigned"];
    // ISO/IEC 18013-5 §9.1.3: a device signature; the Verifier lists no key for a MAC.
    assert_eq!(
        device["deviceAuth"]
            .as_object()
            .expect("deviceAuth")
            .keys()
            .collect::<Vec<_>>(),
        ["deviceSignature"]
    );
    let spaces = device["nameSpaces"].as_object().expect("nameSpaces");
    assert_eq!(spaces.keys().collect::<Vec<_>>(), ["urn:paso:sca:1"]);
    let elements = spaces["urn:paso:sca:1"].as_object().expect("elements");
    // Core A.3: the name space holds exactly the example's elements.
    let mut names: Vec<&String> = elements.keys().collect();
    names.sort();
    a3.sort();
    assert_eq!(names, a3.iter().collect::<Vec<_>>());
    // Core §6.3: the hash a byte string, A.3's h'...'.
    assert_eq!(
        elements["transaction_data_hash"],
        json!({"bstr": hex(&Sha256::digest(entry.as_bytes()))})
    );
    assert_eq!(elements["transaction_data_hash_alg"], json!("sha-256"));
    assert_eq!(elements["display_locale"], json!("en"));
    assert_eq!(elements["metadata_integrity"], integrity);
    assert_eq!(
        elements["request_integrity"],
        json!(sri(request.request_object().expect("signed").as_bytes()))
    );
    assert_eq!(
        elements["wallet_instance_version"],
        json!(host.paso.version)
    );
    assert_eq!(
        elements["jti"],
        json!("00000000-0000-4000-8000-000000000001")
    );
    assert_eq!(elements["risk_signals"], a2_envelopes(&a2));
}
