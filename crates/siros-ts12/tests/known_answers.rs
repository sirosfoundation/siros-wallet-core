//! KA21 to KA24 (each against its source) and I33's TS12 part: expected values from CS-12 §7.2 and
//! §8.1, WE BUILD's test bed, TS12 §3.6 and RFC 4647 §3.4.
//!
//! CS-12 §8.1's examples write `transaction_data_hashes_alg` as a string; OpenID4VP B.3.3.1 defines
//! an array (reading 27), which the entries here hold.

mod common;

use std::num::NonZeroU32;

use common::{CS12_IBAN, CS12_USER, Screen, TESTBED_IBAN, bound_entry};
use siros_openid4vp::host::{
    AttackDetection, Factor, Inherence, Isolation, Knowledge, Modality, Possession, Sensor,
};
use siros_openid4vp::plugins::{Bound, NoCandidate};
use siros_openid4vp::rows::Value;
use siros_paso::outcome::Excluded;
use siros_ts12::{AmrCategory, Ts12Type, amr};

const CS12_PAYMENT: &str = r#"{"type": "urn:eudi:sca:payment:1", "credential_ids": ["sca"],
  "transaction_data_hashes_alg": ["sha-256"],
  "payload": {"transaction_id": "9c3b1e2a-6f21-4e2a-9a71-2b7e6a5d1234",
    "payee": {"name": "Example Merchant B.V.", "id": "NL-KVK-12345678"},
    "currency": "EUR", "amount": 129.95}}"#;

const CS12_LOGIN: &str = r#"{"type": "urn:eudi:sca:login_risk_transaction:1",
  "credential_ids": ["sca"], "transaction_data_hashes_alg": ["sha-256"],
  "payload": {"transaction_id": "3f8a2c71-5d0e-4b1a-8e6f-1c2d3e4f5a6b",
    "service": "Example Bank Online Banking", "action": "Update postal address"}}"#;

/// The test bed's default payment (`nxd-ts12PaymentUtils.js`).
const TESTBED_PAYMENT: &str = r#"{"type": "urn:eudi:sca:payment:1", "credential_ids": ["sca"],
  "transaction_data_hashes_alg": ["sha-256"],
  "payload": {"transaction_id": "0d8a4b9e-3e8e-4b9c-8e6b-2f1a7c5d9e01",
    "date_time": "2026-10-01T12:30:15.123Z",
    "payee": {"name": "Demo Merchant", "id": "merchant-001"},
    "currency": "EUR", "amount": 42.5}}"#;

fn screen(own: &str, kind: Ts12Type, locales: &[&str], bound: &Bound) -> Screen {
    Screen::of(
        own,
        kind,
        locales,
        bound.selected.as_ref().expect("a selected module"),
    )
}

/// The rows' labels and values, as plain text.
fn rows(screen: &Screen, bound: &Bound) -> Vec<(String, String)> {
    bound
        .overlay
        .rows
        .iter()
        .map(|row| {
            let value = match row.value.as_ref().expect("a value") {
                Value::Text(text) => screen.plain(text),
                other => panic!("a text value: {other:?}"),
            };
            (screen.plain(&row.label), value)
        })
        .collect()
}

fn pair(label: &str, value: &str) -> (String, String) {
    (label.to_owned(), value.to_owned())
}

#[test]
fn ka21_cs12s_payment_presents_its_header_and_action() {
    let locales = ["en-GB", "en"];
    let bound = bound_entry(CS12_IBAN, CS12_PAYMENT, &locales).expect("offered");
    let screen = screen(CS12_IBAN, Ts12Type::Payment, &locales, &bound);
    let header = bound.overlay.header.as_ref().expect("the payment's header");
    assert_eq!(screen.plain(&header.counterparty), "Example Merchant B.V.");
    assert_eq!(screen.plain(&header.amount), "129.95 EUR");
    assert_eq!(screen.plain(&bound.header.confirm), "Confirm Payment");
    assert_eq!(screen.plain(&bound.header.cancel), "Cancel Payment");
}

#[test]
fn ka22_cs12s_login_presents_its_rows() {
    let locales = ["en-GB", "en"];
    let bound = bound_entry(CS12_USER, CS12_LOGIN, &locales).expect("offered");
    let screen = screen(CS12_USER, Ts12Type::LoginRisk, &locales, &bound);
    assert!(bound.overlay.header.is_none());
    assert_eq!(
        rows(&screen, &bound),
        [
            pair("Service", "Example Bank Online Banking"),
            pair("Action", "Update postal address"),
        ]
    );
}

#[test]
fn ka23_the_test_beds_payment_hides_its_internal_fields() {
    let locales = ["en-GB", "en"];
    let bound = bound_entry(TESTBED_IBAN, TESTBED_PAYMENT, &locales).expect("offered");
    let screen = screen(TESTBED_IBAN, Ts12Type::Payment, &locales, &bound);
    let header = bound.overlay.header.as_ref().expect("the payment's header");
    assert_eq!(screen.plain(&header.counterparty), "Demo Merchant");
    assert_eq!(screen.plain(&header.amount), "42.50 EUR");
    // Level 4's `transaction_id`, and `date_time` and `payee.id` without metadata, show nowhere;
    // `currency` at level 2 stays beside the header.
    let shown = rows(&screen, &bound);
    assert_eq!(shown.len(), 1, "{shown:?}");
    assert_eq!(shown[0].0, "Currency");
    assert_eq!(screen.plain(&bound.header.confirm), "Confirm payment");
}

#[test]
fn ka24_each_factor_answers_a_value_ts12_lists() {
    let pin = |digits| Factor::Knowledge(Knowledge::Pin(NonZeroU32::new(digits)));
    let phrase = |chars| Factor::Knowledge(Knowledge::Passphrase(NonZeroU32::new(chars)));
    let inherence = |modality, sensor| {
        Factor::Inherence(Inherence {
            modality,
            sensor,
            isolation: Isolation::Hardware,
            false_accepts: None,
            attack_detection: AttackDetection::Present,
        })
    };
    use AmrCategory::{Inherence as I, Knowledge as K, Possession as P};
    let table = [
        (pin(5), K, "pin_less_than_6_digits"),
        (pin(6), K, "pin_6_or_more_digits"),
        (phrase(7), K, "passphrase_less_than_8_chars"),
        (phrase(8), K, "passphrase_8_to_11_chars"),
        (phrase(11), K, "passphrase_8_to_11_chars"),
        (phrase(12), K, "passphrase_12_or_more_chars"),
        (Factor::Knowledge(Knowledge::Pattern), K, "pattern"),
        (Factor::Knowledge(Knowledge::Pin(None)), K, "other"),
        (Factor::Knowledge(Knowledge::Passphrase(None)), K, "other"),
        (Factor::Knowledge(Knowledge::Unknown), K, "other"),
        (
            Factor::Possession(Possession::RemoteWscd),
            P,
            "key_in_remote_wscd",
        ),
        (
            Factor::Possession(Possession::LocalExternalWscd),
            P,
            "key_in_local_external_wscd",
        ),
        (
            Factor::Possession(Possession::LocalInternalWscd),
            P,
            "key_in_local_internal_wscd",
        ),
        (
            Factor::Possession(Possession::LocalNativeWscd),
            P,
            "key_in_local_native_wscd",
        ),
        (Factor::Possession(Possession::Software), P, "other"),
        (
            inherence(Modality::Fingerprint, Sensor::Device),
            I,
            "fingerprint_device",
        ),
        (
            inherence(Modality::Fingerprint, Sensor::External),
            I,
            "fingerprint_external",
        ),
        (inherence(Modality::Face, Sensor::Device), I, "face_device"),
        (
            inherence(Modality::Face, Sensor::External),
            I,
            "face_external",
        ),
        (inherence(Modality::Iris, Sensor::Device), I, "other"),
        (inherence(Modality::Unknown, Sensor::External), I, "other"),
    ];
    for (factor, category, method) in table {
        assert_eq!(amr(&factor), (category, method), "{factor:?}");
    }
}

/// I33: WE BUILD's `en-GB` claim labels are English, so Lookup reaches them from every list that
/// holds English, under the list's first tag (RFC 4647 §3.4), and from no other.
#[test]
fn i33_the_test_beds_english_reaches_every_list_holding_english() {
    for locales in [
        &["en-US", "en"][..],
        &["en-US"][..],
        &["en-GB"][..],
        &["en"][..],
    ] {
        let bound = bound_entry(TESTBED_IBAN, TESTBED_PAYMENT, locales).expect("offered");
        let selected = bound.selected.as_ref().expect("a selected module");
        assert_eq!(selected.locale().as_str(), locales[0]);
        let screen = screen(TESTBED_IBAN, Ts12Type::Payment, locales, &bound);
        assert_eq!(
            screen.plain(&bound.header.confirm),
            "Confirm payment",
            "{locales:?}"
        );
    }
    let refused = bound_entry(TESTBED_IBAN, TESTBED_PAYMENT, &["de"]).expect_err("no English");
    let NoCandidate::Excluded(excluded) = refused else {
        panic!("a fault: {refused:?}");
    };
    let rule: &dyn std::error::Error = excluded.rule();
    assert!(rule.downcast_ref::<Excluded>().is_some(), "{excluded}");
}

/// I33: regions standing alone: the first of `en-GB` and `en-US` converts to `en`, the second keeps
/// its tag and answers its own region.
#[test]
fn i33_the_first_region_alone_converts_and_the_second_keeps_its_tag() {
    assert_eq!(
        siros_ts12::translate::generic_tags(&["en-GB", "en-US"]),
        ["en", "en-US"]
    );
    // An entry under the generic tag keeps every other as written; the script stays.
    assert_eq!(
        siros_ts12::translate::generic_tags(&["en-GB", "EN"]),
        ["en-GB", "EN"]
    );
    assert_eq!(
        siros_ts12::translate::generic_tags(&["zh-Hant-TW", "zh-Hans-CN", "de-1996"]),
        ["zh-Hant", "zh-Hans", "de"]
    );
    let own = TESTBED_IBAN.replace(
        r#""value": "Confirm payment""#,
        r#""value": "Confirm payment"
          },
          {
            "lang": "en-US",
            "value": "Approve payment""#,
    );
    let locales = |tag: &'static str| {
        let locales = [tag];
        let bound = bound_entry(&own, TESTBED_PAYMENT, &locales).expect("offered");
        let screen = screen(&own, Ts12Type::Payment, &locales, &bound);
        screen.plain(&bound.header.confirm)
    };
    assert_eq!(locales("en-GB"), "Confirm payment");
    assert_eq!(locales("en"), "Confirm payment");
    assert_eq!(locales("en-US"), "Approve payment");
}
