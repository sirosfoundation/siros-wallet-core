//! KA21 to KA24 (each against its source) and I33's TS12 part: expected values from CS-12 §7.2 and
//! §8.1, WE BUILD's test bed, TS12 §3.6 and RFC 4647 §3.4. An issuer's label shows as its
//! characters through the source `view::convert` writes.
//!
//! CS-12 §8.1's examples write `transaction_data_hashes_alg` as a string; OpenID4VP B.3.3.1 defines
//! an array (reading 27), which the entries here hold.

mod common;

use std::num::NonZeroU32;

use common::{CS12_IBAN, CS12_USER, TESTBED_IBAN, bound_entry, bound_entry_in, env, registered};
use siros_i18n::Styles;
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
  "payload": {"transaction_id": "3f8a2c71-9b4d-4e3a-8c5e-7a1b2c3d4e5f",
    "service": "Example Bank Online Banking", "action": "Update postal address"}}"#;

/// The test bed's default payment (`nxd-ts12PaymentUtils.js`).
const TESTBED_PAYMENT: &str = r#"{"type": "urn:eudi:sca:payment:1", "credential_ids": ["sca"],
  "transaction_data_hashes_alg": ["sha-256"],
  "payload": {"transaction_id": "0d8a4b9e-3e8e-4b9c-8e6b-2f1a7c5d9e01",
    "date_time": "2026-10-01T12:30:15.123Z",
    "payee": {"name": "Demo Merchant", "id": "merchant-001"},
    "currency": "EUR", "amount": 42.5}}"#;

/// The rows' labels and values, as plain text.
fn rows(bound: &Bound) -> Vec<(String, String)> {
    bound
        .overlay
        .rows
        .iter()
        .map(|row| {
            let value = match row.value.as_ref().expect("a value") {
                Value::Text(text) => text.to_string(),
                other => panic!("a text value: {other:?}"),
            };
            (row.label.to_string(), value)
        })
        .collect()
}

fn pair(label: &str, value: &str) -> (String, String) {
    (label.to_owned(), value.to_owned())
}

#[test]
fn ka21_cs12s_payment_presents_its_header_and_action() {
    let bound = bound_entry(CS12_IBAN, CS12_PAYMENT, &["en-GB", "en"]).expect("offered");
    let header = bound.overlay.header.as_ref().expect("the payment's header");
    assert_eq!(header.counterparty.to_string(), "Example Merchant B.V.");
    assert_eq!(header.amount.to_string(), "129.95 EUR");
    assert_eq!(bound.header.confirm.to_string(), "Confirm Payment");
    assert_eq!(bound.header.cancel.to_string(), "Cancel Payment");
}

#[test]
fn ka22_cs12s_login_presents_its_rows() {
    let bound = bound_entry(CS12_USER, CS12_LOGIN, &["en-GB", "en"]).expect("offered");
    assert!(bound.overlay.header.is_none());
    assert_eq!(
        rows(&bound),
        [
            pair("Service", "Example Bank Online Banking"),
            pair("Action", "Update postal address"),
        ]
    );
}

#[test]
fn ka23_the_test_beds_payment_hides_its_internal_fields() {
    let bound = bound_entry(TESTBED_IBAN, TESTBED_PAYMENT, &["en-GB", "en"]).expect("offered");
    let header = bound.overlay.header.as_ref().expect("the payment's header");
    assert_eq!(header.counterparty.to_string(), "Demo Merchant");
    assert_eq!(header.amount.to_string(), "42.50 EUR");
    // Level 4's `transaction_id`, and `date_time` and `payee.id` without metadata, show nowhere;
    // `currency` at level 2 stays beside the header.
    let shown = rows(&bound);
    assert_eq!(shown.len(), 1, "{shown:?}");
    assert_eq!(shown[0].0, "Currency");
    assert_eq!(bound.header.confirm.to_string(), "Confirm payment");
}

/// Section 4.10.2's display table: a payment's `amount` and `payee.name` and an action's `action`
/// show at level 4, TS12 §3.3.1's level that hides (RTS Art. 5(1)(a)).
#[test]
fn level_4_leaves_the_fields_a_type_always_shows_on_screen() {
    let own = TESTBED_IBAN.replace(r#""visualisation": 1"#, r#""visualisation": 4"#);
    let bound = bound_entry(&own, TESTBED_PAYMENT, &["en"]).expect("offered");
    let header = bound.overlay.header.as_ref().expect("the payment's header");
    assert_eq!(header.counterparty.to_string(), "Demo Merchant");
    assert_eq!(header.amount.to_string(), "42.50 EUR");
    let own = CS12_USER.replace(r#""visualisation": 1"#, r#""visualisation": 4"#);
    let bound = bound_entry(&own, CS12_LOGIN, &["en"]).expect("offered");
    assert_eq!(
        rows(&bound),
        [
            pair("Service", "Example Bank Online Banking"),
            pair("Action", "Update postal address"),
        ]
    );
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
        let read = amr(&factor);
        assert_eq!(
            (read.category(), read.name()),
            (category, method),
            "{factor:?}"
        );
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
        assert_eq!(
            bound.header.confirm.to_string(),
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

/// I33: a tag standing alone answers its language's generic tag, its region and variants dropped
/// and its script kept, and a grandfathered tag stays whole (RFC 5646 §2.1). A list naming the
/// language alone reaches no entry under a script.
#[test]
fn i33_a_tag_standing_alone_answers_its_generic_tag() {
    for (written, list, answers) in [
        ("en-GB", "en", true),
        ("de-1996", "de", true),
        ("zh-Hant-TW", "zh-Hant", true),
        ("zh-Hans-CN", "zh-Hans", true),
        ("zh-Hant-TW", "zh", false),
        ("art-lojban", "art-lojban", true),
        ("art-lojban", "art", false),
        ("en-GB-oed", "en", false),
        ("sgn-BE-FR", "sgn", false),
    ] {
        let own = TESTBED_IBAN.replace(r#""en-GB""#, &format!(r#""{written}""#));
        match bound_entry(&own, TESTBED_PAYMENT, &[list]) {
            Ok(bound) => {
                assert!(answers, "{written} under {list}");
                assert_eq!(
                    bound.header.confirm.to_string(),
                    "Confirm payment",
                    "{written}"
                );
            }
            Err(NoCandidate::Excluded(excluded)) => {
                let rule: &dyn std::error::Error = excluded.rule();
                assert!(
                    !answers && rule.downcast_ref::<Excluded>().is_some(),
                    "{written} under {list}: {excluded}"
                );
            }
            Err(fault) => panic!("{written} under {list}: {fault:?}"),
        }
    }
}

/// I33: of regions standing alone, the first converts and the second keeps its tag and answers its
/// own region; beside an entry under the generic tag, each keeps its tag.
#[test]
fn i33_one_entry_takes_the_generic_tag() {
    let beside = |tag: &str, text: &str| {
        TESTBED_IBAN.replace(
            r#""value": "Confirm payment""#,
            &format!(
                r#""value": "Confirm payment"
              }},
              {{
                "lang": "{tag}",
                "value": "{text}""#
            ),
        )
    };
    let confirm = |own: &str, tag: &'static str| {
        let bound = bound_entry(own, TESTBED_PAYMENT, &[tag]).expect("offered");
        bound.header.confirm.to_string()
    };
    let regions = beside("en-US", "Approve payment");
    assert_eq!(confirm(&regions, "en-GB"), "Confirm payment");
    assert_eq!(confirm(&regions, "en"), "Confirm payment");
    assert_eq!(confirm(&regions, "en-US"), "Approve payment");
    let generic = beside("EN", "Approve payment");
    assert_eq!(confirm(&generic, "en-GB"), "Confirm payment");
    assert_eq!(confirm(&generic, "en"), "Approve payment");
}

/// An issuer's label holding MessageFormat 2's syntax shows as its characters, unstyled, through
/// the source the registration carries: `view::convert` escapes it.
#[test]
fn an_issuers_label_shows_as_its_characters() {
    const LABEL: &str = r".match {$x} {#strong} | \ end";
    let own = TESTBED_IBAN.replace(
        r#""value": "Confirm payment""#,
        &format!(r#""value": "{}""#, LABEL.replace('\\', r"\\")),
    );
    let env = env(&["en"]);
    let context = registered(&own, Ts12Type::Payment, &env);
    let bound = bound_entry_in(&own, TESTBED_PAYMENT, &env, &context).expect("offered");
    let spans: Vec<(&str, Styles)> = bound
        .header
        .confirm
        .spans()
        .iter()
        .map(|span| (span.text.as_str(), span.styles))
        .collect();
    assert_eq!(spans, [(LABEL, Styles::empty())]);
}
