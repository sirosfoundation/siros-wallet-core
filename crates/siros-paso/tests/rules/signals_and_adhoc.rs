//! Risk Signals §3-7, ad-hoc metadata's steps, and the request rules PaSO adds.

use siros_openid4vp::jose::JwsError;
use siros_openid4vp::plugins::Profile;
use siros_openid4vp::refusal::ErrorCode;
use siros_paso::adhoc::{AdhocFailure, AdhocRefusal};
use siros_paso::outcome::{NotCompatible, Outcome};
use siros_paso::{PasoProfile, Rendered};
use siros_testkit::fixtures;
use siros_testkit::verifier::{self, adhoc_jwt, secret_key};

use crate::common::{CARD_TYPE, Card, PAY, en, entry, one_query, parameters};

use super::{render_with, shown};

/// Payment A.1's claims with risk signal members.
pub(super) fn risky(members: &str) -> String {
    format!(
        r#"{{"claims": [{{"path": ["transaction_id"]}}, {{"path": ["amount"], "value_type": "iso_currency_amount", "display": {}}}, {{"path": ["payee", "name"], "display": {}}}, {{"path": ["payee", "id"]}}]{members}}}"#,
        shown("Amount"),
        shown("Payee")
    )
}

#[test]
fn a_signal_type_is_a_urn() {
    use siros_paso::risk::SignalType;
    // RFC 8141: a signal type is urn:, a non-empty namespace identifier, : and a non-empty
    // namespace-specific string.
    assert!(SignalType::parse("urn:paso:risk:global:geolocation:1").is_ok());
    for invalid in ["", "urn:", "urn:paso", "urn::x", "urn:paso:", "paso:risk:x"] {
        assert!(SignalType::parse(invalid).is_err(), "{invalid:?}");
    }
}

#[test]
pub(super) fn each_risk_signal_rule_makes_the_entry_not_compatible() {
    let payload =
        r#"{"transaction_id": "t", "amount": "1.00 EUR", "payee": {"name": "P", "id": "D"}}"#;
    let case = |members: &str| {
        render_with(
            PAY,
            &risky(members),
            payload,
            &en(),
            &PasoProfile::default(),
        )
    };
    decided!(
        case(r#", "risk_signal_profiles": ["urn:paso:risk:global:x:1"]"#),
        Outcome::NotCompatible(NotCompatible::RiskProfiles),
        "Risk Signals §3.2"
    );
    decided!(
        case(r#", "risk_signal_profiles": ["urn:paso:risk-profile:com.example:x:1"]"#),
        Outcome::NotCompatible(NotCompatible::UnknownRiskProfile(_)),
        "Risk Signals §4.1"
    );
    decided!(
        case(r#", "risk_signals": {}"#),
        Outcome::NotCompatible(NotCompatible::RiskSignalsNotArray),
        "Risk Signals §4.1"
    );
    // §3.4: `max_age` a non-negative integer; one beyond 2^64 seconds bounds nothing.
    for max_age in ["-1", "1.5"] {
        decided!(
            case(&format!(
                r#", "risk_signals": [{{"type": "urn:paso:risk:global:amr:1", "max_age": {max_age}}}]"#
            )),
            Outcome::NotCompatible(NotCompatible::RiskSignalMalformed(_)),
            "Risk Signals §3.4; §4.1"
        );
    }
    assert!(
        case(r#", "risk_signals": [{"type": "urn:paso:risk:global:amr:1", "max_age": 100000000000000000000000}]"#)
            .is_ok()
    );
    decided!(
        case(r#", "encrypted": "yes""#),
        Outcome::NotCompatible(NotCompatible::EncryptedNotBoolean),
        "Risk Signals §7.2"
    );
    // The Default profile mandates encryption, and this issuer publishes no key (§7.3).
    decided!(
        case(r#", "risk_signal_profiles": ["urn:paso:risk-profile:global:default:1"]"#),
        Outcome::NotCompatible(NotCompatible::NoEncryptionKey),
        "Risk Signals §7.3"
    );
    // §7.3: a key published without `use` `enc` is no encryption key, whatever its `alg`.
    let signing = r#"{"keys": [{"kty": "EC", "crv": "P-256", "kid": "issuer-key-2", "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0", "alg": "ECDH-ES"}]}"#;
    let card = Card::new(
        "dc+sd-jwt",
        &format!(r#"{{"{PAY}": {}}}"#, risky(r#", "encrypted": true"#)),
        Some(signing),
        verifier::ISSUER,
    );
    let entry_json =
        format!(r#"{{"type": "{PAY}", "credential_ids": ["q"], "payload": {payload}}}"#);
    decided!(
        PasoProfile::default()
            .render(
                &entry(&entry_json),
                siros_openid4vp::routing::ChannelKind::DcApi,
                &card.credential(),
                crate::common::placement(&card.credential().format),
                &en()
            )
            .expect("no fault"),
        Outcome::NotCompatible(NotCompatible::NoEncryptionKey),
        "Risk Signals §7.3"
    );
}

/// The ad-hoc metadata JWT's payload for the SD-JWT card.
pub(super) fn adhoc_payload(sub: &str, format: &str, kind: &str, iss: &str) -> String {
    format!(
        r#"{{"iss": "{iss}", "sub": "{sub}", "format": "{format}", "iat": 1784999940, "exp": 1785000600, "transaction_data_type": "{kind}", "metadata": {}}}"#,
        risky("")
    )
}

pub(super) fn render_adhoc(
    jwt: &str,
    card: &Card,
    profile: &PasoProfile,
) -> Result<Rendered, Outcome> {
    let entry_json = format!(
        r#"{{"type": "{PAY}", "credential_ids": ["q"], "payload": {{"transaction_id": "t", "amount": "1.00 EUR", "payee": {{"name": "P", "id": "D"}}}}, "metadata": "{jwt}"}}"#
    );
    profile
        .render(
            &entry(&entry_json),
            siros_openid4vp::routing::ChannelKind::DcApi,
            &card.credential(),
            crate::common::placement(&card.credential().format),
            &en(),
        )
        .expect("no fault")
}

#[test]
pub(super) fn ad_hoc_metadata_reads_unverified_and_a_refused_jwt_is_not_compatible() {
    let iss = "https://issuer.bank.example";
    let good = adhoc_payload(CARD_TYPE, "dc+sd-jwt", PAY, iss);
    let card = Card::sd_jwt("{}");
    let jwt = |payload: &str, key: &[u8; 32]| {
        adhoc_jwt(payload, key, Some("issuer-key-1"), None).expect("jwt")
    };
    // The matcher reads the JWT as it reads a signed request: a signature under a key the issuer
    // does not publish still renders (section 4.14 of the design); phase 2 verifies it.
    for key in [
        &secret_key("issuer-secret-1"),
        &secret_key("another-secret"),
    ] {
        assert!(render_adhoc(&jwt(&good, key), &card, &PasoProfile::default()).is_ok());
    }
    let signed = |payload: &str| {
        siros_testkit::jose::compact_jws(
            &secret_key("issuer-secret-1"),
            &format!(r#"{{"alg": "ES256", "typ": "{}"}}"#, verifier::ADHOC_TYP),
            payload,
        )
        .expect("jws")
    };
    // What does not read is not compatible (RFC 7515 §7.1; Proof Metadata §5.2).
    let unread: Vec<(String, AdhocFailure)> = vec![
        ("a.b".to_owned(), AdhocFailure::Jws(JwsError::Structure)),
        ("!!.e30.x".to_owned(), AdhocFailure::Jws(JwsError::Base64)),
        (signed("[1]"), AdhocFailure::NotObject),
        (
            signed(&format!(
                r#"{{"iss": "{iss}", "sub": "{CARD_TYPE}", "format": "dc+sd-jwt", "exp": 1785000600, "transaction_data_type": "{PAY}", "metadata": "none"}}"#
            )),
            AdhocFailure::Metadata,
        ),
    ];
    for (jwt, failure) in unread {
        assert_eq!(
            render_adhoc(&jwt, &card, &PasoProfile::default()).map(|_| ()),
            Err(Outcome::NotCompatible(NotCompatible::Adhoc(failure))),
            "{jwt}"
        );
    }
    // A JWT the wallet refused for the credential (§5.3) is not compatible for it, and the
    // stored metadata never stands in: the card lists the type.
    let listing = Card::sd_jwt(&format!(r#"{{"{PAY}": {}}}"#, risky("")));
    let refused = jwt(&good, &secret_key("another-secret"));
    let knowing = PasoProfile::default().with_refusals(&[AdhocRefusal {
        jwt: refused.clone(),
        credential: listing.credential().id.as_str().to_owned(),
        failure: AdhocFailure::Signature,
    }]);
    let rendered = render_adhoc(&refused, &listing, &knowing);
    assert_eq!(
        rendered.as_ref().map(|_| ()),
        Err(&Outcome::NotCompatible(NotCompatible::Adhoc(
            AdhocFailure::Signature
        )))
    );
    assert_eq!(
        rendered.err().map(|outcome| outcome.clause()),
        Some("Proof Metadata §5.3")
    );
}

#[test]
pub(super) fn the_request_rules_paso_adds_refuse_with_their_codes() {
    let entry_with = |extra: &str| {
        format!(
            r#"{{"type": "{PAY}", "credential_ids": ["q"], "payload": {{"transaction_id": "t"}}{extra}}}"#
        )
    };
    let dcql = one_query("dc+sd-jwt");
    let codes = |parameters: &str, signed_request: bool| -> Vec<(String, ErrorCode)> {
        let data = if signed_request {
            fixtures::signed_data(parameters).expect("signs")
        } else {
            parameters.to_owned()
        };
        let received = if signed_request {
            fixtures::signed(&data)
        } else {
            fixtures::unsigned(&data)
        }
        .expect("received");
        let request = fixtures::request_of(&received).expect("request");
        let entries: Vec<_> = request.indexed_entries().map(|(index, _)| index).collect();
        // The rules reach the core through the plug-in contract.
        PasoProfile::default()
            .refusals(&request, &entries)
            .into_iter()
            .map(|refusal| (refusal.text(), refusal.code()))
            .collect()
    };
    let valid = entry_with("");
    assert_eq!(codes(&parameters(&dcql, &[&valid], ""), true), []);
    assert_eq!(
        codes(&parameters(&dcql, &[&valid], ""), false),
        [(
            "PaSO requests are signed; this one is not (Core §3)".to_owned(),
            ErrorCode::INVALID_REQUEST
        )]
    );
    assert_eq!(
        codes(
            &parameters(
                &dcql,
                &[&entry_with(
                    r#", "transaction_data_hashes_alg": ["sha-256"]"#
                )],
                ""
            ),
            true
        ),
        [(
            "PaSO entry 0: unknown member transaction_data_hashes_alg (OpenID4VP §5.1)".to_owned(),
            ErrorCode::INVALID_TRANSACTION_DATA
        )]
    );
    let not_object = format!(r#"{{"type": "{PAY}", "credential_ids": ["q"], "payload": ["x"]}}"#);
    assert_eq!(
        codes(&parameters(&dcql, &[&not_object], ""), true),
        [(
            "PaSO entry 0: payload is not a JSON object (Core §7.1)".to_owned(),
            ErrorCode::INVALID_TRANSACTION_DATA
        )]
    );
    assert_eq!(
        codes(
            &parameters(&dcql, &[&entry_with(r#", "metadata": {"claims": []}"#)], ""),
            true
        ),
        [(
            "PaSO entry 0: metadata is not a string (Proof Metadata §5.1)".to_owned(),
            ErrorCode::INVALID_TRANSACTION_DATA
        )]
    );
    // Core A.6: the counterexample's alternatives are not transposable; the repair is.
    let a6 = |options: &str| {
        format!(
            r#"{{"credentials": [{{"id": "sca_card", "format": "dc+sd-jwt"}}, {{"id": "pid_1", "format": "dc+sd-jwt"}}, {{"id": "pid_2", "format": "dc+sd-jwt"}}, {{"id": "loyalty", "format": "dc+sd-jwt"}}], "credential_sets": [{{"options": {options}}}]}}"#
        )
    };
    let card_entry = format!(
        r#"{{"type": "{PAY}", "credential_ids": ["sca_card"], "payload": {{"transaction_id": "t"}}}}"#
    );
    let blocks = crate::common::annex("paso-core.md", "A.6");
    let options: Vec<String> = blocks
        .iter()
        .map(|block| crate::common::member(&format!("{{{block}}}"), "options"))
        .collect();
    assert_eq!(
        codes(&parameters(&a6(&options[0]), &[&card_entry], ""), true),
        []
    );
    assert_eq!(
        codes(&parameters(&a6(&options[1]), &[&card_entry], ""), true),
        [(
            "PaSO alternatives involving its transaction data are not transposable (Core §7.4.1)"
                .to_owned(),
            ErrorCode::INVALID_TRANSACTION_DATA
        )]
    );
    assert_eq!(
        codes(&parameters(&a6(&options[2]), &[&card_entry], ""), true),
        []
    );
    let two_sets = r#"{"credentials": [{"id": "sca_card", "format": "dc+sd-jwt"}, {"id": "pid_1", "format": "dc+sd-jwt"}], "credential_sets": [{"options": [["sca_card"]]}, {"options": [["sca_card"], ["pid_1"]]}]}"#;
    assert_eq!(
        codes(&parameters(two_sets, &[&card_entry], ""), true),
        [(
            "PaSO transaction data names queries of more than one credential set (Core §7.4.1)"
                .to_owned(),
            ErrorCode::INVALID_TRANSACTION_DATA
        )]
    );
}
