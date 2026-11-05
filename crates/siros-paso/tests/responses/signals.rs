//! The default profile's signals, the payment hint, and an entry whose signals cannot be sent.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value as Json, json};
use siros_openid4vp::plugins::{Binding, Carriage, NoCandidate, Profile};
use siros_paso::PasoProfile;
use siros_paso::Reading;
use siros_paso::risk::DEFAULT_PROFILE;
use siros_testkit::Published;
use siros_testkit::verifier::ISSUER;

use crate::common::{Card, PAY, Screen, annex, en, member, parameters, request_app};

use super::{
    AMR, MODE, answer, card, host_with, ok, payment, payment_meta, proof, registry, registry_of,
};

/// Risk Signals A.6's issuer encryption key set.
pub(super) fn a6_keys() -> String {
    member(
        &annex("paso-proof-risk-signals.md", "A.6")[0],
        "risk_signals_encryption_keys",
    )
}

#[test]
pub(super) fn the_default_profiles_signals_are_enveloped_fresh_and_encrypted_to_the_issuers_key() {
    let entry_json = payment("");
    let parameters = parameters(
        r#"{"credentials": [{"id": "sca_card", "format": "dc+sd-jwt"}]}"#,
        &[&entry_json],
        "",
    );
    siros_testkit::signed_request!(let request = &parameters);
    let meta = payment_meta();
    let typed = format!(
        r#"{}, "risk_signal_profiles": ["{DEFAULT_PROFILE}"], "risk_signals": [{{"type": "{AMR}", "required": false}}]}}"#,
        meta.strip_suffix('}').expect("an object")
    );
    let card = card(
        &format!(r#"{{"{PAY}": {typed}}}"#),
        Some(&a6_keys()),
        ISSUER,
    );
    let host = host_with(vec![
        (
            "urn:paso:risk:global:geolocation:1",
            30,
            ok(r#"{"lat": 1.5}"#),
            true,
        ),
        (
            "urn:paso:risk:global:call_activity:1",
            30,
            Reading::Denied,
            true,
        ),
        (
            "urn:paso:risk:global:device_motion:1",
            601,
            ok(r#"{"w": 1}"#),
            true,
        ),
        (
            "urn:paso:risk:global:screen_capture:1",
            601,
            ok(r#"{"s": 1}"#),
            false,
        ),
        (
            "urn:paso:risk:global:device_basics:1",
            600,
            ok(r#"{"os": "x"}"#),
            true,
        ),
    ]);
    let response = answer(
        &request,
        &card,
        &registry(PasoProfile::default()),
        &Published::default(),
        &host,
    )
    .expect("answered");
    let sealed = proof(&response)["risk_signals"]
        .as_str()
        .expect("a JWE")
        .to_owned();
    let parts: Vec<&str> = sealed.split('.').collect();
    let decode = |part: &str| -> Json {
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).expect("base64url")).expect("json")
    };
    // Risk Signals A.5: the JWE's protected header.
    let a5: Json =
        serde_json::from_str(&annex("paso-proof-risk-signals.md", "A.5")[1]).expect("A.5");
    assert_eq!(decode(parts[0]), a5);
    let plaintext = decode(parts[3]);
    let read: Vec<(String, String, Json, String)> = plaintext
        .as_array()
        .expect("envelopes")
        .iter()
        .map(|e| {
            (
                e["type"]
                    .as_str()
                    .expect("type")
                    .split(':')
                    .nth(4)
                    .expect("name")
                    .to_owned(),
                e["status"].as_str().expect("status").to_owned(),
                e["value"].clone(),
                e["collected_at"].as_str().expect("collected_at").to_owned(),
            )
        })
        .collect();
    // Python's datetime of 1 785 000 000, less 30 and 600 seconds.
    let (now, ago_30, ago_600) = (
        "2026-07-25T17:20:00Z",
        "2026-07-25T17:19:30Z",
        "2026-07-25T17:10:00Z",
    );
    let envelope = |name: &str, status: &str, value: Json, at: &str| {
        (name.to_owned(), status.to_owned(), value, at.to_owned())
    };
    assert_eq!(
        read,
        [
            envelope("response_mode", "ok", json!("dc_api"), now),
            envelope("geolocation", "ok", json!({"lat": 1.5}), ago_30),
            envelope("call_activity", "denied", Json::Null, ago_30),
            envelope("device_motion", "ok", json!({"w": 1}), now),
            envelope("screen_capture", "unavailable", Json::Null, now),
            envelope("device_basics", "ok", json!({"os": "x"}), ago_600),
            envelope("app_vendor_id", "unavailable", Json::Null, now),
        ]
    );
    // Encrypted: the plaintext is json.dumps' default form.
    let text =
        String::from_utf8(URL_SAFE_NO_PAD.decode(parts[3]).expect("base64url")).expect("utf-8");
    assert!(
        text.starts_with(r#"[{"type": "urn:paso:risk:global:response_mode:1", "collected_at": ""#),
        "{text}"
    );
}

#[test]
pub(super) fn a_payment_entry_shows_the_security_hint_exactly_as_its_additional_information() {
    let entry_json = payment("");
    let parameters = parameters(
        r#"{"credentials": [{"id": "sca_card", "format": "dc+sd-jwt"}]}"#,
        &[&entry_json],
        "",
    );
    siros_testkit::signed_request!(let request = &parameters);
    let hint = "Never confirm a payment you did not start yourself.";
    let meta = payment_meta().replacen(
        r#""ui_labels": {"#,
        &format!(r#""ui_labels": {{"security_hint": [{{"locale": "en", "value": "{hint}"}}], "#),
        1,
    );
    let card = card(&format!(r#"{{"{PAY}": {meta}}}"#), None, ISSUER);
    let credential = card.credential();
    let additions = crate::common::additions(&credential);
    let offered: Vec<_> = request.indexed_entries().map(|(index, _)| index).collect();
    let bound = PasoProfile::default()
        .bind(
            Binding {
                request: &request,
                query: &request.queries()[0],
                credential: &credential,
                entries: &offered,
                placement: crate::common::placement(&credential.format),
                additions: &*additions,
                carriage: Carriage::Carried,
            },
            &en(),
        )
        .expect("binds");
    let locale = bound
        .attested
        .get("display_locale")
        .expect("display_locale");
    let screen = Screen::of(
        PAY,
        &meta,
        &en(),
        &siros_openid4vp::ids::LocaleTag::parse(locale).expect("a tag"),
    );
    let payment = bound.overlay.header.as_ref().expect("a payment");
    assert_eq!(
        (
            screen.plain(&payment.counterparty),
            screen.plain(&payment.amount)
        ),
        ("Shop Inc.".to_owned(), "€49.99".to_owned())
    );
    assert_eq!(
        bound.overlay.hint.as_ref().map(|shown| screen.plain(shown)),
        Some(hint.to_owned())
    );
    // The header shows merchant and amount: the overlay's rows leave them out.
    assert!(bound.overlay.rows.is_empty());
    assert_eq!(
        payment
            .rows
            .iter()
            .map(|r| screen.plain(&r.label))
            .collect::<Vec<_>>(),
        ["Payee", "Amount"]
    );
}

/// The entries the profile binds for a two-entry request, v2 first.
pub(super) fn versioned(card: &Card) -> Result<usize, String> {
    let v2 = payment("").replace(PAY, "urn:paso:sca:global:payment:2");
    let parameters = parameters(
        r#"{"credentials": [{"id": "sca_card", "format": "dc+sd-jwt"}]}"#,
        &[&v2, &payment("")],
        "",
    );
    siros_testkit::signed_request!(let request = &parameters);
    let credential = card.credential();
    let additions = crate::common::additions(&credential);
    let offered: Vec<_> = request.indexed_entries().map(|(index, _)| index).collect();
    match PasoProfile::default().bind(
        Binding {
            request: &request,
            query: &request.queries()[0],
            credential: &credential,
            entries: &offered,
            placement: crate::common::placement(&credential.format),
            additions: &*additions,
            carriage: Carriage::Carried,
        },
        &en(),
    ) {
        Ok(bound) => Ok(bound.entries.entries()[0].get()),
        Err(NoCandidate::Excluded(exclude)) => Err(exclude.clause().into_owned()),
        Err(NoCandidate::Fault(fault)) => panic!("{fault}"),
    }
}

#[test]
pub(super) fn an_entry_whose_risk_signals_the_wallet_cannot_send_gives_way_to_the_next() {
    let v1 = payment_meta();
    let v2 = |members: &str| format!(r#"{}{members}}}"#, v1.strip_suffix('}').expect("an object"));
    let types = |members: &str| {
        format!(
            r#"{{"urn:paso:sca:global:payment:2": {}, "{PAY}": {v1}}}"#,
            v2(members)
        )
    };
    let keys = a6_keys();
    let rsa = keys.replace(r#""alg": "ECDH-ES""#, r#""alg": "RSA-OAEP""#);
    assert_ne!(rsa, keys);
    // §7.3: encryption without a key the wallet can use; §4.1: a profile it does not hold.
    assert_eq!(
        versioned(&card(&types(r#", "encrypted": true"#), None, ISSUER)),
        Ok(1)
    );
    assert_eq!(
        versioned(&card(
            &types(r#", "risk_signal_profiles": ["urn:paso:risk-profile:com.example:x:1"]"#),
            None,
            ISSUER
        )),
        Ok(1)
    );
    assert_eq!(
        versioned(&card(
            &types(&format!(
                r#", "risk_signal_profiles": ["{DEFAULT_PROFILE}"]"#
            )),
            Some(&keys),
            ISSUER
        )),
        Ok(0)
    );
    assert_eq!(
        versioned(&card(&types(r#", "encrypted": true"#), Some(&rsa), ISSUER)),
        Ok(1)
    );
}

#[test]
pub(super) fn the_authentication_methods_are_rfc_8176_values_and_one_biometric_class() {
    use std::num::NonZeroU32;

    use siros_explain::AllOf;
    use siros_openid4vp::host::{
        AttackDetection, Authentication, Factor, FalseAcceptRate, Inherence, Isolation, Knowledge,
        Modality, Possession, Sensor, Timestamp,
    };
    use siros_paso::amr::{BiometricClass, methods};

    let facts = |isolation, attempts: u32, attack_detection| Inherence {
        modality: Modality::Face,
        sensor: Sensor::Device,
        isolation,
        false_accepts: NonZeroU32::new(attempts).map(FalseAcceptRate::one_in),
        attack_detection,
    };
    // Registry §2.8: bio_strong needs hardware isolation, FAR 1:50,000 or less, and presentation
    // attack detection; bio_weak needs FAR 1:10,000 or less; an unreported FAR meets neither.
    let strong = Some(BiometricClass::Strong);
    let weak = Some(BiometricClass::Weak);
    let classes = [
        (
            facts(Isolation::Hardware, 50_000, AttackDetection::Present),
            strong,
        ),
        (
            facts(Isolation::Hardware, 1_000_000, AttackDetection::Present),
            strong,
        ),
        (
            facts(Isolation::None, 50_000, AttackDetection::Present),
            weak,
        ),
        (
            facts(Isolation::Unreported, 50_000, AttackDetection::Present),
            weak,
        ),
        (
            facts(Isolation::Hardware, 49_999, AttackDetection::Present),
            weak,
        ),
        (
            facts(Isolation::Hardware, 50_000, AttackDetection::Absent),
            weak,
        ),
        (
            facts(Isolation::Hardware, 50_000, AttackDetection::Unreported),
            weak,
        ),
        (
            facts(Isolation::None, 10_000, AttackDetection::Absent),
            weak,
        ),
        (
            facts(Isolation::Hardware, 9_999, AttackDetection::Present),
            None,
        ),
        (
            facts(Isolation::Hardware, 0, AttackDetection::Present),
            None,
        ),
    ];
    for (inherence, class) in classes {
        assert_eq!(BiometricClass::of(&inherence), class, "{inherence:?}");
    }
    let strong = facts(Isolation::Hardware, 50_000, AttackDetection::Present);
    let weak = facts(Isolation::None, 10_000, AttackDetection::Present);
    let unclassed = facts(Isolation::Hardware, 9_999, AttackDetection::Present);
    let inherence = |modality, facts: Inherence| Factor::Inherence(Inherence { modality, ..facts });
    // RFC 8176 §2 and Risk Signal Registry §2.8, by hand.
    let cases: [(Vec<Factor>, Option<Json>); 7] = [
        (
            vec![
                Factor::Knowledge(Knowledge::Pin(NonZeroU32::new(6))),
                Factor::Possession(Possession::LocalNativeWscd),
            ],
            Some(json!(["pin", "hwk"])),
        ),
        (
            vec![
                Factor::Possession(Possession::Software),
                Factor::Knowledge(Knowledge::Passphrase(None)),
            ],
            Some(json!(["swk", "pwd"])),
        ),
        (
            vec![
                Factor::Possession(Possession::RemoteWscd),
                inherence(Modality::Face, strong),
            ],
            Some(json!(["hwk", "bio_strong", "face"])),
        ),
        (
            vec![
                inherence(Modality::Fingerprint, weak),
                inherence(Modality::Unknown, strong),
                Factor::Knowledge(Knowledge::Pattern),
                Factor::Knowledge(Knowledge::Unknown),
            ],
            Some(json!(["pin", "kba", "bio_strong", "fpt"])),
        ),
        (
            vec![
                Factor::Knowledge(Knowledge::Pin(None)),
                Factor::Knowledge(Knowledge::Pin(NonZeroU32::new(4))),
                inherence(Modality::Iris, weak),
            ],
            Some(json!(["pin", "bio_weak", "iris"])),
        ),
        (
            vec![
                inherence(Modality::Face, unclassed),
                inherence(Modality::Fingerprint, weak),
            ],
            Some(json!(["bio_weak", "face", "fpt"])),
        ),
        (
            vec![
                Factor::Knowledge(Knowledge::Pin(None)),
                inherence(Modality::Face, unclassed),
            ],
            None,
        ),
    ];
    for (factors, want) in cases {
        let all = factors
            .iter()
            .copied()
            .map(AllOf::one)
            .reduce(AllOf::and)
            .expect("one factor or more");
        let authentication = Authentication::new(Timestamp(0), all);
        let got: Option<Json> = methods(&authentication).map(|methods| {
            serde_json::from_str(&methods.python_compact().to_string()).expect("json")
        });
        assert_eq!(got, want, "{factors:?}");
    }
}

#[test]
pub(super) fn a_build_without_cose_encrypt_falls_back_before_authentication_on_an_mdocs_sealed_signals()
 {
    use siros_openid4vp::effects::{Fetch, Resource};
    use siros_openid4vp::host::{ProfileHost, Timestamp};
    use siros_openid4vp::ids::FormatId;
    use siros_openid4vp::matching::{Accepted, Match};
    use siros_openid4vp::plugins::{Answered, Attested, BoundEntries, Member, MemberValue};
    use siros_openid4vp::resolve::{Finding, Outcome as Phase2};
    use siros_openid4vp::wallet::Wallet;
    use siros_paso::outcome::{NotCompatible, Outcome};
    use siros_paso::sca::NAMESPACE;
    use siros_paso::{OptionalModule, PasoFinding};
    use siros_testkit::pin_and_device;

    use crate::paso_host::{PasoHost, SealerlessHost};

    // Risk Signals §7.6: an mdoc seals its signals in a COSE_Encrypt, an SD-JWT VC in a JWE.
    let entry_json = payment("");
    let meta = payment_meta();
    let sealed = format!(
        r#"{}, "encrypted": true, "risk_signals": [{{"type": "{MODE}", "required": true}}]}}"#,
        meta.strip_suffix('}').expect("an object")
    );
    let at = Timestamp(super::NOW);
    for (format, needs_cose) in [("mso_mdoc", true), ("dc+sd-jwt", false)] {
        let parameters = parameters(
            &format!(r#"{{"credentials": [{{"id": "sca_card", "format": "{format}"}}]}}"#),
            &[&entry_json],
            "",
        );
        siros_testkit::signed_request!(let request = &parameters);
        let mut card = Card::new(
            format,
            &format!(r#"{{"{PAY}": {sealed}}}"#),
            Some(&a6_keys()),
            ISSUER,
        );
        card.view = r#"{"answers":["sca_card"],"alg":"A"}"#.to_owned();
        let without = SealerlessHost {
            platform: siros_testkit::TestPlatform::at(at),
            paso: siros_paso::TestPaso::at(at),
            random_ids: siros_paso::TestRandomIds::default(),
        };
        let registry = registry_of::<SealerlessHost>(format, PasoProfile::default());
        let outcome = answer(&request, &card, &registry, &Published::default(), &without);
        if !needs_cose {
            if let Err(outcome) = outcome {
                panic!("{format}: {outcome}");
            }
            assert_eq!(without.platform.authentications(), 1, "{format}");
            continue;
        }
        let Err(Phase2::Fallback(findings)) = outcome else {
            panic!("{format}: phase 2 falls back");
        };
        assert_eq!(without.platform.authentications(), 0, "{format}");
        // With the module, the record revalidates and its risk signals are sealed. The test
        // format's proof carries no mdoc members, so the control stops at the profile.
        let credential = card.credential();
        let offered: Vec<_> = request.indexed_entries().map(|(index, _)| index).collect();
        let entries = BoundEntries::select(&offered, offered.clone()).expect("entries");
        let attested = Attested::new(vec![
            ("display_locale".to_owned(), "en".to_owned()),
            ("metadata_integrity".to_owned(), card.integrity()),
        ])
        .expect("attested");
        let format_id = FormatId::parse(format).expect("format");
        let record = || {
            Answered::new(
                &request,
                &credential,
                &entries,
                &attested,
                crate::common::placement(&format_id),
                siros_testkit::fixtures::mode_of(&request).expect("a mode"),
            )
        };
        let held = PasoHost::at(at);
        let profile = PasoProfile::default();
        assert_eq!(
            record()
                .revalidate(&profile, |_: &Resource| Fetch::Unfetched, &held)
                .expect("no fault"),
            None
        );
        let members = profile
            .respond(record(), &held, &pin_and_device(at))
            .expect("members");
        assert!(members.iter().any(|(member, value)| {
            *member == Member::element(NAMESPACE, "risk_signals")
                && matches!(value, MemberValue::Cbor(_))
        }));
        let [Finding::Revalidation { finding, .. }] = findings.items() else {
            panic!("{findings:?}");
        };
        let data = finding.data::<PasoFinding>().expect("a PaSO finding");
        assert_eq!(data.lacks(), Some(OptionalModule::CoseEncrypt));
        // The re-run over the registry informed of the finding offers the entry no more.
        let wallet = Wallet::new(vec![card.credential()]).expect("wallet");
        let informed = registry.informed(&[finding]).expect("informed");
        let accepted = Accepted::new(&request, &informed).expect("accepted");
        let app = request_app(&request, &[&card], &en());
        let rendering = app.rendering().expect("the rendering");
        let again = Match::run(&accepted, &wallet, &en(), &rendering).expect("match");
        let query = request.indexed_queries().next().expect("query").0;
        assert_eq!(again.candidates(query).len(), 0);
        let entry = request.entries().first().expect("an entry");
        let rendered = <PasoProfile as ProfileHost<SealerlessHost>>::informed(
            &PasoProfile::default(),
            &[data],
        )
        .render(
            entry,
            &card.credential(),
            crate::common::placement(&card.credential().format),
            &en(),
        )
        .expect("no fault");
        assert_eq!(
            rendered.err(),
            Some(Outcome::NotCompatible(NotCompatible::Lacks(
                OptionalModule::CoseEncrypt
            )))
        );
    }
}

#[test]
pub(super) fn an_sd_jwts_signals_are_sealed_to_the_first_issuer_key_the_haip_module_states() {
    use siros_openid4vp::host::Haip;
    use siros_openid4vp::resolve::{Finding, Outcome as Phase2};
    use siros_paso::PasoFinding;
    use siros_testkit::TestHaip;

    // TestHaip states ECDH-ES on P-256; A.6's key is one, the same point under a key wrap is not.
    let a6: Json = serde_json::from_str(&a6_keys()).expect("A.6");
    let mut wrapped = a6["keys"][0].clone();
    wrapped["alg"] = json!("ECDH-ES+A128KW");
    wrapped["kid"] = json!("issuer-enc-wrapped");
    let entry_json = payment("");
    let parameters = parameters(
        r#"{"credentials": [{"id": "sca_card", "format": "dc+sd-jwt"}]}"#,
        &[&entry_json],
        "",
    );
    siros_testkit::signed_request!(let request = &parameters);
    let meta = payment_meta();
    let sealed = format!(
        r#"{}, "encrypted": true, "risk_signals": [{{"type": "{MODE}", "required": true}}]}}"#,
        meta.strip_suffix('}').expect("an object")
    );
    let run = |keys: Json| {
        let card = card(
            &format!(r#"{{"{PAY}": {sealed}}}"#),
            Some(&keys.to_string()),
            ISSUER,
        );
        answer(
            &request,
            &card,
            &registry(PasoProfile::default()),
            &Published::default(),
            &host_with(Vec::new()),
        )
    };
    let response = run(json!({"keys": [wrapped, a6["keys"][0]]})).expect("answered");
    let jwe = proof(&response)["risk_signals"]
        .as_str()
        .expect("a JWE")
        .to_owned();
    let header: Json = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(jwe.split('.').next().expect("a header"))
            .expect("base64url"),
    )
    .expect("json");
    assert_eq!(header["kid"], a6["keys"][0]["kid"]);
    // With the wrapped key alone, phase 2 finds no key the module seals to before it seals.
    let Err(Phase2::Fallback(findings)) = run(json!({"keys": [wrapped]})) else {
        panic!("phase 2 falls back");
    };
    let [Finding::Revalidation { finding, .. }] = findings.items() else {
        panic!("{findings:?}");
    };
    assert_eq!(
        finding
            .data::<PasoFinding>()
            .and_then(PasoFinding::unsealable),
        Some(TestHaip.agreements())
    );
}
