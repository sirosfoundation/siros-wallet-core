//! Ad-hoc metadata, the images phase 2 revalidates, what phase 2 answers, and `collected_at`.

use serde_json::{Value as Json, json};
use siros_openid4vp::effects::MediaType;
use siros_openid4vp::host::Timestamp;
use siros_openid4vp::matching::{Accepted, Match, Views};
use siros_openid4vp::plugins::ProfileFinding;
use siros_openid4vp::request::Request;
use siros_openid4vp::resolve::{Finding, Outcome as Phase2, Prepared};
use siros_openid4vp::rows::{HttpsUrl, Shown};
use siros_openid4vp::wallet::Wallet;
use siros_paso::adhoc::TrustAnchor;
use siros_paso::{PasoFinding, PasoProfile};
use siros_testkit::verifier::{ISSUER, adhoc_jwt};
use siros_testkit::{Published, PublishedResource};

use crate::paso_host::PasoHost;

use crate::common::{CARD_TYPE, Card, PAY, annex, en, parameters, png, request_app, sri};

use super::{NOW, answer, card, digest_b64, payment, payment_meta, proof, registry};

/// The SCA claims of the response to a payment with ad-hoc metadata, the clause excluding the
/// card, or the finding phase 2 falls back on with the number of candidates the match informed
/// of it finds.
pub(super) fn adhoc_case(
    jwt: &str,
    card: &Card,
    profile: PasoProfile,
) -> Result<Vec<String>, AdhocOutcome> {
    let entry_json = payment(&format!(r#", "metadata": "{jwt}""#));
    let parameters = parameters(
        r#"{"credentials": [{"id": "sca_card", "format": "dc+sd-jwt"}]}"#,
        &[&entry_json],
        "",
    );
    siros_testkit::signed_request!(let request = &parameters);
    let registry = registry(profile);
    let host = PasoHost::at(Timestamp(NOW));
    let credential = card.credential();
    let wallet = Wallet::new(vec![credential.clone()]).expect("wallet");
    let app = request_app(&request, &[card], &en());
    let rendering = app.rendering().expect("the rendering");
    {
        let accepted = Accepted::new(&request, &registry).expect("accepted");
        let matched = Match::run(&accepted, &wallet, &en(), &rendering).expect("match");
        if let Some(excluded) = matched.excluded().first() {
            return Err(AdhocOutcome::Excluded(excluded.exclude.rule().to_string()));
        }
    }
    match answer(&request, card, &registry, &Published::default(), &host) {
        Ok(response) => {
            let proof = proof(&response);
            let mut names: Vec<String> = proof
                .as_object()
                .expect("proof")
                .keys()
                .filter(|k| !["aud", "nonce"].contains(&k.as_str()))
                .cloned()
                .collect();
            names.sort();
            Ok(names)
        }
        Err(Phase2::Fallback(findings)) => {
            let [Finding::Revalidation { finding, .. }] = findings.items() else {
                panic!("{findings:?}");
            };
            let data = finding
                .data::<PasoFinding>()
                .expect("a PaSO finding")
                .clone();
            let profile_findings: Vec<&ProfileFinding> = vec![finding];
            let informed = registry.informed(&profile_findings).expect("informed");
            let accepted = Accepted::new(&request, &informed).expect("accepted");
            let again = Match::run(&accepted, &wallet, &en(), &rendering).expect("match");
            let query = request.indexed_queries().next().expect("query").0;
            Err(AdhocOutcome::Fallback(data, again.candidates(query).len()))
        }
        Err(other) => panic!("{other}"),
    }
}

#[derive(Debug, PartialEq)]
pub(super) enum AdhocOutcome {
    Excluded(String),
    Fallback(PasoFinding, usize),
}

pub(super) fn adhoc_claims(iss: &str, exp: u64) -> String {
    format!(
        r#"{{"iss": "{iss}", "sub": "{CARD_TYPE}", "format": "dc+sd-jwt", "iat": {}, "exp": {exp}, "transaction_data_type": "{PAY}", "metadata": {}}}"#,
        NOW - 60,
        payment_meta()
    )
}

#[test]
pub(super) fn ad_hoc_metadata_renders_a_type_the_stored_metadata_lacks_until_it_expires() {
    let claims = adhoc_claims("https://issuer.bank.example", NOW + 600);
    let a2: Json = serde_json::from_str(&annex("paso-core.md", "A.2")[0]).expect("A.2");
    let mut sca: Vec<String> = a2
        .as_object()
        .expect("A.2")
        .keys()
        .filter(|k| {
            ![
                "aud",
                "iat",
                "nonce",
                "sd_hash",
                "risk_signals",
                "metadata_integrity",
            ]
            .contains(&k.as_str())
        })
        .cloned()
        .collect();
    sca.sort();
    let keyed = adhoc_jwt(&claims, "issuer-secret-1", Some("issuer-key-1"), None).expect("jwt");
    // A valid JWT renders a type the stored metadata lacks; metadata_integrity stays out (Core
    // §6.1).
    assert_eq!(
        adhoc_case(&keyed, &card("{}", None, ISSUER), PasoProfile::default()),
        Ok(sca.clone())
    );
    let x5c_issuer = r#"{"iss": "https://issuer.bank.example", "x5c": {"root": "CN=Bank Root", "subject": "CN=Bank Issuer"}}"#;
    let chained = adhoc_jwt(
        &claims,
        "leaf-secret",
        None,
        Some(r#"{"root": "CN=Bank Root", "subject": "CN=Bank Issuer", "key": "leaf-secret"}"#),
    )
    .expect("jwt");
    assert_eq!(
        adhoc_case(
            &chained,
            &card("{}", None, x5c_issuer),
            PasoProfile::default().with_trust(TrustAnchor("CN=Bank Root".to_owned()))
        ),
        Ok(sca)
    );
    // Failing a check of §5.3 leaves no compatible entry, the stored metadata never standing in.
    let failed = adhoc_jwt(&claims, "wrong", Some("issuer-key-1"), None).expect("jwt");
    let listing = card(&format!(r#"{{"{PAY}": {}}}"#, payment_meta()), None, ISSUER);
    assert_eq!(
        adhoc_case(&failed, &listing, PasoProfile::default()),
        Err(AdhocOutcome::Excluded(
            "no PaSO entry is compatible with the credential".to_owned()
        ))
    );
    // Expired by the time phase 2 answers (§5.3 step 5; the matcher reads no clock): the matcher
    // offered it, phase 2 falls back; informed, the matcher no longer binds it.
    let late = adhoc_jwt(
        &adhoc_claims("https://issuer.bank.example", NOW),
        "issuer-secret-1",
        Some("issuer-key-1"),
        None,
    )
    .expect("jwt");
    assert_eq!(
        adhoc_case(&late, &card("{}", None, ISSUER), PasoProfile::default()),
        Err(AdhocOutcome::Fallback(
            PasoFinding::of(None, None, Some(late.clone()), Vec::new()).expect("a finding"),
            0
        ))
    );
}

#[test]
pub(super) fn phase_2_fetches_the_images_the_matcher_could_not_and_falls_back_when_one_fails() {
    let logo = png(16, 16);
    let url = "https://cdn.example/l.png";
    let v2 = format!(
        r#"{{"type": "urn:paso:sca:global:payment:2", "credential_ids": ["sca_card"], "payload": {{"transaction_id": "t", "amount": "1.00 EUR", "payee": {{"name": "Shop", "id": "DE1", "logo": "{url}", "logo#integrity": "{}"}}}}}}"#,
        sri(&logo)
    );
    let v1 = payment("");
    let parameters = parameters(
        r#"{"credentials": [{"id": "sca_card", "format": "dc+sd-jwt"}]}"#,
        &[&v2, &v1],
        "",
    );
    siros_testkit::signed_request!(let request = &parameters);
    let meta = payment_meta();
    let card = card(
        &format!(r#"{{"urn:paso:sca:global:payment:2": {meta}, "{PAY}": {meta}}}"#),
        None,
        ISSUER,
    );
    // The matcher binds the first entry; phase 2 fetches the logo, it verifies, and the
    // response hashes the entry the display showed.
    let published = Published::new(vec![PublishedResource {
        url: HttpsUrl::parse(url).expect("url"),
        content: logo,
        media: MediaType::parse("image/png").expect("media type"),
    }]);
    let response = answer(
        &request,
        &card,
        &registry(PasoProfile::default()),
        &published,
        &PasoHost::at(Timestamp(NOW)),
    )
    .expect("answered");
    assert_eq!(
        proof(&response)["transaction_data_hash"],
        json!(digest_b64(request.entries()[0].raw()))
    );
    // Its fetch fails: phase 2 falls back; informed, first match moves to the next entry, and
    // the response hashes that one.
    let registry = registry(PasoProfile::default());
    let Err(Phase2::Fallback(findings)) = answer(
        &request,
        &card,
        &registry,
        &Published::default(),
        &PasoHost::at(Timestamp(NOW)),
    ) else {
        panic!("phase 2 falls back");
    };
    let [Finding::Revalidation { finding, .. }] = findings.items() else {
        panic!("{findings:?}");
    };
    let data = finding.data::<PasoFinding>().expect("a PaSO finding");
    assert_eq!(
        data.failed()
            .iter()
            .map(|f| f.url.as_str())
            .collect::<Vec<_>>(),
        [url]
    );
    let informed = registry.informed(&[finding]).expect("informed");
    let response = answer(
        &request,
        &card,
        &informed,
        &Published::default(),
        &PasoHost::at(Timestamp(NOW)),
    )
    .expect("answered");
    assert_eq!(
        proof(&response)["transaction_data_hash"],
        json!(digest_b64(request.entries()[1].raw()))
    );
    // An https URL whose host has no A-label form: the matcher shows it pending as any https
    // image; no fetch reaches it, and phase 2 falls back the same way.
    let unreachable = "https://\u{301}x.example/l.png";
    assert!(
        matches!(HttpsUrl::shown(unreachable), Ok(Shown::Unreachable(_)))
            && HttpsUrl::parse(unreachable).is_err()
    );
    let unreachable_v2 = v2.replace(url, unreachable);
    let unreachable_parameters = crate::common::parameters(
        r#"{"credentials": [{"id": "sca_card", "format": "dc+sd-jwt"}]}"#,
        &[&unreachable_v2, &v1],
        "",
    );
    siros_testkit::signed_request!(let request = &unreachable_parameters);
    let registry = crate::registry(PasoProfile::default());
    let Err(Phase2::Fallback(findings)) = answer(
        &request,
        &card,
        &registry,
        &Published::default(),
        &PasoHost::at(Timestamp(NOW)),
    ) else {
        panic!("phase 2 falls back");
    };
    let [Finding::Revalidation { finding, .. }] = findings.items() else {
        panic!("{findings:?}");
    };
    let data = finding.data::<PasoFinding>().expect("a PaSO finding");
    assert_eq!(
        data.failed()
            .iter()
            .map(|f| f.url.as_str())
            .collect::<Vec<_>>(),
        [unreachable]
    );
    let informed = registry.informed(&[finding]).expect("informed");
    let response = answer(
        &request,
        &card,
        &informed,
        &Published::default(),
        &PasoHost::at(Timestamp(NOW)),
    )
    .expect("answered");
    assert_eq!(
        proof(&response)["transaction_data_hash"],
        json!(digest_b64(request.entries()[1].raw()))
    );
}

#[test]
pub(super) fn phase_2_answers_only_the_request_and_records_the_matcher_displayed() {
    let meta = payment_meta();
    let card = card(&format!(r#"{{"{PAY}": {meta}}}"#), None, ISSUER);
    let shown_entry = payment("");
    let shown_parameters = parameters(
        r#"{"credentials": [{"id": "sca_card", "format": "dc+sd-jwt"}]}"#,
        &[&shown_entry],
        "",
    );
    siros_testkit::signed_request!(let shown_request = &shown_parameters);
    let registry = registry(PasoProfile::default());
    let credential = card.credential();
    let wallet = Wallet::new(vec![credential]).expect("wallet");
    let env = en();
    let app = request_app(&shown_request, &[&card], &env);
    let rendering = app.rendering().expect("the rendering");
    let accepted = Accepted::new(&shown_request, &registry).expect("accepted");
    let matched = Match::run(&accepted, &wallet, &env, &rendering).expect("match");
    let views = Views::of(&matched, &env).expect("views");
    let id = views
        .iter()
        .next()
        .expect("a view")
        .record
        .id()
        .as_str()
        .to_owned();
    let outcome = |request: &Request<'_>, id: &str| -> Result<(), Vec<String>> {
        let host = PasoHost::at(Timestamp(NOW));
        let authenticated =
            siros_testkit::fixtures::authenticate(request.envelope(), &registry, &host)
                .expect("authentic");
        let ids: &[&str] = &[id];
        match Prepared::prepare(&authenticated, ids, &wallet, &registry, &env, &rendering).and_then(
            |prepared| prepared.respond(|resource| Published::default().answer(resource), &host),
        ) {
            Ok(_) => Ok(()),
            Err(Phase2::Fallback(findings)) => Err(findings
                .items()
                .iter()
                .map(|f| {
                    format!("{f:?}")
                        .split_whitespace()
                        .next()
                        .unwrap_or_default()
                        .to_owned()
                })
                .collect()),
            Err(other) => panic!("{other}"),
        }
    };
    // The amount changed after the display: every record diverges.
    let swapped_entry = shown_entry.replace("49.99 EUR", "4999.00 EUR");
    let swapped_parameters = parameters(
        r#"{"credentials": [{"id": "sca_card", "format": "dc+sd-jwt"}]}"#,
        &[&swapped_entry],
        "",
    );
    siros_testkit::signed_request!(let swapped = &swapped_parameters);
    assert_eq!(outcome(&swapped, &id), Err(vec!["Diverged".to_owned()]));
    // A record whose attested locale changed diverges too.
    let altered = id.replace(r#""display_locale":"en""#, r#""display_locale":"de""#);
    assert_ne!(altered, id);
    assert_eq!(
        outcome(&shown_request, &altered),
        Err(vec!["Diverged".to_owned()])
    );
    assert_eq!(outcome(&shown_request, &id), Ok(()));
}

#[test]
pub(super) fn collected_at_is_the_instants_utc_civil_time() {
    // Risk Signals §2.2's form; the dates as GNU date writes them for each instant, across the
    // leap rules of 4, 100 and 400 years and the last second of year 9999.
    let known: [(u64, Option<&str>); 13] = [
        (0, Some("1970-01-01T00:00:00Z")),
        (68_169_600, Some("1972-02-29T00:00:00Z")),
        (946_684_799, Some("1999-12-31T23:59:59Z")),
        (951_782_400, Some("2000-02-29T00:00:00Z")),
        (951_868_799, Some("2000-02-29T23:59:59Z")),
        (1_078_099_199, Some("2004-02-29T23:59:59Z")),
        (1_709_251_199, Some("2024-02-29T23:59:59Z")),
        (1_785_000_000, Some("2026-07-25T17:20:00Z")),
        (4_107_542_399, Some("2100-02-28T23:59:59Z")),
        (4_107_542_400, Some("2100-03-01T00:00:00Z")),
        (13_574_649_599, Some("2400-02-29T23:59:59Z")),
        (253_402_300_799, Some("9999-12-31T23:59:59Z")),
        (253_402_300_800, None),
    ];
    for (instant, want) in known {
        assert_eq!(
            siros_paso::respond::stamp(Timestamp(instant)).as_deref(),
            want,
            "{instant}"
        );
    }
}
