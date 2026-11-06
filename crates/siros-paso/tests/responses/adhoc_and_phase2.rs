//! Ad-hoc metadata, the images phase 2 revalidates, what phase 2 answers, and `collected_at`.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value as Json, json};
use siros_openid4vp::effects::MediaType;
use siros_openid4vp::host::Timestamp;
use siros_openid4vp::matching::{Accepted, Match, Views};
use siros_openid4vp::plugins::ProfileFinding;
use siros_openid4vp::request::Request;
use siros_openid4vp::resolve::{Finding, Outcome as Phase2, Prepared};
use siros_openid4vp::routing::ChannelKind;
use siros_openid4vp::rows::{HttpsUrl, Shown};
use siros_openid4vp::wallet::Wallet;
use siros_paso::adhoc::{AdhocFailure, AdhocJwt, AdhocRefusal, Verified};
use siros_paso::outcome::{NotCompatible, Outcome};
use siros_paso::{PasoFinding, PasoProfile};
use siros_testkit::verifier::{ISSUER, adhoc_jwt, secret_key};
use siros_testkit::{Published, PublishedResource};
use siros_x509::test_util as x509;

use crate::paso_host::PasoHost;

use crate::common::{
    CARD_TYPE, Card, ExcludedBy, PAY, annex, en, parameters, png, request_app, sri,
};

use super::{NOW, answer, card, digest_b64, payment, payment_meta, proof, registry};

/// The SCA claims of the response to a payment with ad-hoc metadata, the rule excluding the
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
            return Err(AdhocOutcome::Excluded(ExcludedBy::of(&excluded.exclude)));
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
            Err(AdhocOutcome::Fallback(
                Box::new(data),
                again.candidates(query).len(),
            ))
        }
        Err(other) => panic!("{other}"),
    }
}

#[derive(Debug, PartialEq)]
pub(super) enum AdhocOutcome {
    Excluded(ExcludedBy),
    Fallback(Box<PasoFinding>, usize),
}

pub(super) fn adhoc_claims(iss: &str, exp: u64) -> String {
    format!(
        r#"{{"iss": "{iss}", "sub": "{CARD_TYPE}", "format": "dc+sd-jwt", "iat": {}, "exp": {exp}, "transaction_data_type": "{PAY}", "metadata": {}}}"#,
        NOW - 60,
        payment_meta()
    )
}

/// The scalar of the ad-hoc metadata's x5c leaf.
const LEAF: [u8; 32] = [5; 32];

/// An x5c chain of a leaf of this subject under siros-x509's test root, the root in the host's
/// trust store.
fn chain(subject: &str) -> Vec<String> {
    x509::x5c(&x509::certificate(&x509::Leaf {
        subject,
        point: x509::point(&LEAF),
        dns: &[],
    }))
}

/// An issuer whose keys an x5c chain certifies: the credential's own chain's root and leaf
/// subject.
fn chained_issuer(root: &[u8], subject: &str) -> String {
    format!(
        r#"{{"iss": "https://issuer.bank.example", "x5c": {{"root": "{}", "subject": "{}"}}}}"#,
        STANDARD.encode(root),
        STANDARD.encode(x509::name(subject))
    )
}

/// The SCA claims PaSO Core A.2 shows, without those the wallet leaves out for ad-hoc metadata
/// (`metadata_integrity`, Core §6.1) or the test does not compare.
fn sca_claims() -> Vec<String> {
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
    sca
}

#[test]
pub(super) fn ad_hoc_metadata_renders_a_type_the_stored_metadata_lacks() {
    let claims = adhoc_claims("https://issuer.bank.example", NOW + 600);
    let keyed = adhoc_jwt(
        &claims,
        &secret_key("issuer-secret-1"),
        Some("issuer-key-1"),
        None,
    )
    .expect("a keyed JWT");
    assert_eq!(
        adhoc_case(&keyed, &card("{}", None, ISSUER), PasoProfile::default()),
        Ok(sca_claims())
    );
    let chained =
        adhoc_jwt(&claims, &LEAF, None, Some(&chain("Bank Issuer"))).expect("a chained JWT");
    let issuer = chained_issuer(&x509::root(), "Bank Issuer");
    assert_eq!(
        adhoc_case(&chained, &card("{}", None, &issuer), PasoProfile::default()),
        Ok(sca_claims())
    );
    // In the URI flow the wallet relies on the JWT once it verified it for the credential.
    let card = card("{}", None, ISSUER);
    let (request_parameters, credential) = (adhoc_parameters(&keyed), card.credential());
    siros_testkit::signed_request!(let request = &request_parameters);
    let verified = Verified::of(&request, &[&credential], &PasoHost::at(Timestamp(NOW)))
        .expect("the PaSO document reads");
    assert!(verified.refusals().is_empty(), "{:?}", verified.refusals());
    assert!(
        uri_rendering(
            &PasoProfile::default().with_verified(&verified),
            &request,
            &card
        )
        .is_ok()
    );
    assert_eq!(
        uri_rendering(&PasoProfile::default(), &request, &card).err(),
        Some(AdhocFailure::Unverified),
        "unverified"
    );
}

/// The parameters of a request whose one payment entry carries the ad-hoc metadata JWT.
fn adhoc_parameters(jwt: &str) -> String {
    parameters(
        r#"{"credentials": [{"id": "sca_card", "format": "dc+sd-jwt"}]}"#,
        &[&payment(&format!(r#", "metadata": "{jwt}""#))],
        "",
    )
}

/// The request's one entry as the profile renders it for the card in the URI flow: the step of
/// §5.3 its ad-hoc metadata JWT fails for the card when it is not rendered.
fn uri_rendering(
    profile: &PasoProfile,
    request: &Request<'_>,
    card: &Card,
) -> Result<(), AdhocFailure> {
    let credential = card.credential();
    match profile
        .render(
            &request.entries()[0],
            ChannelKind::Uri,
            &credential,
            crate::common::placement(&credential.format),
            &en(),
        )
        .expect("no fault")
    {
        Ok(_) => Ok(()),
        Err(Outcome::NotCompatible(NotCompatible::Adhoc(failure))) => Err(failure),
        Err(other) => panic!("{other}"),
    }
}

#[test]
pub(super) fn a_jwt_failing_a_step_of_proof_metadata_5_3_is_refused_in_phase_2_and_before_conversion()
 {
    let iss = "https://issuer.bank.example";
    let claims = adhoc_claims(iss, NOW + 600);
    let keyed = |claims: &str, key: &[u8; 32], kid: &str| {
        adhoc_jwt(claims, key, Some(kid), None).expect("a keyed JWT")
    };
    let typed = siros_testkit::jose::compact_jws(
        &secret_key("issuer-secret-1"),
        r#"{"alg": "ES256", "typ": "JWT", "kid": "issuer-key-1"}"#,
        &siros_testkit::verifier::python_json(&claims).expect("claims"),
    )
    .expect("a JWT typed JWT");
    let keys = ISSUER.to_owned();
    let other_root = x509::certificate(&x509::Leaf {
        subject: "Other Root",
        point: x509::point(&[3; 32]),
        dns: &[],
    });
    let elsewhere = adhoc_jwt(
        &claims,
        &LEAF,
        None,
        Some(&[
            chain("Bank Issuer")[0].clone(),
            STANDARD.encode(&other_root),
        ]),
    )
    .expect("a JWT chained elsewhere");
    let chained = adhoc_jwt(&claims, &LEAF, None, Some(&chain("Bank Issuer"))).expect("chained");
    let cases: Vec<(&str, String, String, AdhocFailure)> = vec![
        (
            "step 1",
            typed,
            keys.clone(),
            AdhocFailure::Typ(Some("JWT".to_owned())),
        ),
        (
            "step 2",
            keyed(&claims, &secret_key("another-secret"), "issuer-key-1"),
            keys.clone(),
            AdhocFailure::Signature,
        ),
        (
            "step 3, key set",
            keyed(&claims, &secret_key("issuer-secret-1"), "unknown-key"),
            keys.clone(),
            AdhocFailure::UnknownKey,
        ),
        (
            // The credential's chain ends in the JWT's root, which the trust store lacks.
            "step 3, x5c",
            elsewhere,
            chained_issuer(&other_root, "Bank Issuer"),
            AdhocFailure::Untrusted,
        ),
        (
            "step 4",
            keyed(
                &adhoc_claims("https://other.example", NOW + 600),
                &secret_key("issuer-secret-1"),
                "issuer-key-1",
            ),
            keys.clone(),
            AdhocFailure::Issuer,
        ),
        (
            "step 5",
            keyed(
                &adhoc_claims(iss, NOW),
                &secret_key("issuer-secret-1"),
                "issuer-key-1",
            ),
            keys.clone(),
            AdhocFailure::Expired,
        ),
        (
            "step 6, sub",
            keyed(
                &claims.replace(CARD_TYPE, "org.example.other"),
                &secret_key("issuer-secret-1"),
                "issuer-key-1",
            ),
            keys.clone(),
            AdhocFailure::Binding,
        ),
        (
            "step 6, format",
            keyed(
                &claims.replace(r#""format": "dc+sd-jwt""#, r#""format": "mso_mdoc""#),
                &secret_key("issuer-secret-1"),
                "issuer-key-1",
            ),
            keys.clone(),
            AdhocFailure::Binding,
        ),
        (
            "step 6, the chain's root",
            chained.clone(),
            chained_issuer(&other_root, "Bank Issuer"),
            AdhocFailure::ForeignChain,
        ),
        (
            "step 6, the leaf's subject",
            chained,
            chained_issuer(&x509::root(), "Bank Card Issuer"),
            AdhocFailure::ForeignChain,
        ),
        (
            "step 7",
            keyed(
                &claims.replace(PAY, "urn:paso:sca:com.example:fixture:1"),
                &secret_key("issuer-secret-1"),
                "issuer-key-1",
            ),
            keys,
            AdhocFailure::TransactionType,
        ),
    ];
    let host = PasoHost::at(Timestamp(NOW));
    // The card's stored metadata lists the type: it never stands in for a refused JWT.
    let stored = format!(r#"{{"{PAY}": {}}}"#, payment_meta());
    for (step, jwt, issuer, failure) in cases {
        let card = card(&stored, None, &issuer);
        let refusal = AdhocRefusal {
            jwt: AdhocJwt::new(&jwt),
            credential: card.credential().id.clone().into_owned(),
            failure,
        };
        // The matcher offered the entry; phase 2 refuses the JWT, and the match it informs
        // binds no entry: the stored metadata never stands in (§5.3).
        assert_eq!(
            adhoc_case(&jwt, &card, PasoProfile::default()),
            Err(AdhocOutcome::Fallback(
                Box::new(
                    PasoFinding::of(None, None, Some(refusal.clone()), Vec::new())
                        .expect("a finding")
                ),
                0
            )),
            "{step}"
        );
        // In the URI flow the wallet refuses it before it converts, and binds no entry.
        let request_parameters = adhoc_parameters(&jwt);
        siros_testkit::signed_request!(let request = &request_parameters);
        let credential = card.credential();
        let verified = Verified::of(&request, &[&credential], &host).expect("verified");
        assert_eq!(
            verified.refusals(),
            std::slice::from_ref(&refusal),
            "{step}"
        );
        assert_eq!(verified.jwts().count(), 0, "{step}: nothing converts");
        assert_eq!(
            uri_rendering(
                &PasoProfile::default().with_verified(&verified),
                &request,
                &card
            ),
            Err(refusal.failure),
            "{step}"
        );
    }
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
    let outcome = |request: &Request<'_>, id: &str| -> Result<(), usize> {
        let host = PasoHost::at(Timestamp(NOW));
        let authenticated =
            siros_testkit::fixtures::authenticate(request.envelope(), &registry, &host)
                .expect("authentic");
        let ids: &[&str] = &[id];
        match Prepared::prepare(
            &authenticated,
            ids,
            &wallet,
            &registry,
            &env,
            &rendering,
            &host,
        )
        .and_then(|prepared| {
            prepared.respond(|resource| Published::default().answer(resource), &host)
        }) {
            Ok(_) => Ok(()),
            Err(Phase2::Fallback(findings)) => {
                assert!(
                    findings
                        .items()
                        .iter()
                        .all(|finding| matches!(finding, Finding::Diverged { .. })),
                    "{findings:?}"
                );
                Err(findings.items().len())
            }
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
    assert_eq!(outcome(&swapped, &id), Err(1));
    // A record whose attested locale changed diverges too.
    let altered = id.replace(r#""display_locale":"en""#, r#""display_locale":"de""#);
    assert_ne!(altered, id);
    assert_eq!(outcome(&shown_request, &altered), Err(1));
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
