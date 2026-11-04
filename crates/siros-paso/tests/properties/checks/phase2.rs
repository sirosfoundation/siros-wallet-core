//! Phase 2's findings and the fallback they cause.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use siros_openid4vp::effects::MediaType;
use siros_openid4vp::host::Timestamp;
use siros_openid4vp::ids::FormatId;
use siros_openid4vp::plugins::{Answered, Binding, Bound, Carriage, NoCandidate, Profile};
use siros_openid4vp::request::Request;
use siros_openid4vp::rows::{Env, HttpsUrl};
use siros_paso::{PasoProfile, Reading};
use siros_testkit::{Published, PublishedResource};

use crate::paso_host::PasoHost;

use crate::common::{Card, png, sri};
use crate::generate::{Case, NOW, REMOTE};

use super::{Tally, at, mandate_claims, select};

/// Phase 2's host readings as check_props.py's SIGNALS: the signal, its age at `NOW`, the
/// reading, whether the wallet can measure it again.
pub(super) fn readings() -> Vec<(&'static str, u64, Reading, bool)> {
    let ok = |json: &str| {
        Reading::Ok(serde_json::value::RawValue::from_string(json.to_owned()).expect("json"))
    };
    vec![
        (
            "urn:paso:risk:global:geolocation:1",
            30,
            ok(r#"{"lat": 52.52, "lon": 13.405, "accuracy": 12}"#),
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
            900,
            ok(r#"{"window_ms": 1000}"#),
            true,
        ),
        (
            "urn:paso:risk:global:screen_capture:1",
            900,
            ok(r#"{"active": false}"#),
            false,
        ),
        (
            "urn:paso:risk:global:device_basics:1",
            5,
            ok(r#"{"os": "android"}"#),
            true,
        ),
    ]
}

/// A bound case phase 2 answers: the request and its Request Object, the card, the binding, the
/// bound entry's JSON.
pub(super) struct Answer<'a> {
    pub(super) request: &'a Request<'a>,
    pub(super) request_object: &'a str,
    pub(super) card: &'a Card,
    pub(super) bound: &'a Bound,
    pub(super) entry: &'a Value,
}

impl Answer<'_> {
    /// Whether the entry carried ad-hoc metadata.
    pub(super) fn adhoc(&self) -> Option<&str> {
        self.entry.get("metadata").and_then(Value::as_str)
    }
}

/// Phase 2's resources as check_props.py's RESOURCES: the first remote logo as published, the
/// second altered, the third not fetchable.
pub(super) fn resources() -> Vec<PublishedResource> {
    let logo = png(16, 16);
    let mut altered = logo.clone();
    altered.push(0);
    [(REMOTE[0], logo), (REMOTE[1], altered)]
        .into_iter()
        .map(|(url, content)| PublishedResource {
            url: HttpsUrl::parse(url).expect("an https URL"),
            content,
            media: MediaType::parse("image/png").expect("a media type"),
        })
        .collect()
}

/// What phase 2 must find, as check_props.py states it: the ad-hoc metadata JWT when it expired
/// by `NOW`, and each displayed https image whose fetch fails or whose content misses its
/// `#integrity`, in claim order.
pub(super) fn expected_finding(
    kind: &str,
    answer: &Answer<'_>,
    meta: &Value,
) -> (Option<String>, Vec<String>) {
    let expired = answer
        .adhoc()
        .filter(|jwt| {
            let payload = jwt.split('.').nth(1).expect("a JWS payload");
            let claims: Value =
                serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).expect("base64url"))
                    .expect("the JWT's claims");
            claims["exp"].as_u64().expect("exp") <= NOW
        })
        .map(str::to_owned);
    let images: Vec<Vec<Value>> = if kind.contains(":mandate:") {
        mandate_claims()
            .into_iter()
            .filter(|claim| claim.displayed && claim.value_type.as_deref() == Some("image"))
            .map(|claim| claim.path.iter().map(|p| json!(p)).collect())
            .collect()
    } else {
        meta["claims"]
            .as_array()
            .expect("claims")
            .iter()
            .filter(|claim| {
                claim.get("display").is_some() && claim.get("value_type") == Some(&json!("image"))
            })
            .map(|claim| claim["path"].as_array().expect("a path").clone())
            .collect()
    };
    let resources = resources();
    let payload = &answer.entry["payload"];
    let mut failed = Vec::new();
    for pointer in images {
        for path in select(payload, &pointer) {
            let Some(url) = at(payload, &path)
                .as_str()
                .filter(|url| url.starts_with("https://"))
            else {
                continue;
            };
            let (last, parent) = path.split_last().expect("a path");
            let integrity =
                &at(payload, parent)[format!("{}#integrity", last.as_str().expect("a key"))];
            let verified = resources
                .iter()
                .find(|resource| resource.url.written() == url)
                .is_some_and(|resource| {
                    Some(sri(&resource.content).as_str()) == integrity.as_str()
                });
            if !verified {
                failed.push(url.to_owned());
            }
        }
    }
    (expired, failed)
}

/// Phase 2's revalidation (Proof Metadata §5.3 step 5; View §3, Core §7.4.2 step 3) against
/// `expected_finding`; with a finding, the consent re-run informed of it no longer binds the
/// record's entries.
pub(super) fn phase2(case: &Case, answer: &Answer<'_>, meta: &Value, env: &Env, tally: &mut Tally) {
    let credential = answer.card.credential();
    let format = FormatId::parse(case.format).expect("format");
    let host = PasoHost::at(Timestamp(NOW));
    let published = Published::new(resources());
    let profile = PasoProfile::default();
    let finding = Answered::new(
        answer.request,
        &credential,
        &answer.bound.entries,
        &answer.bound.attested,
        &format,
        siros_testkit::fixtures::mode_of(answer.request).expect("a mode"),
    )
    .revalidate(&profile, |resource| published.answer(resource), &host)
    .expect("no fault");
    let (expired, failed) = expected_finding(case.kind, answer, meta);
    let Some(finding) = finding else {
        assert!(
            expired.is_none() && failed.is_empty(),
            "R-findings: none for {failed:?}"
        );
        return;
    };
    tally.add("phase 2 findings");
    let urls: Vec<String> = finding
        .failed()
        .iter()
        .map(|image| image.url.clone())
        .collect();
    assert_eq!(
        (finding.lacks(), finding.expired(), &urls),
        (None, expired.as_deref(), &failed),
        "R-findings"
    );
    let informed = PasoProfile::default().informed(&[&finding]);
    let offered: Vec<_> = answer
        .request
        .indexed_entries()
        .map(|(index, _)| index)
        .collect();
    let binding = Binding {
        request: answer.request,
        query: &answer.request.queries()[0],
        credential: &credential,
        entries: &offered,
        carriage: Carriage::Carried,
    };
    match informed.bind(binding, env) {
        Ok(again) => assert_ne!(
            again.entries, answer.bound.entries,
            "R-fallback offers the failed record again"
        ),
        Err(NoCandidate::Excluded(_)) => {}
        Err(NoCandidate::Fault(fault)) => panic!("R-fallback: {fault}"),
    }
    tally.add("fallbacks");
}
