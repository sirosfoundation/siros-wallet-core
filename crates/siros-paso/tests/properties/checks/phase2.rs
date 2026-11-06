//! Phase 2's findings and the fallback they cause.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use siros_openid4vp::effects::MediaType;
use siros_openid4vp::host::{ProfileHost, Timestamp};
use siros_openid4vp::plugins::{Binding, Bound, Carriage, NoCandidate, Profile};
use siros_openid4vp::rendering::Rendering;
use siros_openid4vp::request::Request;
use siros_openid4vp::rows::{Env, HttpsUrl};
use siros_paso::adhoc::{AdhocFailure, AdhocJwt, AdhocRefusal};
use siros_paso::{PasoProfile, Reading};
use siros_testkit::verifier;
use siros_testkit::{Published, PublishedResource};

use crate::paso_host::PasoHost;

use crate::common::{CARD_TYPE, Card, png, read_card_record, sri};
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
    pub(super) rendering: &'a Rendering<'a>,
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

/// The first step of Proof Metadata §5.3 the generator's JWT fails for the card: an unpublished
/// `kid` (step 3), a signature other than the issuer key's deterministic ES256 one (step 2, RFC
/// 6979), an `exp` at or before `NOW` (step 5), a `sub` or `format` other than the card's (step
/// 6). The generator writes no other defect.
pub(super) fn refused_step(jwt: &str, format: &str) -> Option<AdhocFailure> {
    let parts: Vec<&str> = jwt.split('.').collect();
    let json = |part: &str| -> Value {
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).expect("base64url")).expect("JSON")
    };
    let (header, claims) = (json(parts[0]), json(parts[1]));
    let input = format!("{}.{}", parts[0], parts[1]);
    let issuers =
        siros_testkit::jose::sign(&verifier::secret_key("issuer-secret-1"), &input).expect("signs");
    if header["kid"] != json!("issuer-key-1") {
        Some(AdhocFailure::UnknownKey)
    } else if parts[2] != issuers {
        Some(AdhocFailure::Signature)
    } else if claims["exp"].as_u64().expect("exp") <= NOW {
        Some(AdhocFailure::Expired)
    } else if claims["sub"] != json!(CARD_TYPE) || claims["format"] != json!(format) {
        Some(AdhocFailure::Binding)
    } else {
        None
    }
}

/// What phase 2 must find: the ad-hoc metadata JWT with the §5.3 step it fails
/// ([`refused_step`]), alone, since the wallet relies on nothing it refused; else each displayed
/// https image whose fetch fails or whose content misses its `#integrity`, in claim order.
pub(super) fn expected_finding(
    case: &Case,
    answer: &Answer<'_>,
    meta: &Value,
) -> (Option<AdhocRefusal>, Vec<String>) {
    let kind = case.kind;
    let refused = answer.adhoc().and_then(|jwt| {
        refused_step(jwt, case.format).map(|failure| AdhocRefusal {
            jwt: AdhocJwt::new(jwt),
            credential: answer.card.credential().id.clone().into_owned(),
            failure,
        })
    });
    if refused.is_some() {
        return (refused, Vec::new());
    }
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
    (refused, failed)
}

/// Phase 2's revalidation (Proof Metadata §5.3; View §3, Core §7.4.2 step 3) against
/// `expected_finding`; with a finding, the consent re-run informed of it no longer binds the
/// record's entries.
pub(super) fn phase2(case: &Case, answer: &Answer<'_>, meta: &Value, env: &Env, tally: &mut Tally) {
    let credential = answer.card.credential();
    let host = PasoHost::at(Timestamp(NOW));
    let published = Published::new(resources());
    let profile = PasoProfile::default();
    let finding = read_card_record(
        answer.request,
        answer.card,
        env,
        answer.rendering,
        |resource| published.answer(resource),
        &host,
        move |record, host| profile.revalidate(record, host),
    )
    .expect("no fault");
    let (refused, failed) = expected_finding(case, answer, meta);
    let Some(finding) = finding else {
        assert!(
            refused.is_none() && failed.is_empty(),
            "R-findings: none for {refused:?} {failed:?}"
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
        (finding.lacks(), finding.refused(), &urls),
        (None, refused.as_ref(), &failed),
        "R-findings"
    );
    let informed =
        <PasoProfile as ProfileHost<PasoHost>>::informed(&PasoProfile::default(), &[&finding]);
    let offered: Vec<_> = answer
        .request
        .indexed_entries()
        .map(|(index, _)| index)
        .collect();
    let additions = crate::common::additions(&credential);
    let binding = Binding {
        request: answer.request,
        query: &answer.request.queries()[0],
        credential: &credential,
        entries: &offered,
        placement: crate::common::placement(&credential.format),
        additions: &*additions,
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
