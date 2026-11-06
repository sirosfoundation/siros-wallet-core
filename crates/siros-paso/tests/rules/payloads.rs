//! Core §7.1 and §7.4.2, View §2-4 and the rulebooks on a payload: conformance, templates,
//! images, the rulebooks' rules, the wallet's bound on items, and the locales.

use siros_openid4vp::media::MediaType;
use siros_openid4vp::rows::{Amounts, HttpsUrl};
use siros_paso::image::ImageFailure;
use siros_paso::outcome::{NotCompatible, Outcome};
use siros_paso::render::ItemBound;
use siros_paso::{Fetch, PasoProfile};

use crate::common::{CUSTOM, PAY, Screen, en, env, png, sri};

use super::{claims, render, render_with, shown};

#[test]
pub(super) fn a_payload_that_does_not_conform_makes_the_entry_not_compatible() {
    let n = format!(r#"{{"path": ["n"], "display": {}}}"#, shown("N"));
    decided!(
        render(
            &claims(&format!(
                r#"{n}, {{"path": ["v"], "value_type": "color", "display": {}}}"#,
                shown("V")
            )),
            r#"{"transaction_id": "t", "n": "a"}"#
        ),
        Outcome::NotCompatible(NotCompatible::ValueType { .. })
    );
    decided!(
        render(&claims(&n), r#"[]"#),
        Outcome::NotCompatible(NotCompatible::PayloadNotObject)
    );
    decided!(
        render(
            &claims(r#"{"path": ["a"]}, {"path": ["a", "b"]}"#),
            r#"{"transaction_id": "t", "a": "x"}"#
        ),
        Outcome::NotCompatible(NotCompatible::Mismatch(_))
    );
    decided!(
        render(
            &claims(&format!(
                r#"{{"path": ["d"], "value_type": "iso_date", "display": {}}}"#,
                shown("D")
            )),
            r#"{"transaction_id": "t", "d": "2026-02-30"}"#
        ),
        Outcome::NotCompatible(NotCompatible::Value { .. })
    );
    decided!(
        render(
            &claims(&format!(
                r#"{{"path": ["i"], "value_type": "image", "display": {}}}"#,
                shown("I")
            )),
            r#"{"transaction_id": "t", "i": 5}"#
        ),
        Outcome::NotCompatible(NotCompatible::ImageNotString(_))
    );
    decided!(
        render(&claims(&n), r#"{"transaction_id": "t", "n": "a\u202eb"}"#),
        Outcome::NotCompatible(NotCompatible::PayloadDirectional { .. })
    );
    assert!(
        render(
            &claims(&n),
            r#"{"transaction_id": "t", "n": "a\u2066b\u2069"}"#
        )
        .is_ok(),
        "a closed isolate passes"
    );
    decided!(
        render(
            &claims(&n),
            r#"{"transaction_id": "t", "n": "a", "extra": "x"}"#
        ),
        Outcome::NotCompatible(NotCompatible::Uncovered(_))
    );
    // Conformance (Core §7.4.2 step 2) decides before the locale (View §4): the entry gives way
    // to the next one instead of excluding the credential.
    let date = format!(
        r#"{{"path": ["d"], "value_type": "iso_date", "display": {}}}"#,
        shown("D")
    );
    decided!(
        render_with(
            CUSTOM,
            &claims(&date),
            r#"{"transaction_id": "t", "d": "2026-02-30"}"#,
            &env(&["de"], Amounts::Formatted),
            &PasoProfile::default()
        ),
        Outcome::NotCompatible(NotCompatible::Value { .. })
    );
    decided!(
        render(
            &claims(&format!(
                r#"{{"path": ["m"], "mandatory": true, "display": {}}}"#,
                shown("M")
            )),
            r#"{"transaction_id": "t"}"#
        ),
        Outcome::NotCompatible(NotCompatible::MandatoryAbsent(_))
    );
    decided!(
        render(
            &claims(&format!(
                r#"{{"path": ["s"], "value_type": "template:mini_markdown", "display": {}}}"#,
                shown("S")
            )),
            r#"{"transaction_id": "t", "s": 5}"#
        ),
        Outcome::NotCompatible(NotCompatible::TemplateNotString(_))
    );
}

#[test]
pub(super) fn each_template_rule_makes_the_entry_not_compatible() {
    let label = |text: &str| {
        format!(
            r#"[{{"locale": "en", "name": "{text}", "display_type": "template:mini_markdown"}}]"#
        )
    };
    decided!(
        render(
            &claims(&format!(
                r#"{{"path": ["i"], "value_type": "label_only", "display": {}}}, {{"path": ["n"], "display": {}}}"#,
                shown("Note"),
                label("See {1}")
            )),
            r#"{"transaction_id": "t", "i": "x", "n": "a"}"#
        ),
        Outcome::NotCompatible(NotCompatible::ForbiddenReference { placeholder, .. })
            if placeholder.get() == 1
    );
    decided!(
        render(
            &claims(&format!(
                r#"{{"path": ["n"], "display": {}}}, {{"path": ["k"]}}"#,
                label("See {2}")
            )),
            r#"{"transaction_id": "t", "n": "a", "k": 5}"#
        ),
        Outcome::NotCompatible(NotCompatible::ReferenceNotString(claim)) if claim.get() == 2
    );
    let items = r#"{"transaction_id": "t", "items": [{"name": "A", "qty": "1"}], "sum": "3"}"#;
    decided!(
        render(
            &claims(&format!(
                r#"{{"path": ["items", null, "name"]}}, {{"path": ["items", null, "qty"], "display": {}}}, {{"path": ["sum"], "display": {}}}"#,
                shown("Q"),
                label("Total for {1}")
            )),
            items
        ),
        Outcome::NotCompatible(NotCompatible::MoreNulls(claim)) if claim.get() == 1
    );
    // No entry survives in any locale: not compatible (View §3 template), not excluded.
    decided!(
        render(
            &claims(&format!(
                r#"{{"path": ["n"], "display": {}}}, {{"path": ["absent"]}}"#,
                label("Total {2}")
            )),
            r#"{"transaction_id": "t", "n": "a"}"#
        ),
        Outcome::NotCompatible(NotCompatible::TemplatesExhausted)
    );
    // §3.3's limits apply to the interpolated label (View §2).
    decided!(
        render(
            &claims(&format!(
                r#"{{"path": ["n"], "display": {}}}"#,
                label("Name {0}")
            )),
            &format!(r#"{{"transaction_id": "{}", "n": "a"}}"#, "t".repeat(60))
        ),
        Outcome::NotCompatible(NotCompatible::RenderedLabel { .. })
    );
}

#[test]
pub(super) fn each_image_failure_makes_the_entry_not_compatible() {
    let meta = claims(&format!(
        r#"{{"path": ["payee", "name"], "display": {}}}, {{"path": ["payee", "logo"], "value_type": "image", "display": {}}}"#,
        shown("Payee"),
        shown("Logo")
    ));
    let url = "https://cdn.example/l.png";
    let logo = png(32, 32);
    let fetched = |content: Vec<u8>, media: &str| {
        PasoProfile::default().with_resource(
            HttpsUrl::parse(url).expect("url"),
            Fetch::Fetched {
                content,
                media: MediaType::parse(media).expect("a media type"),
            },
        )
    };
    let payload = |logo_value: &str, integrity: Option<&str>| {
        let sibling =
            integrity.map_or_else(String::new, |i| format!(r#", "logo#integrity": "{i}""#));
        format!(
            r#"{{"transaction_id": "t", "payee": {{"name": "P", "logo": "{logo_value}"{sibling}}}}}"#
        )
    };
    let cases: [(&str, String, PasoProfile, ImageFailure); 10] = [
        (
            "no #integrity",
            payload(url, None),
            fetched(logo.clone(), "image/png"),
            ImageFailure::NoIntegrity,
        ),
        (
            "digest mismatch",
            payload(url, Some(&sri(b"x"))),
            fetched(logo.clone(), "image/png"),
            ImageFailure::IntegrityMismatch,
        ),
        (
            "over 2048 pixels",
            payload(url, Some(&sri(&png(2049, 1)))),
            fetched(png(2049, 1), "image/png"),
            ImageFailure::Oversized {
                width: 2049,
                height: 1,
            },
        ),
        (
            "over 512 KiB",
            payload(url, Some(&sri(&[logo.as_slice(), &[0; 524_288]].concat()))),
            fetched([logo.as_slice(), &[0; 524_288]].concat(), "image/png"),
            ImageFailure::TooLarge,
        ),
        (
            "its fetch failed",
            payload(url, Some(&sri(&logo))),
            PasoProfile::default().with_resource(
                HttpsUrl::parse(url).expect("url"),
                Fetch::Failed("connection refused".to_owned()),
            ),
            ImageFailure::Fetch("connection refused".to_owned()),
        ),
        (
            "a media type no image has",
            payload(url, Some(&sri(&logo))),
            fetched(logo.clone(), "image/gif"),
            ImageFailure::MediaType("image/gif".to_owned()),
        ),
        (
            "content no image of its type",
            payload(url, Some(&sri(b"GIF89a"))),
            fetched(b"GIF89a".to_vec(), "image/png"),
            ImageFailure::Unreadable,
        ),
        (
            "neither a Data URL nor https",
            payload("http://cdn.example/l.png", Some(&sri(&logo))),
            PasoProfile::default(),
            ImageFailure::NeitherDataNorHttps,
        ),
        (
            "bad base64",
            payload("data:image/png;base64,abc", None),
            PasoProfile::default(),
            ImageFailure::BadBase64,
        ),
        (
            "a Data URL over 512 KiB encoded",
            payload(
                &format!("data:image/png;base64,{}", "A".repeat(524_292)),
                None,
            ),
            PasoProfile::default(),
            ImageFailure::EncodedTooLarge,
        ),
    ];
    for (why, payload, profile, failure) in cases {
        let rendered = render_with(CUSTOM, &meta, &payload, &en(), &profile);
        match &rendered {
            Err(outcome @ Outcome::NotCompatible(NotCompatible::Image { failure: got, .. })) => {
                assert_eq!(
                    (got, outcome.clause()),
                    (&failure, "View §3 image; Core §7.4.2 step 3"),
                    "{why}"
                );
            }
            other => panic!("{why}: {other:?}"),
        }
    }
}

#[test]
pub(super) fn each_rulebook_payload_rule_makes_the_entry_not_compatible() {
    let generic = "urn:paso:sca:global:generic:x:1";
    let g = |payload: &str| {
        let customs: Vec<String> = (0..11)
            .map(|k| {
                format!(
                    r#"{{"path": ["c{k}"], "display": {}}}"#,
                    shown(&format!("C{k}"))
                )
            })
            .collect();
        render_with(
            generic,
            &claims(&customs.join(", ")),
            payload,
            &en(),
            &PasoProfile::default(),
        )
    };
    let eleven: Vec<String> = (0..11).map(|k| format!(r#""c{k}": "v""#)).collect();
    decided!(
        g(&format!(
            r#"{{"transaction_id": "t", {}}}"#,
            eleven.join(", ")
        )),
        Outcome::NotCompatible(NotCompatible::GenericProperties)
    );
    // Eleven properties, the most Generic §3 allows.
    assert!(
        g(&format!(
            r#"{{"transaction_id": "t", {}}}"#,
            eleven[..10].join(", ")
        ))
        .is_ok()
    );
    decided!(
        g(r#"{"c0": "v"}"#),
        Outcome::NotCompatible(NotCompatible::GenericTransactionId)
    );
    decided!(
        g(r#"{"transaction_id": "t", "c0": 5}"#),
        Outcome::NotCompatible(NotCompatible::GenericCustom(_))
    );
    decided!(
        g(r#"{"transaction_id": "t", "zz": "v"}"#),
        Outcome::NotCompatible(NotCompatible::Uncovered(_))
    );
    decided!(
        g(r#"{"transaction_id": "t", "payment_payload": {"amount": "1.00 EUR"}}"#),
        Outcome::NotCompatible(NotCompatible::GenericPayment(_))
    );
    let mandate = "urn:paso:sca:global:mandate:1";
    decided!(
        render_with(
            mandate,
            "{}",
            r#"{"mandate_id": "M", "mandatee": {"name": "A"}, "action": "B", "valid_until": "2026-06-09", "payment_payload": {"amount": "1.00 EUR"}}"#,
            &en(),
            &PasoProfile::default()
        ),
        Outcome::NotCompatible(NotCompatible::MandatePayment(_))
    );
    let payment = claims(&format!(
        r#"{{"path": ["amount"], "value_type": "iso_currency_amount", "display": {}}}, {{"path": ["payee", "name"], "display": {}}}, {{"path": ["payee", "id"]}}"#,
        shown("Amount"),
        shown("Payee")
    ));
    decided!(
        render_with(
            PAY,
            &payment,
            r#"{"transaction_id": "t", "amount": "1.00 EUR", "payee": {"name": "P"}}"#,
            &en(),
            &PasoProfile::default()
        ),
        Outcome::NotCompatible(NotCompatible::PaymentRequired(_))
    );
}

#[test]
pub(super) fn more_items_than_the_wallets_bound_make_the_entry_not_compatible() {
    let meta = claims(&format!(
        r#"{{"path": ["items", null, "v"], "display": {}}}"#,
        shown("V")
    ));
    let items = |n: usize| {
        format!(
            r#"{{"transaction_id": "t", "items": [{}]}}"#,
            vec![r#"{"v": "x"}"#; n].join(", ")
        )
    };
    // View §2: 197 rows and 3 UI elements reach the least bound, 200; 198 rows pass it.
    assert!(render(&meta, &items(197)).is_ok());
    decided!(
        render(&meta, &items(198)),
        Outcome::NotCompatible(NotCompatible::TooManyItems { items: 201, .. })
    );
    // The security hint is a fourth UI element.
    let hinted = format!(
        r#"{}, "ui_labels": {{"security_hint": [{{"locale": "en", "value": "Check"}}]}}}}"#,
        meta.strip_suffix('}').expect("an object")
    );
    assert!(render(&hinted, &items(196)).is_ok());
    decided!(
        render(&hinted, &items(197)),
        Outcome::NotCompatible(NotCompatible::TooManyItems { items: 201, .. })
    );
    let wider = PasoProfile::default().with_bound(ItemBound::new(201).expect("bound"));
    assert!(render_with(CUSTOM, &meta, &items(198), &en(), &wider).is_ok());
    assert!(
        ItemBound::new(199).is_err(),
        "View §2's bound is at least 200"
    );
}

#[test]
pub(super) fn no_locale_completing_every_array_excludes_the_credential() {
    let meta = claims(&format!(r#"{{"path": ["n"], "display": {}}}"#, shown("N")));
    decided!(
        render_with(
            CUSTOM,
            &meta,
            r#"{"transaction_id": "t", "n": "a"}"#,
            &env(&["de"], Amounts::Formatted),
            &PasoProfile::default()
        ),
        Outcome::Excluded(_)
    );
}

/// I33's known answers: RFC 4647 §3.4's Lookup (`de-CH` over `de` gives `de`, `en-US` over `en`
/// gives `en`, `en` over `en-GB` gives none) and View §4 (a default entry is a match and the tag
/// stands; with no match the credential is excluded): the locale selected and the label shown.
/// A claim's `display`, a priority list, and the locale selected with the label shown, or none.
type Selection<'c> = (&'c str, &'c [&'c str], Option<(&'c str, &'c str)>);

#[test]
fn view_4_selects_by_rfc_4647_lookup_and_the_default_entry() {
    let cases: [Selection<'_>; 6] = [
        (
            r#"[{"locale": "de", "name": "N de"}]"#,
            &["de-CH"],
            Some(("de-CH", "N de")),
        ),
        (
            r#"[{"locale": "en", "name": "N en"}]"#,
            &["en-US"],
            Some(("en-US", "N en")),
        ),
        (r#"[{"locale": "en-GB", "name": "N GB"}]"#, &["en"], None),
        (
            r#"[{"locale": "en-GB", "name": "N GB"}, {"name": "N default"}]"#,
            &["en"],
            Some(("en", "N default")),
        ),
        (
            r#"[{"name": "N default"}]"#,
            &["de-CH"],
            Some(("de-CH", "N default")),
        ),
        (
            r#"[{"locale": "fr", "name": "N fr"}, {"locale": "de", "name": "N de"}]"#,
            &["en", "de-CH", "de"],
            Some(("de-CH", "N de")),
        ),
    ];
    for (display, priority, want) in cases {
        let meta = claims(&format!(r#"{{"path": ["n"], "display": {display}}}"#));
        let env = env(priority, Amounts::Formatted);
        let rendered = render_with(
            CUSTOM,
            &meta,
            r#"{"transaction_id": "t", "n": "a"}"#,
            &env,
            &PasoProfile::default(),
        );
        let Some((locale, label)) = want else {
            decided!(rendered, Outcome::Excluded(_));
            continue;
        };
        let view = rendered.expect("renders").view;
        assert_eq!(view.locale.as_str(), locale, "{display} over {priority:?}");
        let screen = Screen::of(CUSTOM, &meta, &env, &view.locale);
        assert_eq!(screen.plain(&view.rows[0].row.label), label, "{display}");
    }
}
