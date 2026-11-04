//! Core §7.1 and §7.4.2, View §2-4 and the rulebooks on a payload: conformance, templates,
//! images, the rulebooks' rules, the wallet's bound on items, and the locales.

use siros_openid4vp::rows::{Amounts, HttpsUrl};
use siros_paso::image::ImageFailure;
use siros_paso::outcome::{NotCompatible, Outcome};
use siros_paso::render::ItemBound;
use siros_paso::{Fetch, PasoProfile};

use crate::common::{CUSTOM, PAY, data_png, en, env, png, sri};

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
        Outcome::NotCompatible(NotCompatible::ValueType { .. }),
        "View §3"
    );
    decided!(
        render(&claims(&n), r#"[]"#),
        Outcome::NotCompatible(NotCompatible::PayloadNotObject),
        "Core §7.1"
    );
    decided!(
        render(
            &claims(r#"{"path": ["a"]}, {"path": ["a", "b"]}"#),
            r#"{"transaction_id": "t", "a": "x"}"#
        ),
        Outcome::NotCompatible(NotCompatible::Mismatch(_)),
        "Core §7.4.2 step 2"
    );
    decided!(
        render(
            &claims(&format!(
                r#"{{"path": ["d"], "value_type": "iso_date", "display": {}}}"#,
                shown("D")
            )),
            r#"{"transaction_id": "t", "d": "2026-02-30"}"#
        ),
        Outcome::NotCompatible(NotCompatible::Value { .. }),
        "View §3"
    );
    decided!(
        render(
            &claims(&format!(
                r#"{{"path": ["i"], "value_type": "image", "display": {}}}"#,
                shown("I")
            )),
            r#"{"transaction_id": "t", "i": 5}"#
        ),
        Outcome::NotCompatible(NotCompatible::ImageNotString(_)),
        "View §3"
    );
    decided!(
        render(&claims(&n), r#"{"transaction_id": "t", "n": "a\u202eb"}"#),
        Outcome::NotCompatible(NotCompatible::PayloadDirectional { .. }),
        "Proof Metadata §3.3"
    );
    decided!(
        render(&claims(&n), r#"{"transaction_id": "t", "n": "a\u2066b"}"#),
        Outcome::NotCompatible(NotCompatible::PayloadDirectional { .. }),
        "Proof Metadata §3.3"
    );
    assert!(
        render(
            &claims(&n),
            r#"{"transaction_id": "t", "n": "a\u2066b\u2069"}"#
        )
        .is_ok(),
        "a closed isolate passes"
    );
    // Coverage: a field no claim path addresses, wherever it sits: a member, an empty container
    // beside a deeper path, a scalar where a path continues, a member of an array element.
    let deep = format!(r#"{{"path": ["p", "q"], "display": {}}}"#, shown("Q"));
    let items = format!(
        r#"{{"path": ["items", null, "name"], "display": {}}}"#,
        shown("I")
    );
    for (meta, payload) in [
        (&n, r#"{"transaction_id": "t", "n": "a", "extra": "x"}"#),
        (
            &deep,
            r#"{"transaction_id": "t", "p": {"q": "a"}, "extra": {}}"#,
        ),
        (&deep, r#"{"transaction_id": "t", "p": "a"}"#),
        (
            &items,
            r#"{"transaction_id": "t", "items": [{"name": "a", "extra": "b"}]}"#,
        ),
    ] {
        decided!(
            render(&claims(meta), payload),
            Outcome::NotCompatible(NotCompatible::Uncovered(_)),
            "Core §7.4.2 step 2"
        );
    }
    // The directional rule reaches the strings inside a covered container.
    let any = format!(
        r#"{{"path": ["i"], "value_type": "label_only", "display": {}}}"#,
        shown("I")
    );
    decided!(
        render(
            &claims(&any),
            r#"{"transaction_id": "t", "i": {"x": ["a\u202eb"]}}"#
        ),
        Outcome::NotCompatible(NotCompatible::PayloadDirectional { .. }),
        "Proof Metadata §3.3"
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
        Outcome::NotCompatible(NotCompatible::Value { .. }),
        "View §3"
    );
    decided!(
        render(
            &claims(&format!(
                r#"{{"path": ["m"], "mandatory": true, "display": {}}}"#,
                shown("M")
            )),
            r#"{"transaction_id": "t"}"#
        ),
        Outcome::NotCompatible(NotCompatible::MandatoryAbsent(_)),
        "Core §7.4.2 step 2"
    );
    decided!(
        render(
            &claims(&format!(
                r#"{{"path": ["s"], "value_type": "template:mini_markdown", "display": {}}}"#,
                shown("S")
            )),
            r#"{"transaction_id": "t", "s": 5}"#
        ),
        Outcome::NotCompatible(NotCompatible::TemplateNotString(_)),
        "View §3 template"
    );
}

#[test]
pub(super) fn each_template_rule_makes_the_entry_not_compatible() {
    let label = |text: &str| {
        format!(
            r#"[{{"locale": "en", "name": "{text}", "display_type": "template:mini_markdown"}}]"#
        )
    };
    let forbidden = [
        (
            r#"{"path": ["i"], "value_type": "image", "display": [{"locale": "en", "name": "Logo"}]}"#,
            format!("\"{}\"", data_png(8, 8)),
        ),
        (
            r#"{"path": ["i"], "value_type": "label_only", "display": [{"locale": "en", "name": "Note"}]}"#,
            "\"x\"".to_owned(),
        ),
        (
            r#"{"path": ["i"], "value_type": "template:mini_markdown", "display": [{"locale": "en", "name": "Sum"}]}"#,
            "\"y\"".to_owned(),
        ),
    ];
    for (reference, value) in forbidden {
        decided!(
            render(
                &claims(&format!(
                    r#"{reference}, {{"path": ["n"], "display": {}}}"#,
                    label("See {1}")
                )),
                &format!(r#"{{"transaction_id": "t", "i": {value}, "n": "a"}}"#)
            ),
            Outcome::NotCompatible(NotCompatible::ForbiddenReference { placeholder: 1, .. }),
            "View §3 template"
        );
    }
    decided!(
        render(
            &claims(&format!(
                r#"{{"path": ["n"], "display": {}}}, {{"path": ["k"]}}"#,
                label("See {2}")
            )),
            r#"{"transaction_id": "t", "n": "a", "k": 5}"#
        ),
        Outcome::NotCompatible(NotCompatible::ReferenceNotString(2)),
        "View §3 template"
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
        Outcome::NotCompatible(NotCompatible::MoreNulls(1)),
        "View §3 template"
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
        Outcome::NotCompatible(NotCompatible::TemplatesExhausted),
        "View §3 template"
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
        Outcome::NotCompatible(NotCompatible::RenderedLabel { .. }),
        "View §2; Proof Metadata §3.3"
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
                media: media.to_owned(),
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
        Outcome::NotCompatible(NotCompatible::GenericProperties),
        "Generic §3"
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
        Outcome::NotCompatible(NotCompatible::GenericTransactionId),
        "Generic §3"
    );
    decided!(
        g(r#"{"transaction_id": "t", "c0": 5}"#),
        Outcome::NotCompatible(NotCompatible::GenericCustom(_)),
        "Generic §3.1"
    );
    decided!(
        g(r#"{"transaction_id": "t", "zz": "v"}"#),
        Outcome::NotCompatible(NotCompatible::Uncovered(_)),
        "Core §7.4.2 step 2"
    );
    decided!(
        g(r#"{"transaction_id": "t", "payment_payload": {"amount": "1.00 EUR"}}"#),
        Outcome::NotCompatible(NotCompatible::GenericPayment(_)),
        "Generic §3.2; Payment §1"
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
        Outcome::NotCompatible(NotCompatible::MandatePayment(_)),
        "Mandate §2.2; Payment §1"
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
        Outcome::NotCompatible(NotCompatible::PaymentRequired(_)),
        "Payment §1; Core §7.4.2 step 2"
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
        Outcome::NotCompatible(NotCompatible::TooManyItems {
            items: 201,
            bound: 200
        }),
        "View §2"
    );
    // The security hint is a fourth UI element.
    let hinted = format!(
        r#"{}, "ui_labels": {{"security_hint": [{{"locale": "en", "value": "Check"}}]}}}}"#,
        meta.strip_suffix('}').expect("an object")
    );
    assert!(render(&hinted, &items(196)).is_ok());
    decided!(
        render(&hinted, &items(197)),
        Outcome::NotCompatible(NotCompatible::TooManyItems {
            items: 201,
            bound: 200
        }),
        "View §2"
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
        Outcome::Excluded(_),
        "View §4"
    );
    // A default entry matches any locale.
    let defaulted = claims(r#"{"path": ["n"], "display": [{"name": "N"}]}"#);
    let rendered = render_with(
        CUSTOM,
        &defaulted,
        r#"{"transaction_id": "t", "n": "a"}"#,
        &env(&["de-CH"], Amounts::Formatted),
        &PasoProfile::default(),
    )
    .expect("renders");
    assert_eq!(rendered.view.locale.tag.as_str(), "de-CH");
}
