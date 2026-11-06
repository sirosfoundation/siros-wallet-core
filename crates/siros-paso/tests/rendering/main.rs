//! What View §2-4 and the rulebooks render, against what their text states: templates, each
//! value type, `label_only`, coverage, pending images, each image format's dimensions and View
//! §3's bounds, the order rules, the rulebook of a type, and first match (Core §7.4.2) through
//! the profile's binding, with PaSO Core A.5 and A.7.

#[path = "../common/mod.rs"]
mod common;

use common::{CUSTOM, Card, PAY, Screen, Seen, en, entry, env, png, shown, sri};
use siros_i18n::Style;
use siros_openid4vp::claims::Concrete;
use siros_openid4vp::media::MediaType;
use siros_openid4vp::rows::{Amounts, Image, RemoteImage, Value};
use siros_paso::outcome::Outcome;
use siros_paso::rulebook::{Family, PasoType};
use siros_paso::{Fetch, PasoProfile};

mod binding;
mod images;

fn render_typed(kind: &str, meta: &str, payload: &str, locales: &[&str]) -> Result<Seen, Outcome> {
    let card = Card::sd_jwt(&format!(r#"{{"{kind}": {meta}}}"#));
    let entry_json =
        format!(r#"{{"type": "{kind}", "credential_ids": ["q"], "payload": {payload}}}"#);
    let env = env(locales, Amounts::Formatted);
    let rendered = PasoProfile::default()
        .render(
            &entry(&entry_json),
            siros_openid4vp::routing::ChannelKind::DcApi,
            &card.credential(),
            crate::common::placement(&card.credential().format),
            &env,
        )
        .expect("no fault")?;
    let screen = Screen::of(kind, meta, &env, &rendered.view.locale);
    Ok(Seen { rendered, screen })
}

fn render(meta: &str, payload: &str) -> Result<Seen, Outcome> {
    render_typed(CUSTOM, meta, payload, &["en"])
}

fn claims(members: &str) -> String {
    format!(r#"{{"claims": [{{"path": ["transaction_id"]}}, {members}]}}"#)
}

fn labels(rendered: &Result<Seen, Outcome>) -> Vec<String> {
    rendered.as_ref().expect("renders").labels()
}

const TEMPLATE: &str = r#""display_type": "template:mini_markdown""#;

#[test]
fn templates_interpolate_in_one_pass_and_discard_a_locale_entry_whose_claim_is_absent() {
    let amount = r#"{"path": ["amount"], "value_type": "iso_currency_amount", "display": [{"locale": "en", "name": "Amount"}]}"#;
    // Single pass: a value's placeholder-like text stays literal; values are formatted.
    let meta = format!(
        r#"{{"claims": [{{"path": ["transaction_id"]}}, {amount}, {{"path": ["who"], "display": [{{"locale": "en", "name": "Payee"}}]}}], "ui_labels": {{"transaction_title": [{{"locale": "en", "value": "Pay {{2}} {{1}}", "value_type": "template:mini_markdown"}}]}}}}"#
    );
    let rendered = render(
        &meta,
        r#"{"transaction_id": "t", "amount": "1.00 EUR", "who": "x {1} y"}"#,
    )
    .expect("renders");
    assert_eq!(rendered.plain(&rendered.view.title), "Pay x {1} y €1.00");
    // An index past the claims stays literal, as does a brace no digits and `}` close.
    assert_eq!(
        labels(&render(
            &claims(&format!(
                r#"{{"path": ["n"], "display": [{{"locale": "en", "name": "Item {{99}} of {{0}} {{0 {{}}", {TEMPLATE}}}]}}"#
            )),
            r#"{"transaction_id": "t", "n": "a"}"#
        )),
        ["Item {99} of t {0 {}"]
    );
    // The claim {2} names is absent: the English entry is discarded, German is selected.
    let two = claims(&format!(
        r#"{{"path": ["n"], "display": [{{"locale": "en", "name": "Total {{2}}", {TEMPLATE}}}, {{"locale": "de", "name": "Summe"}}]}}, {{"path": ["absent"]}}"#
    ));
    let rendered = render_typed(
        CUSTOM,
        &two,
        r#"{"transaction_id": "t", "n": "a"}"#,
        &["en", "de"],
    );
    assert_eq!(
        rendered.as_ref().map(|r| r.view.locale.as_str()).ok(),
        Some("de")
    );
    assert_eq!(labels(&rendered), ["Summe"]);
    // With the locale entry discarded, the default entry matches the same locale.
    let defaulted = claims(&format!(
        r#"{{"path": ["n"], "display": [{{"locale": "en", "name": "Total {{2}}", {TEMPLATE}}}, {{"name": "Total"}}]}}, {{"path": ["absent"]}}"#
    ));
    let rendered = render(&defaulted, r#"{"transaction_id": "t", "n": "a"}"#);
    assert_eq!(
        rendered.as_ref().map(|r| r.view.locale.as_str()).ok(),
        Some("en")
    );
    assert_eq!(labels(&rendered), ["Total"]);
    // A null in the referenced path takes the referencing instance's index.
    let per = claims(&format!(
        r#"{{"path": ["items", null, "name"]}}, {{"path": ["items", null, "qty"], "display": [{{"locale": "en", "name": "Quantity of {{1}}", {TEMPLATE}}}]}}"#
    ));
    let rendered = render(&per, r#"{"transaction_id": "t", "items": [{"name": "A", "qty": "1"}, {"name": "B", "qty": "2"}]}"#).expect("renders");
    assert_eq!(
        rendered
            .rows()
            .into_iter()
            .map(|(label, value, _)| (label, value.map(|(_, text)| text)))
            .collect::<Vec<_>>(),
        [
            ("Quantity of A".to_owned(), Some("1".to_owned())),
            ("Quantity of B".to_owned(), Some("2".to_owned()))
        ]
    );
    // One instance's absent reference discards the claim's entry for every instance; the
    // default entry labels them all.
    let defaulted = claims(&format!(
        r#"{{"path": ["items", null, "name"], "display": [{{"locale": "en", "name": "Name"}}]}}, {{"path": ["items", null, "qty"], "display": [{{"locale": "en", "name": "Quantity of {{1}}", {TEMPLATE}}}, {{"name": "Quantity"}}]}}"#
    ));
    assert_eq!(
        labels(&render(
            &defaulted,
            r#"{"transaction_id": "t", "items": [{"name": "A", "qty": "1"}, {"qty": "2"}]}"#
        )),
        ["Name", "Quantity", "Quantity"]
    );
    // A template value: each referenced value formatted by its value type (View §3 template step
    // 3: CLDR's en amount), the result read by its inner type; a mini_markdown value shows its
    // text without its styles.
    let note = claims(&format!(
        r#"{amount}, {{"path": ["note"], "value_type": "template:mini_markdown", "display": [{{"locale": "en", "name": "Note"}}]}}"#
    ));
    let rendered = render(
        &note,
        r#"{"transaction_id": "t", "amount": "49.99 EUR", "note": "Pay **{1}** now"}"#,
    )
    .expect("renders");
    assert_eq!(
        rendered.rows()[1].1,
        Some(("mini_markdown", "Pay €49.99 now".to_owned()))
    );
    // A template label names the referenced value as its message's argument, formatted by its
    // type, inside the label's styles.
    let title = claims(&format!(
        r#"{amount}, {{"path": ["n"], "display": [{{"locale": "en", "name": "Pay **{{1}}** now", {TEMPLATE}}}]}}"#
    ));
    let rendered = render(
        &title,
        r#"{"transaction_id": "t", "amount": "49.99 EUR", "n": "x"}"#,
    )
    .expect("renders");
    let formatted = rendered.formatted(&rendered.view.rows[1].row.label);
    let strong = formatted
        .spans()
        .iter()
        .find(|span| span.styles() == [Style::Strong])
        .map(|span| span.text());
    assert_eq!(strong, Some("€49.99"));
}

/// Each `value_type` of View §3 reaches its value's kind through the metadata.
#[test]
fn each_value_type_view_section_3_names_renders_a_value() {
    let table = [
        ("boolean", "true"),
        ("frequency", r#""MNTH""#),
        ("iso_date", r#""2026-09-02""#),
        ("iso_time", r#""10:15:30Z""#),
        ("iso_date_time", r#""2026-06-02T10:15:30+02:00""#),
        ("iso_currency", r#""EUR""#),
        ("iso_currency_amount", r#""100 JPY""#),
        ("mini_markdown", r#""*a*""#),
        ("url", r#""https://shop.example/x""#),
    ];
    for (value_type, raw) in table {
        let meta = claims(&format!(
            r#"{{"path": ["v"], "display": [{{"locale": "en", "name": "V"}}], "value_type": "{value_type}"}}"#
        ));
        let rendered = render(&meta, &format!(r#"{{"transaction_id": "t", "v": {raw}}}"#));
        assert!(
            rendered.is_ok_and(|rendered| rendered.rows()[0].1.is_some()),
            "{value_type}"
        );
    }
}

#[test]
fn label_only_shows_the_label_alone_whatever_the_value() {
    let meta = claims(
        r#"{"path": ["i"], "value_type": "label_only", "display": [{"locale": "en", "name": "This is a recurring payment"}]}"#,
    );
    let rendered = render(&meta, r#"{"transaction_id": "t", "i": {"x": [1]}}"#).expect("renders");
    assert_eq!(
        rendered.rows(),
        [shown("This is a recurring payment", None)]
    );
}

#[test]
fn an_integrity_companion_is_covered_and_an_unfetched_image_renders_pending() {
    let meta = claims(
        r#"{"path": ["payee", "name"], "display": [{"locale": "en", "name": "Payee"}]}, {"path": ["payee", "logo"], "value_type": "image", "display": [{"locale": "en", "name": "Logo"}]}"#,
    );
    let logo = png(32, 32);
    let url = "https://cdn.example/l.png";
    let payload = format!(
        r#"{{"transaction_id": "t", "payee": {{"name": "P", "logo": "{url}", "logo#integrity": "{}"}}}}"#,
        sri(&logo)
    );
    // The matcher has not fetched it: the row holds the pending image phase 2 fetches.
    let pending = render(&meta, &payload).expect("renders");
    assert_eq!(
        pending.view.rows[1].row.value,
        Some(Value::Image(Image::Remote(RemoteImage {
            url: url.to_owned(),
            integrity: sri(&logo)
        })))
    );
    let card = Card::sd_jwt(&format!(r#"{{"{CUSTOM}": {meta}}}"#));
    let entry_json =
        format!(r#"{{"type": "{CUSTOM}", "credential_ids": ["q"], "payload": {payload}}}"#);
    let fetched = PasoProfile::default().with_resource(
        siros_openid4vp::rows::HttpsUrl::parse(url).expect("url"),
        Fetch::Fetched {
            content: logo,
            media: MediaType::parse("image/png").expect("a media type"),
        },
    );
    let rendered = fetched
        .render(
            &entry(&entry_json),
            siros_openid4vp::routing::ChannelKind::DcApi,
            &card.credential(),
            crate::common::placement(&card.credential().format),
            &en(),
        )
        .expect("no fault")
        .expect("renders");
    assert!(
        matches!(&rendered.view.rows[1].row.value, Some(Value::Image(Image::Embedded(image))) if image.width == 32)
    );
}

#[test]
fn claims_order_rules_the_view_and_payload_order_the_generic_rulebook() {
    // View §2's recursive rule: claims without null first, then each null group per element.
    let recursive = claims(
        r#"{"path": ["items", null, "a"], "display": [{"locale": "en", "name": "A"}]}, {"path": ["total"], "display": [{"locale": "en", "name": "Total"}]}, {"path": ["items", null, "b"], "display": [{"locale": "en", "name": "B"}]}"#,
    );
    assert_eq!(
        labels(&render(
            &recursive,
            r#"{"transaction_id": "t", "items": [{"a": "1", "b": "2"}, {"a": "3", "b": "4"}], "total": "5"}"#
        )),
        ["Total", "A", "B", "A", "B"]
    );
    // Generic §4: payload member order, recursively, the embedded payment as its section.
    let generic = claims(
        r#"{"path": ["b"], "display": [{"locale": "en", "name": "B"}]}, {"path": ["a"], "display": [{"locale": "en", "name": "A"}]}, {"path": ["payment_payload", "transaction_id"]}, {"path": ["payment_payload", "amount"], "value_type": "iso_currency_amount", "display": [{"locale": "en", "name": "Amount"}]}, {"path": ["payment_payload", "payee", "id"]}, {"path": ["payment_payload", "payee", "name"], "display": [{"locale": "en", "name": "Payee"}]}"#,
    );
    let payload = r#"{"transaction_id": "t", "payment_payload": {"transaction_id": "f", "payee": {"id": "D", "name": "S"}, "amount": "1.00 EUR"}, "a": "x", "b": null}"#;
    let rendered = render_typed(
        "urn:paso:sca:global:generic:x:1",
        &generic,
        payload,
        &["en"],
    )
    .expect("renders");
    assert_eq!(
        rendered
            .rows()
            .into_iter()
            .map(|(label, _, section)| (label, section))
            .collect::<Vec<_>>(),
        [
            ("Payee", Some("Payment Details")),
            ("Amount", Some("Payment Details")),
            ("A", None),
            ("B", None)
        ]
        .map(|(label, section)| (label.to_owned(), section.map(str::to_owned)))
    );
    assert_eq!(
        rendered.view.rows[3].row.value, None,
        "a null custom claim shows its label alone"
    );
    // The same claims under another type keep claims order, without a section.
    assert_eq!(
        labels(&render_typed(
            "urn:paso:sca:com.example:other:1",
            &generic,
            r#"{"transaction_id": "t", "a": "x"}"#,
            &["en"]
        )),
        ["A"]
    );
}

#[test]
fn a_type_takes_its_exact_rulebook_else_its_longest_prefix() {
    for (kind, family) in [
        ("urn:paso:sca:global:payment:1", Family::Payment),
        ("urn:paso:sca:global:payment:2", Family::View),
        ("urn:paso:sca:global:generic:x:1", Family::Generic),
        ("urn:paso:sca:global:mandate:1", Family::Mandate),
    ] {
        assert_eq!(PasoType::parse(kind).map(|kind| kind.family()), Ok(family));
    }
    assert!(PasoType::parse("urn:other:1").is_err());
}

#[test]
fn a_payment_header_shows_the_payee_and_the_amount_wherever_the_claims_put_them() {
    // Payment §1: the merchant is payee.name and the amount amount, here listed payee first.
    let meta = |payee_type: &str| {
        format!(
            r#"{{"claims": [{{"path": ["transaction_id"]}}, {{"path": ["payee", "name"]{payee_type}, "display": [{{"locale": "en", "name": "Payee"}}]}}, {{"path": ["payee", "id"]}}, {{"path": ["amount"], "value_type": "iso_currency_amount", "display": [{{"locale": "en", "name": "Amount"}}]}}]}}"#
        )
    };
    let payload =
        r#"{"transaction_id": "t", "amount": "1.00 EUR", "payee": {"name": "Shop", "id": "D"}}"#;
    let rendered = render_typed(PAY, &meta(""), payload, &["en"]).expect("renders");
    assert_eq!(
        rendered.payment(),
        Some(("Shop".to_owned(), "€1.00".to_owned()))
    );
    let view = &rendered.view;
    let heads = view.payment.as_ref().copied().expect("a payment header");
    let path = |position: usize| -> Vec<String> {
        view.rows[position]
            .path
            .iter()
            .map(|part| match part {
                Concrete::Key(key) => key.to_string(),
                Concrete::Index(index) => index.to_string(),
            })
            .collect()
    };
    assert_eq!(
        (path(heads.merchant().get()), path(heads.amount().get())),
        (
            vec!["payee".to_owned(), "name".to_owned()],
            vec!["amount".to_owned()]
        )
    );
    // A merchant row without a text gives no payment header.
    let rendered = render_typed(
        PAY,
        &meta(r#", "value_type": "label_only""#),
        payload,
        &["en"],
    )
    .expect("renders");
    assert_eq!(rendered.view.payment, None);
}

#[test]
fn a_labels_kind_is_its_display_type() {
    // Proof Metadata §3.3: plain text without display_type; mini_markdown as written with
    // `mini_markdown`; interpolated with `template:mini_markdown`.
    let meta = claims(
        r#"{"path": ["a"], "display": [{"locale": "en", "name": "*A*"}]}, {"path": ["b"], "display": [{"locale": "en", "name": "*B* {1}", "display_type": "mini_markdown"}]}, {"path": ["c"], "display": [{"locale": "en", "name": "*C* {1}", "display_type": "template:mini_markdown"}]}"#,
    );
    let rendered = render(
        &meta,
        r#"{"transaction_id": "t", "a": "x", "b": "y", "c": "z"}"#,
    )
    .expect("renders");
    let spans: Vec<Vec<(String, Vec<Style>)>> = rendered
        .view
        .rows
        .iter()
        .map(|row| {
            rendered
                .formatted(&row.row.label)
                .spans()
                .iter()
                .map(|span| (span.text().to_owned(), span.styles().to_vec()))
                .collect()
        })
        .collect();
    let span = |text: &str, styles: &[Style]| (text.to_owned(), styles.to_vec());
    assert_eq!(
        spans,
        [
            vec![span("*A*", &[])],
            vec![span("B", &[Style::Emphasis]), span(" {1}", &[])],
            vec![span("C", &[Style::Emphasis]), span(" x", &[])],
        ]
    );
}
