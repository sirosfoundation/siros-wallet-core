//! Payload conformance (PaSO Core, Section 7.4.2, step 2), each value type (PaSO View, Section
//! 3), `template:` interpolation and the generic rendering (Section 2): an honest entry and its
//! rows, and a row per rule.

use serde_json::{json, Value};
use siros_dcql::{ComponentIndex, PathError};
use siros_transaction_data::{
    BaseType, ClaimIndex, Incompatibility, Location, LocationStep, PayloadFault, RenderFault,
    RowValue, Scalar, Segment, TemplateFault, TextFault, Unmatched, ValueFault, MAX_ITEMS,
};

use crate::common::{configured, credential, entries, mdoc, query, rows, taken, Host, Shown, CARD};

const TYPE: &str = "urn:paso:sca:com.example:test:1";

fn displayed(path: Value, value_type: Option<&str>, name: &str) -> Value {
    let mut claim = json!({"path": path, "display": [{"locale": "en", "name": name}]});
    if let Some(value_type) = value_type {
        claim["value_type"] = json!(value_type);
    }
    claim
}

/// The definition of the test type: a claim of each value type, a wildcard group, and a
/// template value.
fn definition() -> Value {
    json!({
        "claims": [
            {"path": ["transaction_id"], "mandatory": true},
            displayed(json!(["items", null, "name"]), None, "Item"),
            displayed(json!(["flag"]), Some("boolean"), "Flag"),
            displayed(json!(["every"]), Some("frequency"), "Every"),
            displayed(json!(["day"]), Some("iso_date"), "Day"),
            displayed(json!(["time"]), Some("iso_time"), "Time"),
            displayed(json!(["at"]), Some("iso_date_time"), "At"),
            displayed(json!(["currency"]), Some("iso_currency"), "Currency"),
            displayed(json!(["amount"]), Some("iso_currency_amount"), "Amount"),
            displayed(json!(["note"]), Some("label_only"), "A note"),
            displayed(json!(["terms"]), Some("mini_markdown"), "Terms"),
            displayed(json!(["link"]), Some("url"), "Link"),
            displayed(json!(["text"]), None, "Text"),
            displayed(json!(["items", null, "tags", null]), None, "Tag"),
            displayed(json!(["summary"]), Some("template:mini_markdown"), "Summary"),
            displayed(json!(["logo"]), Some("image"), "Logo"),
            displayed(json!(["spare"]), None, "Spare")
        ],
        "ui_labels": {"affirmative_action_label": [{"locale": "en", "value": "Confirm"}]}
    })
}

fn payload() -> Value {
    json!({
        "transaction_id": "tx-1",
        "items": [{"name": "A", "tags": ["x", "y"]}, {"name": "B", "tags": []}],
        "flag": true,
        "every": "MNTH",
        "day": "2026-06-03",
        "time": "14:30",
        "at": "2026-06-03T14:30:00+02:00",
        "currency": "EUR",
        "amount": "49.99 EUR",
        "note": {"any": "value"},
        "terms": "*Only* today",
        "link": "https://shop.example/terms",
        "text": "Plain",
        "summary": "{8} on {4}"
    })
}

/// The payload with `changes`; a `null` change removes the member.
fn changed(changes: Value) -> Value {
    let mut payload = payload();
    for (name, change) in changes.as_object().unwrap() {
        if change.is_null() {
            payload.as_object_mut().unwrap().remove(name);
        } else {
            payload[name] = change.clone();
        }
    }
    payload
}

/// The definition with the claim at `at` replaced by `claim`.
fn redefined(at: usize, claim: Value) -> Value {
    let mut definition = definition();
    definition["claims"][at] = claim;
    definition
}

fn at(steps: &[Value]) -> Location {
    Location::new(
        steps
            .iter()
            .map(|step| match step {
                Value::String(key) => LocationStep::Key(key.clone()),
                other => LocationStep::Index(other.as_u64().unwrap()),
            })
            .collect(),
    )
}

/// The rows the card shows for an entry of `payload` under `definition`, or why it takes none.
fn outcome(definition: &Value, payload: &Value) -> Shown {
    let host = Host::new(json!([configured(TYPE, CARD, definition)]));
    let entry = json!({"type": TYPE, "credential_ids": ["card"], "payload": payload});
    let entries = entries(&[entry.to_string()], &query(&["card"], CARD));
    rows(&host, &entries[0], &credential(CARD, &[]))
}

fn value_fault(claim: usize, member: &str, fault: ValueFault) -> Shown {
    Err(Incompatibility::Payload(PayloadFault::Value(
        ClaimIndex::new(claim),
        at(&[json!(member)]),
        fault,
    )))
}

fn render(fault: RenderFault) -> Shown {
    Err(Incompatibility::Render(fault))
}

#[test]
fn the_honest_entry_renders_in_claims_order() {
    let host = Host::new(json!([configured(TYPE, CARD, &definition())]));
    let entry = json!({"type": TYPE, "credential_ids": ["card"], "payload": payload()});
    let entries = entries(&[entry.to_string()], &query(&["card"], CARD));
    let selection = host.select(&[&entries[0]], &credential(CARD, &[])).unwrap();
    // The template's values stay typed for the UI to format (View, Section 3, `template:`).
    let summary = taken(&selection)
        .view()
        .rows()
        .iter()
        .find_map(|row| match row.value() {
            RowValue::Template(interpolated) => Some(interpolated.segments().to_vec()),
            _ => None,
        })
        .unwrap();
    assert!(matches!(
        summary.as_slice(),
        [Segment::Value(Scalar::CurrencyAmount(_)), Segment::Text(on), Segment::Value(Scalar::Date(_))] if on == " on "
    ));
    let rows = outcome(&definition(), &payload()).unwrap();
    let expected = [
        ("Flag", "true"),
        ("Every", "MNTH"),
        ("Day", "2026-06-03"),
        ("Time", "14:30"),
        ("At", "2026-06-03T14:30:00+02:00"),
        ("Currency", "EUR"),
        ("Amount", "49.99 EUR"),
        ("A note", "-"),
        ("Terms", "*Only* today"),
        ("Link", "https://shop.example/terms"),
        ("Text", "Plain"),
        ("Summary", "49.99 EUR on 2026-06-03"),
        // The wildcard group, element by element: each item's name, then its tags (View,
        // Section 2).
        ("Item", "A"),
        ("Tag", "x"),
        ("Tag", "y"),
        ("Item", "B"),
    ];
    let expected: Vec<(String, String)> = expected
        .iter()
        .map(|(l, v)| ((*l).to_owned(), (*v).to_owned()))
        .collect();
    assert_eq!(rows, expected);
}

#[test]
fn each_payload_rule_is_refused_alone() {
    let template = |text: &str| changed(json!({"summary": text}));
    let rows: Vec<(&str, Value, Value, Shown)> = vec![
        // Coverage and mandatory claims (Core, Section 7.4.2).
        (
            "a field no claim covers",
            definition(),
            changed(json!({"extra": "x"})),
            Err(Incompatibility::Payload(PayloadFault::Uncovered(at(&[
                json!("extra"),
            ])))),
        ),
        (
            "a mandatory claim absent",
            definition(),
            changed(json!({"transaction_id": null})),
            Err(Incompatibility::Payload(PayloadFault::MandatoryAbsent(
                ClaimIndex::new(0),
            ))),
        ),
        (
            "a mandatory claim absent from one element its null ranges over",
            redefined(
                1,
                json!({"path": ["items", null, "name"], "mandatory": true,
                       "display": [{"locale": "en", "name": "Item"}]}),
            ),
            changed(json!({"items": [{"name": "A"}, {"tags": []}]})),
            Err(Incompatibility::Payload(PayloadFault::MandatoryAbsent(
                ClaimIndex::new(1),
            ))),
        ),
        (
            "a mandatory claim whose null ranges over an empty array",
            redefined(
                1,
                json!({"path": ["items", null, "name"], "mandatory": true,
                       "display": [{"locale": "en", "name": "Item"}]}),
            ),
            changed(json!({"items": []})),
            Err(Incompatibility::Payload(PayloadFault::MandatoryAbsent(
                ClaimIndex::new(1),
            ))),
        ),
        (
            "an #integrity companion beside a text claim",
            definition(),
            changed(json!({"text#integrity": "sha256-AAAA"})),
            Err(Incompatibility::Payload(PayloadFault::Uncovered(at(&[
                json!("text#integrity"),
            ])))),
        ),
        (
            "an #integrity companion of an image that is no string",
            definition(),
            changed(json!({"logo": "data:image/png;base64,iVBORw0KGgo=", "logo#integrity": 1})),
            Err(Incompatibility::Payload(PayloadFault::IntegrityNotString(
                at(&[json!("logo#integrity")]),
            ))),
        ),
        (
            "a path through a member of another kind",
            redefined(16, json!({"path": ["text", "sub"]})),
            payload(),
            Err(Incompatibility::Payload(PayloadFault::Path(
                ClaimIndex::new(16),
                PathError::TypeMismatch {
                    at: ComponentIndex::new(1),
                },
            ))),
        ),
        (
            "a directional override in a payload string",
            definition(),
            changed(json!({"transaction_id": "tx\u{202e}1"})),
            Err(Incompatibility::Payload(PayloadFault::Text(
                at(&[json!("transaction_id")]),
                TextFault::DirectionalOverride('\u{202e}'),
            ))),
        ),
        // Each value type (View, Section 3).
        (
            "a boolean that is a string",
            definition(),
            changed(json!({"flag": "yes"})),
            value_fault(2, "flag", ValueFault::Type(BaseType::Boolean)),
        ),
        (
            "a frequency outside ISO 20022",
            definition(),
            changed(json!({"every": "DAILY"})),
            value_fault(3, "every", ValueFault::Type(BaseType::Frequency)),
        ),
        (
            "a date that does not exist",
            definition(),
            changed(json!({"day": "2026-02-30"})),
            value_fault(4, "day", ValueFault::Type(BaseType::IsoDate)),
        ),
        (
            "an hour of 25",
            definition(),
            changed(json!({"time": "25:00"})),
            value_fault(5, "time", ValueFault::Type(BaseType::IsoTime)),
        ),
        (
            "a date and time without T",
            definition(),
            changed(json!({"at": "2026-06-03 14:30"})),
            value_fault(6, "at", ValueFault::Type(BaseType::IsoDateTime)),
        ),
        (
            "a currency outside ISO 4217",
            definition(),
            changed(json!({"currency": "EURO"})),
            value_fault(7, "currency", ValueFault::Type(BaseType::IsoCurrency)),
        ),
        (
            "an amount with one euro decimal",
            definition(),
            changed(json!({"amount": "49.9 EUR"})),
            value_fault(8, "amount", ValueFault::Type(BaseType::IsoCurrencyAmount)),
        ),
        (
            "an amount without its decimal point",
            definition(),
            changed(json!({"amount": "49 EUR"})),
            value_fault(8, "amount", ValueFault::Type(BaseType::IsoCurrencyAmount)),
        ),
        (
            "an amount with its code first",
            definition(),
            changed(json!({"amount": "EUR 49.99"})),
            value_fault(8, "amount", ValueFault::Type(BaseType::IsoCurrencyAmount)),
        ),
        (
            "mini_markdown that is a number",
            definition(),
            changed(json!({"terms": 1})),
            value_fault(10, "terms", ValueFault::NotString),
        ),
        (
            "a url that is http",
            definition(),
            changed(json!({"link": "http://shop.example"})),
            value_fault(11, "link", ValueFault::Type(BaseType::Url)),
        ),
        (
            "plain text that is a number",
            definition(),
            changed(json!({"text": 1})),
            value_fault(12, "text", ValueFault::NotString),
        ),
        // Templates (View, Section 3, `template:`).
        (
            "a placeholder of an image claim",
            definition(),
            template("{15}"),
            render(RenderFault::Template(TemplateFault::Reference(
                ClaimIndex::new(15),
            ))),
        ),
        (
            "a placeholder of an absent claim",
            definition(),
            template("{16}"),
            render(RenderFault::Template(TemplateFault::Absent(
                ClaimIndex::new(16),
            ))),
        ),
        (
            "a placeholder of a claim with more wildcards",
            definition(),
            template("{1}"),
            render(RenderFault::Template(TemplateFault::Wildcards(
                ClaimIndex::new(1),
            ))),
        ),
        (
            "an interpolated value that is no value of the inner type",
            redefined(
                14,
                displayed(json!(["summary"]), Some("template:iso_date"), "Summary"),
            ),
            template("{12}"),
            render(RenderFault::Value(
                at(&[json!("summary")]),
                ValueFault::Type(BaseType::IsoDate),
            )),
        ),
        (
            "an interpolated label over 60 clusters",
            redefined(
                12,
                json!({"path": ["text"], "display": [{"locale": "en", "name": "{11}{11}{11}", "display_type": "template:mini_markdown"}]}),
            ),
            payload(),
            render(RenderFault::Label(
                Some(ClaimIndex::new(12)),
                TextFault::TooLong(78),
            )),
        ),
        // The rendering cap (View, Section 2).
        (
            "more items than the cap",
            definition(),
            changed(
                json!({"items": (0..MAX_ITEMS).map(|i| json!({"name": i.to_string()})).collect::<Vec<_>>()}),
            ),
            render(RenderFault::TooManyItems(MAX_ITEMS + 12 + 1)),
        ),
    ];
    for (case, definition, payload, expected) in rows {
        assert_eq!(outcome(&definition, &payload), expected, "{case}");
    }
    // A placeholder past the end of the claims stays as written.
    let literal = outcome(&definition(), &template("{99} only")).unwrap();
    assert!(literal.contains(&("Summary".to_owned(), "{99} only".to_owned())));
}

/// Why a credential supports no type: its format, no source, or no entry for the wallet's
/// language.
#[test]
fn a_credential_supports_no_type() {
    let entry = json!({"type": TYPE, "credential_ids": ["card"], "payload": payload()});
    let entries = entries(&[entry.to_string()], &query(&["card"], CARD));
    let configured_host = Host::new(json!([configured(TYPE, CARD, &definition())]));
    assert_eq!(
        rows(&configured_host, &entries[0], &mdoc()),
        Err(Incompatibility::Format)
    );
    assert_eq!(
        rows(&Host::new(json!([])), &entries[0], &credential(CARD, &[])),
        Err(Incompatibility::TypeUnsupported)
    );
    assert_eq!(
        rows(
            &configured_host.speaking("fr"),
            &entries[0],
            &credential(CARD, &[])
        ),
        Err(Incompatibility::Language(Unmatched::Claim(
            ClaimIndex::new(1)
        )))
    );
}
