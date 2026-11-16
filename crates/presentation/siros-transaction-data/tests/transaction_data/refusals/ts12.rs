//! TS12 v1.0.1 type metadata as a source (Sections 3, 3.3 and 4.1; SD-JWT VC, Sections 6 and
//! 7), the TS12 rendering rules of Section 3.3.1, and TS12 logos: a row per rule.

use serde_json::{json, Value};
use siros_codec::member::{ArrayIndex, MemberFault};
use siros_oid4vp::HttpsUrl;
use siros_transaction_data::{
    Channel, ClaimFault, ClaimIndex, DefinitionError, DefinitionMember, EntryFault, ImageFault,
    ImageFormat, Incompatibility, IntegrityFault, LabelsFault, Location, LocationStep, Prominence,
    RenderFault, Selection, SourceKind, TextFault, Ts12Fault, Ts12Member, Ts12Type, UiElementKey,
    Wanted, MAX_IMAGE_BYTES,
};

use crate::common::{
    b64, configured, credential_with, entries, now, query, sri, text, Host, PAYMENT,
};

/// The documents the host holds, by URL.
type Held = Vec<(String, Vec<u8>)>;

const VCT: &str = "https://pay.example/card";
const CLAIMS_URI: &str = "https://pay.example/claims.json";

fn claim(path: &[&str], label: &str) -> Value {
    let mut full = vec!["payload"];
    full.extend_from_slice(path);
    json!({"path": full, "display": [{"lang": "en", "label": label}]})
}

fn claims() -> Value {
    json!([
        claim(&["transaction_id"], "Transaction ID"),
        claim(&["payee", "name"], "Payee"),
        claim(&["payee", "id"], "Payee ID"),
        claim(&["currency"], "Currency"),
        claim(&["amount"], "Amount")
    ])
}

/// The payment entry of the type metadata, with `changes`; a `null` change removes a member.
fn payment_type(changes: Value) -> Value {
    let mut entry = json!({
        "schema_uri": PAYMENT,
        "claims": claims(),
        "ui_labels": {"affirmative_action_label": [{"lang": "en", "value": "Confirm"}]}
    });
    for (name, change) in changes.as_object().unwrap() {
        if change.is_null() {
            entry.as_object_mut().unwrap().remove(name);
        } else {
            entry[name] = change.clone();
        }
    }
    entry
}

fn document(payment: Value) -> Value {
    json!({"vct": VCT, "category": "urn:eu:europa:ec:eudi:sua:sca",
           "transaction_data_types": {PAYMENT: payment}})
}

/// What the card of the claims `extra` takes of a payment of `payload`, the host holding
/// `documents`.
fn outcome(payload: &Value, extra: &Value, documents: Held) -> Selection {
    let mut host = Host::new(json!([]));
    host.held = documents;
    let entry = json!({"type": PAYMENT, "credential_ids": ["pay"],
                       "transaction_data_hashes_alg": ["sha-256"], "payload": payload});
    let entries = entries(&[entry.to_string()], &query(&["pay"], VCT));
    host.select(&[&entries[0]], &credential_with(VCT, &[], extra))
        .unwrap()
}

fn payment() -> Value {
    json!({"transaction_id": "tx-1", "payee": {"name": "Shop", "id": "SE1"}, "currency": "EUR",
           "amount": 9.25})
}

fn served(document: &Value) -> Held {
    vec![(VCT.to_owned(), document.to_string().into_bytes())]
}

fn fault(fault: Ts12Fault) -> Option<Incompatibility> {
    Some(Incompatibility::TypeMetadata(fault))
}

fn cause(selection: Selection) -> Option<Incompatibility> {
    match selection {
        Selection::Takes(_) => None,
        Selection::Excluded(mut causes) => Some(causes.remove(0).1),
    }
}

#[test]
fn each_type_metadata_rule_is_refused_alone() {
    let honest = document(payment_type(json!({})));
    let claims_document = claims().to_string();
    let pin = format!("transaction_data_types['{PAYMENT}'].claims_uri#integrity");
    let referenced = document(payment_type(
        json!({"claims": null, "claims_uri": CLAIMS_URI}),
    ));
    let with_claims = |text: &str| {
        let mut documents = served(&referenced);
        documents.push((CLAIMS_URI.to_owned(), text.as_bytes().to_vec()));
        documents
    };
    let none = json!({});
    let definition = |error| fault(Ts12Fault::Definition(error));
    let rows: Vec<(&str, Value, Held, Option<Incompatibility>)> = vec![
        ("honest type metadata", none.clone(), served(&honest), None),
        (
            "no schema",
            none.clone(),
            served(&document(payment_type(json!({"schema_uri": null})))),
            fault(Ts12Fault::OneOf(Ts12Member::Schema)),
        ),
        (
            "an embedded JSON Schema",
            none.clone(),
            served(&document(payment_type(
                json!({"schema_uri": null, "schema": {"type": "object"}}),
            ))),
            fault(Ts12Fault::SchemaEmbedded),
        ),
        (
            "a schema of no built-in type",
            none.clone(),
            served(&document(payment_type(
                json!({"schema_uri": "urn:example:schema"}),
            ))),
            fault(Ts12Fault::SchemaUnknown("urn:example:schema".to_owned())),
        ),
        (
            "the schema of another type",
            none.clone(),
            served(&document(payment_type(
                json!({"schema_uri": "urn:eudi:sca:login_risk_transaction:1"}),
            ))),
            fault(Ts12Fault::SchemaMismatch(Ts12Type::Payment)),
        ),
        (
            "claims and claims_uri both",
            none.clone(),
            served(&document(payment_type(json!({"claims_uri": CLAIMS_URI})))),
            fault(Ts12Fault::OneOf(Ts12Member::Claims)),
        ),
        (
            "a claims_uri that is no https URL",
            none.clone(),
            served(&document(payment_type(
                json!({"claims": null, "claims_uri": "http://pay.example/c"}),
            ))),
            fault(Ts12Fault::DocumentNotHttps(
                "http://pay.example/c".to_owned(),
            )),
        ),
        (
            "claims referenced and pinned",
            json!({pin.clone(): sri(claims_document.as_bytes())}),
            with_claims(&claims_document),
            None,
        ),
        (
            "claims that do not match their pin (Section 4.1.2)",
            json!({pin.clone(): sri(b"[]")}),
            with_claims(&claims_document),
            fault(Ts12Fault::Integrity(IntegrityFault::Mismatch)),
        ),
        (
            "a document of another vct (SD-JWT VC, Section 6.3)",
            none.clone(),
            served(
                &json!({"vct": "https://pay.example/other", "category": "urn:eu:europa:ec:eudi:sua:sca",
                           "transaction_data_types": {PAYMENT: payment_type(json!({}))}}),
            ),
            fault(Ts12Fault::VctMismatch),
        ),
        (
            "a document that does not match vct#integrity (SD-JWT VC, Section 7)",
            json!({"vct#integrity": sri(b"{}")}),
            served(&honest),
            fault(Ts12Fault::Integrity(IntegrityFault::Mismatch)),
        ),
        (
            "a document vct#integrity pins, absent",
            json!({"vct#integrity": sri(b"{}")}),
            vec![],
            fault(Ts12Fault::NotHeld(HttpsUrl::parse(VCT).unwrap())),
        ),
        (
            "a vct#integrity that is no integrity metadata (SD-JWT VC, Section 7)",
            json!({"vct#integrity": "sha256-short"}),
            served(&honest),
            fault(Ts12Fault::PinValue(IntegrityFault::Malformed)),
        ),
        (
            "no document held",
            none.clone(),
            vec![],
            fault(Ts12Fault::NotHeld(HttpsUrl::parse(VCT).unwrap())),
        ),
        (
            "no SCA category (Section 3.2, step 1): no type",
            none.clone(),
            served(
                &json!({"vct": VCT, "transaction_data_types": {PAYMENT: payment_type(json!({}))}}),
            ),
            Some(Incompatibility::TypeUndeclared),
        ),
        (
            "the SCA category without transaction_data_types (Section 3.2)",
            none.clone(),
            served(&json!({"vct": VCT, "category": "urn:eu:europa:ec:eudi:sua:sca"})),
            fault(Ts12Fault::Member(
                Ts12Member::TransactionDataTypes,
                MemberFault::Absent,
            )),
        ),
        (
            "a path outside payload (Section 2.3)",
            none.clone(),
            served(&document(payment_type(
                json!({"claims": [{"path": ["amount"]}]}),
            ))),
            fault(Ts12Fault::PathOutsidePayload),
        ),
        (
            "a visualisation of 5 (Section 3.3.2)",
            none.clone(),
            served(&document(payment_type(
                json!({"claims": [{"path": ["payload", "amount"], "visualisation": 5}]}),
            ))),
            definition(DefinitionError::Claim(
                ClaimIndex::new(0),
                ClaimFault::Visualisation,
            )),
        ),
        (
            "both lang and locale",
            none.clone(),
            served(&document(payment_type(
                json!({"claims": [{"path": ["payload", "amount"],
                "display": [{"lang": "en", "locale": "en", "label": "Amount"}]}]}),
            ))),
            fault(Ts12Fault::OneOf(Ts12Member::Lang)),
        ),
        (
            "an affirmative_action_label over 30 characters (Section 3.3.3)",
            none.clone(),
            served(&document(payment_type(
                json!({"ui_labels": {"affirmative_action_label":
                [{"lang": "en", "value": "Confirm this payment to the shop"}]}}),
            ))),
            definition(DefinitionError::UiElement(
                UiElementKey::new("affirmative_action_label"),
                LabelsFault::Entry(
                    ArrayIndex::new(0),
                    EntryFault::Text(DefinitionMember::Value, TextFault::TooLong(32)),
                ),
            )),
        ),
        (
            "a security_hint of 200 characters (Section 3.3.3)",
            none.clone(),
            served(&document(payment_type(json!({"ui_labels": {
                "affirmative_action_label": [{"lang": "en", "value": "Confirm"}],
                "security_hint": [{"lang": "en", "value": "h".repeat(200)}]}})))),
            None,
        ),
        (
            "a claim label of 70 characters",
            none.clone(),
            served(&document(payment_type(json!({"claims": [
                claim(&["transaction_id"], "Transaction ID"),
                claim(&["payee", "name"], &"P".repeat(70)),
                claim(&["payee", "id"], "Payee ID"),
                claim(&["currency"], "Currency"),
                claim(&["amount"], "Amount")
            ]})))),
            None,
        ),
        (
            "a description over two lines",
            none.clone(),
            served(&document(payment_type(json!({"claims": [
                claim(&["transaction_id"], "Transaction ID"),
                {"path": ["payload", "payee", "name"], "display":
                    [{"lang": "en", "label": "Payee", "description": "Line one\nLine two"}]},
                claim(&["payee", "id"], "Payee ID"),
                claim(&["currency"], "Currency"),
                claim(&["amount"], "Amount")
            ]})))),
            None,
        ),
        (
            "no affirmative_action_label (Section 3.3.3)",
            none.clone(),
            served(&document(payment_type(json!({"ui_labels": {}})))),
            fault(Ts12Fault::AffirmativeAbsent),
        ),
    ];
    for (case, extra, documents, expected) in rows {
        assert_eq!(
            cause(outcome(&payment(), &extra, documents)),
            expected,
            "{case}"
        );
    }
}

/// Section 3.3.1: each leaf takes its level, 3 when unset, raised to the floor of its type; a
/// leaf of level 4 without a name is left out, any other needs one.
#[test]
fn every_leaf_shows_unless_level_4() {
    let at = |key: &str| Location::new(vec![LocationStep::Key(key.to_owned())]);
    let with_claims = |claims: Value| served(&document(payment_type(json!({"claims": claims}))));
    let mut payload = payment();
    payload["date_time"] = json!("2026-10-26T10:00:00Z");
    let mut leveled = claims();
    leveled
        .as_array_mut()
        .unwrap()
        .push(json!({"path": ["payload", "date_time"], "visualisation": 4}));
    leveled[0]["visualisation"] = json!(4);
    let selection = outcome(&payload, &json!({}), with_claims(leveled));
    let Selection::Takes(taken) = selection else {
        panic!("a level-4 leaf without a name is left out")
    };
    let prominence: Vec<(String, Option<Prominence>)> = taken
        .view()
        .rows()
        .iter()
        .map(|row| (text(row.label()), row.prominence()))
        .collect();
    assert_eq!(
        prominence,
        [
            // Level 4 set, raised to the transaction_id's floor.
            ("Transaction ID".to_owned(), Some(Prominence::Main)),
            ("Payee".to_owned(), Some(Prominence::Prominent)),
            ("Payee ID".to_owned(), Some(Prominence::Main)),
            ("Currency".to_owned(), Some(Prominence::Prominent)),
            ("Amount".to_owned(), Some(Prominence::Prominent)),
        ]
    );
    let mut unnamed = claims();
    unnamed[0] = json!({"path": ["payload", "transaction_id"], "visualisation": 4});
    assert_eq!(
        cause(outcome(&payment(), &json!({}), with_claims(unnamed))),
        Some(Incompatibility::Render(RenderFault::LabelMissing(at(
            "transaction_id"
        ))))
    );
}

/// A TS12 logo is a resolvable URL or a Data URL, with no integrity value required (Section
/// 4.3.1). A logo the request's channel does not admit is left out of the view, and the payment
/// stays compatible (PaSO Proof SD-JWT-VC and SVG, Section 2).
#[test]
fn a_ts12_logo_is_shown_or_left_out() {
    let mut claims = claims();
    claims
        .as_array_mut()
        .unwrap()
        .push(claim(&["payee", "logo"], "Logo"));
    let mut host = Host::new(json!([]));
    host.held = served(&document(payment_type(json!({"claims": claims}))));
    let logo = Location::new(vec![
        LocationStep::Key("payee".to_owned()),
        LocationStep::Key("logo".to_owned()),
    ]);
    let large = format!("data:image/png;base64,{}", "A".repeat(MAX_IMAGE_BYTES + 4));
    let svg = format!("data:image/svg+xml;base64,{}", b64(b"<svg/>"));
    let url = "https://shop.example/logo.png";
    // (case, channel, logo, the fault that leaves it out; `None` when it is shown)
    let rows: Vec<(&str, Channel, &str, Option<ImageFault>)> = vec![
        (
            "an https URL without #integrity",
            Channel::Redirect,
            url,
            None,
        ),
        (
            "an http URL",
            Channel::Redirect,
            "http://shop.example/logo.png",
            Some(ImageFault::NotHttps),
        ),
        (
            "an https URL over the DC API",
            Channel::DcApi,
            url,
            Some(ImageFault::RemoteOverDcApi),
        ),
        (
            "an SVG Data URL over the DC API",
            Channel::DcApi,
            &svg,
            Some(ImageFault::FormatOverDcApi(ImageFormat::Svg)),
        ),
        (
            "a Data URL over 512 KiB over the DC API",
            Channel::DcApi,
            &large,
            Some(ImageFault::TooLarge(MAX_IMAGE_BYTES + 4)),
        ),
    ];
    for (case, channel, value, left_out) in rows {
        host.channel = channel;
        let mut payload = payment();
        payload["payee"]["logo"] = json!(value);
        let entry = json!({"type": PAYMENT, "credential_ids": ["pay"],
                           "transaction_data_hashes_alg": ["sha-256"], "payload": payload});
        let entries = entries(&[entry.to_string()], &query(&["pay"], VCT));
        let selection = host.select(&[&entries[0]], &credential_with(VCT, &[], &json!({})));
        let Ok(Selection::Takes(taken)) = selection else {
            panic!("{case}: {selection:?}")
        };
        let absent: Vec<(Location, ImageFault)> = left_out
            .iter()
            .map(|fault| (logo.clone(), fault.clone()))
            .collect();
        assert_eq!(taken.view().absent_images(), absent, "{case}");
        let shown = if left_out.is_some() { 5 } else { 6 };
        assert_eq!(taken.view().rows().len(), shown, "{case}");
    }
}

/// The TS12 rulebook requires `transaction_data_hashes_alg` whatever the type's key: a type
/// SCA type metadata defines with a built-in schema (Section 4.2).
#[test]
fn a_ts12_rulebook_requires_the_hash_algorithms() {
    let key = "https://standardsbody.org/eudiw-trx/payment";
    let mut host = Host::new(json!([]));
    host.held = served(
        &json!({"vct": VCT, "category": "urn:eu:europa:ec:eudi:sua:sca",
        "transaction_data_types": {key: payment_type(json!({}))}}),
    );
    let select = |alg: Option<Value>| {
        let mut entry = json!({"type": key, "credential_ids": ["pay"], "payload": payment()});
        if let Some(alg) = alg {
            entry["transaction_data_hashes_alg"] = alg;
        }
        let entries = entries(&[entry.to_string()], &query(&["pay"], VCT));
        host.select(&[&entries[0]], &credential_with(VCT, &[], &json!({})))
            .unwrap()
    };
    assert!(matches!(
        select(Some(json!(["sha-256"]))),
        Selection::Takes(_)
    ));
    assert_eq!(cause(select(None)), Some(Incompatibility::HashesAlgAbsent));
}

/// The configuration serves only a credential without transaction metadata of its own: the SCA
/// type metadata of a `vct` declares every type its credentials support (Section 3.2, step 2).
#[test]
fn the_configuration_serves_only_credentials_without_metadata() {
    let limit = "urn:example:limit-change";
    let definition = json!({"claims": [
        {"path": ["action"], "display": [{"locale": "en", "name": "Action"}]}
    ]});
    let mut host = Host::new(json!([configured(limit, VCT, &definition)]));
    let entry = json!({"type": limit, "credential_ids": ["pay"],
                       "payload": {"action": "Raise limit"}});
    let entries = entries(&[entry.to_string()], &query(&["pay"], VCT));
    let card = credential_with(VCT, &[], &json!({}));
    let source = |host: &Host| match host.select(&[&entries[0]], &card).unwrap() {
        Selection::Takes(taken) => Ok(taken.view().source()),
        Selection::Excluded(mut causes) => Err(causes.remove(0).1),
    };
    // Neither held nor recorded absent: whether the credential has metadata is unknown.
    assert_eq!(
        source(&host),
        Err(Incompatibility::TypeMetadata(Ts12Fault::NotHeld(
            HttpsUrl::parse(VCT).unwrap()
        )))
    );
    host.absent = vec![VCT.to_owned()];
    assert_eq!(
        source(&host),
        Ok(SourceKind::Configuration),
        "recorded absent"
    );
    host.absent = Vec::new();
    host.held = served(&json!({"vct": VCT, "name": "Card"}));
    assert_eq!(
        source(&host),
        Ok(SourceKind::Configuration),
        "held without SCA types"
    );
    host.held = served(&document(payment_type(json!({}))));
    assert_eq!(
        source(&host),
        Err(Incompatibility::TypeUndeclared),
        "held with SCA types"
    );
    host.held = served(&json!({"vct": VCT, "category": "urn:example:other",
                               "transaction_data_types": {limit: {}}}));
    assert_eq!(
        source(&host),
        Err(Incompatibility::TypeUndeclared),
        "held with types of another category"
    );
    // Without its issuer metadata, whether the credential is a PaSO Credential is unknown.
    host.absent = vec![VCT.to_owned()];
    host.held = Vec::new();
    host.display = siros_display::DisplayCache::new(Vec::new(), Vec::new()).unwrap();
    assert_eq!(source(&host), Err(Incompatibility::IssuerMetadataNotHeld));

    // A vct that is no https URL locates no document, and a pin of one locates none either.
    let urn = "urn:example:card";
    let host = Host::new(json!([configured(limit, urn, &definition)]));
    let urn_entries = crate::common::entries(&[entry.to_string()], &query(&["pay"], urn));
    let pinned = credential_with(urn, &[], &json!({"vct#integrity": sri(b"{}")}));
    assert_eq!(
        cause(host.select(&[&urn_entries[0]], &pinned).unwrap()),
        Some(Incompatibility::TypeMetadata(Ts12Fault::VctNotHttps))
    );
}

/// The documents the host should hold for a credential without a chain: its Type Metadata and
/// its issuer's metadata, then the documents the Type Metadata references.
#[test]
fn the_host_learns_the_documents_to_hold() {
    let card = credential_with(VCT, &[], &json!({}));
    let issuer_metadata = "https://issuer.bank.example/.well-known/jwt-vc-issuer";
    let url = |text: &str| Wanted::Document(HttpsUrl::parse(text).unwrap());
    let mut host = Host::new(json!([]));
    let wanted = |host: &Host| {
        host.metadata()
            .wanted(&card, &host.display, &host.trust, now())
            .unwrap()
    };
    assert_eq!(wanted(&host), [url(VCT), url(issuer_metadata)]);
    host.absent = vec![issuer_metadata.to_owned()];
    assert_eq!(wanted(&host), [url(VCT)], "recorded absent");
    host.absent = Vec::new();
    let referenced = document(payment_type(
        json!({"claims": null, "claims_uri": CLAIMS_URI}),
    ));
    host.held = served(&referenced);
    assert_eq!(wanted(&host), [url(CLAIMS_URI), url(issuer_metadata)]);
}
