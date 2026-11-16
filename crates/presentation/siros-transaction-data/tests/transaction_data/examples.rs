//! Known answers of the specifications' own examples (see `tests/vectors/paso/SOURCE` and
//! `tests/vectors/cs12/SOURCE`): every example reads, and the definitions render the entries as
//! the annexes show them.

use serde_json::{json, Value};
use siros_codec::json::Json;
use siros_codec::member::ArrayIndex;
use siros_dcql::{DcqlQuery, QueryId};
use siros_oid4vp::RequestSignature;
use siros_transaction_data::{
    BaseType, ClaimFault, ClaimIndex, Definition, DefinitionError, DefinitionMember, EntryFault,
    ImageFault, Incompatibility, IntegrityFault, JwsFault, LabelRules, LabelsFault, Location,
    LocationStep, PayloadFault, Projected, RenderFault, RowValue, Rulebook, Scalar, Selection,
    SignedFault, SourceKind, TextFault, UiElementKey, Unmatched, UnsignedWarning, ValueFault,
};

use crate::common::{
    configured, credential, elements, entries, query, text, view_rows as rows, Host, CARD,
};

macro_rules! vector {
    ($name:literal) => {
        include_str!(concat!("../vectors/", $name))
    };
}

/// The JSON value of the JSON text `text`, as siros-codec reads it.
fn json(text: &str) -> Json {
    Json::parse_unique(text.as_bytes()).unwrap()
}

/// The definitions of a `transaction_data_types` object, by type.
fn types(object: &Json) -> Vec<(String, Definition)> {
    let Json::Object(members) = object else {
        panic!("no object")
    };
    members
        .iter()
        .map(|(name, value)| {
            let definition = Definition::parse(value.clone(), LabelRules::Paso).unwrap();
            (name.clone(), definition)
        })
        .collect()
}

/// The query of the ids the `credential_ids` of the entries `texts` name, of the card's `vct`.
fn query_for(texts: &[&str]) -> DcqlQuery {
    let mut ids: Vec<String> = Vec::new();
    for text in texts {
        for id in value(text)["credential_ids"].as_array().unwrap() {
            let id = id.as_str().unwrap().to_owned();
            if !ids.contains(&id) {
                ids.push(id);
            }
        }
    }
    query(&ids.iter().map(String::as_str).collect::<Vec<_>>(), CARD)
}

/// What the card takes of `entry` under the configured definition `definition`, in `language`.
fn select(entry: &str, type_id: &str, definition: &Value, language: &str) -> Selection {
    let host = Host::new(json!([configured(type_id, CARD, definition)])).speaking(language);
    let query = query_for(&[entry]);
    let entries = entries(&[entry.to_owned()], &query);
    host.select(&entries.iter().collect::<Vec<_>>(), &credential(CARD, &[]))
        .unwrap()
}

/// The location of the member path `keys` in a payload.
fn at(keys: &[&str]) -> Location {
    Location::new(
        keys.iter()
            .map(|k| LocationStep::Key((*k).to_owned()))
            .collect(),
    )
}

/// The JSON value of the vector text `text`, as serde_json reads it.
fn value(text: &str) -> Value {
    serde_json::from_str(text).unwrap()
}

#[test]
fn every_paso_example_reads() {
    let single = [
        vector!("paso/core-a1-entry.json"),
        vector!("paso/metadata-a4-entry.json"),
        vector!("paso/payment-a1-entry.json"),
        vector!("paso/generic-a1-entry.json"),
        vector!("paso/generic-a2-entry.json"),
        vector!("paso/generic-a3-entry.json"),
        vector!("paso/generic-a4-entry.json"),
        vector!("paso/mandate-a1-entry.json"),
        vector!("paso/mandate-a2-entry.json"),
        vector!("paso/mandate-a3-entry.json"),
    ];
    for text in single {
        assert_eq!(entries(&[text.to_owned()], &query_for(&[text])).len(), 1);
    }
    for list in [
        vector!("paso/core-a5-entries.json"),
        vector!("paso/core-a7-entries.json"),
    ] {
        let texts = elements(list);
        let all: Vec<&str> = texts.iter().map(String::as_str).collect();
        assert_eq!(entries(&texts, &query_for(&all)).len(), texts.len());
    }
    // The definitions: Metadata A.2's `transaction_data_types`, the `metadata` of the ad-hoc
    // JWTs of A.4 and A.5, and the rulebooks' entries.
    let a2 = json(vector!("paso/metadata-a2-payload.json"));
    let a2_types = a2
        .member("credential_metadata")
        .unwrap()
        .member("transaction_data_types")
        .unwrap();
    assert_eq!(types(a2_types).len(), 1);
    for payload in [
        vector!("paso/metadata-a4-payload.json"),
        vector!("paso/metadata-a5-payload.json"),
    ] {
        Definition::parse(
            json(payload).member("metadata").unwrap().clone(),
            LabelRules::Paso,
        )
        .unwrap();
    }
    for object in [
        vector!("paso/payment-a1-types.json"),
        vector!("paso/generic-a1-types.json"),
        vector!("paso/generic-a3-types.json"),
        vector!("paso/generic-a4-types.json"),
    ] {
        assert_eq!(types(&json(object)).len(), 1);
    }
    // Generic A.2 names its last claim in 69 extended grapheme clusters, over the 60 of Proof
    // Metadata, Section 3.3: the type is not supported.
    let aisp = json(vector!("paso/generic-a2-types.json"));
    assert_eq!(
        Definition::parse(
            aisp.member("urn:paso:sca:global:generic:aisp:1")
                .unwrap()
                .clone(),
            LabelRules::Paso
        ),
        Err(DefinitionError::Claim(
            ClaimIndex::new(4),
            ClaimFault::Display(LabelsFault::Entry(
                ArrayIndex::new(0),
                EntryFault::Text(DefinitionMember::Name, TextFault::TooLong(69))
            ))
        ))
    );
}

#[test]
fn the_paso_examples_render_as_the_annexes_show() {
    // Core A.1 with the definition of Metadata A.2: Core A.4's screen, in English and in German.
    let a2 = value(vector!("paso/metadata-a2-payload.json"));
    let payment =
        &a2["credential_metadata"]["transaction_data_types"]["urn:paso:sca:global:payment:1"];
    let a1 = vector!("paso/core-a1-entry.json");
    for (language, expected) in [
        ("en", [("Amount", "49.99 EUR"), ("Payee", "Shop Inc.")]),
        ("de", [("Betrag", "49.99 EUR"), ("Empfänger", "Shop Inc.")]),
        (
            "de-CH",
            [("Betrag", "49.99 EUR"), ("Empfänger", "Shop Inc.")],
        ),
    ] {
        let selection = select(a1, "urn:paso:sca:global:payment:1", payment, language);
        let view = crate::common::taken(&selection).view();
        let expected: Vec<(String, String)> = expected
            .iter()
            .map(|(l, v)| ((*l).to_owned(), (*v).to_owned()))
            .collect();
        assert_eq!(rows(view), expected, "{language}");
        assert!(matches!(
            view.rows()[0].value(),
            RowValue::Value(Scalar::CurrencyAmount(amount)) if amount.amount() == "49.99" && amount.currency().as_str() == "EUR"
        ));
    }
    // No `fr` entry and no default entry: the type is not usable in French (View, Section 4).
    let french = select(a1, "urn:paso:sca:global:payment:1", payment, "fr");
    assert_eq!(
        french,
        Selection::Excluded(vec![(
            siros_transaction_data::EntryPosition::new(0),
            Incompatibility::Language(Unmatched::Claim(ClaimIndex::new(1)))
        )])
    );

    // Generic A.1, A.3 and A.4, each with its definition.
    let generic = |entry: &str, object: &str, type_id: &str, language: &str| {
        select(entry, type_id, &value(object)[type_id], language)
    };
    let login = generic(
        vector!("paso/generic-a1-entry.json"),
        vector!("paso/generic-a1-types.json"),
        "urn:paso:sca:global:generic:login:1",
        "de",
    );
    let view = crate::common::taken(&login).view();
    assert_eq!(
        rows(view),
        [
            ("Dienstanbieter".to_owned(), "Acme Cloud".to_owned()),
            (
                "Gerät".to_owned(),
                "Chrome on macOS · Berlin, DE".to_owned()
            ),
            ("Zweck".to_owned(), "Sign in to your account".to_owned()),
        ]
    );
    assert_eq!(
        text(view.transaction_title().unwrap()),
        "Anmeldung bestätigen"
    );
    assert_eq!(text(view.affirmative_action_label().unwrap()), "Anmelden");

    let mandate = generic(
        vector!("paso/generic-a3-entry.json"),
        vector!("paso/generic-a3-types.json"),
        "urn:paso:sca:global:generic:emandate:1",
        "en",
    );
    let view = crate::common::taken(&mandate).view();
    assert_eq!(
        rows(view),
        [
            ("Mandate reference".to_owned(), "MND-2026-0042".to_owned()),
            (
                "Frequency".to_owned(),
                "Monthly, up to 24 months".to_owned()
            ),
            ("Amount per collection".to_owned(), "19.99 EUR".to_owned()),
            ("Payee".to_owned(), "Streaming Co.".to_owned()),
        ]
    );
    assert_eq!(
        view.security_hint().unwrap().as_str(),
        "Streaming Co. will be able to collect up to the amount shown each month for up to 24 months."
    );
    // Its `security_hint` has an English entry alone: in German the type is not usable.
    let german = generic(
        vector!("paso/generic-a3-entry.json"),
        vector!("paso/generic-a3-types.json"),
        "urn:paso:sca:global:generic:emandate:1",
        "de",
    );
    assert!(matches!(
        &german,
        Selection::Excluded(causes) if causes[0].1 == Incompatibility::Language(Unmatched::UiElement(UiElementKey::new("security_hint")))
    ));

    let limit = generic(
        vector!("paso/generic-a4-entry.json"),
        vector!("paso/generic-a4-types.json"),
        "urn:paso:sca:global:generic:limit-change:1",
        "en",
    );
    let view = crate::common::taken(&limit).view();
    assert_eq!(
        rows(view),
        [
            (
                "Limit type".to_owned(),
                "Daily transaction limit".to_owned()
            ),
            ("Current limit".to_owned(), "1000.00 EUR".to_owned()),
            ("New limit".to_owned(), "2500.00 EUR".to_owned()),
            ("Effective from".to_owned(), "2026-06-03".to_owned()),
        ]
    );

    // Metadata A.4's ad-hoc JWT is abbreviated, so it does not verify, and no other source
    // serves the entry (Section 5.3), the configuration's included.
    let a4 = value(vector!("paso/metadata-a4-payload.json"));
    let a4_entry = vector!("paso/metadata-a4-entry.json");
    let unverified = select(
        a4_entry,
        "urn:paso:sca:global:payment:1",
        &a4["metadata"],
        "en",
    );
    assert!(matches!(
        &unverified,
        Selection::Excluded(causes) if causes[0].1 == Incompatibility::AdHoc(SignedFault::Jws(JwsFault::Segments))
    ));
    // Its definition serving the entry without the JWT: the amount "EUR 45.00" is no
    // `iso_currency_amount`.
    let mut bare = value(a4_entry);
    bare.as_object_mut().unwrap().remove("metadata");
    let adhoc = select(
        &bare.to_string(),
        "urn:paso:sca:global:payment:1",
        &a4["metadata"],
        "en",
    );
    let amount = at(&["amount"]);
    assert!(matches!(
        &adhoc,
        Selection::Excluded(causes) if causes[0].1 == Incompatibility::Payload(PayloadFault::Value(
            ClaimIndex::new(1), amount.clone(), ValueFault::Type(BaseType::IsoCurrencyAmount)))
    ));

    // Payment A.1 pins its logo with a placeholder, which is no SHA-256 digest.
    let payment_types = value(vector!("paso/payment-a1-types.json"));
    let logo = select(
        vector!("paso/payment-a1-entry.json"),
        "urn:paso:sca:global:payment:1",
        &payment_types["urn:paso:sca:global:payment:1"],
        "en",
    );
    let at = at(&["payee", "logo"]);
    assert!(matches!(
        &logo,
        Selection::Excluded(causes) if causes[0].1 == Incompatibility::Payload(PayloadFault::Value(
            ClaimIndex::new(4), at.clone(), ValueFault::Image(ImageFault::Integrity(IntegrityFault::Malformed))))
    ));
}

/// CS-12's requests read, its `transaction_data_hashes_alg` string included, and its type
/// metadata serves its types: TS12 requires a name for every leaf, which the illustrative
/// metadata gives `amount` and `payee.name` alone.
#[test]
fn the_cs12_examples_read() {
    let iban: DcqlQuery = DcqlQuery::from_json(vector!("cs12/sca-iban-dcql.json")).unwrap();
    let user: DcqlQuery = DcqlQuery::from_json(vector!("cs12/sca-user-dcql.json")).unwrap();
    let payment = entries(&[vector!("cs12/payment-entry.json").to_owned()], &iban);
    entries(&[vector!("cs12/login-entry-iban.json").to_owned()], &iban);
    entries(&[vector!("cs12/login-entry-user.json").to_owned()], &user);
    assert_eq!(
        payment[0].credential_ids(),
        [QueryId::parse("sca_iban").unwrap()]
    );

    let vct = "https://issuer.bank.example/credentials/sca/iban/1.0";
    let mut host = Host::new(json!([])).speaking("en-GB");
    host.signature = RequestSignature::Unsigned;
    host.held.push((
        vct.to_owned(),
        vector!("cs12/sca-iban-type-metadata.json")
            .as_bytes()
            .to_vec(),
    ));
    let card = credential(vct, &[]);
    let selection = host.select(&[&payment[0]], &card).unwrap();
    let transaction_id = at(&["transaction_id"]);
    assert_eq!(
        selection,
        Selection::Excluded(vec![(
            siros_transaction_data::EntryPosition::new(0),
            Incompatibility::Render(RenderFault::LabelMissing(transaction_id))
        )])
    );
    // The claims are labelled `en-GB` alone: Lookup never takes them for `en`.
    let english = Host {
        language: siros_display::Locale::parse("en").unwrap(),
        ..host
    };
    assert!(matches!(
        english.select(&[&payment[0]], &card).unwrap(),
        Selection::Excluded(causes) if causes[0].1 == Incompatibility::Language(Unmatched::Claim(ClaimIndex::new(0)))
    ));
}

/// The UI elements catalogue of EC TS12 v1.0.1, Section 3.3.3 labels the controls of a payment
/// in German, and an unsigned request asks for explicit confirmation (Section 3.1).
#[test]
fn the_ts12_catalogue_labels_the_controls() {
    let vct = "https://pay.example/card";
    let claim = |path: &[&str], label: &str| {
        let mut full = vec!["payload"];
        full.extend_from_slice(path);
        json!({"path": full, "display": [{"lang": "de", "label": label}]})
    };
    let catalogue: Value = serde_json::from_str(
        r#"{
    "affirmative_action_label": [
        {
            "lang": "de",
            "value": "Zahlung bestätigen"
        },
        {
            "lang": "en",
            "value": "Confirm Payment"
        }
    ],
    "denial_action_label": [
        {
            "lang": "de",
            "value": "Zahlung abbrechen"
        },
        {
            "lang": "en",
            "value": "Cancel Payment"
        }
    ]
}"#,
    )
    .unwrap();
    let metadata = json!({
        "vct": vct,
        "category": "urn:eu:europa:ec:eudi:sua:sca",
        "transaction_data_types": {"urn:eudi:sca:payment:1": {
            "schema": "urn:eudi:sca:payment:1",
            "claims": [
                claim(&["transaction_id"], "Transaktionsnummer"),
                claim(&["payee", "name"], "Empfänger"),
                claim(&["payee", "id"], "Kennung"),
                claim(&["currency"], "Währung"),
                claim(&["amount"], "Betrag")
            ],
            "ui_labels": catalogue
        }}
    });
    let mut host = Host::new(json!([])).speaking("de");
    host.signature = RequestSignature::Unsigned;
    host.held
        .push((vct.to_owned(), metadata.to_string().into_bytes()));
    let entry = json!({
        "type": "urn:eudi:sca:payment:1", "credential_ids": ["pay"],
        "transaction_data_hashes_alg": ["sha-256"],
        "payload": {"transaction_id": "tx-1", "payee": {"name": "Shop AB", "id": "SE1"},
                    "currency": "EUR", "amount": 49.99}
    });
    let entries = entries(&[entry.to_string()], &query(&["pay"], vct));
    let selection = host.select(&[&entries[0]], &credential(vct, &[])).unwrap();
    let view = crate::common::taken(&selection).view();
    assert_eq!(
        text(view.affirmative_action_label().unwrap()),
        "Zahlung bestätigen"
    );
    assert_eq!(
        text(view.denial_action_label().unwrap()),
        "Zahlung abbrechen"
    );
    assert_eq!(view.unsigned_warning(), UnsignedWarning::Required);
    assert_eq!(
        rows(view).last(),
        Some(&("Betrag".to_owned(), "49.99".to_owned()))
    );
}

/// The definition of Metadata A.2 projected to German: each array keeps its German entry, every
/// other member stays, and the text reads back to the projection.
#[test]
fn the_projection_keeps_one_entry_per_array() {
    let a2 = json(vector!("paso/metadata-a2-payload.json"));
    let definition = a2
        .member("credential_metadata")
        .unwrap()
        .member("transaction_data_types")
        .unwrap()
        .member("urn:paso:sca:global:payment:1")
        .unwrap();
    let definition = Definition::parse(definition.clone(), LabelRules::Paso).unwrap();
    let german = siros_display::Locale::parse("de-AT").unwrap();
    let projected = definition
        .project(&german, SourceKind::CredentialMetadata, Rulebook::Generic)
        .unwrap();
    let text = projected.to_json();
    let expected = json!({
        "language": "de-AT", "source": "credential_metadata", "rulebook": "generic",
        "definition": {
            "claims": [
                {"path": ["transaction_id"], "mandatory": true},
                {"path": ["amount"], "mandatory": true, "value_type": "iso_currency_amount",
                 "display": [{"locale": "de", "name": "Betrag"}]},
                {"path": ["payee", "name"], "mandatory": true,
                 "display": [{"locale": "de", "name": "Empfänger"}]},
                {"path": ["payee", "id"], "mandatory": true}
            ],
            "ui_labels": {}
        }
    });
    assert_eq!(serde_json::from_str::<Value>(&text).unwrap(), expected);
    assert_eq!(Projected::parse(&text), Ok(projected));
}
