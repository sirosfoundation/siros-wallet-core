//! The projection a registration carries (K1): it reads back to itself, whatever the member
//! order of its source, and its reader refuses what is no projection, a row per rule.

use serde_json::{json, Value};
use siros_codec::json::Json;
use siros_codec::member::ArrayIndex;
use siros_display::Locale;
use siros_transaction_data::{
    ClaimFault, ClaimIndex, Definition, DefinitionError, DefinitionMember, EntryFault, LabelsFault,
    Projected, ProjectionError, Rulebook, SourceKind, TextFault, Ts12Type, Unmatched,
};

/// The projection of `definition`, its labels under the rules of `source`, in `language`.
fn project(
    definition: &Value,
    language: &str,
    source: SourceKind,
    rulebook: Rulebook,
) -> Projected {
    let read = Json::parse_unique(definition.to_string().as_bytes()).unwrap();
    Definition::parse(read, source.label_rules())
        .unwrap()
        .project(&Locale::parse(language).unwrap(), source, rulebook)
        .unwrap()
}

/// The additional parameters write in the member order of RFC 8785, so two definitions that
/// differ in member order alone write one text; a TS12 projection reads back with its
/// `visualisation` and its descriptions.
#[test]
fn a_projection_reads_back_whatever_the_member_order() {
    let claims = json!([{"path": ["amount"], "display": [{"locale": "en", "name": "Amount"}]}]);
    let one: Value = serde_json::from_str(&format!(
        r#"{{"claims": {claims}, "zeta": {{"b": 1, "a": [{{"d": 4, "c": 3}}]}}, "alpha": true}}"#
    ))
    .unwrap();
    let other: Value = serde_json::from_str(&format!(
        r#"{{"alpha": true, "zeta": {{"a": [{{"c": 3, "d": 4}}], "b": 1}}, "claims": {claims}}}"#
    ))
    .unwrap();
    let generic = |definition: &Value| {
        project(
            definition,
            "en",
            SourceKind::Configuration,
            Rulebook::Generic,
        )
        .to_json()
    };
    let text = generic(&one);
    assert_eq!(generic(&other), text);
    assert!(
        text.ends_with(r#""alpha":true,"zeta":{"a":[{"c":3,"d":4}],"b":1}}}"#),
        "{text}"
    );
    assert_eq!(
        Projected::parse(&text),
        Ok(project(
            &one,
            "en",
            SourceKind::Configuration,
            Rulebook::Generic
        ))
    );

    let ts12 = json!({"claims": [{"path": ["amount"], "visualisation": 1, "display": [
        {"locale": "en", "name": &"A".repeat(70), "description": "Line one\nLine two"},
        {"locale": "de", "name": "Betrag"}]}],
        "ui_labels": {"security_hint": [{"locale": "en", "value": &"h".repeat(250)}]}});
    let payment = Rulebook::Ts12(Ts12Type::Payment);
    let projected = project(&ts12, "en-GB", SourceKind::TypeMetadata, payment);
    assert_eq!(Projected::parse(&projected.to_json()), Ok(projected));
}

#[test]
fn each_projection_rule_is_refused_alone() {
    let honest = json!({"language": "en", "source": "configuration", "rulebook": "generic",
        "definition": {"claims": [{"path": ["amount"],
            "display": [{"locale": "en", "name": "Amount"}]}]}});
    let changed = |name: &str, value: Value| {
        let mut projection = honest.clone();
        projection[name] = value;
        projection
    };
    let display = |entries: Value| {
        changed(
            "definition",
            json!({"claims": [{"path": ["amount"], "display": entries}]}),
        )
    };
    let rows: Vec<(&str, Value, Result<(), ProjectionError>)> = vec![
        ("the honest projection", honest.clone(), Ok(())),
        (
            "a source no source names",
            changed("source", json!("registry")),
            Err(ProjectionError::Source("registry".to_owned())),
        ),
        (
            "a rulebook no rulebook names",
            changed("rulebook", json!("urn:eudi:sca:unknown:1")),
            Err(ProjectionError::Rulebook(
                "urn:eudi:sca:unknown:1".to_owned(),
            )),
        ),
        (
            "a member a projection does not define",
            changed("note", json!("x")),
            Err(ProjectionError::MemberUnknown("note".to_owned())),
        ),
        (
            "two entries in an array",
            display(
                json!([{"locale": "en", "name": "Amount"}, {"locale": "de", "name": "Betrag"}]),
            ),
            Err(ProjectionError::EntryCount(Unmatched::Claim(
                ClaimIndex::new(0),
            ))),
        ),
        (
            "an entry of another language",
            display(json!([{"locale": "de", "name": "Betrag"}])),
            Err(ProjectionError::Unmatched(Unmatched::Claim(
                ClaimIndex::new(0),
            ))),
        ),
        (
            "a claim name over PaSO's 60 from the configuration",
            display(json!([{"locale": "en", "name": "A".repeat(61)}])),
            Err(ProjectionError::Definition(DefinitionError::Claim(
                ClaimIndex::new(0),
                ClaimFault::Display(LabelsFault::Entry(
                    ArrayIndex::new(0),
                    EntryFault::Text(DefinitionMember::Name, TextFault::TooLong(61)),
                )),
            ))),
        ),
    ];
    for (case, projection, expected) in rows {
        assert_eq!(
            Projected::parse(&projection.to_string()).map(drop),
            expected,
            "{case}"
        );
    }
}
