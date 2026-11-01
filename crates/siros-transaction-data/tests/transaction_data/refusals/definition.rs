//! The rules of a definition (PaSO Proof Metadata, Sections 3.1 to 3.3): label lengths by role
//! in extended grapheme clusters, or in characters under TS12's rules (EC TS12 v1.0.1, Section
//! 3.3.3), label characters, and the structural rules.

use serde_json::{json, Value};
use siros_codec::json::Json;
use siros_codec::member::{ArrayIndex, MemberFault};
use siros_display::{Locale, LocaleError};
use siros_transaction_data::{
    ClaimFault, ClaimIndex, Definition, DefinitionError, DefinitionMember, EntryFault, LabelRules,
    LabelsFault, Rulebook, SourceKind, TextFault, UiElementKey,
};

/// The honest definition: one displayed claim, and the four UI elements of Section 3.2.
fn honest() -> Value {
    json!({
        "claims": [{"path": ["amount"], "mandatory": true, "value_type": "iso_currency_amount",
                    "display": [{"locale": "en", "name": "Amount"}]}],
        "ui_labels": {
            "transaction_title": [{"locale": "en", "value": "Confirm"}],
            "affirmative_action_label": [{"locale": "en", "value": "Pay"}],
            "denial_action_label": [{"locale": "en", "value": "Cancel"}],
            "security_hint": [{"locale": "en", "value": "Check the amount"}]
        }
    })
}

/// The honest definition with its claim's display name `name`.
fn named(name: &str) -> Value {
    let mut definition = honest();
    definition["claims"][0]["display"][0]["name"] = json!(name);
    definition
}

/// The honest definition with the UI element `element`'s array `entries`.
fn labelled(element: &str, entries: Value) -> Value {
    let mut definition = honest();
    definition["ui_labels"][element] = entries;
    definition
}

/// The honest definition with its claims `claims`.
fn claims(claims: Value) -> Value {
    let mut definition = honest();
    definition["claims"] = claims;
    definition
}

/// The honest claim with `changes`; a `null` change removes the member.
fn claim(changes: Value) -> Value {
    let mut claim = honest()["claims"][0].clone();
    for (name, change) in changes.as_object().unwrap() {
        if change.is_null() {
            claim.as_object_mut().unwrap().remove(name);
        } else {
            claim[name] = change.clone();
        }
    }
    claim
}

/// `n` extended grapheme clusters of an `e` with a combining acute accent: twice as many
/// characters.
fn graphemes(n: usize) -> String {
    "e\u{301}".repeat(n)
}

fn text(fault: TextFault) -> DefinitionError {
    name_fault(EntryFault::Text(DefinitionMember::Name, fault))
}

fn name_fault(fault: EntryFault) -> DefinitionError {
    DefinitionError::Claim(
        ClaimIndex::new(0),
        ClaimFault::Display(LabelsFault::Entry(ArrayIndex::new(0), fault)),
    )
}

fn element(element: &str, fault: TextFault) -> DefinitionError {
    DefinitionError::UiElement(
        UiElementKey::new(element),
        LabelsFault::Entry(
            ArrayIndex::new(0),
            EntryFault::Text(DefinitionMember::Value, fault),
        ),
    )
}

fn value(text: &str) -> Value {
    json!([{"locale": "en", "value": text}])
}

#[test]
fn each_definition_rule_is_refused_alone() {
    let display = |entries: Value| claims(json!([claim(json!({"display": entries}))]));
    let many = |n: usize| {
        let claims: Vec<Value> = (0..n).map(|i| json!({"path": [format!("c{i}")]})).collect();
        json!({"claims": claims})
    };
    let rows: Vec<(&str, Value, Result<(), DefinitionError>)> = vec![
        ("the honest definition", honest(), Ok(())),
        // Lengths (Section 3.3), counted in extended grapheme clusters (UAX #29).
        (
            "a name of 60 clusters, 120 characters",
            named(&graphemes(60)),
            Ok(()),
        ),
        (
            "a name of 61 clusters",
            named(&graphemes(61)),
            Err(text(TextFault::TooLong(61))),
        ),
        (
            "a title of 100",
            labelled("transaction_title", value(&graphemes(100))),
            Ok(()),
        ),
        (
            "a title of 101",
            labelled("transaction_title", value(&graphemes(101))),
            Err(element("transaction_title", TextFault::TooLong(101))),
        ),
        (
            "an action label of 40",
            labelled("affirmative_action_label", value(&graphemes(40))),
            Ok(()),
        ),
        (
            "an affirmative action label of 41",
            labelled("affirmative_action_label", value(&graphemes(41))),
            Err(element("affirmative_action_label", TextFault::TooLong(41))),
        ),
        (
            "a denial action label of 41",
            labelled("denial_action_label", value(&graphemes(41))),
            Err(element("denial_action_label", TextFault::TooLong(41))),
        ),
        (
            "a security hint of 160",
            labelled("security_hint", value(&graphemes(160))),
            Ok(()),
        ),
        (
            "a security hint of 161",
            labelled("security_hint", value(&graphemes(161))),
            Err(element("security_hint", TextFault::TooLong(161))),
        ),
        (
            "another element of 100",
            labelled("reward_note", value(&graphemes(100))),
            Ok(()),
        ),
        (
            "another element of 101",
            labelled("reward_note", value(&graphemes(101))),
            Err(element("reward_note", TextFault::TooLong(101))),
        ),
        (
            "a template name of 61, checked after interpolation",
            display(
                json!([{"locale": "en", "name": graphemes(61), "display_type": "template:mini_markdown"}]),
            ),
            Ok(()),
        ),
        // Characters (Section 3.3).
        (
            "a line feed in a name",
            named("Am\nount"),
            Err(text(TextFault::Control('\n'))),
        ),
        (
            "a C1 control in a name",
            named("Am\u{85}ount"),
            Err(text(TextFault::Control('\u{85}'))),
        ),
        (
            "a right-to-left override in a name",
            named("Am\u{202e}ount"),
            Err(text(TextFault::DirectionalOverride('\u{202e}'))),
        ),
        (
            "an isolate terminated",
            named("Am\u{2067}ou\u{2069}nt"),
            Ok(()),
        ),
        (
            "an isolate left open",
            named("Am\u{2067}ount"),
            Err(text(TextFault::IsolateUnterminated)),
        ),
        ("a pop of no isolate", named("Am\u{2069}ount"), Ok(())),
        (
            "a DEL in a name",
            named("Am\u{7f}ount"),
            Err(text(TextFault::Control('\u{7f}'))),
        ),
        (
            "a line break in a description",
            display(json!([{"locale": "en", "name": "A", "description": "One\nTwo"}])),
            Ok(()),
        ),
        (
            "a right-to-left override in a description",
            display(json!([{"locale": "en", "name": "A", "description": "O\u{202e}ne"}])),
            Err(name_fault(EntryFault::Text(
                DefinitionMember::Description,
                TextFault::DirectionalOverride('\u{202e}'),
            ))),
        ),
        // Structure (Section 3.3).
        ("100 claims", many(100), Ok(())),
        (
            "101 claims",
            many(101),
            Err(DefinitionError::TooManyClaims(101)),
        ),
        (
            "two claims of one path",
            claims(json!([claim(json!({})), claim(json!({}))])),
            Err(DefinitionError::PathRepeated(ClaimIndex::new(1))),
        ),
        (
            "two entries of one locale",
            display(json!([{"locale": "en", "name": "A"}, {"locale": "EN", "name": "B"}])),
            Err(DefinitionError::Claim(
                ClaimIndex::new(0),
                ClaimFault::Display(LabelsFault::LocaleRepeated(Locale::parse("en").unwrap())),
            )),
        ),
        (
            "two default entries",
            display(json!([{"name": "A"}, {"name": "B"}])),
            Err(DefinitionError::Claim(
                ClaimIndex::new(0),
                ClaimFault::Display(LabelsFault::DefaultRepeated),
            )),
        ),
        (
            "a locale that is no language tag",
            display(json!([{"locale": "en_GB", "name": "A"}])),
            Err(name_fault(EntryFault::Locale(LocaleError::Malformed))),
        ),
        (
            "no claims",
            json!({"ui_labels": {}}),
            Err(DefinitionError::Member(
                DefinitionMember::Claims,
                MemberFault::Absent,
            )),
        ),
        // Claims (Section 3.1; PaSO View, Section 3).
        (
            "a value type without a display",
            claims(json!([claim(json!({"display": null}))])),
            Err(DefinitionError::Claim(
                ClaimIndex::new(0),
                ClaimFault::ValueTypeWithoutDisplay,
            )),
        ),
        (
            "a mandatory label_only claim",
            claims(json!([claim(json!({"value_type": "label_only"}))])),
            Err(DefinitionError::Claim(
                ClaimIndex::new(0),
                ClaimFault::LabelOnlyMandatory,
            )),
        ),
        (
            "a value type PaSO View does not define",
            claims(json!([claim(json!({"value_type": "money"}))])),
            Err(DefinitionError::Claim(
                ClaimIndex::new(0),
                ClaimFault::ValueTypeUnknown("money".to_owned()),
            )),
        ),
        (
            "an image as a display_type: the entry leaves the array (PaSO View, Section 3)",
            display(json!([{"locale": "en", "name": "A", "display_type": "image"}])),
            Ok(()),
        ),
        (
            "a url as a ui_labels value_type",
            labelled(
                "transaction_title",
                json!([{"locale": "en", "value": "T", "value_type": "url"}]),
            ),
            Err(DefinitionError::UiElement(
                UiElementKey::new("transaction_title"),
                LabelsFault::Entry(ArrayIndex::new(0), EntryFault::Format("url".to_owned())),
            )),
        ),
        (
            "a security hint with a value_type",
            labelled(
                "security_hint",
                json!([{"locale": "en", "value": "Check", "value_type": "mini_markdown"}]),
            ),
            Err(DefinitionError::UiElement(
                UiElementKey::new("security_hint"),
                LabelsFault::Entry(ArrayIndex::new(0), EntryFault::HintFormat),
            )),
        ),
    ];
    for (case, definition, expected) in rows {
        let read = Json::parse_unique(definition.to_string().as_bytes()).unwrap();
        assert_eq!(
            Definition::parse(read, LabelRules::Paso).map(drop),
            expected,
            "{case}"
        );
    }
}

/// TS12's limits, in characters, for the UI elements it names, and none for claim names (EC
/// TS12 v1.0.1, Section 3.3.3).
#[test]
fn ts12_rules_set_ts12_limits() {
    let characters = |n: usize| "e".repeat(n);
    let rows: Vec<(&str, Value, Result<(), DefinitionError>)> = vec![
        ("a name of 70", named(&graphemes(70)), Ok(())),
        (
            "a security hint of 200",
            labelled("security_hint", value(&characters(200))),
            Ok(()),
        ),
        (
            "a security hint of 250",
            labelled("security_hint", value(&characters(250))),
            Ok(()),
        ),
        (
            "a security hint of 251",
            labelled("security_hint", value(&characters(251))),
            Err(element("security_hint", TextFault::TooLong(251))),
        ),
        (
            "an action label of 30",
            labelled("affirmative_action_label", value(&characters(30))),
            Ok(()),
        ),
        (
            "an action label of 31",
            labelled("affirmative_action_label", value(&characters(31))),
            Err(element("affirmative_action_label", TextFault::TooLong(31))),
        ),
        (
            "a title of 51",
            labelled("transaction_title", value(&characters(51))),
            Err(element("transaction_title", TextFault::TooLong(51))),
        ),
        (
            "a line feed in a name",
            named("Am\nount"),
            Err(text(TextFault::Control('\n'))),
        ),
    ];
    for (case, definition, expected) in rows {
        let read = Json::parse_unique(definition.to_string().as_bytes()).unwrap();
        assert_eq!(
            Definition::parse(read, LabelRules::Ts12).map(drop),
            expected,
            "{case}"
        );
    }
}

/// A `display` entry whose `display_type` is not a label format leaves the locale function: the
/// default entry serves (PaSO View, Section 3).
#[test]
fn an_unsupported_display_type_leaves_the_locale_function() {
    let definition = claims(json!([claim(json!({"display": [
        {"locale": "en", "name": "Linked", "display_type": "url"},
        {"name": "Default"}
    ]}))]));
    let read = Json::parse_unique(definition.to_string().as_bytes()).unwrap();
    let english = Locale::parse("en").unwrap();
    let projected = Definition::parse(read, LabelRules::Paso)
        .unwrap()
        .project(&english, SourceKind::Configuration, Rulebook::Generic)
        .unwrap();
    let display = projected.claims()[0].display().unwrap();
    assert_eq!(display.name().as_str(), "Default");
}
