//! Claims path pointers (§7): the §7.1.1 processing over JSON, and the §7.2 mdoc form.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use serde_json::{json, Value};
use siros_dcql::{
    mdoc_components, resolve_json, ClaimPath, ClaimPathError, ComponentIndex, PathComponent,
    PathError,
};

fn path(json: Value) -> ClaimPath {
    ClaimPath::parse(&json).unwrap()
}

/// The example from §7's own text: a nested object claim.
#[test]
fn selects_a_nested_key() {
    let c = json!({"address": {"street_address": "Weidenstraße 22"}});
    let got = resolve_json(&c, &path(json!(["address", "street_address"]))).unwrap();
    assert_eq!(got, vec![&json!("Weidenstraße 22")]);
}

/// Null selects every element of an array (§7.1 "all elements").
#[test]
fn null_selects_all_array_elements() {
    let c = json!({"degrees": [{"type": "BA"}, {"type": "MA"}]});
    let got = resolve_json(&c, &path(json!(["degrees", null, "type"]))).unwrap();
    assert_eq!(got, vec![&json!("BA"), &json!("MA")]);
}

#[test]
fn integer_selects_one_array_element() {
    let c = json!({"degrees": [{"type": "BA"}, {"type": "MA"}]});
    let got = resolve_json(&c, &path(json!(["degrees", 1, "type"]))).unwrap();
    assert_eq!(got, vec![&json!("MA")]);
}

/// §7.1.1 2.1 — a key that does not exist removes the element from the
/// selection. With nothing left, step 3 makes that an Empty error, which
/// is a different thing from the query being malformed.
#[test]
fn missing_key_is_empty_not_a_type_error() {
    let c = json!({"given_name": "Erika"});
    assert_eq!(
        resolve_json(&c, &path(json!(["family_name"]))),
        Err(PathError::Empty)
    );
}

/// A missing key removes only *that* element; siblings survive. This is
/// the case that separates "remove from selection" from "abort".
#[test]
fn missing_key_removes_only_the_element_that_lacks_it() {
    let c = json!({"degrees": [{"type": "BA"}, {"other": "x"}, {"type": "MA"}]});
    let got = resolve_json(&c, &path(json!(["degrees", null, "type"]))).unwrap();
    assert_eq!(got, vec![&json!("BA"), &json!("MA")]);
}

/// §7.1.1 2.3 — an out-of-range index removes the array from the
/// selection rather than aborting.
#[test]
fn out_of_range_index_is_empty_not_a_type_error() {
    let c = json!({"degrees": [{"type": "BA"}]});
    assert_eq!(
        resolve_json(&c, &path(json!(["degrees", 7]))),
        Err(PathError::Empty)
    );
}

/// §7.1.1 2.1 — a string component applied to a non-object aborts.
#[test]
fn string_component_on_a_non_object_aborts() {
    let c = json!({"name": "Erika"});
    assert_eq!(
        resolve_json(&c, &path(json!(["name", "first"]))),
        Err(PathError::TypeMismatch {
            at: ComponentIndex::new(1)
        })
    );
}

/// §7.1.1 2.2 and 2.3 — null or an index on a non-array aborts.
#[test]
fn null_or_index_on_a_non_array_aborts() {
    let c = json!({"name": "Erika"});
    assert_eq!(
        resolve_json(&c, &path(json!(["name", null]))),
        Err(PathError::TypeMismatch {
            at: ComponentIndex::new(1)
        })
    );
    assert_eq!(
        resolve_json(&c, &path(json!(["name", 0]))),
        Err(PathError::TypeMismatch {
            at: ComponentIndex::new(1)
        })
    );
}

/// An empty array yields nothing, but that only becomes an error at step
/// 3 — it is not a type mismatch.
#[test]
fn null_over_an_empty_array_is_empty_not_a_type_error() {
    let c = json!({"degrees": []});
    assert_eq!(
        resolve_json(&c, &path(json!(["degrees", null]))),
        Err(PathError::Empty)
    );
}

/// §7: "a non-empty array of strings, nulls and non-negative integers". One rule per row.
#[test]
fn a_claims_path_is_a_non_empty_array_of_components() {
    let cases = [
        (json!("given_name"), ClaimPathError::NotArray),
        (json!([]), ClaimPathError::Empty),
        (
            json!(["degrees", -1]),
            ClaimPathError::Component(ComponentIndex::new(1)),
        ),
        (
            json!(["degrees", 0.5]),
            ClaimPathError::Component(ComponentIndex::new(1)),
        ),
        (
            json!([true]),
            ClaimPathError::Component(ComponentIndex::new(0)),
        ),
    ];
    for (value, error) in cases {
        assert_eq!(ClaimPath::parse(&value), Err(error), "{value}");
    }
}

/// §7.2.1 step 1 — mdoc pointers are exactly two strings.
#[test]
fn mdoc_path_must_be_exactly_two_strings() {
    let pair = path(json!(["org.iso.18013.5.1", "family_name"]));
    assert_eq!(
        mdoc_components(&pair),
        Ok(("org.iso.18013.5.1", "family_name"))
    );
    assert_eq!(
        mdoc_components(&path(json!(["only_one"]))),
        Err(PathError::MdocElement)
    );
    assert_eq!(
        mdoc_components(&path(json!(["a", "b", "c"]))),
        Err(PathError::MdocElement)
    );
    assert_eq!(
        mdoc_components(&path(json!(["ns", 0]))),
        Err(PathError::MdocElement)
    );
}

/// The dotted ISO namespace stays one component. Flattening it and
/// splitting on the first dot yields namespace `org`, which matches
/// nothing while looking entirely reasonable.
#[test]
fn dotted_iso_namespace_is_one_component() {
    let pair = path(json!(["org.iso.18013.5.1", "age_over_18"]));
    let (ns, id) = mdoc_components(&pair).unwrap();
    assert_eq!(ns, "org.iso.18013.5.1");
    assert_eq!(id, "age_over_18");
}

/// Wire form: strings, integers and nulls all round-trip.
#[test]
fn components_deserialise_from_the_wire_form() {
    let p: ClaimPath = serde_json::from_str(r#"["degrees", null, 0, "type"]"#).unwrap();
    assert_eq!(
        p.components(),
        [
            PathComponent::Key("degrees".into()),
            PathComponent::Null,
            PathComponent::Index(0),
            PathComponent::Key("type".into())
        ]
    );
    assert_eq!(
        serde_json::to_string(&p).unwrap(),
        r#"["degrees",null,0,"type"]"#
    );
}
