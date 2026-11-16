//! The validator's own proof: a document that violates the schema is
//! refused, and a conforming one passes.

use engine_conformance::schema::validate;

#[test]
fn a_violating_document_is_refused() {
    let schema = serde_json::json!({
        "type": "object",
        "required": ["id"],
        "properties": {
            "id": { "type": "string", "pattern": "^[a-z0-9]+(\\.[a-z0-9]+)*$" }
        }
    });
    // Missing the required member, and the id violates the pattern.
    let document = serde_json::json!({ "id": "Not-Lowercase-1" });
    let errors = validate(&schema, &document).expect_err("the violation must be refused");
    assert!(
        errors.iter().any(|e| e.contains("does not match")),
        "the pattern violation must be among the errors: {errors:?}"
    );
}

#[test]
fn a_conforming_document_passes() {
    let schema = serde_json::json!({
        "type": "object",
        "required": ["id"],
        "properties": {
            "id": { "type": "string", "pattern": "^[a-z0-9]+(\\.[a-z0-9]+)*$" }
        }
    });
    let document = serde_json::json!({ "id": "vci.preauth.basic.001" });
    validate(&schema, &document).expect("a conforming document passes");
}
