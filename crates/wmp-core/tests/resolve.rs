//! The vctm projection of a type metadata document (WMP Core 5.8.1).

use wmp_core::resolve::{project_vctm, VctmError};

#[test]
fn projects_the_carried_members_verbatim() {
    let doc = br#"{
        "vct": "VerifiableCredential",
        "name": "Name",
        "description": "Described",
        "display": null,
        "claims": {"given_name": {}},
        "schema": {"a": 1},
        "extra": "dropped"
    }"#;
    let out = project_vctm(doc, "https://fallback.example").expect("project");
    let value: serde_json::Value = serde_json::from_str(out.get()).expect("parse");
    assert_eq!(
        value.get("vct"),
        Some(&serde_json::json!("VerifiableCredential"))
    );
    assert_eq!(value.get("name"), Some(&serde_json::json!("Name")));
    assert_eq!(value.get("display"), Some(&serde_json::Value::Null));
    assert!(value.get("extra").is_none());
}

#[test]
fn vct_falls_back_to_the_uri() {
    let doc = br#"{"name": "Name"}"#;
    let out = project_vctm(doc, "https://uri.example").expect("project");
    let value: serde_json::Value = serde_json::from_str(out.get()).expect("parse");
    assert_eq!(
        value.get("vct"),
        Some(&serde_json::json!("https://uri.example"))
    );
}

#[test]
fn refuses_documents_that_cannot_be_carried() {
    // Not an object.
    assert!(matches!(project_vctm(b"[]", "u"), Err(VctmError::Invalid)));
    // No vct and no uri.
    assert!(matches!(
        project_vctm(br#"{"name":"n"}"#, ""),
        Err(VctmError::Invalid)
    ));
    // A name that is not a string.
    assert!(matches!(
        project_vctm(br#"{"vct":"v","name":42}"#, "u"),
        Err(VctmError::Invalid)
    ));
    // A vct that is not a string.
    assert!(matches!(
        project_vctm(br#"{"vct":42}"#, "u"),
        Err(VctmError::Invalid)
    ));
}
