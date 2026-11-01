//! Runs the request vectors in `tests/vectors/request/` (format in its README): each case is
//! one rule of the nym_auth catalogue 0.5, or a query that follows them all.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::fs;
use std::path::PathBuf;

use serde_json::{json, Value};
use siros_dcql::CredentialQuery;
use siros_zkp_req::{ZkpFormats, ZkpReqQuery};
use siros_zkp_req_nym_auth::catalogue::{CatalogueRule, Catalogued, NymAuthQuery};

fn member(vector: &Value, value_key: &str, text_key: &str) -> Value {
    match (vector.get(value_key), vector.get(text_key)) {
        (Some(v), _) => v.clone(),
        (None, Some(Value::String(t))) => serde_json::from_str(t).unwrap_or(Value::Null),
        _ => Value::Null,
    }
}

fn rule_json(rule: CatalogueRule) -> Value {
    let mut out = json!({"error": rule.code()});
    match rule {
        CatalogueRule::FunctionUnknown { item }
        | CatalogueRule::ParamUnknown { item }
        | CatalogueRule::PseudonymReturnMissing { item }
        | CatalogueRule::ConfigInvalid { item, .. }
        | CatalogueRule::VerInvalid { item, .. }
        | CatalogueRule::PrfInvalid { item, .. }
        | CatalogueRule::PrfUndefined { item, .. }
        | CatalogueRule::VerifierContextInvalid { item, .. }
        | CatalogueRule::RangeSyntax { item, .. }
        | CatalogueRule::RangeInverted { item } => out["item"] = item.value().into(),
        CatalogueRule::PseudonymRepeated { option }
        | CatalogueRule::AgeCheckRepeated { option } => {
            out["option"] = option.map(|option| option.value()).into();
        }
        CatalogueRule::SchemaIdInvalid(_) | CatalogueRule::HolderBindingWaived => {}
    }
    out
}

fn verdict(vector: &Value) -> Value {
    let query = member(vector, "query", "query_text");
    let metadata = member(vector, "client_metadata", "client_metadata_text");
    let query = match CredentialQuery::parse(&query) {
        Ok(query) => query,
        Err(error) => return json!({"error": error.code()}),
    };
    let parsed = match ZkpReqQuery::parse(&query) {
        Ok(parsed) => parsed,
        Err(rule) => return json!({"error": rule.code()}),
    };
    if let Err(rule) = ZkpFormats::from_client_metadata(&metadata) {
        return json!({"error": rule.code()});
    }
    match NymAuthQuery::from_query(parsed) {
        Ok(applies) => json!({"valid": {"catalogue": matches!(applies, Catalogued::NymAuth(_))}}),
        Err(rule) => rule_json(rule),
    }
}

#[test]
fn request_vectors() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/request");
    let mut paths: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    paths.sort();
    assert!(!paths.is_empty(), "no vector in {}", dir.display());
    let failures: Vec<String> = paths
        .iter()
        .filter_map(|path| {
            let vector: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
            let got = verdict(&vector);
            (got != vector["expect"]).then(|| {
                format!(
                    "{}: got {got}, want {}",
                    path.file_stem().unwrap().to_string_lossy(),
                    vector["expect"]
                )
            })
        })
        .collect();
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}
