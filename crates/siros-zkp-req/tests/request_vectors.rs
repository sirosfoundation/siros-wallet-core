//! Runs the request vectors in `tests/vectors/request/` (format in its README): each case is
//! one rule of `zkp_req`, Sections 1.1, 1.2, 2 and 2.1, or of DCQL, which parses the query
//! first, or a query that follows them all.

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
use siros_zkp_req::{ReqSets, RequestRule, ZkpFormats, ZkpReqQuery};

/// A JSON member, or the JSON a text member holds; text that is not JSON reads as `null`.
fn member(vector: &Value, value_key: &str, text_key: &str) -> Value {
    match (vector.get(value_key), vector.get(text_key)) {
        (Some(v), _) => v.clone(),
        (None, Some(Value::String(t))) => serde_json::from_str(t).unwrap_or(Value::Null),
        _ => Value::Null,
    }
}

fn rule_json(rule: RequestRule) -> Value {
    let mut out = json!({"error": rule.code()});
    match rule {
        RequestRule::ItemNotObject { item }
        | RequestRule::ItemMemberUnknown { item }
        | RequestRule::FnIdInvalid { item, .. }
        | RequestRule::ParamsNotObject { item }
        | RequestRule::ReturnInvalid { item, .. }
        | RequestRule::ReturnRepeated { item } => out["item"] = item.value().into(),
        RequestRule::OptionInvalid { option, .. } => out["option"] = option.value().into(),
        _ => {}
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
        Err(rule) => return rule_json(rule),
    };
    if let Err(rule) = ZkpFormats::from_client_metadata(&metadata) {
        return rule_json(rule);
    }
    let options: Vec<Vec<usize>> = parsed
        .options()
        .iter()
        .map(|o| o.items().iter().map(|i| i.value()).collect())
        .collect();
    let req_sets = parsed.req_sets() == ReqSets::Present;
    json!({"valid": {"options": options, "req_sets": req_sets}})
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
