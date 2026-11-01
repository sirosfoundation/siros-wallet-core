//! The plaintext states of the privatedata-spec test vectors.
//!
//! SOURCE: privatedata-spec `0c7405a` (Spec 3.1). `privatedata/vectors.jsonl` is
//! `test-vectors/vectors.jsonl`, and `privatedata/fixtures/` holds the two files of
//! `test-vectors/fixtures/` that carry a plaintext state, all copied verbatim.

use serde::Deserialize;
use serde_json::value::RawValue;
use serde_json::Value;
use siros_wallet_state::WalletState;

const VECTORS: &str = include_str!("privatedata/vectors.jsonl");
const FIXTURES: [(&str, &str); 2] = [
    (
        "fixtures/single-credential-v3.json",
        include_str!("privatedata/fixtures/single-credential-v3.json"),
    ),
    (
        "fixtures/multi-passkey-v3.json",
        include_str!("privatedata/fixtures/multi-passkey-v3.json"),
    ),
];

/// The states a reader refuses, with the reason.
const REFUSED: [(&str, &str); 2] = [
    // The vector's own rule: a version 4 reader refuses `S.schemaVersion` 5.
    (
        "vectors.jsonl schema-version-unknown-state-001",
        "schema_version_unsupported",
    ),
    // Its `metadata` is an object. Section 6.0 reads a version 3 `metadata` as version 4, an
    // array of objects. The vector of the same id in vectors.jsonl carries no `metadata`.
    ("fixtures/single-credential-v3.json", "metadata_malformed"),
];

#[derive(Deserialize)]
struct Vector<'a> {
    #[serde(borrow, default)]
    id: Option<&'a str>,
    #[serde(borrow, default)]
    inputs: Option<Inputs<'a>>,
}

#[derive(Deserialize)]
struct Inputs<'a> {
    #[serde(borrow, rename = "plaintextState", default)]
    plaintext_state: Option<Plaintext<'a>>,
}

#[derive(Deserialize)]
struct Plaintext<'a> {
    #[serde(borrow, rename = "S")]
    s: &'a RawValue,
}

/// Each plaintext state with its label.
fn states() -> Vec<(String, &'static str)> {
    let vectors = VECTORS.lines().filter(|line| !line.trim().is_empty());
    let mut states: Vec<(String, &'static str)> = vectors
        .filter_map(|line| {
            let vector: Vector<'static> = serde_json::from_str(line).unwrap();
            let s = vector.inputs?.plaintext_state?.s;
            Some((format!("vectors.jsonl {}", vector.id.unwrap()), s.get()))
        })
        .collect();
    for (label, text) in FIXTURES {
        let vector: Vector<'static> = serde_json::from_str(text).unwrap();
        let s = vector.inputs.unwrap().plaintext_state.unwrap().s;
        states.push((label.to_owned(), s.get()));
    }
    states
}

/// Every plaintext state parses, except the refused ones with their stated reason. A parsed
/// state holds what the state's JSON holds, with each `metadata` value as its exact text.
#[test]
fn every_plaintext_state() {
    let states = states();
    assert_eq!(states.len(), 19);
    for (label, text) in states {
        let refusal = REFUSED.iter().find(|(l, _)| *l == label).map(|(_, c)| *c);
        let parsed = WalletState::parse(text);
        let state = match (parsed, refusal) {
            (Ok(state), None) => state,
            (Err(e), Some(code)) => {
                assert_eq!(e.code(), code, "{label}");
                continue;
            }
            (Ok(_), Some(code)) => panic!("{label}: accepted, expected {code}"),
            (Err(e), None) => panic!("{label}: refused: {e}"),
        };
        let json: Value = serde_json::from_str(text).unwrap();
        holds(&label, text, &state, &json);
    }
}

fn holds(label: &str, text: &str, state: &WalletState, json: &Value) {
    let entries = json["credentials"].as_array().unwrap();
    assert_eq!(state.credentials().len(), entries.len(), "{label}");
    for (entry, stored) in state.credentials().iter().zip(entries) {
        let known = |member: &str| Some(stored[member].as_str().unwrap()).filter(|s| !s.is_empty());
        assert_eq!(
            entry.credential_id().to_string(),
            stored["credentialId"].to_string()
        );
        assert_eq!(entry.format().as_str(), stored["format"]);
        assert_eq!(entry.data().as_str(), stored["data"]);
        assert_eq!(entry.key_id().map(|k| k.as_str()), known("kid"));
        assert_eq!(
            entry.issuer().map(|i| i.as_str()),
            known("credentialIssuerIdentifier")
        );
        assert_eq!(
            entry.configuration_id().map(|c| c.as_str()),
            known("credentialConfigurationId")
        );
        assert_eq!(
            format!("{:?} {:?}", entry.instance_id(), entry.batch_id()),
            format!(
                "InstanceId({}) BatchId({})",
                stored["instanceId"], stored["batchId"]
            ),
        );
        let metadata = stored["metadata"].as_array().cloned().unwrap_or_default();
        assert_eq!(entry.metadata().len(), metadata.len(), "{label}");
        for (m, stored) in entry.metadata().iter().zip(&metadata) {
            assert_eq!(m.kind().as_str(), stored["type"], "{label}");
            let value: Value = serde_json::from_str(m.value().json()).unwrap();
            assert_eq!(value, stored["value"], "{label}");
            assert!(text.contains(m.value().json()), "{label}: not verbatim");
        }
    }
    let presentations = json["presentations"].as_array().unwrap();
    assert_eq!(state.presentations().len(), presentations.len(), "{label}");
    for (record, stored) in state.presentations().iter().zip(presentations) {
        let ids: Vec<String> = record
            .used_credential_ids()
            .iter()
            .map(|id| id.to_string())
            .collect();
        let stored: Vec<String> = stored["usedCredentialIds"]
            .as_array()
            .unwrap()
            .iter()
            .map(Value::to_string)
            .collect();
        assert_eq!(ids, stored, "{label}");
    }
    let kids: Vec<&str> = json["keypairs"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|k| k.get("kid").and_then(Value::as_str))
        .collect();
    let key_ids: Vec<&str> = state.key_ids().iter().map(|k| k.as_str()).collect();
    assert_eq!(key_ids, kids, "{label}");
}
