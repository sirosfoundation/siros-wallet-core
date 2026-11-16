//! D1 over the privatedata vector `delivered-secret-strip-001`.
//!
//! SOURCE: privatedata-spec `0c7405a` (Spec 3.1), `test-vectors/vectors.jsonl`, the line of
//! `delivered-secret-strip-001`, copied verbatim to `vectors/delivered-secret-strip-001.json`.
//! Each case gives the configuration's `credential_metadata` and the Credential Response's;
//! the issuer metadata around the first is written here.

use serde_json::{json, Value};
use siros_display::IssuerMetadata;

const VECTOR: &str = include_str!("vectors/delivered-secret-strip-001.json");

/// The Credential Issuer Metadata of one configuration `nym` with `credential_metadata`.
fn issuer_metadata(credential_metadata: Option<&Value>) -> Value {
    let mut configuration =
        json!({"format": "mso_mdoc", "doctype": "eu.europa.ec.eudi.nym_auth.1"});
    if let Some(metadata) = credential_metadata {
        configuration["credential_metadata"] = metadata.clone();
    }
    json!({
        "credential_issuer": "https://issuer.example",
        "credential_endpoint": "https://issuer.example/credential",
        "credential_configurations_supported": {"nym": configuration}
    })
}

#[test]
fn the_response_overwrites_the_configuration_without_its_auxiliary_data() {
    let vector: Value = serde_json::from_str(VECTOR).unwrap();
    let cases = vector["inputs"]["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 3);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let response = &case["responseCredentialMetadata"];
        let expected = &case["expected"];
        let opening = response["auxiliary_data"][0]["opening"].as_str().unwrap();

        let merged = IssuerMetadata::merge(
            &issuer_metadata(Some(&case["issuerCredentialMetadata"])),
            "nym",
            Some(response),
        )
        .unwrap_or_else(|e| panic!("{name}: {e}"));
        let record = merged.to_json();
        assert_eq!(
            record["credential_metadata"], expected["mergedDisplayMetadata"],
            "{name}"
        );
        assert!(
            !record.to_string().contains(opening),
            "{name}: the seed is in the record"
        );

        // Over a configuration without `credential_metadata`, the merge is the stripped response.
        let stripped = IssuerMetadata::merge(&issuer_metadata(None), "nym", Some(response))
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(
            stripped.to_json()["credential_metadata"],
            expected["strippedResponse"],
            "{name}"
        );

        // The record is what the display cache holds, and reads back as itself.
        let cached = IssuerMetadata::parse(&record).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(cached.to_json(), record, "{name}");
    }

    // Issuer metadata that carries a delivered secret is refused (Section 5A.3, NEVER PUBLIC).
    let published = cases[0]["responseCredentialMetadata"].clone();
    let refused = IssuerMetadata::merge(&issuer_metadata(Some(&published)), "nym", None);
    assert_eq!(
        refused.map(|_| ()).map_err(|e| e.code()),
        Err("auxiliary_data_published")
    );
}
