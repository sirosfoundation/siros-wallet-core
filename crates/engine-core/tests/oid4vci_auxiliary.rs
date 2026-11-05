//! The advertisement parse (§5), the §7 rule, the usability verdict
//! (§§4.1, 5), and the plain-response check (§7.1) — each rule
//! pinned by its accept and its refusal.
use serde_json::Value;

use engine_core::claims_path::{ClaimsPathError, ComponentError};
use engine_core::oid4vci::auxiliary::*;

fn config_with(advertisement: Value) -> Value {
    serde_json::json!({
        "format": "dc+sd-jwt",
        "vct": "https://example/PID",
        "proof_types_supported": {"jwt": {}},
        "auxiliary_data_supported": advertisement,
    })
}

fn hash_commitment(alg: &str, path: Value) -> Value {
    serde_json::json!({
        "type": "hash_commitment",
        "alg": alg,
        "path": path,
    })
}

/// The path an issuer writes as the JSON text `text`.
fn path(text: &str) -> Value {
    serde_json::from_str(text).expect("the path is JSON")
}

/// The delivery of a configuration of the credential format `format` with
/// one `to_wallet` `hash_commitment` entry per path.
fn with_paths(format: &str, paths: &[Value]) -> Result<SecretDelivery, SecretDeliveryError> {
    let entries: Vec<Value> = paths
        .iter()
        .map(|path| hash_commitment("sha-256", path.clone()))
        .collect();
    secret_delivery_of(&serde_json::json!({
        "format": format,
        "proof_types_supported": {"jwt": {}},
        "auxiliary_data_supported": {"to_wallet": entries},
    }))
}

#[test]
fn a_to_wallet_hash_commitment_requires_encryption() {
    // §7.1: a to_wallet hash_commitment entry carries a Secret Value,
    // so the response must be encrypted.
    let delivery = secret_delivery_of(&config_with(serde_json::json!({
        "to_wallet": [hash_commitment("sha-256", serde_json::json!(["family_name"]))],
    })))
    .expect("the advertisement parses");
    assert!(delivery.require_encryption);
    assert_eq!(delivery.to_wallet.len(), 1);
    assert!(!delivery.to_issuer_recognised);
    assert!(delivery.unusable.is_none());
}

#[test]
fn an_unsupported_to_wallet_alg_makes_the_configuration_unusable() {
    // §4.1: MUST NOT request a credential whose to_wallet entry it
    // cannot check.
    let config = config_with(serde_json::json!({
        "to_wallet": [hash_commitment("sha-512", serde_json::json!(["family_name"]))],
    }));
    let delivery = secret_delivery_of(&config).expect("parses");
    assert!(
        usable(&delivery, &config).is_err(),
        "the sha-512 entry the wallet cannot check"
    );
}

#[test]
fn an_unsupported_to_wallet_encoding_makes_the_configuration_unusable() {
    let config = config_with(serde_json::json!({
        "to_wallet": [{
            "type": "hash_commitment",
            "alg": "sha-256",
            "path": ["family_name"],
            "encoding": "base32",
        }],
    }));
    let delivery = secret_delivery_of(&config).expect("parses");
    assert!(usable(&delivery, &config).is_err());
}

#[test]
fn a_required_to_issuer_entry_the_wallet_can_send_is_carried() {
    let config = config_with(serde_json::json!({
        "to_issuer": [{
            "type": "hash_commitment",
            "alg": "sha-256",
            "path": ["family_name"],
            "required": true,
        }],
    }));
    let delivery = secret_delivery_of(&config).expect("parses");
    // The entry is sendable, so it rides the proof ask.
    assert_eq!(delivery.to_issuer.len(), 1);
    assert!(delivery.to_issuer_recognised);
    assert!(delivery.required_to_issuer);
    // The config declares a jwt proof, so the verdict passes.
    assert!(usable(&delivery, &config).is_ok());
}

#[test]
fn a_required_to_issuer_entry_without_a_carrier_proof_type_refuses() {
    // §§4.1, 5: a required to_issuer entry needs a key proof the
    // engine can inspect (jwt or attestation).
    let config = serde_json::json!({
        "format": "dc+sd-jwt",
        "vct": "https://example/PID",
        "proof_types_supported": {"cwt": {}},
        "auxiliary_data_supported": {"to_issuer": [{
            "type": "hash_commitment",
            "alg": "sha-256",
            "path": ["family_name"],
            "required": true,
        }]},
    });
    let delivery = secret_delivery_of(&config).expect("parses");
    let refusal = usable(&delivery, &config).expect_err("no carrier");
    assert!(
        refusal.reason.contains("jwt or attestation"),
        "the refusal names the need: {refusal}"
    );
}

#[test]
fn a_required_to_issuer_entry_of_an_unrecognised_type_refuses() {
    // §3 + §5: an unrecognised type is ignored — but a required one
    // cannot be sent, so the credential is not requested.
    let config = config_with(serde_json::json!({
        "to_issuer": [{
            "type": "future_scheme",
            "required": true,
        }],
    }));
    let delivery = secret_delivery_of(&config).expect("parses");
    assert!(
        usable(&delivery, &config).is_err(),
        "a required entry of an unrecognised type"
    );
    // And it is not carried.
    assert!(delivery.to_issuer.is_empty());
}

#[test]
fn an_unrequired_unrecognised_entry_is_ignored() {
    // §3: the recipient ignores an entry of an unrecognised type.
    let config = config_with(serde_json::json!({
        "to_issuer": [{"type": "future_scheme"}],
    }));
    let delivery = secret_delivery_of(&config).expect("parses");
    assert!(delivery.unusable.is_none());
    // Carried verbatim (the Go behaviour): the wallet places what it
    // can and ignores the type it cannot — the engine drops nothing
    // it did not refuse.
    assert_eq!(delivery.to_issuer.len(), 1);
    // But nothing of a type the engine knows is in it.
    assert!(!delivery.to_issuer_recognised);
    assert!(!delivery.required_to_issuer);
}

#[test]
fn auxiliary_data_in_issuer_metadata_fails_closed() {
    // §7: auxiliary_data MUST NOT appear in the issuer's
    // credential_metadata.
    let config = serde_json::json!({
        "format": "dc+sd-jwt",
        "credential_metadata": {"auxiliary_data": {}},
        "auxiliary_data_supported": {"to_wallet": [hash_commitment(
            "sha-256",
            serde_json::json!(["family_name"]),
        )]},
    });
    assert!(
        matches!(
            secret_delivery_of(&config),
            Err(SecretDeliveryError::AuxiliaryDataInIssuerMetadata(_))
        ),
        "the §7 rule fails closed"
    );
}

#[test]
fn a_hash_commitment_entry_with_an_opening_is_malformed() {
    // §4.1: values, never metadata — no opening or commitment at any
    // depth.
    let config = config_with(serde_json::json!({
        "to_wallet": [{
            "type": "hash_commitment",
            "alg": "sha-256",
            "path": ["family_name"],
            "opening": "the-secret",
        }],
    }));
    assert!(secret_delivery_of(&config).is_err());
}

#[test]
fn two_entries_of_the_same_type_and_path_are_malformed() {
    let config = config_with(serde_json::json!({
        "to_wallet": [
            hash_commitment("sha-256", serde_json::json!(["family_name"])),
            hash_commitment("sha-256", serde_json::json!(["family_name"])),
        ],
    }));
    assert!(secret_delivery_of(&config).is_err());
}

#[test]
fn a_required_member_in_to_wallet_is_malformed() {
    // §5: only to_issuer entries may carry required.
    let config = config_with(serde_json::json!({
        "to_wallet": [{
            "type": "hash_commitment",
            "alg": "sha-256",
            "path": ["family_name"],
            "required": true,
        }],
    }));
    assert!(secret_delivery_of(&config).is_err());
}

#[test]
fn a_missing_alg_or_path_is_malformed() {
    let no_alg = config_with(serde_json::json!({
        "to_wallet": [{"type": "hash_commitment", "path": ["x"]}],
    }));
    assert!(secret_delivery_of(&no_alg).is_err());
    let no_path = config_with(serde_json::json!({
        "to_wallet": [{"type": "hash_commitment", "alg": "sha-256"}],
    }));
    assert!(secret_delivery_of(&no_path).is_err());
}

#[test]
fn an_absent_advertisement_is_the_zero_delivery() {
    let config = serde_json::json!({
        "format": "dc+sd-jwt",
        "vct": "https://example/PID",
    });
    let delivery = secret_delivery_of(&config).expect("absent is zero");
    assert!(!delivery.require_encryption);
    assert!(delivery.to_issuer.is_empty());
    assert!(delivery.to_wallet.is_empty());
    assert!(delivery.unusable.is_none());
    assert!(usable(&delivery, &config).is_ok());
}

#[test]
fn neither_to_wallet_nor_to_issuer_is_malformed() {
    let config = config_with(serde_json::json!({}));
    assert!(secret_delivery_of(&config).is_err());
}

#[test]
fn a_plain_response_carrying_auxiliary_data_is_refused() {
    // §7.1's check: the member in a response-level metadata (the
    // credential_metadata object itself).
    assert!(has_auxiliary_data_member(
        &serde_json::json!({"auxiliary_data": {}})
    ));
    assert!(!has_auxiliary_data_member(
        &serde_json::json!({"display": "x"})
    ));
    assert!(!has_auxiliary_data_member(&serde_json::json!({"x": 1})));
    // Not an object: the member cannot be there.
    assert!(!has_auxiliary_data_member(&serde_json::json!([
        "auxiliary_data"
    ])));
}

#[test]
fn an_encoding_is_absent_base64url_base64_or_hex() {
    // The supported encodings, one at a time — and the alg.
    for encoding in [None, Some("base64url"), Some("base64"), Some("hex")] {
        let mut entry = hash_commitment("sha-256", serde_json::json!(["x"]));
        if let Some(encoding) = encoding {
            entry["encoding"] = serde_json::Value::String(encoding.to_owned());
        }
        let config = config_with(serde_json::json!({"to_wallet": [entry]}));
        let delivery = secret_delivery_of(&config).expect("parses");
        assert!(
            usable(&delivery, &config).is_ok(),
            "the encoding {encoding:?}"
        );
    }
    // An unsupported encoding refuses.
    let config = config_with(serde_json::json!({
        "to_wallet": [{
            "type": "hash_commitment",
            "alg": "sha-256",
            "path": ["x"],
            "encoding": "quoted-printable",
        }],
    }));
    let delivery = secret_delivery_of(&config).expect("parses");
    assert!(usable(&delivery, &config).is_err());
}

/// A JSON number is the value its decimal text writes (RFC 8259 §6): two
/// spellings of one integer are one path, so the second entry is a
/// duplicate, and two integers are two paths.
#[test]
fn the_duplicate_key_is_the_normal_form() {
    // (the format, a path, another path, whether they are one path)
    let pairs = [
        ("dc+sd-jwt", r#"["p", 1]"#, r#"["p", 1.0]"#, true),
        ("dc+sd-jwt", r#"["p", 1]"#, r#"["p", 1e0]"#, true),
        ("dc+sd-jwt", r#"["p", 1]"#, r#"["p", 10e-1]"#, true),
        ("dc+sd-jwt", r#"["p", 1]"#, r#"["p", 0.1e1]"#, true),
        ("dc+sd-jwt", r#"["p", 0]"#, r#"["p", -0]"#, true),
        ("dc+sd-jwt", r#"["p", 1]"#, r#"["p", 2]"#, false),
        (
            "mso_mdoc",
            r#"["ns", "el", -1]"#,
            r#"["ns", "el", -1.0]"#,
            true,
        ),
        (
            "mso_mdoc",
            r#"["ns", "el", -1]"#,
            r#"["ns", "el", 1]"#,
            false,
        ),
    ];
    for (format, first, second, one_path) in pairs {
        let delivery = with_paths(format, &[path(first), path(second)]);
        if one_path {
            assert!(
                matches!(
                    delivery,
                    Err(SecretDeliveryError::MalformedAdvertisement(_))
                ),
                "{format}: {first} and {second} are one path: {delivery:?}"
            );
        } else {
            assert!(
                delivery.is_ok(),
                "{format}: {first} and {second} are two paths: {delivery:?}"
            );
        }
    }
}

/// OpenID4VCI 1.0 Appendix C: a claims path pointer is "a non-empty array
/// of strings, nulls and integers". Into a JSON-based Credential,
/// "Negative integer values are not used" (C.1). Into an ISO mdoc, it
/// "always contains at least two path components of type string", the
/// namespace and the data element identifier, and a later component is a
/// map key ("string or integer"), an index or null (C.2). An index is at
/// most 2^64 − 1, a range limit RFC 8259 §6 allows; an mdoc integer is a
/// CBOR integer, at least −2^64 (RFC 8949 §3.1). One rule per row, each
/// path as the issuer's JSON text.
#[test]
fn a_path_follows_appendix_c_for_its_format() {
    let component = |at, why| Err(ClaimsPathError::Component { at, why });
    let cases = [
        ("dc+sd-jwt", r#"[null, "x"]"#, Ok(())),
        ("dc+sd-jwt", r#"["p", 18446744073709551615]"#, Ok(())),
        ("dc+sd-jwt", r#""p""#, Err(ClaimsPathError::NotArray)),
        ("dc+sd-jwt", "[]", Err(ClaimsPathError::Empty)),
        (
            "dc+sd-jwt",
            r#"["p", true]"#,
            component(1, ComponentError::WrongType),
        ),
        // binary64 rounds this fraction to 1.
        (
            "dc+sd-jwt",
            r#"["p", 1.0000000000000001]"#,
            component(1, ComponentError::Fraction),
        ),
        (
            "dc+sd-jwt",
            r#"["p", -1]"#,
            component(1, ComponentError::Negative),
        ),
        // 2^64.
        (
            "dc+sd-jwt",
            r#"["p", 18446744073709551616]"#,
            component(1, ComponentError::OutOfRange),
        ),
        ("mso_mdoc", r#"["org.example.1", "member"]"#, Ok(())),
        (
            "mso_mdoc",
            r#"["org.example.1", "member", "k", null, 0, -1]"#,
            Ok(()),
        ),
        // −2^64.
        (
            "mso_mdoc",
            r#"["org.example.1", "member", -18446744073709551616]"#,
            Ok(()),
        ),
        (
            "mso_mdoc",
            r#"["org.example.1"]"#,
            Err(ClaimsPathError::MdocTooShort),
        ),
        (
            "mso_mdoc",
            r#"["org.example.1", 0]"#,
            component(1, ComponentError::NotString),
        ),
        // −2^64 − 1.
        (
            "mso_mdoc",
            r#"["org.example.1", "member", -18446744073709551617]"#,
            component(2, ComponentError::OutOfRange),
        ),
        // The other JSON-based Credential Format Profiles (Appendix A.1).
        (
            "jwt_vc_json",
            r#"["p", -1]"#,
            component(1, ComponentError::Negative),
        ),
        (
            "ldp_vc",
            r#"["p", -1]"#,
            component(1, ComponentError::Negative),
        ),
        (
            "jwt_vc_json-ld",
            r#"["p", -1]"#,
            component(1, ComponentError::Negative),
        ),
    ];
    for (format, text, expected) in cases {
        let delivery = with_paths(format, &[path(text)]);
        match expected {
            Ok(()) => assert!(delivery.is_ok(), "{format} {text}: {delivery:?}"),
            Err(expected) => assert!(
                matches!(
                    delivery,
                    Err(SecretDeliveryError::MalformedClaimsPath { error, .. }) if error == expected
                ),
                "{format} {text}: {delivery:?}"
            ),
        }
    }
}

/// A `hash_commitment` path reads by its credential's format (OpenID4VCI
/// 1.0 Appendix C), and Appendix A defines the formats.
#[test]
fn a_path_in_a_format_appendix_a_does_not_define_is_refused() {
    let delivery = with_paths("example_format", &[path(r#"["p"]"#)]);
    assert!(
        matches!(
            delivery,
            Err(SecretDeliveryError::UnknownCredentialFormat { list: "to_wallet" })
        ),
        "{delivery:?}"
    );
}
