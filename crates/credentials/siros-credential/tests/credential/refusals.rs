//! One refusal per construction rule of siros-wallet-state and siros-credential. The honest
//! inputs each row edits are accepted, so each row breaks only its rule.

use serde_json::{json, Value};
use siros_codec::cbor::Value as Cbor;
use siros_credential::Credential;
use siros_wallet_state::WalletState;

use crate::common::{
    disclosure, entry, mdoc, mdoc_chained, sd_jwt, sd_jwt_headed, sd_jwt_text, state, tdate,
};

/// The outcome of parsing the `S` `text` and reading each of its credentials.
fn outcome(text: &str) -> Result<(), &'static str> {
    let state = WalletState::parse(text).map_err(|e| e.code())?;
    for entry in state.credentials() {
        Credential::parse(entry).map_err(|e| e.code())?;
    }
    Ok(())
}

/// The payload of an honest SD-JWT VC, with `given_name` selectively disclosed.
fn honest_payload(given_name_digest: &str) -> Value {
    json!({
        "iss": "https://issuer.example",
        "vct": "https://credentials.example/identity",
        "cnf": {"jwk": {"kty": "EC", "crv": "P-256", "x": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE", "y": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI"}},
        "nbf": 1_700_000_000,
        "exp": 1_900_000_000,
        "_sd": [given_name_digest]
    })
}

/// An `S` holding one SD-JWT VC entry with `payload` and `disclosures`.
fn vc_state(payload: &Value, disclosures: &[&str]) -> String {
    let data = sd_jwt(payload, disclosures);
    state(vec![entry(1, 1, 0, "dc+sd-jwt", &data)], vec![])
}

/// An `S` holding one SD-JWT VC entry of `data`, edited by `edit`.
fn entry_state(data: &str, edit: impl FnOnce(&mut Value)) -> String {
    let mut credential = entry(1, 1, 0, "dc+sd-jwt", data);
    edit(&mut credential);
    state(vec![credential], vec![])
}

/// An `S` edited by `edit`.
fn edited_state(edit: impl FnOnce(&mut Value)) -> String {
    let mut s: Value = serde_json::from_str(&state(vec![], vec![])).unwrap();
    edit(&mut s);
    s.to_string()
}

fn presentation() -> Value {
    json!({
        "presentationId": 1,
        "transactionId": 1,
        "data": "",
        "usedCredentialIds": [1],
        "presentationTimestampSeconds": 1_750_000_000,
        "audience": "https://verifier.example"
    })
}

#[test]
fn each_rule_refuses_its_input() {
    let (given_name, given_name_digest) = disclosure(&json!(["s0", "given_name", "Ada"]));
    let honest = honest_payload(&given_name_digest);
    let with = |edit: &dyn Fn(&mut Value)| {
        let mut payload = honest.clone();
        edit(&mut payload);
        payload
    };
    let (vct, vct_digest) = disclosure(&json!([
        "s1",
        "vct",
        "https://credentials.example/identity"
    ]));
    let (jwk, jwk_digest) = disclosure(&json!(["s2", "jwk", {"kty": "EC"}]));
    let valid = ("2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z");
    let mdoc_state = |elements| {
        let data = mdoc(elements, valid.0, valid.1);
        state(vec![entry(1, 1, 0, "mso_mdoc", &data)], vec![])
    };
    let data = sd_jwt(&honest, &[&given_name]);
    let full_date = |t: &str| Cbor::Tag(1004, Box::new(Cbor::text(t)));
    let privileges = |key: Cbor| {
        Cbor::Array(vec![Cbor::Map(vec![
            (key, Cbor::text("B")),
            (Cbor::text("issue_date"), full_date("2024-02-29")),
        ])])
    };

    let accepted = [
        edited_state(|_| {}),
        entry_state(&data, |_| {}),
        mdoc_state(vec![
            ("given_name", Cbor::text("Ada")),
            ("issue_date", full_date("2024-02-29")),
            ("expiry_date", tdate("2027-01-01T00:00:00Z")),
            (
                "driving_privileges",
                privileges(Cbor::text("vehicle_category_code")),
            ),
            ("portrait", Cbor::Bytes(vec![0xff, 0xd8])),
            ("age_in_years", Cbor::Unsigned(40)),
            ("age_over_18", Cbor::Bool(true)),
        ]),
    ];
    for input in &accepted {
        assert_eq!(outcome(input), Ok(()));
    }

    let rows: Vec<(&str, &str, String)> = vec![
        // W1
        ("S is an array", "state_malformed", "[]".into()),
        (
            "no schemaVersion: version 1",
            "schema_version_unsupported",
            edited_state(|s| drop(s.as_object_mut().unwrap().remove("schemaVersion"))),
        ),
        (
            "schemaVersion 2",
            "schema_version_unsupported",
            edited_state(|s| s["schemaVersion"] = json!(2)),
        ),
        // W2
        (
            "no credentials",
            "credentials_malformed",
            edited_state(|s| drop(s.as_object_mut().unwrap().remove("credentials"))),
        ),
        (
            "a credential entry is a string",
            "credential_entry_malformed",
            edited_state(|s| s["credentials"] = json!(["entry"])),
        ),
        (
            "no kid",
            "credential_member_malformed",
            entry_state(&data, |e| drop(e.as_object_mut().unwrap().remove("kid"))),
        ),
        (
            "a negative credentialId",
            "credential_member_malformed",
            entry_state(&data, |e| e["credentialId"] = json!(-1)),
        ),
        (
            "a credentialId of 2^64",
            "credential_member_malformed",
            entry_state(&data, |e| {
                e["credentialId"] = serde_json::from_str("18446744073709551616").unwrap()
            }),
        ),
        (
            "a batchId as a string",
            "credential_member_malformed",
            entry_state(&data, |e| e["batchId"] = json!("1")),
        ),
        (
            "a repeated credentialId",
            "credential_id_repeated",
            state(
                vec![
                    entry(1, 1, 0, "dc+sd-jwt", &data),
                    entry(1, 1, 1, "dc+sd-jwt", &data),
                ],
                vec![],
            ),
        ),
        (
            "metadata as an object",
            "metadata_malformed",
            entry_state(&data, |e| e["metadata"] = json!({"type": "a", "value": 1})),
        ),
        (
            "metadata of an empty type",
            "metadata_malformed",
            entry_state(&data, |e| e["metadata"] = json!([{"type": "", "value": 1}])),
        ),
        (
            "metadata without a value",
            "metadata_malformed",
            entry_state(&data, |e| e["metadata"] = json!([{"type": "a"}])),
        ),
        // W3
        (
            "no keypairs",
            "keypairs_malformed",
            edited_state(|s| drop(s.as_object_mut().unwrap().remove("keypairs"))),
        ),
        (
            "a presentation without audience",
            "presentations_malformed",
            edited_state(|s| {
                let mut p = presentation();
                drop(p.as_object_mut().unwrap().remove("audience"));
                s["presentations"] = json!([p]);
            }),
        ),
        (
            "a presentation after 9999",
            "presentations_malformed",
            edited_state(|s| {
                let mut p = presentation();
                p["presentationTimestampSeconds"] = json!(253_402_300_800_i64);
                s["presentations"] = json!([p]);
            }),
        ),
        // C1
        (
            "format jwt_vc_json",
            "format_unsupported",
            state(vec![entry(1, 1, 0, "jwt_vc_json", &data)], vec![]),
        ),
        (
            "an SD-JWT without a signature",
            "issuer_jwt_malformed",
            state(
                vec![entry(1, 1, 0, "vc+sd-jwt", "eyJhbGciOiJFUzI1NiJ9.e30~")],
                vec![],
            ),
        ),
        (
            "an mdoc that is not base64url",
            "encoding",
            state(vec![entry(1, 1, 0, "mso_mdoc", "a+b")], vec![]),
        ),
        // SD-JWT VC
        (
            "no vct",
            "vct_malformed",
            vc_state(
                &with(&|p| drop(p.as_object_mut().unwrap().remove("vct"))),
                &[&given_name],
            ),
        ),
        (
            "vct a number",
            "vct_malformed",
            vc_state(&with(&|p| p["vct"] = json!(1)), &[&given_name]),
        ),
        (
            "vct selectively disclosed",
            "claim_selectively_disclosed",
            vc_state(
                &with(&|p| {
                    drop(p.as_object_mut().unwrap().remove("vct"));
                    p["_sd"] = json!([given_name_digest, vct_digest]);
                }),
                &[&given_name, &vct],
            ),
        ),
        (
            "a sub-claim of cnf selectively disclosed",
            "claim_selectively_disclosed",
            vc_state(
                &with(&|p| p["cnf"] = json!({"_sd": [jwk_digest]})),
                &[&given_name, &jwk],
            ),
        ),
        (
            "cnf a string",
            "cnf_malformed",
            vc_state(&with(&|p| p["cnf"] = json!("key-1")), &[&given_name]),
        ),
        (
            "cnf without jwk",
            "holder_key_jwk",
            vc_state(
                &with(&|p| p["cnf"] = json!({"kid": "key-1"})),
                &[&given_name],
            ),
        ),
        (
            "cnf.jwk of another curve",
            "holder_key_type",
            vc_state(
                &with(&|p| p["cnf"]["jwk"]["crv"] = json!("P-384")),
                &[&given_name],
            ),
        ),
        (
            "cnf.jwk with a coordinate not of 32 bytes",
            "holder_key_coordinate",
            vc_state(
                &with(&|p| p["cnf"]["jwk"]["x"] = json!("AQ")),
                &[&given_name],
            ),
        ),
        (
            "nbf a string",
            "numeric_date_malformed",
            vc_state(&with(&|p| p["nbf"] = json!("1700000000")), &[&given_name]),
        ),
        (
            "exp after 9999",
            "numeric_date_malformed",
            vc_state(
                &with(&|p| p["exp"] = json!(253_402_300_800.5)),
                &[&given_name],
            ),
        ),
        (
            "a number beyond f64",
            "issuer_jwt_malformed",
            state(
                vec![entry(
                    1,
                    1,
                    0,
                    "dc+sd-jwt",
                    &sd_jwt_text(
                        &honest.to_string().replacen('{', r#"{"weight":1e400,"#, 1),
                        &[&given_name],
                    ),
                )],
                vec![],
            ),
        ),
        // TR2
        (
            "an x5c certificate that is no base64",
            "issuer_jwt_x5c_malformed",
            state(
                vec![entry(
                    1,
                    1,
                    0,
                    "dc+sd-jwt",
                    &sd_jwt_headed(
                        &json!({"alg": "ES256", "typ": "dc+sd-jwt", "x5c": ["!"]}),
                        &honest.to_string(),
                        &[&given_name],
                    ),
                )],
                vec![],
            ),
        ),
        (
            "an x5chain certificate that is no DER certificate",
            "certificate_der",
            state(
                vec![entry(
                    1,
                    1,
                    0,
                    "mso_mdoc",
                    &mdoc_chained(
                        vec![("given_name", Cbor::text("Ada"))],
                        valid.0,
                        valid.1,
                        b"no certificate",
                    ),
                )],
                vec![],
            ),
        ),
        // C2
        (
            "a full-date of 2023-02-29",
            "full_date_malformed",
            mdoc_state(vec![("issue_date", full_date("2023-02-29"))]),
        ),
        (
            "a tdate with a fraction of a second",
            "tdate_malformed",
            mdoc_state(vec![("expiry_date", tdate("2027-01-01T00:00:00.5Z"))]),
        ),
        (
            "a value under tag 24",
            "claim_tag_unsupported",
            mdoc_state(vec![(
                "portrait",
                Cbor::Tag(24, Box::new(Cbor::Bytes(vec![0xf6]))),
            )]),
        ),
        (
            "an integer map key inside an array",
            "map_key_not_text",
            mdoc_state(vec![("driving_privileges", privileges(Cbor::Unsigned(1)))]),
        ),
        (
            "undefined",
            "claim_undefined",
            mdoc_state(vec![("given_name", Cbor::Encoded(vec![0xf7]))]),
        ),
    ];
    for (case, code, text) in rows {
        assert_eq!(outcome(&text), Err(code), "{case}");
    }
}
