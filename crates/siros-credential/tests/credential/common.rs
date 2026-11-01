//! Wallet states, SD-JWT VCs and mdocs for the tests, and typed values as JSON.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use siros_codec::base64url;
use siros_codec::cbor::Value as Cbor;
use siros_credential::{Credential, TypedValue};
use siros_wallet_state::WalletState;

pub const NAME_SPACE: &str = "org.example.1";
pub const DOC_TYPE: &str = "org.example.doc.1";

/// The issuer chain of the test mdocs: one certificate, which `vectors/issuer.sh` wrote.
pub const ISSUER: &[u8] = include_bytes!("vectors/issuer.der");

/// An `S` of version 4.
pub fn state(credentials: Vec<Value>, presentations: Vec<Value>) -> String {
    json!({
        "schemaVersion": 4,
        "credentials": credentials,
        "keypairs": [],
        "presentations": presentations,
        "settings": {"openidRefreshTokenMaxAgeInSeconds": "0"},
        "credentialIssuanceSessions": []
    })
    .to_string()
}

/// A credential entry with the eight members of privatedata Section 6.0.
pub fn entry(
    credential_id: u64,
    batch_id: u64,
    instance_id: u64,
    format: &str,
    data: &str,
) -> Value {
    json!({
        "credentialId": credential_id,
        "format": format,
        "data": data,
        "kid": "key-1",
        "instanceId": instance_id,
        "batchId": batch_id,
        "credentialIssuerIdentifier": "https://issuer.example",
        "credentialConfigurationId": "example"
    })
}

/// The credentials of the state `text`.
pub fn credentials(text: &str) -> Vec<Credential> {
    let state = WalletState::parse(text).unwrap();
    state
        .credentials()
        .iter()
        .map(|entry| Credential::parse(entry).unwrap())
        .collect()
}

/// The credential of an entry holding `data` in `format`.
pub fn credential(format: &str, data: &str) -> Credential {
    credentials(&state(vec![entry(1, 1, 0, format, data)], vec![])).remove(0)
}

/// The disclosure of `array` and its SHA-256 digest.
pub fn disclosure(array: &Value) -> (String, String) {
    let encoded = base64url::encode(array.to_string().as_bytes()).into_string();
    let digest = base64url::encode(&Sha256::digest(encoded.as_bytes())).into_string();
    (encoded, digest)
}

/// The compact SD-JWT of `payload` and `disclosures`, with a placeholder signature.
pub fn sd_jwt(payload: &Value, disclosures: &[&str]) -> String {
    sd_jwt_text(&payload.to_string(), disclosures)
}

/// The compact SD-JWT of the payload text `payload` and `disclosures`.
pub fn sd_jwt_text(payload: &str, disclosures: &[&str]) -> String {
    sd_jwt_headed(
        &json!({"alg": "ES256", "typ": "dc+sd-jwt"}),
        payload,
        disclosures,
    )
}

/// The compact SD-JWT of the header `header`, the payload text `payload` and `disclosures`.
pub fn sd_jwt_headed(header: &Value, payload: &str, disclosures: &[&str]) -> String {
    let mut out = format!(
        "{}.{}.{}~",
        base64url::encode(header.to_string().as_bytes()).into_string(),
        base64url::encode(payload.as_bytes()).into_string(),
        base64url::encode(&[7; 64]).into_string(),
    );
    for d in disclosures {
        out.push_str(d);
        out.push('~');
    }
    out
}

fn text(s: &str) -> Cbor {
    Cbor::text(s)
}

fn map(entries: Vec<(&str, Cbor)>) -> Cbor {
    Cbor::Map(entries.into_iter().map(|(k, v)| (text(k), v)).collect())
}

pub fn tdate(t: &str) -> Cbor {
    Cbor::Tag(0, Box::new(text(t)))
}

fn tagged_bytes(item: &Cbor) -> Cbor {
    Cbor::Tag(24, Box::new(Cbor::Bytes(item.encode())))
}

/// Base64url of an `IssuerSigned` whose MSO lists the digests of `elements`, all in
/// [`NAME_SPACE`], and is valid from `valid_from` until `valid_until`, with the issuer chain
/// [`ISSUER`].
pub fn mdoc(elements: Vec<(&str, Cbor)>, valid_from: &str, valid_until: &str) -> String {
    mdoc_chained(elements, valid_from, valid_until, ISSUER)
}

/// [`mdoc`] with the `x5chain` certificate `chain`.
pub fn mdoc_chained(
    elements: Vec<(&str, Cbor)>,
    valid_from: &str,
    valid_until: &str,
    chain: &[u8],
) -> String {
    let items: Vec<Cbor> = elements
        .into_iter()
        .zip(0..)
        .map(|((identifier, value), digest_id)| {
            tagged_bytes(&map(vec![
                ("digestID", Cbor::Unsigned(digest_id)),
                ("random", Cbor::Bytes(vec![0x11; 16])),
                ("elementIdentifier", text(identifier)),
                ("elementValue", value),
            ]))
        })
        .collect();
    let digests = items
        .iter()
        .zip(0..)
        .map(|(item, id)| {
            (
                Cbor::Unsigned(id),
                Cbor::Bytes(Sha256::digest(item.encode()).to_vec()),
            )
        })
        .collect();
    let mso = map(vec![
        ("version", text("1.0")),
        ("digestAlgorithm", text("SHA-256")),
        (
            "valueDigests",
            Cbor::Map(vec![(text(NAME_SPACE), Cbor::Map(digests))]),
        ),
        (
            "deviceKeyInfo",
            map(vec![(
                "deviceKey",
                Cbor::Map(vec![
                    (Cbor::Unsigned(1), Cbor::Unsigned(2)),
                    (Cbor::Negative(0), Cbor::Unsigned(1)),
                    (Cbor::Negative(1), Cbor::Bytes(vec![0x01; 32])),
                    (Cbor::Negative(2), Cbor::Bytes(vec![0x02; 32])),
                ]),
            )]),
        ),
        ("docType", text(DOC_TYPE)),
        (
            "validityInfo",
            map(vec![
                ("signed", tdate(valid_from)),
                ("validFrom", tdate(valid_from)),
                ("validUntil", tdate(valid_until)),
            ]),
        ),
    ]);
    let issuer_auth = Cbor::Array(vec![
        Cbor::Bytes(vec![0xa1, 0x01, 0x26]),
        Cbor::Map(vec![(Cbor::Unsigned(33), Cbor::Bytes(chain.to_vec()))]),
        Cbor::Bytes(tagged_bytes(&mso).encode()),
        Cbor::Bytes(vec![0; 64]),
    ]);
    let issuer_signed = map(vec![
        (
            "nameSpaces",
            Cbor::Map(vec![(text(NAME_SPACE), Cbor::Array(items))]),
        ),
        ("issuerAuth", issuer_auth),
    ]);
    base64url::encode(&issuer_signed.encode()).into_string()
}

/// `value` as JSON, each type distinct: bytes, full-dates and date-times as one-member
/// objects naming their type.
pub fn json(value: TypedValue<'_>) -> Value {
    match value {
        TypedValue::Null => Value::Null,
        TypedValue::Bool(b) => json!(b),
        TypedValue::Integer(i) => json!(i64::try_from(i).unwrap()),
        TypedValue::Number(n) => Value::Number(n.clone()),
        TypedValue::Text(t) => json!(t),
        TypedValue::Bytes(b) => json!({"bytes": base64url::encode(b).into_string()}),
        TypedValue::FullDate(d) => json!({"full-date": d.to_string()}),
        TypedValue::DateTime(t) => json!({"date-time": t.to_string()}),
        TypedValue::Array(a) => a.elements().map(json).collect(),
        TypedValue::Object(o) => Value::Object(
            o.members()
                .map(|(name, value)| (name.to_owned(), json(value)))
                .collect(),
        ),
    }
}
