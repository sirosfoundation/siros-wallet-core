//! Fixtures of RFC 9901, crafted compact SD-JWTs, and the processed payload of a claim tree.

use std::path::Path;

use serde_json::Value;
use sha2::{Digest, Sha256};
use siros_codec::base64url;
use siros_sdjwt::{ClaimValue, Element, Object};

/// The text of the fixture `path` under `rfc9901/`.
pub fn fixture(path: &str) -> String {
    let full = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/sd_jwt/rfc9901")
        .join(path);
    std::fs::read_to_string(&full).unwrap_or_else(|e| panic!("{}: {e}", full.display()))
}

/// A base64url fixture with the RFC's line breaks and indentation removed.
pub fn compact_fixture(path: &str) -> String {
    fixture(path).split_whitespace().collect()
}

/// A JSON fixture.
pub fn json_fixture(path: &str) -> Value {
    serde_json::from_str(&fixture(path)).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// The issued SD-JWT of the example `dir`. For A.1 and A.2, which print the issuer JWT only in
/// the presentation, it is that JWT followed by every Disclosure the example lists.
pub fn issued(dir: &str) -> String {
    let stated = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/sd_jwt/rfc9901")
        .join(dir)
        .join("issued.txt");
    if stated.exists() {
        return compact_fixture(&format!("{dir}/issued.txt"));
    }
    let presentation = compact_fixture(&format!("{dir}/presentation.txt"));
    let issuer_jwt = presentation.split('~').next().unwrap();
    let mut issued = format!("{issuer_jwt}~");
    for disclosure in fixture(&format!("{dir}/disclosures.txt")).split("\n\n") {
        issued.extend(disclosure.split_whitespace());
        issued.push('~');
    }
    issued
}

/// The disclosure of `array` and its SHA-256 digest.
pub fn disclosure(array: &Value) -> (String, String) {
    let encoded = base64url::encode(array.to_string().as_bytes()).into_string();
    let digest = base64url::encode(&Sha256::digest(encoded.as_bytes())).into_string();
    (encoded, digest)
}

/// A SHA-256 digest no disclosure has.
pub fn decoy(seed: &str) -> String {
    base64url::encode(&Sha256::digest(seed.as_bytes())).into_string()
}

/// The compact SD-JWT of the payload text `payload` and of `disclosures`. Its signature is a
/// placeholder.
pub fn compact(payload: &str, disclosures: &[&str]) -> String {
    let mut out = format!(
        "{}.{}.{}~",
        base64url::encode(br#"{"alg":"ES256","typ":"dc+sd-jwt"}"#).into_string(),
        base64url::encode(payload.as_bytes()).into_string(),
        base64url::encode(&[7; 64]).into_string(),
    );
    for d in disclosures {
        out.push_str(d);
        out.push('~');
    }
    out
}

/// The Processed SD-JWT Payload of RFC 9901, Section 7.1: withheld elements removed.
pub fn processed(object: &Object) -> Value {
    Value::Object(
        object
            .members()
            .map(|(name, claim)| (name.to_owned(), value(claim.value())))
            .collect(),
    )
}

fn value(v: &ClaimValue) -> Value {
    match v {
        ClaimValue::Null => Value::Null,
        ClaimValue::Bool(b) => Value::Bool(*b),
        ClaimValue::Number(n) => Value::Number(n.clone()),
        ClaimValue::String(s) => Value::String(s.clone()),
        ClaimValue::Array(elements) => elements
            .iter()
            .filter_map(|e| match e {
                Element::Present(claim) => Some(value(claim.value())),
                Element::Withheld => None,
            })
            .collect(),
        ClaimValue::Object(object) => processed(object),
    }
}
