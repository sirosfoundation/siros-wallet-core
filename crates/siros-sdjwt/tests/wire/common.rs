//! Fixtures of RFC 9901, crafted compact SD-JWTs, and the processed payload of a claim tree.

use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use siros_openid4vp::json::Node;
use siros_sdjwt::{ClaimValue, Element, Object};

/// The text of the fixture `path` under `rfc9901/`.
pub fn fixture(path: &str) -> String {
    let full = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/wire/rfc9901")
        .join(path);
    std::fs::read_to_string(&full).unwrap_or_else(|e| panic!("{}: {e}", full.display()))
}

/// A base64url fixture with the RFC's line breaks and indentation removed.
pub fn compact_fixture(path: &str) -> String {
    fixture(path).split_whitespace().collect()
}

/// A JSON fixture.
pub fn json_fixture(path: &str) -> Node<'static> {
    let text = fixture(path);
    Node::parse(&text)
        .unwrap_or_else(|e| panic!("{path}: {e}"))
        .into_owned()
}

/// The issued SD-JWT of the example `dir`. For A.1 and A.2, which print the issuer JWT only in
/// the presentation, it is that JWT followed by every Disclosure the example lists.
pub fn issued(dir: &str) -> String {
    let stated = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/wire/rfc9901")
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

/// The disclosure of the JSON array `array` and its SHA-256 digest.
pub fn disclosure(array: &str) -> (String, String) {
    let encoded = URL_SAFE_NO_PAD.encode(array);
    let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(encoded.as_bytes()));
    (encoded, digest)
}

/// A SHA-256 digest no disclosure has.
pub fn decoy(seed: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(seed.as_bytes()))
}

/// The compact SD-JWT of the payload text `payload` and of `disclosures`. Its signature is a
/// placeholder.
pub fn compact(payload: &str, disclosures: &[&str]) -> String {
    let mut out = format!(
        "{}.{}.{}~",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","typ":"dc+sd-jwt"}"#),
        URL_SAFE_NO_PAD.encode(payload.as_bytes()),
        URL_SAFE_NO_PAD.encode([7; 64]),
    );
    for d in disclosures {
        out.push_str(d);
        out.push('~');
    }
    out
}

/// The Processed SD-JWT Payload of RFC 9901, Section 7.1: withheld elements removed.
pub fn processed(object: &Object) -> Node<'static> {
    Node::object(
        object
            .members()
            .map(|(name, claim)| (name.to_owned().into(), value(claim.value()))),
    )
    .unwrap()
}

fn value(v: &ClaimValue) -> Node<'static> {
    match v {
        ClaimValue::Null => Node::Null,
        ClaimValue::Bool(b) => Node::Bool(*b),
        ClaimValue::Number(n) => Node::Number(n.clone()),
        ClaimValue::String(s) => Node::String(s.clone().into()),
        ClaimValue::Array(elements) => Node::Array(
            elements
                .iter()
                .filter_map(|e| match e {
                    Element::Present(claim) => Some(value(claim.value())),
                    Element::Withheld(_) => None,
                })
                .collect(),
        ),
        ClaimValue::Object(object) => processed(object),
    }
}
