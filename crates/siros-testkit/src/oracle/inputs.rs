//! The model's response members and the readers of its JSON members.

use std::borrow::Cow;

use serde_json::Value;
use siros_openid4vp::cbor::Item;
use siros_openid4vp::plugins::{JsonText, Member, MemberValue};

use super::OracleError;
use crate::cose::cose_encrypt;

/// The input error for a member `name` absent or not of its type.
pub fn missing(name: &str) -> OracleError {
    OracleError::Input {
        detail: format!("no {name} of its type"),
    }
}

/// A member of an object.
pub fn field<'v>(value: &'v Value, name: &str) -> Result<&'v Value, OracleError> {
    value.get(name).ok_or_else(|| missing(name))
}

/// A string member.
pub fn text<'v>(value: &'v Value, name: &str) -> Result<&'v str, OracleError> {
    field(value, name)?.as_str().ok_or_else(|| missing(name))
}

/// The bytes of a hexadecimal text.
pub fn bytes(hex: &str) -> Result<Vec<u8>, OracleError> {
    if !hex.len().is_multiple_of(2) {
        return Err(missing("hexadecimal text"));
    }
    hex.as_bytes()
        .chunks(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|digits| u8::from_str_radix(digits, 16).ok())
                .ok_or_else(|| missing("hexadecimal text"))
        })
        .collect()
}

/// A response member: a claim's name, or `[name space, data element]`, with its value tagged
/// `text`, `bytes` (hexadecimal), `json` (its compact text, members in their order) or `cbor`
/// (the model's COSE_Encrypt stand-in, which becomes the testkit's tagged COSE_Encrypt).
pub fn member(written: &Value) -> Result<(Member, MemberValue), OracleError> {
    let name = match field(written, "name")? {
        Value::String(name) => Member::Claim(Cow::Owned(name.clone())),
        Value::Array(parts) => match parts.as_slice() {
            [Value::String(namespace), Value::String(element)] => Member::Element {
                namespace: Cow::Owned(namespace.clone()),
                element: Cow::Owned(element.clone()),
            },
            _ => return Err(missing("member name")),
        },
        _ => return Err(missing("member name")),
    };
    let value = field(written, "value")?;
    let value = if let Some(text) = value.get("text").and_then(Value::as_str) {
        MemberValue::Text(text.to_owned())
    } else if let Some(hex) = value.get("bytes").and_then(Value::as_str) {
        MemberValue::Bytes(bytes(hex)?)
    } else if let Some(json) = value.get("json").and_then(Value::as_str) {
        MemberValue::Json(JsonText::parse(json).map_err(|e| OracleError::Input {
            detail: e.to_string(),
        })?)
    } else {
        MemberValue::Cbor(sealed(text(value, "cbor")?)?)
    };
    Ok((name, value))
}

/// The testkit's tagged COSE_Encrypt of the model's stand-in `{"COSE_Encrypt": {"protected":
/// {"alg", "enc", "kid"}, "ciphertext": {"bstr": hex}}}`.
fn sealed(stand_in: &str) -> Result<Item, OracleError> {
    let written: Value = serde_json::from_str(stand_in).map_err(|e| OracleError::Input {
        detail: e.to_string(),
    })?;
    let sealed = field(&written, "COSE_Encrypt")?;
    let protected = field(sealed, "protected")?;
    let alg = text(protected, "alg")?;
    let alg = crate::cose::AGREEMENTS
        .iter()
        .map(|(known, _)| *known)
        .find(|known| known.as_str() == alg)
        .ok_or_else(|| missing("COSE_Encrypt alg"))?;
    let enc = text(protected, "enc")?;
    let enc = crate::cose::ENCRYPTIONS
        .iter()
        .map(|(known, _)| *known)
        .find(|known| known.as_str() == enc)
        .ok_or_else(|| missing("COSE_Encrypt enc"))?;
    let plaintext = bytes(text(field(sealed, "ciphertext")?, "bstr")?)?;
    let encoded = cose_encrypt(alg, enc, text(protected, "kid")?, &plaintext)?;
    Item::parse(encoded).map_err(|e| OracleError::Port {
        detail: format!("the COSE_Encrypt stand-in: {e}"),
    })
}
