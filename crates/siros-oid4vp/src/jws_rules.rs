//! The rules of a JWS that need no key: the `signatures` of a JSON Serialization, the form of the
//! protected header, its `alg` and `crit`, and the signature's length (RFC 7515; RFC 7518,
//! Section 3.4), and the `typ` of a Request Object (RFC 9101, Section 10.8). Intake applies
//! them before it verifies a signature; the credential picker applies them and verifies none.

use serde_json::{Map, Value};

/// The `typ` of a Request Object (RFC 9101, Section 10.8).
const REQUEST_OBJECT_TYP: &str = "oauth-authz-req+jwt";

/// The bytes of an ES256 signature, `r ‖ s` (RFC 7518, Section 3.4).
const ES256_SIGNATURE_LEN: usize = 64;

/// A rule of a JWS that needs no key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}", self.code())]
pub enum JwsRule {
    /// A JSON Serialization has no array `signatures` (RFC 7515, Section 7.2.1).
    Serialization,
    /// The protected header is no JSON object.
    Header,
    /// The signature is not the 64 bytes of an ES256 `r ‖ s`.
    Signature,
    /// `alg` is not `ES256`.
    Algorithm,
    /// The header has `crit` (RFC 7515, Section 4.1.11): the wallet understands no extension.
    Critical,
}

impl JwsRule {
    /// A stable identifier, intake's for the same rule.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Serialization | Self::Header | Self::Signature => "jws_malformed",
            Self::Algorithm => "algorithm_unsupported",
            Self::Critical => "critical_header",
        }
    }
}

/// The `signatures` of the JWS JSON Serialization `jws`.
///
/// # Errors
///
/// [`JwsRule::Serialization`] when `jws` has no array `signatures`.
pub(crate) fn signatures(jws: &Value) -> Result<&[Value], JwsRule> {
    jws.get("signatures")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or(JwsRule::Serialization)
}

/// The decoded protected header `decoded`, a JSON object.
///
/// # Errors
///
/// [`JwsRule::Header`] when `decoded` is no JSON object.
pub(crate) fn header(decoded: &[u8]) -> Result<Map<String, Value>, JwsRule> {
    match serde_json::from_slice(decoded) {
        Ok(Value::Object(header)) => Ok(header),
        _ => Err(JwsRule::Header),
    }
}

/// Checks that the decoded `signature` has the length of an ES256 `r ‖ s`.
///
/// # Errors
///
/// [`JwsRule::Signature`] for another length.
pub(crate) fn signature_length(signature: &[u8]) -> Result<(), JwsRule> {
    if signature.len() == ES256_SIGNATURE_LEN {
        Ok(())
    } else {
        Err(JwsRule::Signature)
    }
}

/// Checks that the protected `header` names `alg` `ES256` and holds no `crit`.
///
/// # Errors
///
/// [`JwsRule::Algorithm`] or [`JwsRule::Critical`].
pub(crate) fn es256(header: &Map<String, Value>) -> Result<(), JwsRule> {
    if header.get("alg").and_then(Value::as_str) != Some("ES256") {
        return Err(JwsRule::Algorithm);
    }
    if header.contains_key("crit") {
        return Err(JwsRule::Critical);
    }
    Ok(())
}

/// Whether the protected `header` names the `typ` of a Request Object.
pub(crate) fn is_request_object(header: &Map<String, Value>) -> bool {
    header.get("typ").and_then(Value::as_str) == Some(REQUEST_OBJECT_TYP)
}
