//! The Verifier's and the issuer's side: `transaction_data` entries encoded as OpenID4VP §5.1
//! sends them, a signed Request Object, a PaSO credential's document as the wallet registers it
//! from the issuer's signed credential metadata JWT, and ad-hoc metadata JWTs. An issuer key is
//! named by its secret: an ad-hoc metadata JWT is signed with ES256 under the secret's P-256
//! scalar ([`secret_key`]), and the PaSO document names the scalar's public JWK. The Request
//! Object and the credential metadata JWT, whose text alone the wallet reads, carry an HMAC under
//! the secret in place of a signature.
//!
//! Objects are given as JSON text and written as Python's `json.dumps(value,
//! ensure_ascii=False)` writes them, so their bytes equal the reference model's.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use siros_explain::Explain;
use siros_openid4vp::json::{JsonError, Node};
use siros_openid4vp::sri::integrity;

use crate::jose::P256Scalar;

/// The Origin a signed request's `expected_origins` hold: the default Origin.
pub const ORIGINS: [&str; 1] = ["https://verifier.example"];

/// The `typ` of an ad-hoc metadata JWT (PaSO Proof Metadata §5).
pub const ADHOC_TYP: &str = "adhoc-transaction-metadata+jwt";

/// The issuer of the PaSO credentials: its identifier and its key set, `kid` to the key's secret.
pub const ISSUER: &str =
    r#"{"iss": "https://issuer.bank.example", "keys": {"issuer-key-1": "issuer-secret-1"}}"#;

/// The P-256 scalar of an issuer key's secret: its SHA-256, hashed again while it is no scalar.
#[must_use]
pub fn secret_key(secret: &str) -> P256Scalar {
    let mut digest: [u8; 32] = Sha256::digest(secret.as_bytes()).into();
    loop {
        if let Some(scalar) = P256Scalar::new(digest) {
            return scalar;
        }
        digest = Sha256::digest(digest).into();
    }
}

/// Why an encoder could not write its output.
#[derive(Debug, thiserror::Error, Explain)]
#[explain(domain = "testkit.encode")]
pub enum EncodeError {
    /// An input is no JSON with unique member names.
    #[error(transparent)]
    Json(#[from] JsonError),
    /// The HMAC refused the key.
    #[error("the HMAC refused the key")]
    Key,
    /// The issuer names no `iss`, or a key set whose keys are no secrets.
    #[error("the issuer names no iss, or a key that is no secret")]
    Issuer,
    /// The key is no P-256 scalar.
    #[error(transparent)]
    Sign(#[from] siros_openid4vp::plugins::Fault),
}

/// A JSON text written as Python's `json.dumps(value, ensure_ascii=False)` writes it.
pub fn python_json(json: &str) -> Result<String, JsonError> {
    Ok(Node::parse(json)?.python_text().to_string())
}

/// base64url without padding over the UTF-8 JSON, as a Verifier writes an entry.
pub fn encode(json: &str) -> Result<String, JsonError> {
    Ok(URL_SAFE_NO_PAD.encode(python_json(json)?))
}

/// The stand-in signature: base64url without padding of HMAC-SHA-256 under the secret.
pub fn mac(secret: &str, signing_input: &[u8]) -> Result<String, EncodeError> {
    let mut hmac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).map_err(|_| EncodeError::Key)?;
    hmac.update(signing_input);
    Ok(URL_SAFE_NO_PAD.encode(hmac.finalize().into_bytes()))
}

/// A compact JWS of a header and a payload, signed with the stand-in under the secret.
pub fn jws(header: &str, payload: &str, secret: &str) -> Result<String, EncodeError> {
    let signing_input = format!("{}.{}", encode(header)?, encode(payload)?);
    let signature = mac(secret, signing_input.as_bytes())?;
    Ok(format!("{signing_input}.{signature}"))
}

/// A signed Request Object as a Verifier sends it (JAR); its text is all the wallet hashes.
pub fn signed_request() -> Result<String, EncodeError> {
    jws(
        r#"{"alg": "ES256", "typ": "oauth-authz-req+jwt"}"#,
        r#"{"response_type": "vp_token", "nonce": "n-0S6_WzA2Mj"}"#,
        "verifier-secret",
    )
}

/// An ad-hoc metadata JWT (PaSO Proof Metadata §5.2) signed with ES256 under a P-256 scalar, its
/// header naming the key by `kid` or carrying the `x5c` chain, each item base64 DER.
pub fn adhoc_jwt(
    payload: &str,
    key: &P256Scalar,
    kid: Option<&str>,
    x5c: Option<&[String]>,
) -> Result<String, EncodeError> {
    let quote = siros_openid4vp::json::quote;
    let mut header = format!("{{\"alg\": \"ES256\", \"typ\": {}", quote(ADHOC_TYP));
    if let Some(kid) = kid {
        header.push_str(&format!(", \"kid\": {}", quote(kid)));
    }
    if let Some(items) = x5c {
        let items: Vec<String> = items.iter().map(|item| quote(item)).collect();
        header.push_str(&format!(", \"x5c\": [{}]", items.join(", ")));
    }
    header.push('}');
    Ok(crate::jose::compact_jws(
        key,
        &header,
        &python_json(payload)?,
    )?)
}

/// The issuer's signed credential metadata JWT (PaSO Proof Metadata §4) as the wallet registers
/// it: the JWT's integrity value, the credential's type, the issuer's key material, its key set
/// naming each key's public JWK in place of its secret, the `transaction_data_types`, and the
/// risk signal encryption keys when the metadata publishes them. `types`, `keys` and `issuer` are
/// JSON texts.
pub fn paso_document(
    credential_type: &str,
    credential_format: &str,
    types: &str,
    keys: Option<&str>,
    issuer: &str,
) -> Result<String, EncodeError> {
    let quote = siros_openid4vp::json::quote;
    let issuer_node = Node::parse(issuer)?;
    let iss = issuer_node
        .get("iss")
        .and_then(Node::as_str)
        .ok_or(EncodeError::Issuer)?;
    let key_set = issuer_node.get("keys").and_then(Node::as_object);
    let kid = key_set
        .and_then(|keys| keys.names().next())
        .unwrap_or("x5c");
    let secret = key_set
        .and_then(|keys| keys.get(kid))
        .and_then(Node::as_str)
        .unwrap_or("x5c-secret");
    let mut metadata = format!("\"transaction_data_types\": {}", python_json(types)?);
    if let Some(keys) = keys {
        metadata.push_str(&format!(
            ", \"risk_signals_encryption_keys\": {}",
            python_json(keys)?
        ));
    }
    let header = format!(
        "{{\"typ\": \"credential-metadata+jwt\", \"kid\": {}}}",
        quote(kid)
    );
    let payload = format!(
        "{{\"iss\": {}, \"sub\": {}, \"format\": {}, \"iat\": 1780000000, \"exp\": 1790000000, \"credential_metadata_uri\": {}, \"credential_metadata\": {{{metadata}}}}}",
        quote(iss),
        quote(credential_type),
        quote(credential_format),
        quote(&format!("{iss}/metadata")),
    );
    let jwt = jws(&header, &payload, secret)?;
    let published = match key_set {
        None => python_json(issuer)?,
        Some(keys) => {
            let mut jwks = Vec::new();
            for member in keys.members() {
                let secret = member.value.as_str().ok_or(EncodeError::Issuer)?;
                let jwk = crate::jose::key_jwk(&secret_key(secret))?;
                jwks.push(format!("{}: {}", quote(&member.name), jwk.python_text()));
            }
            let mut written = String::from("{");
            for member in issuer_node
                .as_object()
                .ok_or(EncodeError::Issuer)?
                .members()
            {
                if written.len() > 1 {
                    written.push_str(", ");
                }
                written.push_str(&quote(&member.name));
                written.push_str(": ");
                if member.name == "keys" {
                    written.push_str(&format!("{{{}}}", jwks.join(", ")));
                } else {
                    written.push_str(&member.value.python_text().to_string());
                }
            }
            written.push('}');
            written
        }
    };
    Ok(format!(
        "{{\"integrity\": {}, \"type\": {}, \"issuer\": {published}, {metadata}}}",
        quote(integrity(jwt.as_bytes()).as_str()),
        quote(credential_type),
    ))
}
