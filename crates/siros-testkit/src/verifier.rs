//! The Verifier's and the issuer's side: `transaction_data` entries encoded as OpenID4VP §5.1
//! sends them, a signed Request Object, a PaSO credential's document as the wallet registers it
//! from the issuer's signed credential metadata JWT, and ad-hoc metadata JWTs signed with ES256
//! under the issuer's P-256 key. The Request Object and the credential metadata JWT, whose text
//! alone the wallet reads, carry an HMAC under a secret in place of a signature.
//!
//! Objects are given as JSON text and written as Python's `json.dumps(value,
//! ensure_ascii=False)` writes them, so their bytes equal the reference model's.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use siros_explain::Explain;
use siros_openid4vp::json::{JsonError, Node};
use siros_openid4vp::sri::integrity;

/// The Origin a signed request's `expected_origins` hold: the default Origin.
pub const ORIGINS: [&str; 1] = ["https://verifier.example"];

/// The `typ` of an ad-hoc metadata JWT (PaSO Proof Metadata §5).
pub const ADHOC_TYP: &str = "adhoc-transaction-metadata+jwt";

/// The P-256 scalar of the PaSO credentials' issuer key, `issuer-key-1`.
pub const ISSUER_KEY: [u8; 32] = [1; 32];

/// A P-256 scalar whose key the issuer does not publish.
pub const OTHER_KEY: [u8; 32] = [2; 32];

/// The issuer of the PaSO credentials: its identifier and its key set, `kid` to public JWK: the
/// key of [`ISSUER_KEY`], its point computed by P-256's scalar multiplication (SEC 2 §2.4.2).
pub const ISSUER: &str = r#"{"iss": "https://issuer.bank.example", "keys": {"issuer-key-1": {"kty": "EC", "crv": "P-256", "x": "b_A7lJJBzh2t1DUZ5pYOCoW0GmmgXDKBA6orzhWUyhY", "y": "PE91OlW_AdxT9sCwx-7ni0DG_30lqW4igrmJzvccFEo"}}}"#;

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
    /// The issuer names no `iss`.
    #[error("the issuer names no iss")]
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
    key: &[u8; 32],
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
/// it: the JWT's integrity value, the credential's type, the issuer's key material, the
/// `transaction_data_types`, and the risk signal encryption keys when the metadata publishes
/// them. `types`, `keys` and `issuer` are JSON texts.
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
    let jwt = jws(&header, &payload, "issuer-metadata-secret")?;
    Ok(format!(
        "{{\"integrity\": {}, \"type\": {}, \"issuer\": {}, {metadata}}}",
        quote(&integrity(jwt.as_bytes())),
        quote(credential_type),
        python_json(issuer)?
    ))
}
