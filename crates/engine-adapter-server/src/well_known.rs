//! The well-known document's signed form (issue #100, CS-15 §7.2):
//! the configuration as **attestation** — `Accept: application/jwt`
//! answers the same document as a JWS signed under the participant
//! certificate's key, the chain in the `x5c` header, verifiable
//! without the TLS session. The eDelivery profile's trust model reads
//! the document as a statement the participant stands behind, not just
//! configuration the endpoint happens to serve.
//!
//! The plain JSON stays the default answer; the signed form is a
//! content negotiation, exactly the two shapes CS-15's §17 conformance
//! table names for the well-known route (`application/json` or
//! `application/jwt`).

use axum::http::{header, HeaderMap};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;

use crate::participant::ParticipantCredential;

/// True when the caller's `Accept` names `application/jwt` — the
/// request for the signed form. The signed form wins when named: no
/// client names both media types preferring the unsigned one (the
/// attestation is strictly the stronger answer, and a checker that
/// asks for it wants exactly it).
pub(crate) fn wants_signed_form(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|accept| {
            accept.split(',').any(|entry| {
                entry
                    .split(';')
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .eq_ignore_ascii_case("application/jwt")
            })
        })
}

/// The certificate chain's DER blobs, leaf first, from a PEM document —
/// one or more `BEGIN CERTIFICATE` blocks, the order they appear. An
/// empty or malformed document answers `None`.
pub(crate) fn certificate_chain_der(pem_text: &str) -> Option<Vec<Vec<u8>>> {
    let mut chain = Vec::new();
    let mut body = String::new();
    let mut inside = false;
    for line in pem_text.lines() {
        let line = line.trim();
        if line == "-----BEGIN CERTIFICATE-----" {
            inside = true;
            body.clear();
        } else if line == "-----END CERTIFICATE-----" {
            if inside && !body.is_empty() {
                chain.push(BASE64_STANDARD.decode(body.as_bytes()).ok()?);
            }
            inside = false;
        } else if inside {
            body.push_str(line);
        }
    }
    (!chain.is_empty()).then_some(chain)
}

/// The well-known document as a compact JWS: the JSON document as the
/// payload, the participant chain in the `x5c` header (RFC 7515
/// §4.1.6: standard-alphabet base64 DER, not base64url), the signature
/// under the credential the server holds — wherever its key lives, the
/// PEM pair or a PKCS#11 token, the trait is the boundary (issue #100:
/// CS-15 §8.4, the key's home is deployment material). `None` when the
/// signing does not hold together — a JWT whose key does not match its
/// own chain is not served; the caller learns the credential is broken,
/// not a document that cannot verify.
pub(crate) fn signed_document(
    credential: &dyn ParticipantCredential,
    document: &serde_json::Value,
) -> Option<String> {
    let chain = credential.certificate_chain();
    let leaf = chain.first()?.clone();
    let payload = serde_json::to_vec(document).ok()?;
    let mut header = jose_rs::header::JoseHeader::new(credential.algorithm());
    header.typ = Some("wmp-configuration+jwt".to_owned());
    header.x5c = Some(
        chain
            .iter()
            .map(|der| BASE64_STANDARD.encode(der))
            .collect(),
    );
    let jwt = credential.sign_compact(&payload, &header).ok()?;
    // Fail closed on a key/certificate mismatch: the document verifies
    // under the chain's leaf before it is served — the same check a
    // counterpart's parser runs, done here so a broken deployment fails
    // loudly at its own edge.
    let verifying = jose_rs::jwk::cert::public_jwk_from_certificate_der(&leaf).ok()?;
    jose_rs::jws::compact::verify_with_jwk(&verifying, &jwt).ok()?;
    Some(jwt)
}
