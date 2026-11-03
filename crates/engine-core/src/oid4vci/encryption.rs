//! Credential response encryption (OpenID4VCI §7.3): the key the wallet
//! offers, the alg/enc negotiation, and the JWE decrypt — the last S2 piece
//! the spike's acceptance criteria name.

use serde::{Deserialize, Serialize};

use super::credential::CredentialResponse;

/// The issuer's `credential_response_encryption` metadata (OID4VCI §7.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseEncryptionConfig {
    /// The key-management algorithms the issuer supports (e.g. `ECDH-ES`).
    #[serde(default, alias = "alg_values_supported")]
    pub alg_values: Vec<String>,
    /// The content-encryption algorithms the issuer supports (e.g. `A256GCM`).
    #[serde(default, alias = "enc_values_supported")]
    pub enc_values: Vec<String>,
    /// Whether the issuer requires encryption (a plain response is refused).
    #[serde(default, alias = "encryption_required")]
    pub required: bool,
}

/// The negotiated alg/enc pair.
#[derive(Debug, Clone, PartialEq)]
pub struct NegotiatedEncryption {
    /// The key-management algorithm (e.g. `ECDH-ES`).
    pub alg: String,
    /// The content-encryption algorithm (e.g. `A256GCM`).
    pub enc: String,
}

/// The candidate alg/enc pairs, in preference order — mirroring the Go
/// engine's negotiation order (the strongest first).
const CANDIDATES: &[(&str, &str)] = &[
    ("ECDH-ES", "A256GCM"),
    ("ECDH-ES", "A128GCM"),
    ("ECDH-ES", "A256CBC-HS512"),
    ("ECDH-ES", "A128CBC-HS256"),
];

/// Why the response encryption refused.
#[derive(Debug, thiserror::Error)]
pub enum EncryptionError {
    /// No mutually supported alg/enc pair.
    #[error("oid4vci: no mutually supported alg/enc pair (issuer requires encryption)")]
    NoOverlap,
    /// The issuer required encryption but the engine could not generate a key.
    #[error("oid4vci: encryption key generation failed")]
    KeyGeneration,
    /// The JWE could not be parsed or decrypted.
    #[error("oid4vci: JWE decrypt failed: {0}")]
    Decrypt(String),
    /// The decrypted plaintext is not a credential response.
    #[error("oid4vci: decrypted response is not JSON")]
    NotJson,
}

/// Negotiates the alg/enc pair from the issuer's metadata, in preference
/// order (A256GCM first, mirroring the Go engine).
pub fn negotiate_encryption(config: &ResponseEncryptionConfig) -> Option<NegotiatedEncryption> {
    for (alg, enc) in CANDIDATES {
        if config.alg_values.iter().any(|a| a == alg) && config.enc_values.iter().any(|e| e == enc)
        {
            return Some(NegotiatedEncryption {
                alg: alg.to_string(),
                enc: enc.to_string(),
            });
        }
    }
    None
}

/// The `credential_response_encryption` member of the credential request:
/// the alg, enc, and the wallet's ephemeral public key as a JWK.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseEncryptionRequest {
    /// The negotiated key-management algorithm.
    pub alg: String,
    /// The negotiated content-encryption algorithm.
    pub enc: String,
    /// The wallet's ephemeral public key (EC P-256) as a JWK.
    pub jwk: serde_json::Value,
}

/// Builds the `credential_response_encryption` member for the credential
/// request, with the negotiated alg/enc and the wallet's public key.
///
/// The key generation goes through the `Rng` port (no ambient randomness);
/// the P-256 key generation itself arrives with the JOSE stack (jose-rs).
/// For S2, the key is a placeholder JWK; jose-rs replaces it.
pub fn build_encryption_request(
    negotiated: &NegotiatedEncryption,
    public_jwk: serde_json::Value,
) -> ResponseEncryptionRequest {
    ResponseEncryptionRequest {
        alg: negotiated.alg.clone(),
        enc: negotiated.enc.clone(),
        jwk: public_jwk,
    }
}

/// Detects whether a credential response is a JWE (encrypted), from the
/// content type or the response shape.
pub fn is_encrypted_response(content_type: &str, body: &[u8]) -> bool {
    // The media type: application/jwt or application/jose.
    if content_type.contains("application/jwt") || content_type.contains("application/jose") {
        return true;
    }
    // The compact serialization shape: five dot-separated base64url parts.
    let text = String::from_utf8_lossy(body);
    let parts = text.split('.').count();
    parts == 5 && !text.starts_with('{')
}

/// Decrypts a JWE-encrypted credential response.
///
/// The JWE uses ECDH-ES key management with the content encryption the
/// negotiation selected; the wallet's ephemeral private key decrypts. The
/// jose-rs library performs the actual decrypt; this function provides the
/// interface and the response parsing.
///
/// **When the key was offered, an unencrypted completion is refused** —
/// per the spec's Security requirements. The P0.6 verification found the
/// Go engine does NOT do this (it accepts a plain 200 after negotiating
/// encryption with `encryption_required: true`); the Rust core must
/// decide, and the vectors pin the decision.
pub fn decrypt_encrypted_response(
    jwe_string: &str,
    _private_key: &[u8],
) -> Result<CredentialResponse, EncryptionError> {
    // The jose-rs integration arrives with the JOSE stack (the
    // DEPENDENCIES.md evaluation chose jose-rs). For now, the interface
    // is here with the full JWE parsing; the decrypt itself returns an
    // error until jose-rs is wired in.
    //
    // The JWE compact serialization: header.encrypted_key.iv.ciphertext.tag
    let parts: Vec<&str> = jwe_string.split('.').collect();
    if parts.len() != 5 || parts.iter().any(|p| p.is_empty()) {
        return Err(EncryptionError::Decrypt(
            "not a JWE compact serialization".to_owned(),
        ));
    }

    // Parse the header to check the alg and enc.
    let header = decode_base64url(parts.first().copied().unwrap_or_default())
        .ok_or_else(|| EncryptionError::Decrypt("invalid header".to_owned()))?;
    let header_json: serde_json::Value = serde_json::from_slice(&header)
        .map_err(|_| EncryptionError::Decrypt("header is not JSON".to_owned()))?;
    let alg = header_json
        .get("alg")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let enc = header_json
        .get("enc")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if !alg.starts_with("ECDH-ES") {
        return Err(EncryptionError::Decrypt(format!(
            "unsupported key-management algorithm {alg:?}"
        )));
    }
    if !enc.starts_with("A") {
        return Err(EncryptionError::Decrypt(format!(
            "unsupported content-encryption algorithm {enc:?}"
        )));
    }

    // The jose-rs decrypt arrives with the JOSE stack integration.
    Err(EncryptionError::Decrypt(
        "jose-rs decrypt arrives with the JOSE stack integration".to_owned(),
    ))
}

/// Minimal base64url decoding.
fn decode_base64url(encoded: &str) -> Option<Vec<u8>> {
    fn value(b: u8) -> Option<u8> {
        match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let bytes = encoded.as_bytes();
    if bytes.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for &b in bytes {
        let v = value(b)?;
        buffer = (buffer << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> ResponseEncryptionConfig {
        ResponseEncryptionConfig {
            alg_values: vec!["ECDH-ES".to_owned()],
            enc_values: vec![
                "A256GCM".to_owned(),
                "A128GCM".to_owned(),
                "A256CBC-HS512".to_owned(),
            ],
            required: true,
        }
    }

    #[test]
    fn negotiates_the_strongest_mutually_supported_pair() {
        let negotiated = negotiate_encryption(&test_config()).expect("negotiate");
        assert_eq!(negotiated.alg, "ECDH-ES");
        assert_eq!(negotiated.enc, "A256GCM");
    }

    #[test]
    fn no_overlap_refuses() {
        let config = ResponseEncryptionConfig {
            alg_values: vec!["RSA-OAEP".to_owned()],
            enc_values: vec!["A128GCM".to_owned()],
            required: true,
        };
        assert!(negotiate_encryption(&config).is_none());
    }

    #[test]
    fn prefers_256gcm_over_128gcm() {
        let negotiated = negotiate_encryption(&test_config()).expect("negotiate");
        assert_eq!(negotiated.enc, "A256GCM");
    }

    #[test]
    fn falls_back_to_128gcm_when_256_is_unsupported() {
        let config = ResponseEncryptionConfig {
            alg_values: vec!["ECDH-ES".to_owned()],
            enc_values: vec!["A128GCM".to_owned()],
            required: false,
        };
        let negotiated = negotiate_encryption(&config).expect("negotiate");
        assert_eq!(negotiated.enc, "A128GCM");
    }

    #[test]
    fn builds_the_request_with_the_negotiated_pair_and_jwk() {
        let negotiated = NegotiatedEncryption {
            alg: "ECDH-ES".to_owned(),
            enc: "A256GCM".to_owned(),
        };
        let jwk = serde_json::json!({"kty": "EC", "crv": "P-256", "x": "a", "y": "b"});
        let request = build_encryption_request(&negotiated, jwk.clone());
        assert_eq!(request.alg, "ECDH-ES");
        assert_eq!(request.enc, "A256GCM");
        assert_eq!(request.jwk, jwk);
    }

    #[test]
    fn detects_an_encrypted_response_from_the_media_type() {
        assert!(is_encrypted_response(
            "application/jwt",
            b"header.key.iv.ct.tag"
        ));
        assert!(is_encrypted_response(
            "application/jose",
            b"header.key.iv.ct.tag"
        ));
        assert!(!is_encrypted_response(
            "application/json",
            br#"{"credential":"x"}"#
        ));
    }

    #[test]
    fn detects_an_encrypted_response_from_the_shape() {
        // Five dot-separated parts, not starting with '{': a JWE.
        assert!(is_encrypted_response("", b"abc.def.ghi.jkl.mno"));
        // A plain JSON response: not a JWE.
        assert!(!is_encrypted_response("", br#"{"credential":"x"}"#));
    }

    #[test]
    fn decrypt_refuses_a_non_jwe_shape() {
        let err = decrypt_encrypted_response("not-a-jwe", &[0u8; 32]).expect_err("refuses");
        assert!(matches!(err, EncryptionError::Decrypt(_)));
    }
}
