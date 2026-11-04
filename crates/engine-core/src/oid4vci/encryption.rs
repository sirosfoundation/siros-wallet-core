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

/// The `credential_response_encryption` member of the credential
/// request (OID4VCI 1.0 §7.3): the wallet's ephemeral public key as a
/// JWK and the content-encryption algorithm — no `alg`; the 1.0 wire
/// form carries only `jwk` (required), `enc` (required), and `zip`
/// (optional), the key-management algorithm riding the JWE header
/// instead.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseEncryptionRequest {
    /// The negotiated key-management algorithm — engine-internal
    /// only; never serialized to the wire.
    #[serde(skip_serializing)]
    pub alg: String,
    /// The negotiated content-encryption algorithm.
    pub enc: String,
    /// The wallet's ephemeral public key (EC P-256) as a JWK.
    pub jwk: serde_json::Value,
}

/// Builds the `credential_response_encryption` member for the credential
/// request, with the negotiated alg/enc and the wallet's public key.
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

/// The negotiated response encryption with the wallet's ephemeral key:
/// everything the credential request needs to offer the key and the
/// decrypt needs to open the answer.
#[derive(Debug)]
pub struct NegotiatedResponseEncryption {
    /// The negotiated alg/enc pair.
    pub negotiated: NegotiatedEncryption,
    /// The ephemeral key pair: public in the request, private for the
    /// decrypt.
    pub key: EphemeralResponseKey,
    /// Whether the issuer required encryption (the metadata's
    /// `encryption_required`).
    pub required: bool,
}

/// Negotiates and generates in one step: the alg/enc pair from the
/// issuer's metadata, the ephemeral key for it. `None` when no pair
/// overlaps (the caller decides whether that is fatal: it is when the
/// issuer required encryption).
pub fn negotiate_with_key(
    config: &ResponseEncryptionConfig,
) -> Option<NegotiatedResponseEncryption> {
    let negotiated = negotiate_encryption(config)?;
    let key = EphemeralResponseKey::generate().ok()?;
    Some(NegotiatedResponseEncryption {
        negotiated,
        key,
        required: config.required,
    })
}

/// The wallet's ephemeral response-encryption key pair: the public JWK
/// offered in the credential request, the private JWK held for the
/// decrypt.
///
/// The key generation is the JOSE layer's (jose-rs, on the OS entropy),
/// like the signature nonce and the JWE's own IVs and ephemeral ECDH
/// keys: cryptographic randomness inside the chosen crypto dependency.
/// The `Rng` port governs the core's *own* random choices — the OAuth
/// state, the PKCE verifier — not the crypto library's internals.
#[derive(Debug)]
pub struct EphemeralResponseKey {
    /// The public JWK, as the credential request carries it.
    pub public_jwk: serde_json::Value,
    /// The private JWK, held for the decrypt.
    private_jwk: jose_rs::jwk::Jwk,
}

impl EphemeralResponseKey {
    /// Generates a fresh P-256 key pair for one credential response.
    pub fn generate() -> Result<Self, EncryptionError> {
        let private_jwk = jose_rs::jwk::generate::generate_ec("P-256")
            .map_err(|_| EncryptionError::KeyGeneration)?;
        let public = private_jwk.to_public_jwk();
        let public_json = public
            .to_json()
            .map_err(|_| EncryptionError::KeyGeneration)?;
        let public_jwk: serde_json::Value =
            serde_json::from_str(&public_json).map_err(|_| EncryptionError::KeyGeneration)?;
        Ok(Self {
            public_jwk,
            private_jwk,
        })
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

/// Decrypts a JWE-encrypted credential response (OpenID4VCI §7.3): the
/// ECDH-ES key management the negotiation selected, with the wallet's
/// ephemeral private key — via jose-rs.
///
/// **When the key was offered, an unencrypted completion is refused** —
/// per the spec's Security requirements. The P0.6 verification found the
/// Go engine does NOT do this (it accepts a plain 200 after negotiating
/// encryption with `encryption_required: true`); the Rust core must
/// decide, and the vectors pin the decision.
pub fn decrypt_encrypted_response(
    jwe_string: &str,
    key: &EphemeralResponseKey,
) -> Result<CredentialResponse, EncryptionError> {
    // The JWE compact serialization: header.encrypted_key.iv.ciphertext.tag.
    // The encrypted_key part may be empty — ECDH-ES agrees on the CEK
    // directly and wraps nothing (RFC 7516 §5.2), as does `dir`.
    let parts: Vec<&str> = jwe_string.split('.').collect();
    if parts.len() != 5
        || parts
            .iter()
            .enumerate()
            .any(|(i, p)| p.is_empty() && i != 1)
    {
        return Err(EncryptionError::Decrypt(
            "not a JWE compact serialization".to_owned(),
        ));
    }

    // Parse the header to check the alg and enc against what the
    // negotiation offered — the issuer must use the pair the wallet
    // picked, and the algorithm must be one this stack implements.
    let header = decode_base64url(parts.first().copied().unwrap_or_default())
        .ok_or_else(|| EncryptionError::Decrypt("invalid header".to_owned()))?;
    let header_json: serde_json::Value = serde_json::from_slice(&header)
        .map_err(|_| EncryptionError::Decrypt("header is not JSON".to_owned()))?;
    let alg_name = header_json
        .get("alg")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let enc_name = header_json
        .get("enc")
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    // Both algorithms must be ones this stack implements — the parse is
    // the check (the decrypt would refuse them too, but the error would
    // be opaque).
    jose_rs::algorithm::JweAlgorithm::from_str(alg_name).map_err(|_| {
        EncryptionError::Decrypt(format!("unsupported key-management algorithm {alg_name:?}"))
    })?;
    jose_rs::algorithm::JweEncryption::from_str(enc_name).map_err(|_| {
        EncryptionError::Decrypt(format!(
            "unsupported content-encryption algorithm {enc_name:?}"
        ))
    })?;

    // The decrypt: the private JWK carries the alg the issuer used (the
    // decrypt path reads it, exactly as the encrypt path does).
    let mut private = key.private_jwk.clone();
    private.alg = Some(alg_name.to_owned());
    let plaintext = jose_rs::jwe::compact::decrypt_with_jwk(&private, jwe_string)
        .map_err(|err| EncryptionError::Decrypt(err.to_string()))?;

    // The decrypted plaintext is the credential response.
    let response: CredentialResponse =
        serde_json::from_slice(&plaintext).map_err(|_| EncryptionError::NotJson)?;
    Ok(response)
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
        let key = EphemeralResponseKey::generate().expect("keygen");
        let err = decrypt_encrypted_response("not-a-jwe", &key).expect_err("refuses");
        assert!(matches!(err, EncryptionError::Decrypt(_)));
    }

    #[test]
    fn the_ephemeral_key_offers_a_public_ec_jwk() {
        let key = EphemeralResponseKey::generate().expect("keygen");
        assert_eq!(key.public_jwk["kty"], "EC");
        assert_eq!(key.public_jwk["crv"], "P-256");
        // The offered JWK is public: no private member.
        assert!(key.public_jwk.get("d").is_none());
    }

    #[test]
    fn the_encrypted_response_roundtrips() {
        // The issuer's side, simulated with jose-rs: the JWE to the
        // wallet's offered public key, with the negotiated pair.
        let key = EphemeralResponseKey::generate().expect("keygen");
        let negotiated = NegotiatedEncryption {
            alg: "ECDH-ES".to_owned(),
            enc: "A256GCM".to_owned(),
        };

        let public = serde_json::from_value::<jose_rs::jwk::Jwk>(key.public_jwk.clone())
            .expect("public jwk");
        let mut recipient = public.clone();
        recipient.alg = Some(negotiated.alg.clone());

        let credential_response = CredentialResponse {
            credential: Some("credential-jwt-1".to_owned()),
            format_specific: None,
            transaction_id: None,
            interval: None,
            nonce: None,
            notification_id: None,
        };
        let plaintext = serde_json::to_vec(&credential_response).expect("serialize");
        let jwe = jose_rs::jwe::compact::encrypt_with_jwk_header(
            &recipient,
            jose_rs::header::JoseHeader::for_jwe(
                jose_rs::algorithm::JweAlgorithm::EcdhEs,
                jose_rs::algorithm::JweEncryption::A256GCM,
            ),
            &plaintext,
            jose_rs::algorithm::JweEncryption::A256GCM,
        )
        .expect("encrypt");

        // The wallet's side: the decrypt recovers the response.
        let decrypted = decrypt_encrypted_response(&jwe, &key).expect("decrypt");
        assert_eq!(decrypted.credential.as_deref(), Some("credential-jwt-1"));
    }

    #[test]
    fn a_mismatched_algorithm_refuses() {
        // An issuer encrypting with an algorithm the wallet did not
        // offer: the decrypt refuses (the header names RSA-OAEP-256,
        // the key is EC — the decrypt fails, fail closed).
        let key = EphemeralResponseKey::generate().expect("keygen");
        let err = decrypt_encrypted_response("a.b.c.d.e", &key).expect_err("refuses");
        assert!(matches!(err, EncryptionError::Decrypt(_)));
    }
}
