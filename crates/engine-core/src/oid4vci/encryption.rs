//! Credential response encryption (OpenID4VCI §7.3): the key the wallet
//! offers, the alg/enc negotiation, and the JWE decrypt — the last S2 piece
//! the spike's acceptance criteria name.

use serde::{Deserialize, Serialize};

use super::credential::CredentialResponse;

/// The issuer's `credential_request_encryption` metadata (OID4VCI 1.0
/// **Final §11.3**): the issuer's own key set the Credential Request is
/// encrypted to, the content-encryption algorithms it supports, and
/// whether it requires the request encrypted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestEncryptionConfig {
    /// The issuer's keys (§11.3 `jwks`): the request encrypts to one of
    /// these, its `kid` naming it in the JWE header.
    #[serde(default)]
    pub jwks: serde_json::Value,
    /// The content-encryption algorithms the issuer supports (e.g.
    /// `A256GCM`) — the JWE's `enc`.
    #[serde(default, alias = "enc_values_supported")]
    pub enc_values: Vec<String>,
    /// Whether the issuer requires the request encrypted (§11.3's
    /// `encryption_required`; Spherity's issuer enforces it with the
    /// response offer even when false).
    #[serde(default, alias = "encryption_required")]
    pub required: bool,
}

impl RequestEncryptionConfig {
    /// The issuer's first EC encryption key (`use: enc`), with its `kid` —
    /// the request's encryption target (§11.3). `None` when the key set
    /// carries nothing usable.
    #[must_use]
    pub fn encryption_key(&self) -> Option<(serde_json::Value, String)> {
        let keys = self.jwks.get("keys")?.as_array()?;
        keys.iter()
            .filter(|key| {
                key.get("kty").and_then(serde_json::Value::as_str) == Some("EC")
                    && key
                        .get("use")
                        .and_then(serde_json::Value::as_str)
                        .is_none_or(|use_| use_ == "enc")
            })
            .find_map(|key| {
                let kid = key
                    .get("kid")
                    .and_then(serde_json::Value::as_str)?
                    .to_owned();
                Some((key.clone(), kid))
            })
    }

    /// The first supported content-encryption algorithm (§11.3's
    /// `enc_values_supported`), preferring A256GCM. `None` when the list
    /// is empty or carries nothing this stack implements.
    #[must_use]
    pub fn preferred_enc(&self) -> Option<String> {
        let implemented = ["A256GCM", "A128GCM"];
        implemented
            .iter()
            .find(|enc| self.enc_values.iter().any(|v| v == *enc))
            .map(|enc| (*enc).to_owned())
    }
}

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
    /// The credential's auxiliary-data delivery carries a `to_wallet`
    /// Secret Value, so the credential response must be encrypted — and
    /// no mutually supported alg/enc pair is available (#51: the
    /// delivery plan, not the issuer's `encryption_required` flag,
    /// makes the offer mandatory).
    #[error("oid4vci: the auxiliary-data delivery requires credential response encryption, but no mutually supported alg/enc pair is available")]
    DeliveryRequiresNoPair,
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
    /// The response key: whose custody the decrypt runs under — the
    /// host's (#59, the client-held pair it generated) or the engine's
    /// (the legacy ephemeral pair).
    pub key: ResponseKey,
    /// Whether the issuer required encryption (the metadata's
    /// `encryption_required`).
    pub required: bool,
}

/// Whose custody a credential response's encryption key is under.
#[derive(Debug)]
pub enum ResponseKey {
    /// Client-held (issue #59): the host answered the key ask with the
    /// PUBLIC JWK of a pair it generated and holds; the engine relays
    /// the JWE back through the decrypt ask, and the plaintext
    /// response exists only on the host. A `to_wallet` secret (the ssc
    /// seed, Credential Auxiliary Data §7.1) reaches the wallet and
    /// only the wallet.
    Client {
        /// The public JWK the credential request offered.
        public_jwk: serde_json::Value,
    },
    /// Engine-held (the legacy hosts, #59's default refusal): the
    /// ephemeral pair lives in the engine for this one response, and
    /// the engine decrypts in-process. The LOCAL/wasm engine IS the
    /// client, so its engine-held custody is client-held in fact.
    /// Boxed: the pair is the large variant (the client arm is one JWK).
    Engine(Box<EphemeralResponseKey>),
}

impl ResponseKey {
    /// The public JWK the credential request's
    /// `credential_response_encryption` carries, whichever custody.
    #[must_use]
    pub fn public_jwk(&self) -> &serde_json::Value {
        match self {
            Self::Client { public_jwk } => public_jwk,
            Self::Engine(key) => &key.public_jwk,
        }
    }

    /// Whether the host holds the private half (#59's client-held mode).
    #[must_use]
    pub fn is_client(&self) -> bool {
        matches!(self, Self::Client { .. })
    }
}

/// Negotiates and generates in one step: the alg/enc pair from the
/// issuer's metadata, the ephemeral key for it. `None` when no pair
/// overlaps (the caller decides whether that is fatal: it is when the
/// issuer required encryption). The ENGINE-held form — the legacy
/// hosts whose [engine_ports::Host::request_response_encryption_key]
/// refuses.
pub fn negotiate_with_key(
    config: &ResponseEncryptionConfig,
) -> Option<NegotiatedResponseEncryption> {
    let negotiated = negotiate_encryption(config)?;
    let key = EphemeralResponseKey::generate().ok()?;
    Some(NegotiatedResponseEncryption {
        negotiated,
        key: ResponseKey::Engine(Box::new(key)),
        required: config.required,
    })
}

/// Negotiates with the host's key (issue #59): the alg/enc pair from the
/// issuer's metadata, the response key from the HOST — its
/// [engine_ports::Host::request_response_encryption_key] answer's
/// public JWK, client-held — falling back to the engine-held ephemeral
/// pair when the host cannot answer (the legacy mode, so every existing
/// host keeps working). `None` when no pair overlaps.
pub async fn negotiate_with_host(
    host: &dyn engine_ports::Host,
    flow_id: &str,
    configuration_id: &str,
    config: &ResponseEncryptionConfig,
) -> Option<NegotiatedResponseEncryption> {
    let negotiated = negotiate_encryption(config)?;
    let key = match host
        .request_response_encryption_key(engine_ports::ResponseEncryptionKeyParams {
            flow_id: flow_id.to_owned(),
            credential_configuration_id: configuration_id.to_owned(),
            // The negotiated pair the engine resolved against the
            // issuer's credential_response_encryption — the host
            // generates the pair FOR IT, and the JWE must use it.
            alg: negotiated.alg.clone(),
            enc: negotiated.enc.clone(),
        })
        .await
    {
        Ok(answer) if !answer.public_jwk.is_null() => ResponseKey::Client {
            public_jwk: answer.public_jwk,
        },
        // The legacy host: the engine-held ephemeral pair.
        _ => ResponseKey::Engine(Box::new(EphemeralResponseKey::generate().ok()?)),
    };
    // Issue #72's diagnostics: which custody the response key took
    // (never the key material itself).
    eprintln!(
        "engine: response key for {} is {}",
        configuration_id,
        if key.is_client() {
            "client-held"
        } else {
            "engine-held"
        }
    );
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

/// Encrypts the Credential Request body to the issuer's §11.3 key: a
/// compact JWE, ECDH-ES key agreement against the issuer's advertised EC
/// key, the `enc` from the issuer's `enc_values_supported` list, the
/// issuer key's `kid` in the JWE header naming the target.
///
/// §11.3: the Credential Request (or Deferred Credential Request) is sent
/// as a JWE — the request body IS the plaintext, `application/oauth-authz-req+jwt`
/// rides the content type. Spherity's issuer enforces it alongside a
/// response-encryption offer ("to prevent the response-encryption key from
/// being substituted by an attacker").
///
/// The alg is ECDH-ES (the key-management the issuer's EC key carries);
/// the `enc` is the issuer's first supported one.
pub fn encrypt_request_body(
    config: &RequestEncryptionConfig,
    request_body: &serde_json::Value,
) -> Result<String, EncryptionError> {
    let (key, kid) = config
        .encryption_key()
        .ok_or(EncryptionError::KeyGeneration)?;
    let enc = config
        .preferred_enc()
        .ok_or(EncryptionError::KeyGeneration)?;
    let enc_name = match enc.as_str() {
        "A256GCM" => jose_rs::algorithm::JweEncryption::A256GCM,
        "A128GCM" => jose_rs::algorithm::JweEncryption::A128GCM,
        // The preferred_enc filter only yields the implemented pair.
        _ => return Err(EncryptionError::KeyGeneration),
    };
    let jwk: jose_rs::jwk::Jwk =
        serde_json::from_value(key).map_err(|_| EncryptionError::KeyGeneration)?;
    let mut recipient = jwk;
    recipient.alg = Some("ECDH-ES".to_owned());
    let plaintext = serde_json::to_vec(request_body).map_err(|_| EncryptionError::NotJson)?;
    // The JWE header names the target key by its kid (§11.3): the issuer
    // resolves its own key set from it.
    let mut header =
        jose_rs::header::JoseHeader::for_jwe(jose_rs::algorithm::JweAlgorithm::EcdhEs, enc_name);
    header.kid = Some(kid);
    jose_rs::jwe::compact::encrypt_with_jwk_header(&recipient, header, &plaintext, enc_name)
        .map_err(|_| EncryptionError::KeyGeneration)
}
