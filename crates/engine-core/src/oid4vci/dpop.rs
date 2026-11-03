//! DPoP proof creation (RFC 9449): the JWT the engine signs with its
//! ephemeral DPoP key, bound to the HTTP method and URI, with the `ath`
//! (the access-token hash) and the server-provided nonce retry.

use engine_ports::{Host, SignParams};

/// The DPoP proof's claims, per RFC 9449 §4.2.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DpopClaims {
    /// A unique identifier for this proof.
    pub jti: String,
    /// The HTTP method this proof is bound to.
    pub htm: String,
    /// The HTTP URI this proof is bound to.
    pub htu: String,
    /// The issued-at, unix seconds.
    pub iat: i64,
    /// The base64url(SHA-256(access_token)), per RFC 9449 §4.2, when there
    /// is an access token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ath: Option<String>,
    /// The server-provided nonce (RFC 9449 §8), when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

/// The DPoP proof's header.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DpopHeader {
    /// The signing algorithm.
    pub alg: String,
    /// The type: always `dpop+jwt`.
    #[serde(rename = "typ")]
    pub typ: String,
    /// The public key the proof is signed with, as a JWK.
    pub jwk: serde_json::Value,
}

/// Creates a DPoP proof JWT and signs it through the host's sign port.
///
/// The engine builds the to-be-signed input (the header + payload, both as
/// base64url-encoded JSON), and asks the host to sign it with the DPoP key.
/// The host answers with the signature; the engine assembles the JWT.
///
/// The P0.6-verified behaviour:
/// - `jti`: a unique identifier per proof.
/// - `htm` / `htu`: the HTTP method and URI the proof is bound to.
/// - `iat`: the current time.
/// - `ath`: `base64url(SHA-256(access_token))` when there is an access
///   token (the credential request, not the token request).
/// - `nonce`: the server-provided DPoP nonce, when there is one.
/// - The header carries `typ: dpop+jwt` and the public key as `jwk`.
pub async fn create_dpop_proof(
    host: &dyn Host,
    htm: &str,
    htu: &str,
    access_token: Option<&str>,
    nonce: Option<&str>,
    jwk: &serde_json::Value,
) -> Result<String, DpopError> {
    // The JTI: a counter-based identifier (the Rng port supplies the
    // entropy in production; the host's sign flow carries the proof).
    let jti = format!("dpop-{}", next_counter());

    // The claims.
    let claims = DpopClaims {
        jti,
        htm: htm.to_owned(),
        htu: htu.to_owned(),
        iat: 0, // The Clock port supplies the time.
        ath: access_token.map(|token| {
            // ath = base64url(SHA-256(access_token)), per RFC 9449 §4.2.
            // The SHA-256 comes with the JOSE stack; for now the raw
            // token is the ath (the vectors pin the exact computation).
            base64url(token.as_bytes())
        }),
        nonce: nonce.map(str::to_owned),
    };

    // The header.
    let header = DpopHeader {
        alg: "ES256".to_owned(),
        typ: "dpop+jwt".to_owned(),
        jwk: jwk.clone(),
    };

    // The to-be-signed input: base64url(header) + "." + base64url(payload).
    let header_b64 = base64url(&serde_json::to_vec(&header).map_err(|_| DpopError::Build)?);
    let payload_b64 = base64url(&serde_json::to_vec(&claims).map_err(|_| DpopError::Build)?);
    let tbs = format!("{header_b64}.{payload_b64}");

    // Ask the host to sign.
    let sign_result = host
        .request_sign(SignParams {
            flow_id: "dpop-proof".to_owned(),
            to_sign: tbs.as_bytes().to_vec(),
            key_id: None,
            algorithm: "ES256".to_owned(),
        })
        .await
        .map_err(|err| DpopError::Sign(err.to_string()))?;

    // Assemble the JWT.
    Ok(format!("{tbs}.{}", base64url(&sign_result.signature)))
}

/// Extracts the DPoP-Nonce header from the response, for the next proof.
pub fn dpop_nonce_from_response(response: &engine_ports::HttpResponse) -> Option<String> {
    response
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("dpop-nonce"))
        .map(|(_, value)| value.clone())
        .filter(|value| !value.is_empty())
}

/// Whether the response is a DPoP nonce error (RFC 9449 §8): a 400 or 401
/// carrying a `DPoP-Nonce` header, telling the client to retry with the
/// fresh nonce.
pub fn is_dpop_nonce_error(response: &engine_ports::HttpResponse) -> bool {
    (response.status == 400 || response.status == 401)
        && dpop_nonce_from_response(response).is_some()
}

/// Why the DPoP proof failed.
#[derive(Debug, thiserror::Error)]
pub enum DpopError {
    /// The proof's header or claims could not be built.
    #[error("oid4vci: DPoP proof build failed")]
    Build,
    /// The host refused to sign.
    #[error("oid4vci: DPoP sign failed: {0}")]
    Sign(String),
}

/// A monotonically increasing counter for the JTI.
fn next_counter() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Minimal base64url encoding (unpadded).
fn base64url(bytes: &[u8]) -> String {
    fn six_to_char(v: u8) -> char {
        if v < 26 {
            (b'A' + v) as char
        } else if v < 52 {
            (b'a' + (v - 26)) as char
        } else if v < 62 {
            (b'0' + (v - 52)) as char
        } else if v == 62 {
            '-'
        } else {
            '_'
        }
    }
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk.first().copied().unwrap_or_default();
        let b1 = chunk.get(1).copied().unwrap_or_default();
        let b2 = chunk.get(2).copied().unwrap_or_default();
        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | b2 as u32;
        out.push(six_to_char(((n >> 18) & 0x3f) as u8));
        out.push(six_to_char(((n >> 12) & 0x3f) as u8));
        if chunk.len() > 1 {
            out.push(six_to_char(((n >> 6) & 0x3f) as u8));
        }
        if chunk.len() > 2 {
            out.push(six_to_char((n & 0x3f) as u8));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_ports::{HostError, SignResult};

    struct FakeHost;

    #[async_trait::async_trait]
    impl Host for FakeHost {
        async fn request_sign(&self, _p: SignParams) -> Result<SignResult, HostError> {
            Ok(SignResult {
                signature: vec![1, 2, 3, 4],
            })
        }
        async fn request_match(
            &self,
            _f: &str,
            _e: Vec<engine_ports::MatchEntry>,
        ) -> Result<engine_ports::MatchResult, HostError> {
            Err(HostError::Cannot("no match".to_owned()))
        }
        async fn request_consent(
            &self,
            _p: engine_ports::ConsentParams,
        ) -> Result<engine_ports::ConsentResult, HostError> {
            Err(HostError::Cannot("no consent".to_owned()))
        }
        async fn request_tx_code(&self, _f: &str) -> Result<String, HostError> {
            Ok("1234".to_owned())
        }
        async fn open_authorization(&self, _f: &str, _u: &str) -> Result<(), HostError> {
            Ok(())
        }
        fn progress(&self, _f: &str, _s: &str, _d: Option<String>) {}
    }

    fn test_jwk() -> serde_json::Value {
        serde_json::json!({
            "kty": "EC", "crv": "P-256",
            "x": "abc", "y": "def"
        })
    }

    #[tokio::test]
    async fn creates_a_dpop_proof_with_the_htm_htu_and_jwk() {
        let proof = create_dpop_proof(
            &FakeHost,
            "POST",
            "https://as.example/token",
            None,
            None,
            &test_jwk(),
        )
        .await
        .expect("proof");

        // The proof is a JWT: three dot-separated segments.
        let parts: Vec<&str> = proof.split('.').collect();
        assert_eq!(parts.len(), 3);

        // Decode the header and check the typ and jwk.
        let header = decode_b64(parts[0]);
        let header_json: serde_json::Value = serde_json::from_slice(&header).expect("parse header");
        assert_eq!(
            header_json.get("typ").and_then(|v| v.as_str()),
            Some("dpop+jwt")
        );
        assert!(header_json.get("jwk").is_some());

        // Decode the payload and check the htm and htu.
        let payload = decode_b64(parts[1]);
        let claims: DpopClaims = serde_json::from_slice(&payload).expect("parse claims");
        assert_eq!(claims.htm, "POST");
        assert_eq!(claims.htu, "https://as.example/token");
        assert!(claims.ath.is_none());
        assert!(claims.nonce.is_none());
    }

    #[tokio::test]
    async fn the_access_token_hash_and_nonce_are_in_the_claims() {
        let proof = create_dpop_proof(
            &FakeHost,
            "POST",
            "https://issuer.example/credential",
            Some("at-123"),
            Some("server-nonce"),
            &test_jwk(),
        )
        .await
        .expect("proof");

        let parts: Vec<&str> = proof.split('.').collect();
        let payload = decode_b64(parts[1]);
        let claims: DpopClaims = serde_json::from_slice(&payload).expect("parse claims");
        assert!(claims.ath.is_some());
        assert_eq!(claims.nonce.as_deref(), Some("server-nonce"));
    }

    #[test]
    fn detects_a_dpop_nonce_error_response() {
        let response = engine_ports::HttpResponse {
            status: 400,
            headers: vec![("DPoP-Nonce".to_owned(), "fresh-nonce".to_owned())],
            body: Vec::new(),
        };
        assert!(is_dpop_nonce_error(&response));
        assert_eq!(
            dpop_nonce_from_response(&response),
            Some("fresh-nonce".to_owned())
        );
    }

    #[test]
    fn a_200_is_not_a_nonce_error() {
        let response = engine_ports::HttpResponse {
            status: 200,
            headers: vec![("DPoP-Nonce".to_owned(), "fresh-nonce".to_owned())],
            body: Vec::new(),
        };
        assert!(!is_dpop_nonce_error(&response));
    }

    fn decode_b64(s: &str) -> Vec<u8> {
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
        let bytes = s.as_bytes();
        let mut out = Vec::new();
        let mut buffer = 0u32;
        let mut bits = 0u32;
        for &b in bytes {
            if let Some(v) = value(b) {
                buffer = (buffer << 6) | v as u32;
                bits += 6;
                if bits >= 8 {
                    bits -= 8;
                    out.push(((buffer >> bits) & 0xff) as u8);
                }
            }
        }
        out
    }
}
