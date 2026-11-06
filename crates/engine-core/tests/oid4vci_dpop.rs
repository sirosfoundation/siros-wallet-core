use engine_core::oid4vci::dpop::*;
use engine_ports::{Host, SignParams};
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
        _params: engine_ports::MatchParams,
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
        1_000,
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
        1_000,
    )
    .await
    .expect("proof");

    let parts: Vec<&str> = proof.split('.').collect();
    let payload = decode_b64(parts[1]);
    let claims: DpopClaims = serde_json::from_slice(&payload).expect("parse claims");
    assert!(claims.ath.is_some());
    // RFC 9449 §4.2: ath = base64url(SHA-256(access_token)) — the
    // digest, not the token.
    assert_eq!(
        claims.ath.as_deref(),
        Some("pZOyhFN0Z9eQivPyniH1Gg1OzUpcjUffjr7n0FzCLck")
    );
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

struct FakeRng;
impl engine_ports::Rng for FakeRng {
    fn fill(&self, buf: &mut [u8]) -> bool {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = i as u8;
        }
        true
    }
}

#[test]
fn the_engine_held_key_signs_a_verifiable_proof() {
    let key = DpopKey::generate().expect("keygen");
    let proof = key
        .proof(
            &FakeRng,
            "POST",
            "https://as.example/token",
            Some("at-123"),
            Some("server-nonce"),
            1_000,
        )
        .expect("proof");

    // The header: typ dpop+jwt, the public JWK, ES256.
    let parts: Vec<&str> = proof.split('.').collect();
    assert_eq!(parts.len(), 3);
    let header = decode_b64(parts[0]);
    let header: serde_json::Value = serde_json::from_slice(&header).expect("header");
    assert_eq!(header["typ"], "dpop+jwt");
    assert_eq!(header["alg"], "ES256");
    assert_eq!(header["jwk"]["kty"], "EC");

    // The claims: htm/htu binding, the ath digest, the nonce.
    let payload = decode_b64(parts[1]);
    let claims: serde_json::Value = serde_json::from_slice(&payload).expect("claims");
    assert_eq!(claims["htm"], "POST");
    assert_eq!(claims["htu"], "https://as.example/token");
    assert_eq!(claims["iat"], 1_000);
    assert_eq!(claims["nonce"], "server-nonce");
    assert_eq!(claims["ath"], "pZOyhFN0Z9eQivPyniH1Gg1OzUpcjUffjr7n0FzCLck");

    // The proof verifies under the public JWK: a token request's
    // DPoP header an AS can actually check.
    let public: jose_rs::jwk::Jwk =
        serde_json::from_value(key.public_jwk().clone()).expect("public jwk");
    let verified = jose_rs::jws::compact::verify_with_jwk(&public, &proof).expect("verify");
    assert_eq!(verified, payload);
}
