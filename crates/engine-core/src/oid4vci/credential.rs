//! The credential request: the key proofs through the Host, the credential
//! endpoint POST, and the response — S2's second step.

use engine_ports::{FetchPurpose, Host, HttpClient, HttpError, HttpRequest, RedirectPolicy};
use serde::{Deserialize, Serialize};

use super::token::TokenResponse;
use super::types::IssuerMetadata;

/// The maximum size of a credential response: 4 MiB (the encrypted forms
/// are larger than the plain form).
const MAX_CREDENTIAL_BYTES: usize = 4 << 20;

/// The parsed credential response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialResponse {
    /// The credential, when the issuer answered directly (the plain form
    /// or the format-specific member).
    #[serde(default)]
    pub credential: Option<String>,
    /// The format-specific member (`jwt`, `sd_jwt`, etc), when present.
    #[serde(default)]
    pub format_specific: Option<serde_json::Value>,
    /// The transaction id, when the issuer deferred the credential.
    #[serde(default)]
    pub transaction_id: Option<String>,
    /// The acceptance interval, when deferred.
    #[serde(default)]
    pub interval: Option<i64>,
    /// The nonce, when the issuer sent a new one.
    #[serde(default)]
    pub nonce: Option<String>,
}

/// Why the credential request refused.
#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    /// The host could not provide the proofs.
    #[error("oid4vci: key proofs failed: {0}")]
    Proofs(String),
    /// The credential endpoint answered a non-200.
    #[error("oid4vci: credential endpoint answered {0}")]
    Status(u16),
    /// The transport failed.
    #[error("oid4vci: credential request failed: {0}")]
    Fetch(String),
    /// The response body is not a credential response.
    #[error("oid4vci: credential response is not JSON")]
    NotJson,
}

/// Requests a credential from the issuer's credential endpoint, with the
/// key proofs the host signed and the access token.
///
/// The proof is a JWT the host signs over the `proof_tokens` the engine
/// builds: the JWT header + payload for the issuer's `nonce` and
/// `credential_issuer` audience. The engine builds the to-be-signed input
/// and asks the host through `Host::request_sign`; the host signs with the
/// key the credential is bound to.
pub async fn request_credential(
    http: &dyn HttpClient,
    host: &dyn Host,
    metadata: &IssuerMetadata,
    token: &TokenResponse,
    configuration_id: &str,
    nonce: Option<&str>,
) -> Result<CredentialResponse, CredentialError> {
    // Build the proof's to-be-signed input: a JWT with the `nonce` and
    // the `credential_issuer` audience (OpenID4VCI §7.5, JWT proof).
    let iat = 0; // The Clock port supplies the time; the host signs.
    let proof_payload = serde_json::json!({
        "iss": metadata.credential_issuer,
        "aud": metadata.credential_issuer,
        "iat": iat,
        "nonce": nonce.unwrap_or_default(),
    });
    let proof_header = serde_json::json!({
        "typ": "openid4vci-proof+jwt",
        "alg": "ES256",
    });
    let proof_tbs = format!(
        "{}.{}",
        base64url_json(&proof_header),
        base64url_json(&proof_payload),
    );

    // Ask the host to sign the proof.
    let sign_result = host
        .request_sign(engine_ports::SignParams {
            flow_id: "oid4vci-credential".to_owned(),
            to_sign: proof_tbs.as_bytes().to_vec(),
            key_id: None,
            algorithm: "ES256".to_owned(),
        })
        .await
        .map_err(|err| CredentialError::Proofs(err.to_string()))?;

    // Assemble the signed proof JWT: the TBS plus the base64url signature.
    let proof_jwt = format!("{}.{}", proof_tbs, base64url(&sign_result.signature),);

    // Build the credential request body.
    let request_body = serde_json::json!({
        "credential_identifier": configuration_id,
        "proof": {
            "proof_type": "jwt",
            "jwt": proof_jwt,
        },
    });

    // Send the credential request.
    let credential_endpoint = format!(
        "{}/credential",
        metadata.credential_issuer.trim_end_matches('/'),
    );
    let response = http
        .send(HttpRequest {
            method: "POST".to_owned(),
            url: credential_endpoint,
            headers: vec![
                ("content-type".to_owned(), "application/json".to_owned()),
                ("accept".to_owned(), "application/json".to_owned()),
                (
                    "authorization".to_owned(),
                    format!("Bearer {}", token.access_token),
                ),
            ],
            body: serde_json::to_vec(&request_body).map_err(|_| CredentialError::NotJson)?,
            purpose: FetchPurpose::Credential,
            max_response_bytes: MAX_CREDENTIAL_BYTES,
            redirects: RedirectPolicy::None,
            allow_plaintext: false,
            timeout_ms: 30_000,
        })
        .await
        .map_err(|err| match err {
            HttpError::Refused => CredentialError::Fetch("refused by the adapter".to_owned()),
            HttpError::Transport(detail) => CredentialError::Fetch(detail),
        })?;

    if response.status != 200 {
        return Err(CredentialError::Status(response.status));
    }

    // Decode the response.
    let value: serde_json::Value =
        serde_json::from_slice(&response.body).map_err(|_| CredentialError::NotJson)?;

    let credential_response: CredentialResponse =
        serde_json::from_value(value).map_err(|_| CredentialError::NotJson)?;

    Ok(credential_response)
}

/// Minimal base64url encoding of JSON bytes.
fn base64url_json(value: &serde_json::Value) -> String {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    base64url(&bytes)
}

/// Minimal base64url encoding.
fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or_default();
        let b2 = chunk.get(2).copied().unwrap_or_default();
        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | b2 as u32;
        out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((n >> 6) & 0x3f) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(n & 0x3f) as usize] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_ports::{HostError, SignParams, SignResult};

    struct FakeHttp {
        status: u16,
        body: Vec<u8>,
    }

    #[async_trait::async_trait]
    impl HttpClient for FakeHttp {
        async fn send(
            &self,
            request: HttpRequest,
        ) -> Result<engine_ports::HttpResponse, HttpError> {
            assert_eq!(request.purpose, FetchPurpose::Credential);
            assert_eq!(request.max_response_bytes, MAX_CREDENTIAL_BYTES);
            Ok(engine_ports::HttpResponse {
                status: self.status,
                headers: Vec::new(),
                body: self.body.clone(),
            })
        }
    }

    struct FakeHost;

    #[async_trait::async_trait]
    impl Host for FakeHost {
        async fn request_sign(&self, _p: SignParams) -> Result<SignResult, HostError> {
            Ok(SignResult {
                signature: vec![0xde, 0xad, 0xbe, 0xef],
            })
        }
        async fn request_match(
            &self,
            _f: &str,
            _e: Vec<engine_ports::MatchEntry>,
        ) -> Result<engine_ports::MatchResult, HostError> {
            Err(HostError::Cannot("no match in the test".to_owned()))
        }
        async fn request_consent(
            &self,
            _p: engine_ports::ConsentParams,
        ) -> Result<engine_ports::ConsentResult, HostError> {
            Err(HostError::Cannot("no consent in the test".to_owned()))
        }
        async fn request_tx_code(&self, _f: &str) -> Result<String, HostError> {
            Ok("1234".to_owned())
        }
        async fn open_authorization(&self, _f: &str, _u: &str) -> Result<(), HostError> {
            Ok(())
        }
        fn progress(&self, _f: &str, _s: &str, _d: Option<String>) {}
    }

    fn test_metadata() -> IssuerMetadata {
        IssuerMetadata {
            credential_issuer: "https://issuer.example".to_owned(),
            authorization_servers: Vec::new(),
            credential_configurations: serde_json::json!({}),
            signed_metadata: None,
            is_signed: false,
        }
    }

    fn test_token() -> TokenResponse {
        TokenResponse {
            access_token: "at-test".to_owned(),
            token_type: "Bearer".to_owned(),
            expires_in: Some(3600),
            refresh_token: None,
            c_nonce: None,
            nonce: Some("nonce-1".to_owned()),
        }
    }

    #[tokio::test]
    async fn requests_a_credential_with_the_host_signed_proof() {
        let http = FakeHttp {
            status: 200,
            body: br#"{"credential":"eyJhbGciOiJFUzI1NiJ9.payload.sig"}"#.to_vec(),
        };
        let response = request_credential(
            &http,
            &FakeHost,
            &test_metadata(),
            &test_token(),
            "UniversityDegree",
            Some("nonce-1"),
        )
        .await
        .expect("request");
        assert!(response.credential.is_some());
    }

    #[tokio::test]
    async fn a_deferred_credential_answer_names_the_transaction() {
        let http = FakeHttp {
            status: 200,
            body: br#"{"transaction_id":"tx-1","interval":5}"#.to_vec(),
        };
        let response = request_credential(
            &http,
            &FakeHost,
            &test_metadata(),
            &test_token(),
            "UniversityDegree",
            Some("nonce-1"),
        )
        .await
        .expect("request");
        assert_eq!(response.transaction_id, Some("tx-1".to_owned()));
        assert_eq!(response.interval, Some(5));
    }

    #[tokio::test]
    async fn a_non_200_refuses() {
        let http = FakeHttp {
            status: 400,
            body: Vec::new(),
        };
        assert!(matches!(
            request_credential(&http, &FakeHost, &test_metadata(), &test_token(), "X", None).await,
            Err(CredentialError::Status(400))
        ));
    }
}
