//! The token exchange: the pre-authorized-code grant, the tx_code sub-flow,
//! and the OAuth 2.0 token endpoint POST — S2's first step.

use engine_ports::{FetchPurpose, Host, HttpClient, HttpError, HttpRequest, RedirectPolicy};
use serde::{Deserialize, Serialize};

use super::types::AsMetadata;

/// The maximum size of a token endpoint response: 1 MiB.
const MAX_TOKEN_BYTES: usize = 1 << 20;

/// The parsed token response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    /// The access token.
    pub access_token: String,
    /// The token type (always "Bearer" for OID4VCI).
    #[serde(default)]
    pub token_type: String,
    /// The expires-in, in seconds.
    #[serde(default)]
    pub expires_in: Option<i64>,
    /// The refresh token, when the issuer issued one.
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// The c_nonce, when the issuer sent one (the legacy nonce).
    #[serde(default)]
    pub c_nonce: Option<String>,
    /// The nonce, when the issuer sent one (the current form).
    #[serde(default)]
    pub nonce: Option<String>,
    /// The `authorization_details` the AS granted, when it sent any (raw
    /// JSON, as received). The granted `credential_identifiers` inside are
    /// the Credential Request's `credential_identifier` substitution source.
    #[serde(default)]
    pub authorization_details: Option<serde_json::Value>,
}

/// Why the token exchange refused.
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    /// No token endpoint was resolvable (the AS metadata had none and the
    /// guess was not attempted).
    #[error("oid4vci: no token endpoint")]
    NoTokenEndpoint,
    /// The host declined to provide the tx_code.
    #[error("oid4vci: tx_code declined")]
    TxCodeDeclined,
    /// The token endpoint answered a non-200.
    #[error("oid4vci: token endpoint answered {0}: {1}")]
    Status(u16, String),
    /// The transport failed.
    #[error("oid4vci: token exchange failed: {0}")]
    Fetch(String),
    /// The response body is not a token response.
    #[error("oid4vci: token response is not JSON")]
    NotJson,
}

/// Exchanges a pre-authorized code for an access token, asking the host
/// for the tx_code when the grant requires it.
///
/// The grant params: `grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code`,
/// `pre-authorized_code=<code>`, and the optional `tx_code` from the host.
/// The request goes through the `HttpClient` port with the declared
/// `FetchPurpose::Token` and the 1 MiB size limit.
pub async fn exchange_pre_authorized_code(
    http: &dyn HttpClient,
    host: &dyn Host,
    as_metadata: &AsMetadata,
    pre_authorized_code: &str,
    tx_code_required: bool,
) -> Result<TokenResponse, TokenError> {
    // Ask the host for the tx_code when the grant requires it.
    let tx_code = if tx_code_required {
        host.request_tx_code("oid4vci-token")
            .await
            .map_err(|_| TokenError::TxCodeDeclined)?
    } else {
        String::new()
    };

    // Build the form body.
    let mut form = format!(
        "grant_type=urn%3A%2F%2Fietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code&pre_authorized_code={}",
        url_encode(pre_authorized_code),
    );
    if !tx_code.is_empty() {
        form.push_str(&format!("&tx_code={}", url_encode(&tx_code)));
    }

    // Resolve the token endpoint.
    let token_endpoint = as_metadata.token_endpoint.clone();
    if token_endpoint.is_empty() {
        return Err(TokenError::NoTokenEndpoint);
    }

    // Send the token request.
    let response = http
        .send(HttpRequest {
            method: "POST".to_owned(),
            url: token_endpoint.clone(),
            headers: vec![
                (
                    "content-type".to_owned(),
                    "application/x-www-form-urlencoded".to_owned(),
                ),
                ("accept".to_owned(), "application/json".to_owned()),
            ],
            body: form.into_bytes(),
            purpose: FetchPurpose::Token,
            max_response_bytes: MAX_TOKEN_BYTES,
            redirects: RedirectPolicy::None,
            allow_plaintext: false,
            timeout_ms: 15_000,
        })
        .await
        .map_err(|err| match err {
            HttpError::Refused => TokenError::Fetch("refused by the adapter".to_owned()),
            HttpError::Transport(detail) => TokenError::Fetch(detail),
        })?;

    if response.status != 200 {
        // The safe error code only: no raw body in the error.
        let error_code = response
            .body
            .split(|&b| b == b'"')
            .nth(3)
            .map(|s| String::from_utf8_lossy(s).to_string())
            .unwrap_or_default();
        return Err(TokenError::Status(
            response.status,
            if error_code.is_empty() {
                "unknown".to_owned()
            } else {
                error_code
            },
        ));
    }

    // Decode the token response.
    let token: TokenResponse =
        serde_json::from_slice(&response.body).map_err(|_| TokenError::NotJson)?;

    Ok(token)
}

/// Minimal URL form-encoding for the grant params.
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char);
            }
            b' ' => out.push_str("%20"),
            _ => out.push_str(&format!("%{b:02X}")),
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
            assert_eq!(request.purpose, FetchPurpose::Token);
            assert_eq!(request.max_response_bytes, MAX_TOKEN_BYTES);
            Ok(engine_ports::HttpResponse {
                status: self.status,
                headers: Vec::new(),
                body: self.body.clone(),
            })
        }
    }

    struct FakeHost {
        tx_code: String,
    }

    #[async_trait::async_trait]
    impl Host for FakeHost {
        async fn request_sign(&self, _p: SignParams) -> Result<SignResult, HostError> {
            Err(HostError::Cannot("no key in the test".to_owned()))
        }
        async fn request_match(
            &self,
            _flow_id: &str,
            _entries: Vec<engine_ports::MatchEntry>,
        ) -> Result<engine_ports::MatchResult, HostError> {
            Err(HostError::Cannot("no match in the test".to_owned()))
        }
        async fn request_consent(
            &self,
            _p: engine_ports::ConsentParams,
        ) -> Result<engine_ports::ConsentResult, HostError> {
            Err(HostError::Cannot("no consent in the test".to_owned()))
        }
        async fn request_tx_code(&self, _flow_id: &str) -> Result<String, HostError> {
            if self.tx_code.is_empty() {
                Err(HostError::Declined)
            } else {
                Ok(self.tx_code.clone())
            }
        }
        async fn open_authorization(&self, _f: &str, _u: &str) -> Result<(), HostError> {
            Ok(())
        }
        fn progress(&self, _f: &str, _s: &str, _d: Option<String>) {}
    }

    fn test_as() -> AsMetadata {
        AsMetadata {
            issuer: "https://as.example".to_owned(),
            token_endpoint: "https://as.example/token".to_owned(),
            authorization_endpoint: String::new(),
            par_endpoint: String::new(),
            require_par: false,
            code_challenge_methods: None,
            grant_types: Vec::new(),
        }
    }

    #[tokio::test]
    async fn exchanges_a_pre_authorized_code_without_tx_code() {
        let http = FakeHttp {
            status: 200,
            body: br#"{"access_token":"at-1","token_type":"Bearer"}"#.to_vec(),
        };
        let host = FakeHost {
            tx_code: String::new(),
        };
        let token = exchange_pre_authorized_code(&http, &host, &test_as(), "pre-auth-1", false)
            .await
            .expect("exchange");
        assert_eq!(token.access_token, "at-1");
        assert_eq!(token.token_type, "Bearer");
    }

    #[tokio::test]
    async fn asks_the_host_for_the_tx_code_when_required() {
        let http = FakeHttp {
            status: 200,
            body: br#"{"access_token":"at-2"}"#.to_vec(),
        };
        let host = FakeHost {
            tx_code: "1234".to_owned(),
        };
        let token = exchange_pre_authorized_code(&http, &host, &test_as(), "pre-auth-2", true)
            .await
            .expect("exchange");
        assert_eq!(token.access_token, "at-2");
    }

    #[tokio::test]
    async fn a_declined_tx_code_refuses_the_exchange() {
        let http = FakeHttp {
            status: 200,
            body: Vec::new(),
        };
        let host = FakeHost {
            tx_code: String::new(),
        };
        assert!(matches!(
            exchange_pre_authorized_code(&http, &host, &test_as(), "pre-auth-3", true).await,
            Err(TokenError::TxCodeDeclined)
        ));
    }

    #[tokio::test]
    async fn a_non_200_answer_refuses_with_the_safe_error_code() {
        let http = FakeHttp {
            status: 400,
            body: br#"{"error":"invalid_grant","error_description":"Bad code"}"#.to_vec(),
        };
        let host = FakeHost {
            tx_code: String::new(),
        };
        let err = exchange_pre_authorized_code(&http, &host, &test_as(), "bad", false)
            .await
            .expect_err("refused");
        assert!(matches!(
            err,
            TokenError::Status(400, code) if code == "invalid_grant"
        ));
    }
}
