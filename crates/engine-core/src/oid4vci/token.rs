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
    /// The AS demanded a server-provided challenge in the Client
    /// Attestation PoP (`use_attestation_challenge`): the response
    /// headers, for the challenge resolution. The retry loop consumes
    /// this.
    #[error("oid4vci: token endpoint demanded an attestation challenge")]
    ChallengeNeeded {
        /// The rejection response's headers.
        response_headers: Vec<(String, String)>,
    },
    /// The transport failed.
    #[error("oid4vci: token exchange failed: {0}")]
    Fetch(String),
    /// The response body is not a token response.
    #[error("oid4vci: token response is not JSON")]
    NotJson,
}

/// The flow context the token exchange needs: the client identity, the
/// DPoP binding, and the entropy and time the proofs carry.
#[derive(Clone)]
pub struct TokenExchangeContext<'a> {
    /// The flow the exchange belongs to (the attestation ask).
    pub flow_id: &'a str,
    /// The device DPoP key to sign with, when the flow names one — a
    /// renewal reuses the key its refresh_token was bound to at
    /// issuance (RFC 9449 / ARF 3.0 §6.6.6.2.2).
    pub dpop_key_id: Option<&'a str>,
    /// The wallet's client_id (the form member; the attestation PoP's
    /// `iss`).
    pub client_id: &'a str,
    /// The flow's DPoP key, when there is one (the engine-held legacy
    /// mode).
    pub dpop: Option<&'a super::dpop::DpopKey>,
    /// The Rng port (the DPoP proof's `jti`).
    pub rng: &'a dyn engine_ports::Rng,
    /// The Clock port's now (the DPoP proof's `iat`).
    pub now_unix: i64,
}

/// Exchanges a pre-authorized code for an access token, asking the host
/// for the tx_code when the grant requires it.
///
/// The grant params: `grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code`,
/// `pre-authorized_code=<code>`, and the optional `tx_code` from the host.
/// The request goes through the `HttpClient` port with the declared
/// `FetchPurpose::Token` and the 1 MiB size limit.
///
/// The client-auth loop (the Go engine's `doTokenExchange`): each attempt
/// carries the host-supplied OAuth-Client-Attestation headers and a fresh
/// DPoP proof over the token endpoint. A DPoP nonce error (RFC 9449 §8)
/// captures the fresh nonce and retries; a `use_attestation_challenge`
/// rejection resolves the challenge and re-asks the host; three attempts
/// in all — the tx_code is asked once, before the loop.
pub async fn exchange_pre_authorized_code(
    http: &dyn HttpClient,
    host: &dyn Host,
    as_metadata: &AsMetadata,
    pre_authorized_code: &str,
    tx_code_required: bool,
    exchange: &TokenExchangeContext<'_>,
) -> Result<TokenResponse, TokenError> {
    // Ask the host for the tx_code when the grant requires it — once,
    // not per attempt.
    let tx_code = if tx_code_required {
        host.request_tx_code("oid4vci-token")
            .await
            .map_err(|_| TokenError::TxCodeDeclined)?
    } else {
        String::new()
    };

    if as_metadata.token_endpoint.is_empty() {
        return Err(TokenError::NoTokenEndpoint);
    }

    // Build the form body: the grant, the code, the tx_code, and the
    // client_id (some AS require it in the form even with attestation
    // in the headers).
    let mut form = format!(
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code&pre-authorized_code={}",
        url_encode(pre_authorized_code),
    );
    if !tx_code.is_empty() {
        form.push_str(&format!("&tx_code={}", url_encode(&tx_code)));
    }
    if !exchange.client_id.is_empty() {
        form.push_str(&format!("&client_id={}", url_encode(exchange.client_id)));
    }

    token_exchange_loop(http, host, as_metadata, form, exchange).await
}

/// Exchanges a refresh token (the renewal grant): the same client-auth
/// loop as every grant — the attestation headers, a fresh DPoP proof
/// per attempt, the nonce and challenge retries.
///
/// **The DPoP key is the one the refresh_token was bound to at
/// issuance** (RFC 9449 / ARF 3.0 §6.6.6.2.2): the caller's exchange
/// context names the client-held key or carries the relayed
/// engine-held key; a fresh key here would be rejected by the issuer.
pub async fn exchange_refresh_token(
    http: &dyn HttpClient,
    host: &dyn Host,
    as_metadata: &AsMetadata,
    refresh_token: &str,
    exchange: &TokenExchangeContext<'_>,
) -> Result<TokenResponse, TokenError> {
    if as_metadata.token_endpoint.is_empty() {
        return Err(TokenError::NoTokenEndpoint);
    }
    let mut form = format!(
        "grant_type=refresh_token&refresh_token={}",
        url_encode(refresh_token),
    );
    if !exchange.client_id.is_empty() {
        form.push_str(&format!("&client_id={}", url_encode(exchange.client_id)));
    }
    token_exchange_loop(http, host, as_metadata, form, exchange).await
}

/// The shared token-endpoint loop: the client-auth state (the
/// attestation the host supplied, the server's DPoP nonce once it
/// demands one), three attempts, the tx_code already in the form.
async fn token_exchange_loop(
    http: &dyn HttpClient,
    host: &dyn Host,
    as_metadata: &AsMetadata,
    form: String,
    exchange: &TokenExchangeContext<'_>,
) -> Result<TokenResponse, TokenError> {
    // Resolve the token endpoint.
    let token_endpoint = as_metadata.token_endpoint.clone();
    if token_endpoint.is_empty() {
        return Err(TokenError::NoTokenEndpoint);
    }
    let mut attestation = super::attestation::request_client_attestation(
        host,
        exchange.flow_id,
        &as_metadata.issuer,
        exchange.client_id,
        "",
    )
    .await;
    let mut dpop_nonce: Option<String> = None;

    for attempt in 0..3 {
        // The headers: the attestation pair, and a fresh DPoP proof
        // per attempt (a new `jti`, the current nonce).
        let mut headers: Vec<(String, String)> = vec![
            (
                "content-type".to_owned(),
                "application/x-www-form-urlencoded".to_owned(),
            ),
            ("accept".to_owned(), "application/json".to_owned()),
        ];
        headers.extend(super::attestation::attestation_headers(
            attestation.as_ref(),
        ));
        if let Some(proof) = super::dpop::proof_for(
            host,
            exchange.dpop,
            super::dpop::ProofRequest {
                flow_id: exchange.flow_id,
                key_id: exchange.dpop_key_id,
                htm: "POST",
                htu: &token_endpoint,
                access_token: None,
                nonce: dpop_nonce.as_deref(),
                rng: exchange.rng,
                now_unix: exchange.now_unix,
            },
        )
        .await
        {
            headers.push(("DPoP".to_owned(), proof));
        }

        let response = http
            .send(HttpRequest {
                method: "POST".to_owned(),
                url: token_endpoint.clone(),
                headers,
                body: form.clone().into_bytes(),
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

        if response.status == 200 {
            // Decode the token response.
            let token: TokenResponse =
                serde_json::from_slice(&response.body).map_err(|_| TokenError::NotJson)?;
            return Ok(token);
        }

        // The DPoP nonce demand (RFC 9449 §8): capture the fresh nonce
        // and retry with a new proof.
        if super::dpop::is_dpop_nonce_error(&response) && attempt < 2 {
            dpop_nonce = super::dpop::dpop_nonce_from_response(&response);
            continue;
        }

        // The attestation challenge demand: resolve the fresh
        // challenge and re-ask the host for a PoP bound to it.
        if super::attestation::is_attestation_challenge_error(response.status, &response.body)
            && attempt < 2
        {
            if let Some(challenge) =
                super::attestation::resolve_challenge(http, as_metadata, &response.headers).await
            {
                attestation = super::attestation::request_client_attestation(
                    host,
                    exchange.flow_id,
                    &as_metadata.issuer,
                    exchange.client_id,
                    &challenge,
                )
                .await;
                continue;
            }
        }

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

    Err(TokenError::Fetch(
        "token exchange attempts exhausted".to_owned(),
    ))
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
            _params: engine_ports::MatchParams,
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

    struct FakeRng;
    impl engine_ports::Rng for FakeRng {
        fn fill(&self, buf: &mut [u8]) -> bool {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = i as u8;
            }
            true
        }
    }

    /// The exchange context with no DPoP key (the unauthenticated shape
    /// the existing tests run).
    fn plain_exchange() -> TokenExchangeContext<'static> {
        static FAKE_RNG: FakeRng = FakeRng;
        TokenExchangeContext {
            flow_id: "flow-1",
            dpop_key_id: None,
            client_id: "client-1",
            dpop: None,
            rng: &FAKE_RNG,
            now_unix: 1_000,
        }
    }

    fn test_as() -> AsMetadata {
        AsMetadata {
            issuer: "https://as.example".to_owned(),
            token_endpoint: "https://as.example/token".to_owned(),
            authorization_endpoint: String::new(),
            par_endpoint: String::new(),
            require_par: false,
            challenge_endpoint: String::new(),
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
        let token = exchange_pre_authorized_code(
            &http,
            &host,
            &test_as(),
            "pre-auth-1",
            false,
            &plain_exchange(),
        )
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
        let token = exchange_pre_authorized_code(
            &http,
            &host,
            &test_as(),
            "pre-auth-2",
            true,
            &plain_exchange(),
        )
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
            exchange_pre_authorized_code(
                &http,
                &host,
                &test_as(),
                "pre-auth-3",
                true,
                &plain_exchange()
            )
            .await,
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
        let err =
            exchange_pre_authorized_code(&http, &host, &test_as(), "bad", false, &plain_exchange())
                .await
                .expect_err("refused");
        assert!(matches!(
            err,
            TokenError::Status(400, code) if code == "invalid_grant"
        ));
    }

    /// A sequenced HTTP: scripted answers per URL, recording requests.
    struct SequencedHttp {
        answers: std::sync::Mutex<Vec<engine_ports::HttpResponse>>,
        seen: std::sync::Mutex<Vec<HttpRequest>>,
    }

    impl SequencedHttp {
        fn new(answers: Vec<engine_ports::HttpResponse>) -> Self {
            Self {
                answers: std::sync::Mutex::new(answers),
                seen: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl HttpClient for SequencedHttp {
        async fn send(
            &self,
            request: HttpRequest,
        ) -> Result<engine_ports::HttpResponse, HttpError> {
            self.seen.lock().map(|mut s| s.push(request.clone())).ok();
            let answer = self.answers.lock().ok().and_then(|mut a| {
                if a.is_empty() {
                    None
                } else {
                    Some(a.remove(0))
                }
            });
            Ok(answer.unwrap_or(engine_ports::HttpResponse {
                status: 404,
                headers: Vec::new(),
                body: Vec::new(),
            }))
        }
    }

    #[tokio::test]
    async fn the_pre_auth_exchange_carries_dpop_and_retries_the_nonce() {
        let key = super::super::dpop::DpopKey::generate().expect("keygen");
        let http = SequencedHttp::new(vec![
            // The DPoP nonce demand (RFC 9449 §8).
            engine_ports::HttpResponse {
                status: 400,
                headers: vec![("DPoP-Nonce".to_owned(), "fresh-nonce".to_owned())],
                body: Vec::new(),
            },
            // The retry answers a DPoP-bound token.
            engine_ports::HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: br#"{"access_token":"at-1","token_type":"DPoP"}"#.to_vec(),
            },
        ]);
        let host = FakeHost {
            tx_code: String::new(),
        };
        let token = exchange_pre_authorized_code(
            &http,
            &host,
            &test_as(),
            "pre-auth-1",
            false,
            &TokenExchangeContext {
                flow_id: "flow-1",
                dpop_key_id: None,
                client_id: "client-1",
                dpop: Some(&key),
                rng: &FakeRng,
                now_unix: 1_000,
            },
        )
        .await
        .expect("exchange");
        assert_eq!(token.token_type, "DPoP");

        let seen = http.seen.lock().expect("lock");
        assert_eq!(seen.len(), 2);
        // Both attempts carried a DPoP proof; the retry's proof carries
        // the fresh nonce.
        let first = seen[0].headers.iter().find(|(n, _)| n == "DPoP");
        let second = seen[1].headers.iter().find(|(n, _)| n == "DPoP");
        assert!(first.is_some() && second.is_some());
        // The form carried the client_id.
        let body = String::from_utf8_lossy(&seen[1].body).into_owned();
        assert!(body.contains("client_id=client-1"));

        // The retry's proof: decode the nonce claim.
        let proof = second.expect("dpop header").1.clone();
        let payload = proof.split('.').nth(1).unwrap_or_default();
        let decoded = crate::oid4vp::test_util::base64url_decode(payload.as_bytes());
        let claims: serde_json::Value = serde_json::from_slice(&decoded).expect("claims");
        assert_eq!(claims["nonce"], "fresh-nonce");
    }

    /// A host whose device-held key signs DPoP proofs on demand — the
    /// target design (go-wallet-backend#317).
    struct ClientHeldDpopHost {
        tx_code: String,
        proofs: std::sync::Mutex<Vec<engine_ports::DpopProofParams>>,
    }

    #[async_trait::async_trait]
    impl Host for ClientHeldDpopHost {
        async fn request_sign(&self, _p: SignParams) -> Result<SignResult, HostError> {
            Err(HostError::Cannot("no plain sign".to_owned()))
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
            Ok(self.tx_code.clone())
        }
        async fn open_authorization(&self, _f: &str, _u: &str) -> Result<(), HostError> {
            Ok(())
        }
        fn progress(&self, _f: &str, _s: &str, _d: Option<String>) {}

        async fn request_dpop_proof(
            &self,
            params: engine_ports::DpopProofParams,
        ) -> Result<engine_ports::DpopProofResult, HostError> {
            self.proofs.lock().map(|mut p| p.push(params)).ok();
            Ok(engine_ports::DpopProofResult {
                proof: "client-held-proof".to_owned(),
            })
        }
    }

    #[tokio::test]
    async fn the_client_held_dpop_proof_is_preferred() {
        // The host signs the whole proof with the device's key; the
        // engine never needs its own.
        let host = ClientHeldDpopHost {
            tx_code: String::new(),
            proofs: std::sync::Mutex::new(Vec::new()),
        };
        let http = SequencedHttp::new(vec![engine_ports::HttpResponse {
            status: 200,
            headers: Vec::new(),
            body: br#"{"access_token":"at-1","token_type":"Bearer"}"#.to_vec(),
        }]);
        let token = exchange_pre_authorized_code(
            &http,
            &host,
            &test_as(),
            "pre-auth-1",
            false,
            &TokenExchangeContext {
                flow_id: "flow-1",
                dpop_key_id: None,
                client_id: "client-1",
                dpop: None, // no engine-held fallback
                rng: &FakeRng,
                now_unix: 1_000,
            },
        )
        .await
        .expect("exchange");
        assert_eq!(token.access_token, "at-1");

        // The host was asked once, and its proof is the header.
        let proofs = host.proofs.lock().expect("lock");
        assert_eq!(proofs.len(), 1);
        assert_eq!(proofs[0].htu, "https://as.example/token");
        let seen = http.seen.lock().expect("lock");
        let dpop = seen[0]
            .headers
            .iter()
            .find(|(n, _)| n == "DPoP")
            .map(|(_, v)| v.clone());
        assert_eq!(dpop.as_deref(), Some("client-held-proof"));
    }
}
