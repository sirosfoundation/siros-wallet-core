use engine_core::oid4vci::token::*;
use engine_core::oid4vci::types::AsMetadata;
use engine_ports::{FetchPurpose, Host, HttpClient, HttpError, HttpRequest};
use engine_ports::{HostError, SignParams, SignResult};

/// The token response limit stated on `exchange_pre_authorized_code`.
const TOKEN_LIMIT: usize = 1024 * 1024;

struct FakeHttp {
    status: u16,
    body: Vec<u8>,
}

#[async_trait::async_trait]
impl HttpClient for FakeHttp {
    async fn send(&self, request: HttpRequest) -> Result<engine_ports::HttpResponse, HttpError> {
        assert_eq!(request.purpose, FetchPurpose::Token);
        assert_eq!(request.max_response_bytes, TOKEN_LIMIT);
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
        client_key_kid: None,
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
        token_endpoint_auth_methods: Vec::new(),
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
    async fn send(&self, request: HttpRequest) -> Result<engine_ports::HttpResponse, HttpError> {
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
    let key = engine_core::oid4vci::dpop::DpopKey::generate().expect("keygen");
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
            client_key_kid: None,
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
    let decoded = jose_rs::base64url::decode(payload).expect("base64url");
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
            client_key_kid: None,
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
