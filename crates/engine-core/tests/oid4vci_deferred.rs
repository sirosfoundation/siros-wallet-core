use engine_core::oid4vci::deferred::*;
use engine_core::oid4vci::token::TokenResponse;
use engine_core::oid4vci::types::IssuerMetadata;
use engine_ports::{Clock, FetchPurpose, Host, HttpClient, HttpError, HttpRequest};

struct FakeHttp {
    status: u16,
    body: Vec<u8>,
    calls: std::sync::Mutex<usize>,
}

impl FakeHttp {
    fn credential_ready() -> Self {
        Self {
            status: 200,
            body: br#"{"credential":"jwt-credential"}"#.to_vec(),
            calls: std::sync::Mutex::new(0),
        }
    }

    fn pending() -> Self {
        Self {
            status: 202,
            body: Vec::new(),
            calls: std::sync::Mutex::new(0),
        }
    }
}

#[async_trait::async_trait]
impl HttpClient for FakeHttp {
    async fn send(&self, _r: HttpRequest) -> Result<engine_ports::HttpResponse, HttpError> {
        let _ = self.calls.lock().map(|mut c| *c += 1);
        assert_eq!(_r.purpose, FetchPurpose::Deferred);
        Ok(engine_ports::HttpResponse {
            status: self.status,
            headers: Vec::new(),
            body: self.body.clone(),
        })
    }
}

struct InstantClock;

#[async_trait::async_trait]
impl Clock for InstantClock {
    fn now_unix(&self) -> i64 {
        0
    }
    async fn sleep(&self, _duration_ms: u64) {}
}

fn test_metadata() -> IssuerMetadata {
    IssuerMetadata {
        nonce_endpoint: None,
        deferred_credential_endpoint: None,
        credential_endpoint: String::new(),
        token_endpoint: String::new(),
        notification_endpoint: String::new(),
        credential_issuer: "https://issuer.example".to_owned(),
        authorization_servers: Vec::new(),
        credential_configurations: serde_json::json!({}),
        signed_metadata: None,
        is_signed: false,
        raw: Vec::new(),
    }
}

fn test_token() -> TokenResponse {
    TokenResponse {
        access_token: "at-deferred".to_owned(),
        token_type: "Bearer".to_owned(),
        expires_in: Some(3600),
        refresh_token: None,
        c_nonce: None,
        nonce: None,
        authorization_details: None,
        dpop_nonce: None,
    }
}

/// A refusing host: the deferred tests poll with Bearer tokens, so
/// no sub-flow ask is ever answered.
struct TestHost;

#[async_trait::async_trait]
impl Host for TestHost {
    async fn request_sign(
        &self,
        _p: engine_ports::SignParams,
    ) -> Result<engine_ports::SignResult, engine_ports::HostError> {
        Err(engine_ports::HostError::Cannot(
            "no keys in the test".to_owned(),
        ))
    }
    async fn request_match(
        &self,
        _p: engine_ports::MatchParams,
    ) -> Result<engine_ports::MatchResult, engine_ports::HostError> {
        Err(engine_ports::HostError::Cannot(
            "no match in the test".to_owned(),
        ))
    }
    async fn request_consent(
        &self,
        _p: engine_ports::ConsentParams,
    ) -> Result<engine_ports::ConsentResult, engine_ports::HostError> {
        Err(engine_ports::HostError::Cannot(
            "no consent in the test".to_owned(),
        ))
    }
    async fn request_tx_code(&self, _f: &str) -> Result<String, engine_ports::HostError> {
        Err(engine_ports::HostError::Cannot(
            "no tx code in the test".to_owned(),
        ))
    }
    async fn open_authorization(&self, _f: &str, _u: &str) -> Result<(), engine_ports::HostError> {
        Ok(())
    }
    fn progress(&self, _f: &str, _s: &str, _d: Option<String>) {}
}

#[tokio::test]
async fn polls_until_the_credential_is_ready() {
    let http = FakeHttp::credential_ready();
    let result = poll_deferred_credential(
        &http,
        &TestHost,
        &InstantClock,
        &test_metadata(),
        &test_token(),
        None,
        "tx-1",
        Some(1),
        &|_| {},
    )
    .await
    .expect("credential");
    assert!(result.credential.is_some());
    assert_eq!(*http.calls.lock().expect("lock"), 1);
}

#[tokio::test]
async fn times_out_after_the_max_attempts() {
    let http = FakeHttp::pending();
    let err = poll_deferred_credential(
        &http,
        &TestHost,
        &InstantClock,
        &test_metadata(),
        &test_token(),
        None,
        "tx-2",
        Some(1),
        &|_| {},
    )
    .await
    .expect_err("timeout");
    assert!(matches!(err, DeferredError::Timeout(60)));
    assert_eq!(*http.calls.lock().expect("lock"), 60);
}

#[tokio::test]
async fn a_non_200_non_202_is_terminal() {
    let http = FakeHttp {
        status: 404,
        body: Vec::new(),
        calls: std::sync::Mutex::new(0),
    };
    assert!(matches!(
        poll_deferred_credential(
            &http,
            &TestHost,
            &InstantClock,
            &test_metadata(),
            &test_token(),
            None,
            "tx-3",
            Some(1),
            &|_| {},
        )
        .await,
        Err(DeferredError::Status(404))
    ));
}
