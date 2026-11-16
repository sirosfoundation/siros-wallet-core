use engine_core::oid4vci::nonce::*;
use engine_ports::HttpError;
use engine_ports::{FetchPurpose, Host, HttpClient, HttpRequest};

/// The test host: answers nothing beyond the sign asks the nonce
/// path never makes when no DPoP binding rides the aux.
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

struct FakeHttp {
    status: u16,
    body: Vec<u8>,
}

#[async_trait::async_trait]
impl HttpClient for FakeHttp {
    async fn send(&self, request: HttpRequest) -> Result<engine_ports::HttpResponse, HttpError> {
        assert_eq!(request.purpose, FetchPurpose::Nonce);
        Ok(engine_ports::HttpResponse {
            status: self.status,
            headers: Vec::new(),
            body: self.body.clone(),
        })
    }
}

#[tokio::test]
async fn an_invalid_nonce_from_the_endpoint_retries() {
    let http = FakeHttp {
        status: 200,
        body: br#"{"nonce":"fresh-1"}"#.to_vec(),
    };
    let response = br#"{"error":"invalid_nonce"}"#;
    let outcome = handle_invalid_nonce(
        &http,
        &TestHost,
        response,
        Some("https://i.example/nonce"),
        false,
    )
    .await
    .expect("handle");
    assert_eq!(outcome, NonceOutcome::RetryWith("fresh-1".to_owned()));
}

#[tokio::test]
async fn the_c_nonce_fallback_when_no_endpoint() {
    let http = FakeHttp {
        status: 500,
        body: Vec::new(),
    };
    let response = br#"{"error":"invalid_nonce","c_nonce":"c-1"}"#;
    let outcome = handle_invalid_nonce(&http, &TestHost, response, None, false)
        .await
        .expect("handle");
    assert_eq!(outcome, NonceOutcome::RetryWith("c-1".to_owned()));
}

#[tokio::test]
async fn terminal_after_the_retry() {
    let http = FakeHttp {
        status: 200,
        body: b"{}".to_vec(),
    };
    let response = br#"{"error":"invalid_nonce","c_nonce":"c-1"}"#;
    let outcome = handle_invalid_nonce(
        &http,
        &TestHost,
        response,
        Some("https://i.example/nonce"),
        true,
    )
    .await
    .expect("handle");
    assert!(matches!(
        outcome,
        NonceOutcome::Terminal(NonceError::Terminal)
    ));
}

#[tokio::test]
async fn a_non_error_response_needs_no_retry() {
    let http = FakeHttp {
        status: 200,
        body: Vec::new(),
    };
    let response = br#"{"credential":"jwt"}"#;
    let outcome = handle_invalid_nonce(&http, &TestHost, response, None, false)
        .await
        .expect("handle");
    assert_eq!(outcome, NonceOutcome::NoRetry);
}

#[tokio::test]
async fn no_source_available_is_terminal() {
    let http = FakeHttp {
        status: 500,
        body: Vec::new(),
    };
    let response = br#"{"error":"invalid_nonce"}"#;
    let outcome = handle_invalid_nonce(&http, &TestHost, response, None, false)
        .await
        .expect("handle");
    assert!(matches!(
        outcome,
        NonceOutcome::Terminal(NonceError::NoSource)
    ));
}
