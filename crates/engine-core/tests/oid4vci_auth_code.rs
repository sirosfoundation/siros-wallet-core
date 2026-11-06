use engine_core::oid4vci::auth_code::*;
use engine_core::oid4vci::token::TokenError;
use engine_core::oid4vci::types::AsMetadata;
use engine_ports::HttpResponse;
use engine_ports::{HttpClient, HttpError, HttpRequest, Rng};

struct FakeRng;
impl Rng for FakeRng {
    fn fill(&self, buf: &mut [u8]) -> bool {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(7);
        }
        true
    }
}

struct FailingRng;
impl Rng for FailingRng {
    fn fill(&self, _buf: &mut [u8]) -> bool {
        false
    }
}

struct FakeHttp {
    status: u16,
    body: Vec<u8>,
    requests: std::sync::Mutex<Vec<HttpRequest>>,
}

#[async_trait::async_trait]
impl HttpClient for FakeHttp {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, HttpError> {
        self.requests.lock().map(|mut r| r.push(request)).ok();
        Ok(HttpResponse {
            status: self.status,
            headers: Vec::new(),
            body: self.body.clone(),
        })
    }
}

fn test_as() -> AsMetadata {
    AsMetadata {
        issuer: "https://as.example".to_owned(),
        token_endpoint: "https://as.example/token".to_owned(),
        authorization_endpoint: "https://as.example/authorize".to_owned(),
        par_endpoint: "https://as.example/par".to_owned(),
        token_endpoint_auth_methods: Vec::new(),
        require_par: false,
        challenge_endpoint: String::new(),
        code_challenge_methods: None,
        grant_types: vec!["authorization_code".to_owned()],
    }
}

// ─── client attestation ──────────────────────────────────────────

struct TestRng;
impl engine_ports::Rng for TestRng {
    fn fill(&self, buf: &mut [u8]) -> bool {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = i as u8;
        }
        true
    }
}

/// A host that supplies the (WIA, PoP) pair and records the
/// challenges it was asked to bind.
struct AttestingHost {
    challenges: std::sync::Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl engine_ports::Host for AttestingHost {
    async fn request_sign(
        &self,
        _p: engine_ports::SignParams,
    ) -> Result<engine_ports::SignResult, engine_ports::HostError> {
        Err(engine_ports::HostError::Cannot("no sign".to_owned()))
    }
    async fn request_match(
        &self,
        _params: engine_ports::MatchParams,
    ) -> Result<engine_ports::MatchResult, engine_ports::HostError> {
        Err(engine_ports::HostError::Cannot("no match".to_owned()))
    }
    async fn request_consent(
        &self,
        _p: engine_ports::ConsentParams,
    ) -> Result<engine_ports::ConsentResult, engine_ports::HostError> {
        Err(engine_ports::HostError::Cannot("no consent".to_owned()))
    }
    async fn request_tx_code(&self, _f: &str) -> Result<String, engine_ports::HostError> {
        Err(engine_ports::HostError::Cannot("no tx code".to_owned()))
    }
    async fn open_authorization(&self, _f: &str, _u: &str) -> Result<(), engine_ports::HostError> {
        Ok(())
    }
    fn progress(&self, _f: &str, _s: &str, _d: Option<String>) {}

    async fn request_attestation(
        &self,
        params: engine_ports::AttestationParams,
    ) -> Result<engine_ports::AttestationResult, engine_ports::HostError> {
        self.challenges
            .lock()
            .map(|mut c| c.push(params.challenge.clone()))
            .ok();
        Ok(engine_ports::AttestationResult {
            wia: "wia-jwt".to_owned(),
            pop: format!("pop-for-{}", params.challenge),
        })
    }
}

/// An HTTP fake with a scripted answer sequence per URL.
struct SequencedHttp {
    answers: std::sync::Mutex<Vec<(String, HttpResponse)>>,
    seen: std::sync::Mutex<Vec<HttpRequest>>,
}

impl SequencedHttp {
    fn new(answers: Vec<(String, HttpResponse)>) -> Self {
        Self {
            answers: std::sync::Mutex::new(answers),
            seen: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn take_answer(&self, url: &str) -> Option<HttpResponse> {
        let mut answers = self.answers.lock().ok()?;
        let index = answers.iter().position(|(u, _)| u == url)?;
        Some(answers.remove(index).1)
    }
}

#[async_trait::async_trait]
impl HttpClient for SequencedHttp {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, HttpError> {
        self.seen.lock().map(|mut s| s.push(request.clone())).ok();
        match self.take_answer(&request.url) {
            Some(response) => Ok(response),
            None => Ok(HttpResponse {
                status: 404,
                headers: Vec::new(),
                body: Vec::new(),
            }),
        }
    }
}

#[tokio::test]
async fn the_par_push_carries_the_attestation_headers() {
    let http = SequencedHttp::new(vec![(
        "https://as.example/par".to_owned(),
        HttpResponse {
            status: 201,
            headers: Vec::new(),
            body: br#"{"request_uri":"urn:par:1"}"#.to_vec(),
        },
    )]);
    let host = AttestingHost {
        challenges: std::sync::Mutex::new(Vec::new()),
    };
    let uri = push_authorization_request_with_attestation(
        &http,
        &host,
        &test_as(),
        &ParPushSpec {
            flow_id: "flow-1",
            client_id: "client-1",
            client_key_kid: None,
            rng: &TestRng,
            now_unix: 1_000,
        },
        &[("response_type".to_owned(), "code".to_owned())],
    )
    .await
    .expect("push");
    assert_eq!(uri, "urn:par:1");

    // The attestation pair arrived as the two headers.
    let seen = http.seen.lock().expect("lock");
    assert_eq!(seen.len(), 1);
    let attestation = seen[0]
        .headers
        .iter()
        .find(|(name, _)| name == "OAuth-Client-Attestation")
        .map(|(_, value)| value.clone());
    let pop = seen[0]
        .headers
        .iter()
        .find(|(name, _)| name == "OAuth-Client-Attestation-PoP")
        .map(|(_, value)| value.clone());
    assert_eq!(attestation.as_deref(), Some("wia-jwt"));
    assert_eq!(pop.as_deref(), Some("pop-for-"));

    // The host was asked once, unchallenged.
    let challenges = host.challenges.lock().expect("lock");
    assert_eq!(challenges.len(), 1);
}

/// A host that signs and records the key ids it was asked for.
struct SigningHost {
    key_ids: std::sync::Mutex<Vec<Option<String>>>,
}

#[async_trait::async_trait]
impl engine_ports::Host for SigningHost {
    async fn request_sign(
        &self,
        p: engine_ports::SignParams,
    ) -> Result<engine_ports::SignResult, engine_ports::HostError> {
        self.key_ids
            .lock()
            .map(|mut ids| ids.push(p.key_id))
            .map_err(|_| engine_ports::HostError::Cannot("lock".to_owned()))?;
        Ok(engine_ports::SignResult {
            signature: vec![1, 2, 3, 4],
        })
    }
    async fn request_match(
        &self,
        _params: engine_ports::MatchParams,
    ) -> Result<engine_ports::MatchResult, engine_ports::HostError> {
        Err(engine_ports::HostError::Cannot("no match".to_owned()))
    }
    async fn request_consent(
        &self,
        _p: engine_ports::ConsentParams,
    ) -> Result<engine_ports::ConsentResult, engine_ports::HostError> {
        Err(engine_ports::HostError::Cannot("no consent".to_owned()))
    }
    async fn request_tx_code(&self, _f: &str) -> Result<String, engine_ports::HostError> {
        Err(engine_ports::HostError::Cannot("no tx code".to_owned()))
    }
    async fn open_authorization(&self, _f: &str, _u: &str) -> Result<(), engine_ports::HostError> {
        Ok(())
    }
    fn progress(&self, _f: &str, _s: &str, _d: Option<String>) {}
}

#[tokio::test]
async fn the_par_push_carries_the_private_key_jwt_assertion_with_the_registered_kid() {
    // The AS names the method: the pushed request authenticates the
    // client with the RFC 7523 assertion, signed with the registered
    // kid (RFC 9126 §2.1 — the client authentication rides the pushed
    // parameters beside the authorization ones).
    let mut as_metadata = test_as();
    as_metadata.token_endpoint_auth_methods = vec!["private_key_jwt".to_owned()];
    let http = SequencedHttp::new(vec![(
        "https://as.example/par".to_owned(),
        HttpResponse {
            status: 201,
            headers: Vec::new(),
            body: br#"{"request_uri":"urn:par:1"}"#.to_vec(),
        },
    )]);
    let host = SigningHost {
        key_ids: std::sync::Mutex::new(Vec::new()),
    };
    let uri = push_authorization_request_with_attestation(
        &http,
        &host,
        &as_metadata,
        &ParPushSpec {
            flow_id: "flow-1",
            client_id: "client-1",
            client_key_kid: Some("client-key-1"),
            rng: &TestRng,
            now_unix: 1_000,
        },
        &[("response_type".to_owned(), "code".to_owned())],
    )
    .await
    .expect("push");
    assert_eq!(uri, "urn:par:1");

    // The pushed form carries the assertion's type and value.
    let seen = http.seen.lock().expect("lock");
    assert_eq!(seen.len(), 1);
    let form = String::from_utf8_lossy(&seen[0].body).into_owned();
    assert!(form.contains(
        "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer"
    ));
    assert!(form.contains("client_assertion="));

    // The assertion's sign ask named the registered kid.
    let key_ids = host.key_ids.lock().expect("lock");
    assert!(
        key_ids
            .iter()
            .any(|id| id.as_deref() == Some("client-key-1")),
        "the sign asks carried the registered kid: {key_ids:?}"
    );
}

#[tokio::test]
async fn a_par_attestation_challenge_retries_once_with_the_fresh_challenge() {
    let http = SequencedHttp::new(vec![
        (
            "https://as.example/par".to_owned(),
            HttpResponse {
                status: 400,
                headers: vec![(
                    "OAuth-Client-Attestation-Challenge".to_owned(),
                    "challenge-1".to_owned(),
                )],
                body: br#"{"error":"use_attestation_challenge"}"#.to_vec(),
            },
        ),
        (
            "https://as.example/par".to_owned(),
            HttpResponse {
                status: 201,
                headers: Vec::new(),
                body: br#"{"request_uri":"urn:par:2"}"#.to_vec(),
            },
        ),
    ]);
    let host = AttestingHost {
        challenges: std::sync::Mutex::new(Vec::new()),
    };
    let uri = push_authorization_request_with_attestation(
        &http,
        &host,
        &test_as(),
        &ParPushSpec {
            flow_id: "flow-1",
            client_id: "client-1",
            client_key_kid: None,
            rng: &TestRng,
            now_unix: 1_000,
        },
        &[],
    )
    .await
    .expect("push after the challenge");
    assert_eq!(uri, "urn:par:2");

    // The host was asked twice: unchallenged, then with the fresh
    // challenge from the response header.
    let challenges = host.challenges.lock().expect("lock");
    assert_eq!(*challenges, vec![String::new(), "challenge-1".to_owned()]);

    // The retry's PoP was bound to the challenge.
    let seen = http.seen.lock().expect("lock");
    let pop = seen[1]
        .headers
        .iter()
        .find(|(name, _)| name == "OAuth-Client-Attestation-PoP")
        .map(|(_, value)| value.clone());
    assert_eq!(pop.as_deref(), Some("pop-for-challenge-1"));
}

#[tokio::test]
async fn the_par_challenge_retry_happens_once() {
    let challenge = HttpResponse {
        status: 400,
        headers: vec![(
            "OAuth-Client-Attestation-Challenge".to_owned(),
            "challenge-1".to_owned(),
        )],
        body: br#"{"error":"use_attestation_challenge"}"#.to_vec(),
    };
    let http = SequencedHttp::new(vec![
        ("https://as.example/par".to_owned(), challenge.clone()),
        ("https://as.example/par".to_owned(), challenge),
    ]);
    let host = AttestingHost {
        challenges: std::sync::Mutex::new(Vec::new()),
    };
    assert!(push_authorization_request_with_attestation(
        &http,
        &host,
        &test_as(),
        &ParPushSpec {
            flow_id: "flow-1",
            client_id: "client-1",
            client_key_kid: None,
            rng: &TestRng,
            now_unix: 1_000,
        },
        &[],
    )
    .await
    .is_err());
    // Two pushes, two host asks — not more.
    let challenges = host.challenges.lock().expect("lock");
    assert_eq!(challenges.len(), 2);
}

#[tokio::test]
async fn the_code_exchange_carries_the_attestation_and_retries_the_challenge() {
    let http = SequencedHttp::new(vec![
        (
            "https://as.example/token".to_owned(),
            HttpResponse {
                status: 401,
                headers: vec![(
                    "OAuth-Client-Attestation-Challenge".to_owned(),
                    "challenge-1".to_owned(),
                )],
                body: br#"{"error":"use_attestation_challenge"}"#.to_vec(),
            },
        ),
        (
            "https://as.example/token".to_owned(),
            HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: br#"{"access_token":"at-1","token_type":"Bearer"}"#.to_vec(),
            },
        ),
    ]);
    let host = AttestingHost {
        challenges: std::sync::Mutex::new(Vec::new()),
    };
    let token = exchange_authorization_code_with_attestation(
        &http,
        &host,
        &test_as(),
        &CodeExchangeSpec {
            flow_id: "flow-1",
            dpop_key_id: None,
            client_key_kid: None,
            client_id: "client-1",
            code: "code-1",
            redirect_uri: "https://wallet.example/cb",
            code_verifier: "verifier-1",
            resource: None,
            dpop: None,
            rng: &TestRng,
            now_unix: 1_000,
        },
    )
    .await
    .expect("exchange");
    assert_eq!(token.access_token, "at-1");

    let challenges = host.challenges.lock().expect("lock");
    assert_eq!(*challenges, vec![String::new(), "challenge-1".to_owned()]);
}

// ─── PKCE ─────────────────────────────────────────────────────────

#[test]
fn the_verifier_is_43_unreserved_characters() {
    let pkce = PkcePair::generate(&FakeRng).expect("generate");
    assert_eq!(pkce.code_verifier.len(), 43);
    assert!(pkce
        .code_verifier
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
}

#[test]
fn the_challenge_is_the_s256_of_the_verifier() {
    let pkce = PkcePair::generate(&FakeRng).expect("generate");
    assert_eq!(pkce.code_challenge, s256_challenge(&pkce.code_verifier));
    // RFC 7636's own test vector (appendix B): the deterministic
    // verifier and its challenge.
    assert_eq!(
        s256_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
}

#[test]
fn an_rng_that_cannot_fill_refuses() {
    assert!(PkcePair::generate(&FailingRng).is_none());
    assert!(generate_state(&FailingRng).is_none());
}

#[test]
fn pkce_support_follows_the_declaration() {
    // Absent: assume S256 (the OID4VCI default).
    assert!(test_as().supports_pkce_s256());
    // An explicit list naming S256.
    let mut as_meta = test_as();
    as_meta.code_challenge_methods = Some(vec!["S256".to_owned(), "plain".to_owned()]);
    assert!(as_meta.supports_pkce_s256());
    // An explicit list without S256: no PKCE.
    as_meta.code_challenge_methods = Some(vec!["plain".to_owned()]);
    assert!(!as_meta.supports_pkce_s256());
    // An explicitly empty list: no PKCE.
    as_meta.code_challenge_methods = Some(Vec::new());
    assert!(!as_meta.supports_pkce_s256());
}

// ─── PAR ──────────────────────────────────────────────────────────

#[tokio::test]
async fn par_posts_the_parameters_and_takes_the_request_uri() {
    let http = FakeHttp {
        status: 201,
        body: br#"{"request_uri":"urn:ietf:params:oauth:request_uri:abc","expires_in":90}"#
            .to_vec(),
        requests: std::sync::Mutex::new(Vec::new()),
    };
    let params = vec![
        ("response_type".to_owned(), "code".to_owned()),
        ("scope".to_owned(), "openid".to_owned()),
    ];
    let uri = push_authorization_request(&http, "https://as.example/par", &params)
        .await
        .expect("push");
    assert_eq!(uri, "urn:ietf:params:oauth:request_uri:abc");

    let requests = http.requests.lock().expect("lock");
    let body = String::from_utf8_lossy(&requests[0].body).into_owned();
    assert!(body.contains("response_type=code"));
    assert!(body.contains("scope=openid"));
    assert_eq!(requests[0].url, "https://as.example/par");
}

#[tokio::test]
async fn a_par_error_carries_the_as_error_code() {
    let http = FakeHttp {
        status: 400,
        body: br#"{"error":"invalid_client","error_description":"unknown client"}"#.to_vec(),
        requests: std::sync::Mutex::new(Vec::new()),
    };
    let err = push_authorization_request(&http, "https://as.example/par", &[])
        .await
        .expect_err("refuses");
    assert!(matches!(err, ParError::Status { status: 400, .. }));
}

#[tokio::test]
async fn a_par_response_without_a_request_uri_refuses() {
    let http = FakeHttp {
        status: 200,
        body: br#"{}"#.to_vec(),
        requests: std::sync::Mutex::new(Vec::new()),
    };
    assert!(matches!(
        push_authorization_request(&http, "https://as.example/par", &[]).await,
        Err(ParError::NoRequestUri)
    ));
}

// ─── the authorization URL ────────────────────────────────────────

#[test]
fn the_par_url_carries_only_client_id_and_request_uri() {
    let url = build_authorization_url(
        "https://as.example/authorize?tenant=x",
        "client-1",
        &[("scope".to_owned(), "openid".to_owned())],
        Some("urn:ietf:params:oauth:request_uri:abc"),
    );
    // The fixed tenant parameter is preserved; nothing else leaks.
    assert_eq!(
        url,
        "https://as.example/authorize?tenant=x&client_id=client-1&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Aabc"
    );
}

#[test]
fn the_plain_url_carries_all_parameters_and_preserves_the_fixed_ones() {
    let url = build_authorization_url(
        "https://as.example/authorize?tenant=x",
        "client-1",
        &[
            ("response_type".to_owned(), "code".to_owned()),
            ("scope".to_owned(), "openid".to_owned()),
        ],
        None,
    );
    assert!(url.contains("tenant=x"));
    assert!(url.contains("response_type=code"));
    assert!(url.contains("scope=openid"));
    assert!(url.contains("client_id=client-1"));
}

#[test]
fn an_appended_parameter_overrides_a_fixed_one() {
    let url = build_authorization_url(
        "https://as.example/authorize?client_id=fixed",
        "client-1",
        &[],
        None,
    );
    // client_id is set, not duplicated.
    assert!(url.contains("client_id=client-1"));
    assert!(!url.contains("client_id=fixed"));
}

// ─── the exchange ─────────────────────────────────────────────────

#[tokio::test]
async fn the_code_exchanges_with_the_verifier_and_resource() {
    let http = FakeHttp {
        status: 200,
        body: br#"{"access_token":"at-1","token_type":"Bearer","expires_in":3600}"#.to_vec(),
        requests: std::sync::Mutex::new(Vec::new()),
    };
    let token = exchange_authorization_code(
        &http,
        &test_as(),
        "code-1",
        "https://wallet.example/cb",
        "verifier-1",
        Some("https://issuer.example"),
    )
    .await
    .expect("exchange");
    assert_eq!(token.access_token, "at-1");

    let requests = http.requests.lock().expect("lock");
    let body = String::from_utf8_lossy(&requests[0].body).into_owned();
    assert!(body.contains("grant_type=authorization_code"));
    assert!(body.contains("code=code-1"));
    assert!(body.contains("code_verifier=verifier-1"));
    assert!(body.contains("resource=https%3A%2F%2Fissuer.example"));
    assert_eq!(requests[0].url, "https://as.example/token");
}

#[tokio::test]
async fn a_failed_exchange_reports_the_safe_error_code() {
    let http = FakeHttp {
        status: 400,
        body: br#"{"error":"invalid_grant"}"#.to_vec(),
        requests: std::sync::Mutex::new(Vec::new()),
    };
    let err = exchange_authorization_code(
        &http,
        &test_as(),
        "code-1",
        "https://wallet.example/cb",
        "verifier-1",
        None,
    )
    .await
    .expect_err("refuses");
    assert!(matches!(
        err,
        TokenError::Status(400, ref error_code) if error_code == "invalid_grant"
    ));
}
