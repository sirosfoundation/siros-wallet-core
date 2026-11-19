use engine_core::oid4vci::credential::*;
use engine_core::oid4vci::token::TokenResponse;
use engine_core::oid4vci::types::IssuerMetadata;
use engine_ports::{FetchPurpose, Host, HttpClient, HttpError, HttpRequest};
use engine_ports::{HostError, SignParams, SignResult};
use serde_json::Value;

struct FakeHttp {
    status: u16,
    body: Vec<u8>,
    /// The request bodies this HTTP saw (the §11.3 pin reads the one the
    /// credential request produced).
    sent: std::sync::Mutex<Vec<Vec<u8>>>,
    /// The headers of the last request (the §11.3 pin asserts the wire
    /// content type follows the encrypted body).
    last_headers: std::sync::Mutex<Vec<(String, String)>>,
}

impl FakeHttp {
    /// The last request body this HTTP saw.
    fn last_sent(&self) -> Vec<u8> {
        self.sent
            .lock()
            .expect("lock")
            .last()
            .cloned()
            .unwrap_or_default()
    }
}

#[async_trait::async_trait]
impl HttpClient for FakeHttp {
    async fn send(&self, request: HttpRequest) -> Result<engine_ports::HttpResponse, HttpError> {
        assert_eq!(request.purpose, FetchPurpose::Credential);
        // docs/engine-spec.md §Fetch policy: every request carries a size limit.
        assert!(request.max_response_bytes < usize::MAX);
        *self.last_headers.lock().expect("lock") = request.headers.clone();
        self.sent.lock().expect("lock").push(request.body.clone());
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
    async fn request_tx_code(&self, _f: &str) -> Result<String, HostError> {
        Ok("1234".to_owned())
    }
    async fn open_authorization(&self, _f: &str, _u: &str) -> Result<(), HostError> {
        Ok(())
    }
    fn progress(&self, _f: &str, _s: &str, _d: Option<String>) {}
}

/// A host that answers the signing-key ask: the app holds the key,
/// so the proof header can identify it (the public JWK + the RFC
/// 7638 thumbprint kid — the SDK's shape).
struct KeyHost {
    jwk: Value,
    /// The asks recorded: (sign?, configuration id, key id) — the #558-twin
    /// pin reads them.
    asks: std::sync::Mutex<Vec<RecordedAsk>>,
}

/// One recorded ask: which kind (sign vs signing-key) and the configuration
/// it names — the #558-twin pin reads them. (The key id rides the asks the
/// other tests already assert.)
#[derive(Clone)]
struct RecordedAsk {
    sign: bool,
    configuration_id: Option<String>,
}

#[async_trait::async_trait]
impl Host for KeyHost {
    async fn request_sign(&self, p: SignParams) -> Result<SignResult, HostError> {
        self.asks
            .lock()
            .map(|mut asks| {
                asks.push(RecordedAsk {
                    sign: true,
                    configuration_id: p.credential_configuration_id.clone(),
                })
            })
            .ok();
        Ok(SignResult {
            signature: vec![0xde, 0xad, 0xbe, 0xef],
        })
    }
    async fn request_signing_key(
        &self,
        params: engine_ports::SigningKeyParams,
    ) -> Result<engine_ports::SigningKeyResult, HostError> {
        self.asks
            .lock()
            .map(|mut asks| {
                asks.push(RecordedAsk {
                    sign: false,
                    configuration_id: params.credential_configuration_id.clone(),
                })
            })
            .ok();
        Ok(engine_ports::SigningKeyResult {
            jwk: self.jwk.clone(),
        })
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
        credential_response_encryption: None,
        credential_request_encryption: None,
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
        batch_credential_issuance: None,
        envelope_key_material: None,
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
        authorization_details: None,
        dpop_nonce: None,
    }
}

#[tokio::test]
async fn a_batch_shaped_answer_is_the_credential() {
    // The GDC apigw answers a single-credential request with the BATCH
    // shape (credentials[] rather than a flat credential) - 1b78321's
    // finding, restored 2026-11-16 after the #11 tests-out-of-src merge
    // swept the decoding (found via the wallet-frontend wasm: the
    // issuance answered "the issuer returned no credential" while the
    // credential sat in credentials[0]). This test pins the fallback so
    // the next test-relocating merge cannot land silently (backlog E).
    let http = FakeHttp {
        status: 200,
        body: br#"{"credentials":[{"credential":"eyJhbGciOiJFUzI1NiJ9.batch.sig","format":"dc+sd-jwt"}]}"#.to_vec(),
        sent: std::sync::Mutex::new(Vec::new()),
        last_headers: std::sync::Mutex::new(Vec::new()),
    };
    let response = request_credential(
        &http,
        &FakeHost,
        &test_metadata(),
        &test_token(),
        "UniversityDegree",
        "flow-1",
        None,
        Some("nonce-1"),
    )
    .await
    .expect("request");
    assert_eq!(
        response.credential.as_deref(),
        Some("eyJhbGciOiJFUzI1NiJ9.batch.sig"),
        "the first credentials[] entry IS the credential"
    );
}

#[tokio::test]
async fn an_encrypted_batch_shaped_answer_is_the_credential() {
    // The realeyes repro (2026-11-18, wallet-core's #53 follow-on): the
    // issuer answers the two-member encryption offer with a JWE whose
    // plaintext is the Final §8.3 BATCH shape - the credential in
    // credentials[0], no top-level credential member. The decrypt path
    // used to return the parsed response EARLY, before the batch fill
    // (credentials[0].credential -> credential) that the plain path runs -
    // the completion carried credential.unwrap_or_default() = "" and the
    // wallet reported "the issuance delivered no credential" while the
    // credential sat in the decrypted credentials[0] (the same
    // shape-class as #53: the parse found the member where the draft
    // put it, not where the Final does). Both paths converge on the
    // fill now; this pins it for the encrypted path.
    let key = engine_core::oid4vci::encryption::EphemeralResponseKey::generate().expect("keygen");
    let public =
        serde_json::from_value::<jose_rs::jwk::Jwk>(key.public_jwk.clone()).expect("public jwk");
    let mut recipient = public;
    recipient.alg = Some("ECDH-ES".to_owned());
    let plaintext = serde_json::json!({
        "credentials": [{
            "credential": "ompuYW1lU3BhY2U.bWV0YWRhdGE.c2ln",
            "format": "mso_mdoc",
        }],
        "credential_metadata": { "auxiliary_data": {} },
    })
    .to_string();
    let jwe = jose_rs::jwe::compact::encrypt_with_jwk_header(
        &recipient,
        jose_rs::header::JoseHeader::for_jwe(
            jose_rs::algorithm::JweAlgorithm::EcdhEs,
            jose_rs::algorithm::JweEncryption::A256GCM,
        ),
        plaintext.as_bytes(),
        jose_rs::algorithm::JweEncryption::A256GCM,
    )
    .expect("the issuer encrypts to the offered key");
    let http = FakeHttp {
        status: 200,
        body: jwe.into_bytes(),
        sent: std::sync::Mutex::new(Vec::new()),
        last_headers: std::sync::Mutex::new(Vec::new()),
    };
    let response = request_credential(
        &http,
        &FakeHost,
        &test_metadata(),
        &test_token(),
        "UniversityDegree",
        "flow-1",
        Some(&engine_core::oid4vci::credential::CredentialRequestAux {
            encryption: Some(
                &engine_core::oid4vci::encryption::NegotiatedResponseEncryption {
                    negotiated: engine_core::oid4vci::encryption::NegotiatedEncryption {
                        alg: "ECDH-ES".to_owned(),
                        enc: "A256GCM".to_owned(),
                    },
                    // The ENGINE-held form (the legacy path this test
                    // pins): the pair generated below.
                    key: engine_core::oid4vci::encryption::ResponseKey::Engine(Box::new(key)),
                    required: true,
                },
            ),
            dpop: None,
            reissuance_kid: None,
            auxiliary_data_to_issuer: &[],
            auxiliary_data_to_wallet: &[],
            now_unix: 1_000,
        }),
        Some("nonce-1"),
    )
    .await
    .expect("request");
    assert_eq!(
        response.credential.as_deref(),
        Some("ompuYW1lU3BhY2U.bWV0YWRhdGE.c2ln"),
        "the decrypted batch entry IS the credential (the fill runs on the encrypted path)"
    );
}

#[tokio::test]
async fn requests_a_credential_with_the_host_signed_proof() {
    let http = FakeHttp {
        status: 200,
        body: br#"{"credential":"eyJhbGciOiJFUzI1NiJ9.payload.sig"}"#.to_vec(),
        sent: std::sync::Mutex::new(Vec::new()),
        last_headers: std::sync::Mutex::new(Vec::new()),
    };
    let response = request_credential(
        &http,
        &FakeHost,
        &test_metadata(),
        &test_token(),
        "UniversityDegree",
        "flow-1",
        None,
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
        sent: std::sync::Mutex::new(Vec::new()),
        last_headers: std::sync::Mutex::new(Vec::new()),
    };
    let response = request_credential(
        &http,
        &FakeHost,
        &test_metadata(),
        &test_token(),
        "UniversityDegree",
        "flow-1",
        None,
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
        sent: std::sync::Mutex::new(Vec::new()),
        last_headers: std::sync::Mutex::new(Vec::new()),
    };
    assert!(matches!(
        request_credential(
            &http,
            &FakeHost,
            &test_metadata(),
            &test_token(),
            "X",
            "flow-1",
            None,
            None
        )
        .await,
        Err(CredentialError::Status(400))
    ));
}

/// An issuer that honours §7.3: reads the request's encryption offer
/// and answers a JWE to the offered key.
struct EncryptingHttp;

#[async_trait::async_trait]
impl HttpClient for EncryptingHttp {
    async fn send(&self, request: HttpRequest) -> Result<engine_ports::HttpResponse, HttpError> {
        let body: serde_json::Value =
            serde_json::from_slice(&request.body).expect("request body json");
        let offer = body["credential_response_encryption"]
            .as_object()
            .expect("the offer is in the request");
        // The 1.0 wire form (§7.3): `alg` + `jwk` + `enc` — the negotiated
        // key-management algorithm rides the OFFER itself (Spherity's issuer
        // reads it and refuses `<missing>`; found in the 20:42 scan's
        // refusal body, #72 round 4 — the earlier pin had it absent).
        assert_eq!(
            offer["alg"], "ECDH-ES",
            "the offer carries the negotiated alg"
        );
        assert_eq!(offer["enc"], "A256GCM");
        assert_eq!(offer["jwk"]["kty"], "EC");

        // The issuer's encrypt: to the wallet's offered public key
        // (ECDH-ES, the 1.0 response-encryption algorithm).
        let jwk: jose_rs::jwk::Jwk =
            serde_json::from_value(offer["jwk"].clone()).expect("offered jwk");
        let mut recipient = jwk.clone();
        recipient.alg = Some("ECDH-ES".to_owned());
        let plaintext = br#"{"credential":"encrypted-credential-1"}"#.to_vec();
        let jwe = jose_rs::jwe::compact::encrypt_with_jwk_header(
            &recipient,
            jose_rs::header::JoseHeader::for_jwe(
                jose_rs::algorithm::JweAlgorithm::EcdhEs,
                jose_rs::algorithm::JweEncryption::A256GCM,
            ),
            &plaintext,
            jose_rs::algorithm::JweEncryption::A256GCM,
        )
        .expect("issuer encrypt");

        Ok(engine_ports::HttpResponse {
            status: 200,
            headers: vec![("content-type".to_owned(), "application/jwt".to_owned())],
            body: jwe.into_bytes(),
        })
    }
}

fn negotiated_encryption() -> engine_core::oid4vci::encryption::NegotiatedResponseEncryption {
    engine_core::oid4vci::encryption::negotiate_with_key(
        &engine_core::oid4vci::encryption::ResponseEncryptionConfig {
            alg_values: vec!["ECDH-ES".to_owned()],
            enc_values: vec!["A256GCM".to_owned()],
            required: true,
        },
    )
    .expect("negotiate")
}

#[tokio::test]
async fn an_encrypted_answer_to_the_offer_decrypts() {
    let encryption = negotiated_encryption();
    let response = request_credential(
        &EncryptingHttp,
        &FakeHost,
        &test_metadata(),
        &test_token(),
        "UniversityDegree",
        "flow-1",
        Some(&CredentialRequestAux {
            auxiliary_data_to_issuer: &[],
            auxiliary_data_to_wallet: &[],
            encryption: Some(&encryption),
            dpop: None,
            reissuance_kid: None,
            now_unix: 1_000,
        }),
        Some("nonce-1"),
    )
    .await
    .expect("request");
    assert_eq!(
        response.credential.as_deref(),
        Some("encrypted-credential-1")
    );
}

#[tokio::test]
async fn a_plain_answer_after_the_offer_refuses() {
    let encryption = negotiated_encryption();
    let http = FakeHttp {
        status: 200,
        body: br#"{"credential":"plain"}"#.to_vec(),
        sent: std::sync::Mutex::new(Vec::new()),
        last_headers: std::sync::Mutex::new(Vec::new()),
    };
    // §7.3: the issuer MUST encrypt when a key was offered. The Go
    // engine accepts the plain answer (P0.6); the Rust core refuses.
    assert!(matches!(
        request_credential(
            &http,
            &FakeHost,
            &test_metadata(),
            &test_token(),
            "UniversityDegree",
            "flow-1",
            Some(&CredentialRequestAux {
                auxiliary_data_to_issuer: &[],
                auxiliary_data_to_wallet: &[],
                encryption: Some(&encryption),
                dpop: None,
                reissuance_kid: None,
                now_unix: 1_000,
            }),
            Some("nonce-1"),
        )
        .await,
        Err(CredentialError::PlainAfterKeyOffered)
    ));
}

#[tokio::test]
async fn an_encrypted_answer_without_an_offer_refuses() {
    let http = FakeHttp {
        status: 200,
        body: b"header.key.iv.ciphertext.tag".to_vec(),
        sent: std::sync::Mutex::new(Vec::new()),
        last_headers: std::sync::Mutex::new(Vec::new()),
    };
    assert!(matches!(
        request_credential(
            &http,
            &FakeHost,
            &test_metadata(),
            &test_token(),
            "UniversityDegree",
            "flow-1",
            None,
            Some("nonce-1"),
        )
        .await,
        Err(CredentialError::EncryptedWithoutKey)
    ));
}

/// A fake that records the URL it was asked for.
struct RecordingHttp {
    status: u16,
    body: Vec<u8>,
    urls: std::sync::Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl HttpClient for RecordingHttp {
    async fn send(&self, request: HttpRequest) -> Result<engine_ports::HttpResponse, HttpError> {
        self.urls
            .lock()
            .map(|mut u| u.push(request.url.clone()))
            .ok();
        Ok(engine_ports::HttpResponse {
            status: self.status,
            headers: Vec::new(),
            body: self.body.clone(),
        })
    }
}

#[tokio::test]
async fn the_credential_endpoint_comes_from_the_metadata_not_the_path() {
    // The metadata names its endpoint: the request goes there, never
    // to the constructed `{issuer}/credential` path.
    let metadata = IssuerMetadata {
        credential_endpoint: "https://issuer.example/issue-credential".to_owned(),
        ..test_metadata()
    };
    let http = RecordingHttp {
        status: 200,
        body: br#"{"credential":"jwt-1"}"#.to_vec(),
        urls: std::sync::Mutex::new(Vec::new()),
    };
    request_credential(
        &http,
        &FakeHost,
        &metadata,
        &test_token(),
        "UniversityDegree",
        "flow-1",
        None,
        Some("nonce-1"),
    )
    .await
    .expect("request");
    assert_eq!(
        http.urls.lock().expect("lock").as_slice(),
        ["https://issuer.example/issue-credential"]
    );

    // Without the member: the constructed fallback.
    let http = RecordingHttp {
        status: 200,
        body: br#"{"credential":"jwt-1"}"#.to_vec(),
        urls: std::sync::Mutex::new(Vec::new()),
    };
    request_credential(
        &http,
        &FakeHost,
        &test_metadata(),
        &test_token(),
        "UniversityDegree",
        "flow-1",
        None,
        Some("nonce-1"),
    )
    .await
    .expect("request");
    assert_eq!(
        http.urls.lock().expect("lock").as_slice(),
        ["https://issuer.example/credential"]
    );
}

/// A stateful fake: the nonce endpoint answers the fresh nonce; the
/// credential endpoint fails the first N calls with `invalid_nonce`,
/// then answers the credential.
struct RetryHttp {
    nonce_body: Vec<u8>,
    error_body: Vec<u8>,
    error_status: u16,
    failures: std::sync::atomic::AtomicUsize,
    credential_calls: std::sync::atomic::AtomicUsize,
    nonce_calls: std::sync::atomic::AtomicUsize,
}

impl RetryHttp {
    fn always_invalid_nonce() -> Self {
        Self {
            nonce_body: br#"{"nonce":"fresh-2"}"#.to_vec(),
            error_body: br#"{"error":"invalid_nonce","c_nonce":"fresh-1"}"#.to_vec(),
            error_status: 400,
            failures: std::sync::atomic::AtomicUsize::new(usize::MAX),
            credential_calls: std::sync::atomic::AtomicUsize::new(0),
            nonce_calls: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn fail_once() -> Self {
        Self {
            failures: std::sync::atomic::AtomicUsize::new(1),
            ..Self::always_invalid_nonce()
        }
    }

    fn calls(&self, which: &str) -> usize {
        match which {
            "credential" => self
                .credential_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            "nonce" => self.nonce_calls.load(std::sync::atomic::Ordering::SeqCst),
            _ => 0,
        }
    }
}

#[async_trait::async_trait]
impl HttpClient for RetryHttp {
    async fn send(&self, request: HttpRequest) -> Result<engine_ports::HttpResponse, HttpError> {
        match request.purpose {
            FetchPurpose::Nonce => {
                self.nonce_calls
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(engine_ports::HttpResponse {
                    status: 200,
                    headers: Vec::new(),
                    body: self.nonce_body.clone(),
                })
            }
            FetchPurpose::Credential => {
                self.credential_calls
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let failed = self.failures.load(std::sync::atomic::Ordering::SeqCst) > 0;
                self.failures
                    .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                if failed {
                    Ok(engine_ports::HttpResponse {
                        status: self.error_status,
                        headers: Vec::new(),
                        body: self.error_body.clone(),
                    })
                } else {
                    Ok(engine_ports::HttpResponse {
                        status: 200,
                        headers: Vec::new(),
                        body: br#"{"credential":"jwt-1"}"#.to_vec(),
                    })
                }
            }
            _ => panic!("unexpected fetch purpose: {:?}", request.purpose),
        }
    }
}

fn metadata_with_nonce_endpoint() -> IssuerMetadata {
    IssuerMetadata {
        credential_response_encryption: None,
        nonce_endpoint: Some("https://issuer.example/nonce".to_owned()),
        ..test_metadata()
    }
}

#[tokio::test]
async fn an_invalid_nonce_retries_once_with_the_endpoint_nonce_and_succeeds() {
    let http = RetryHttp::fail_once();
    let response = request_credential_with_retry(
        &http,
        &FakeHost,
        &metadata_with_nonce_endpoint(),
        &test_token(),
        "UniversityDegree",
        "flow-1",
        None,
        Some("nonce-1"),
    )
    .await
    .expect("retry succeeds");
    assert_eq!(response.credential.as_deref(), Some("jwt-1"));
    // The initial nonce came from the endpoint; the retry refreshed it
    // from the endpoint again (preferred over the error body's
    // c_nonce, per §7).
    assert_eq!(http.calls("nonce"), 2);
    assert_eq!(http.calls("credential"), 2);
}

#[tokio::test]
async fn an_invalid_nonce_after_the_retry_is_terminal() {
    let http = RetryHttp::always_invalid_nonce();
    assert!(matches!(
        request_credential_with_retry(
            &http,
            &FakeHost,
            &metadata_with_nonce_endpoint(),
            &test_token(),
            "UniversityDegree",
            "flow-1",
            None,
            Some("nonce-1"),
        )
        .await,
        Err(CredentialError::InvalidNonce { .. })
    ));
    assert_eq!(http.calls("credential"), 2);
}

#[tokio::test]
async fn a_c_nonce_carrying_error_body_triggers_the_retry_without_a_nonce_endpoint() {
    // P0.6: any error body carrying a refreshed c_nonce is retryable,
    // and without an advertised endpoint the body's c_nonce is the
    // fallback source.
    let http = RetryHttp::fail_once();
    // With no endpoint, the fresh nonce comes from the body.
    let mut http = http;
    http.nonce_body = Vec::new(); // unused; the endpoint is never called
    let response = request_credential_with_retry(
        &http,
        &FakeHost,
        &test_metadata(),
        &test_token(),
        "UniversityDegree",
        "flow-1",
        None,
        Some("nonce-1"),
    )
    .await
    .expect("retry succeeds");
    assert_eq!(response.credential.as_deref(), Some("jwt-1"));
    assert_eq!(http.calls("nonce"), 0);
    assert_eq!(http.calls("credential"), 2);
}

struct TestRng;
impl engine_ports::Rng for TestRng {
    fn fill(&self, buf: &mut [u8]) -> bool {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = i as u8;
        }
        true
    }
}

#[tokio::test]
async fn a_dpop_bound_token_authorizes_the_credential_request_with_a_proof() {
    // A DPoP-bound token: the credential request carries the DPoP
    // scheme and a fresh `ath`-bound proof, signed with the same
    // key that proved the token request.
    let key = engine_core::oid4vci::dpop::DpopKey::generate().expect("keygen");
    let token = TokenResponse {
        access_token: "at-dpop".to_owned(),
        token_type: "DPoP".to_owned(),
        ..test_token()
    };
    // A recording fake that also captures headers.
    struct HeaderHttp {
        status: u16,
        body: Vec<u8>,
        headers: std::sync::Mutex<Vec<Vec<(String, String)>>>,
    }
    #[async_trait::async_trait]
    impl HttpClient for HeaderHttp {
        async fn send(
            &self,
            request: HttpRequest,
        ) -> Result<engine_ports::HttpResponse, HttpError> {
            self.headers
                .lock()
                .map(|mut h| h.push(request.headers.clone()))
                .ok();
            Ok(engine_ports::HttpResponse {
                status: self.status,
                headers: Vec::new(),
                body: self.body.clone(),
            })
        }
    }
    let http = HeaderHttp {
        status: 200,
        body: br#"{"credential":"jwt-1"}"#.to_vec(),
        headers: std::sync::Mutex::new(Vec::new()),
    };

    let aux = CredentialRequestAux {
        auxiliary_data_to_issuer: &[],
        auxiliary_data_to_wallet: &[],
        encryption: None,
        reissuance_kid: None,
        now_unix: 1_000,
        dpop: Some(ResourceDpop {
            flow_id: "flow-1",
            key_id: None,
            key: &key,
            rng: &TestRng,
            now_unix: 1_000,
            dpop_nonce: None,
        }),
    };
    request_credential(
        &http,
        &FakeHost,
        &test_metadata(),
        &token,
        "X",
        "flow-1",
        Some(&aux),
        None,
    )
    .await
    .expect("request");

    let headers = http.headers.lock().expect("lock");
    assert_eq!(headers.len(), 1);
    let authorization = headers[0]
        .iter()
        .find(|(n, _)| n == "authorization")
        .map(|(_, v)| v.clone());
    assert_eq!(authorization.as_deref(), Some("DPoP at-dpop"));
    let proof = headers[0]
        .iter()
        .find(|(n, _)| n == "DPoP")
        .map(|(_, v)| v.clone())
        .expect("a DPoP header");
    let payload = proof.split('.').nth(1).unwrap_or_default();
    let decoded = jose_rs::base64url::decode(payload).expect("base64url");
    let claims: serde_json::Value = serde_json::from_slice(&decoded).expect("claims");
    assert_eq!(claims["ath"], engine_core::oid4vci::dpop::ath_of("at-dpop"));
    assert_eq!(claims["htm"], "POST");
    assert_eq!(claims["htu"], "https://issuer.example/credential");
}

#[tokio::test]
async fn a_dpop_nonce_demand_on_the_credential_endpoint_is_retried_with_the_fresh_nonce() {
    // The resource server may demand its own DPoP nonce (RFC 9449
    // §8.1): the first credential request answers 401
    // `use_dpop_nonce` with a fresh `DPoP-Nonce` header, and the
    // retried proof carries that nonce.
    struct NonceHttp {
        responses: Vec<engine_ports::HttpResponse>,
        headers: std::sync::Mutex<Vec<Vec<(String, String)>>>,
    }
    #[async_trait::async_trait]
    impl HttpClient for NonceHttp {
        async fn send(
            &self,
            request: HttpRequest,
        ) -> Result<engine_ports::HttpResponse, HttpError> {
            let index = {
                let mut calls = self.headers.lock().expect("lock");
                let index = calls.len();
                calls.push(request.headers.clone());
                index
            };
            Ok(self
                .responses
                .get(index)
                .cloned()
                .unwrap_or_else(|| engine_ports::HttpResponse {
                    status: 200,
                    headers: Vec::new(),
                    body: br#"{"credential":"jwt-1"}"#.to_vec(),
                }))
        }
    }
    let key = engine_core::oid4vci::dpop::DpopKey::generate().expect("keygen");
    let token = TokenResponse {
        access_token: "at-dpop".to_owned(),
        token_type: "DPoP".to_owned(),
        ..test_token()
    };
    let http = NonceHttp {
        responses: vec![engine_ports::HttpResponse {
            status: 401,
            headers: vec![("DPoP-Nonce".to_owned(), "fresh-nonce".to_owned())],
            body: br#"{"error":"invalid_token"}"#.to_vec(),
        }],
        headers: std::sync::Mutex::new(Vec::new()),
    };

    let aux = CredentialRequestAux {
        auxiliary_data_to_issuer: &[],
        auxiliary_data_to_wallet: &[],
        encryption: None,
        reissuance_kid: None,
        now_unix: 1_000,
        dpop: Some(ResourceDpop {
            flow_id: "flow-1",
            key_id: None,
            key: &key,
            rng: &TestRng,
            now_unix: 1_000,
            dpop_nonce: None,
        }),
    };
    let response = request_credential(
        &http,
        &FakeHost,
        &test_metadata(),
        &token,
        "X",
        "flow-1",
        Some(&aux),
        None,
    )
    .await
    .expect("the nonce retry succeeds");
    assert_eq!(response.credential.as_deref(), Some("jwt-1"));

    let headers = http.headers.lock().expect("lock");
    assert_eq!(headers.len(), 2, "the request is sent twice");
    let first_proof = headers[0]
        .iter()
        .find(|(n, _)| n == "DPoP")
        .map(|(_, v)| v.clone())
        .expect("the first request carries a proof");
    let second_proof = headers[1]
        .iter()
        .find(|(n, _)| n == "DPoP")
        .map(|(_, v)| v.clone())
        .expect("the retried request carries a proof");
    let decode = |proof: &str| {
        let payload = proof.split('.').nth(1).unwrap_or_default();
        let decoded = jose_rs::base64url::decode(payload).expect("base64url");
        let claims: serde_json::Value = serde_json::from_slice(&decoded).expect("claims");
        claims
    };
    assert!(decode(&first_proof)["nonce"].is_null());
    assert_eq!(decode(&second_proof)["nonce"], "fresh-nonce");
}

#[tokio::test]
async fn the_proof_header_identifies_the_key_with_the_jwk_and_the_thumbprint_kid() {
    // The app holds the signing key, so the engine asks for its
    // public JWK and identifies it in the proof header: the public
    // JWK and the RFC 7638 thumbprint as the `kid` (the SDK's
    // `jose.calculateJwkThumbprint` convention — never a random or
    // conventional name). The proof's `iat` is the Clock's now.
    struct BodyHttp {
        body: std::sync::Mutex<Vec<u8>>,
    }
    #[async_trait::async_trait]
    impl HttpClient for BodyHttp {
        async fn send(
            &self,
            request: HttpRequest,
        ) -> Result<engine_ports::HttpResponse, HttpError> {
            self.body.lock().map(|mut b| *b = request.body.clone()).ok();
            Ok(engine_ports::HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: br#"{"credential":"jwt-1"}"#.to_vec(),
            })
        }
    }
    let host = KeyHost {
        jwk: serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "yD-oreWV0aEuPH94c_DGCtOvqIvFujzIoloNCcfjZyY",
            "y": "HO-K1-uhDZXpdSn3U6sxr0792PwurIcGraTFIV4x51k",
        }),
        asks: std::sync::Mutex::new(Vec::new()),
    };
    let http = BodyHttp {
        body: std::sync::Mutex::new(Vec::new()),
    };

    let aux = CredentialRequestAux {
        auxiliary_data_to_issuer: &[],
        auxiliary_data_to_wallet: &[],
        encryption: None,
        reissuance_kid: None,
        now_unix: 1_000,
        dpop: None,
    };
    request_credential(
        &http,
        &host,
        &test_metadata(),
        &test_token(),
        "X",
        "flow-1",
        Some(&aux),
        Some("nonce-1"),
    )
    .await
    .expect("request");

    let body = http.body.lock().expect("lock").clone();
    let request: serde_json::Value = serde_json::from_slice(&body).expect("body");
    let jwt = request["proofs"]["jwt"][0].as_str().expect("the proof jwt");
    let decode = |part: usize| {
        let payload = jwt.split('.').nth(part).unwrap_or_default();
        jose_rs::base64url::decode(payload).expect("base64url")
    };
    let header: Value = serde_json::from_slice(&decode(0)).expect("the JOSE header");
    let claims: Value = serde_json::from_slice(&decode(1)).expect("the claims");

    // The public JWK rides the header, public members only, with
    // the thumbprint kid and verify-only key ops — and it is the
    // ONLY key identification (exactly one of jwk/kid/x5c).
    // RFC 7638's thumbprint, computed by jose-rs.
    let expected_thumbprint = jose_rs::jwk::thumbprint::thumbprint_sha256(
        &jose_rs::jwk::Jwk::from_json(&host.jwk.to_string()).expect("the JWK"),
    )
    .expect("the thumbprint");
    assert!(!expected_thumbprint.is_empty());
    assert_eq!(header["jwk"]["kty"], "EC");
    assert!(header["jwk"].get("d").is_none());
    assert_eq!(header["jwk"]["kid"], expected_thumbprint);
    assert!(header.get("kid").is_none());
    assert!(header.get("x5c").is_none());
    // No `key_ops` in a PROOF header's JWK: a key that is SIGNING with
    // `key_ops: ["verify"]` is semantically contradictory, and a strict
    // issuer rejects the proof (the GDC drive's finding, 1b78321). Pinned
    // here because the #11 merge sweep restored the insert with its
    // conflict resolution and the moved test asserted the wrong shape.
    assert!(
        header["jwk"]
            .get("key_ops")
            .map(serde_json::Value::is_null)
            .unwrap_or(true)
            || header["jwk"].get("key_ops").is_none(),
        "a proof header's JWK carries no key_ops"
    );
    // The iat is the Clock's now, not a placeholder.
    assert_eq!(claims["iat"], 1_000);
}

#[tokio::test]
async fn a_bearer_token_does_not_carry_a_dpop_proof() {
    struct HeaderHttp {
        status: u16,
        body: Vec<u8>,
        headers: std::sync::Mutex<Vec<Vec<(String, String)>>>,
    }
    #[async_trait::async_trait]
    impl HttpClient for HeaderHttp {
        async fn send(
            &self,
            request: HttpRequest,
        ) -> Result<engine_ports::HttpResponse, HttpError> {
            self.headers
                .lock()
                .map(|mut h| h.push(request.headers.clone()))
                .ok();
            Ok(engine_ports::HttpResponse {
                status: self.status,
                headers: Vec::new(),
                body: self.body.clone(),
            })
        }
    }

    let key = engine_core::oid4vci::dpop::DpopKey::generate().expect("keygen");
    let http = HeaderHttp {
        status: 200,
        body: br#"{"credential":"jwt-1"}"#.to_vec(),
        headers: std::sync::Mutex::new(Vec::new()),
    };
    let aux = CredentialRequestAux {
        auxiliary_data_to_issuer: &[],
        auxiliary_data_to_wallet: &[],
        encryption: None,
        reissuance_kid: None,
        now_unix: 1_000,
        dpop: Some(ResourceDpop {
            flow_id: "flow-1",
            key_id: None,
            key: &key,
            rng: &TestRng,
            now_unix: 1_000,
            dpop_nonce: None,
        }),
    };
    // A Bearer token: the Bearer scheme, and no DPoP header even
    // with the key available.
    request_credential(
        &http,
        &FakeHost,
        &test_metadata(),
        &test_token(),
        "X",
        "flow-1",
        Some(&aux),
        None,
    )
    .await
    .expect("request");
    let headers = http.headers.lock().expect("lock");
    let authorization = headers[0]
        .iter()
        .find(|(n, _)| n == "authorization")
        .map(|(_, v)| v.clone());
    assert_eq!(authorization.as_deref(), Some("Bearer at-test"));
    assert!(!headers[0].iter().any(|(n, _)| n == "DPoP"));
}

/// go-wallet-backend#558's twin: every sign ask of one configuration's
/// credential — the signing-key ask and the proof ask — names the
/// configuration, so the client pairs each key (and the credential it
/// binds) with the completion entry carrying the same id. The asks that
/// are not one configuration's (the DPoP proof, the client-auth proof)
/// carry none.
#[tokio::test]
async fn every_configuration_ask_names_its_credential_configuration_id() {
    struct PlainHttp;
    #[async_trait::async_trait]
    impl HttpClient for PlainHttp {
        async fn send(
            &self,
            _request: HttpRequest,
        ) -> Result<engine_ports::HttpResponse, HttpError> {
            Ok(engine_ports::HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: br#"{"credential":"jwt-1"}"#.to_vec(),
            })
        }
    }
    let host = KeyHost {
        jwk: serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "yD-oreWV0aEuPH94c_DGCtOvqIvFujzIoloNCcfjZyY",
            "y": "HO-K1-uhDZXpdSn3U6sxr0792PwurIcGraTFIV4x51k",
        }),
        asks: std::sync::Mutex::new(Vec::new()),
    };
    let response = request_credential(
        &PlainHttp,
        &host,
        &test_metadata(),
        &test_token(),
        "UniversityDegree",
        "flow-1",
        None,
        Some("nonce-1"),
    )
    .await
    .expect("request");
    assert_eq!(response.credential.as_deref(), Some("jwt-1"));

    // Every ask names the configuration this credential issues under.
    let asks = host.asks.lock().expect("lock");
    assert!(!asks.is_empty(), "the proof path asked the host");
    for ask in asks.iter() {
        let kind = if ask.sign { "sign" } else { "signing-key" };
        assert_eq!(
            ask.configuration_id.as_deref(),
            Some("UniversityDegree"),
            "the {kind} ask names its credential_configuration_id"
        );
    }
}

// ─── Issue #59: the client-held response key ──────────────────────────────

/// The host that HOLDS the response-encryption pair (issue #59): it
/// answers the key ask with the public half (generated on the host,
/// never the engine), and the decrypt ask with the plaintext it
/// opened with the private half — recording what the engine asked, so
/// the pin can prove the engine relays and never decrypts.
struct ClientKeyHost {
    /// The pair the host generated for the key ask.
    private: std::sync::Mutex<Option<jose_rs::jwk::Jwk>>,
    /// The decrypt asks, recorded: (flow, configuration, deferred, jwe).
    decrypt_asks: std::sync::Mutex<Vec<(String, String, bool, String)>>,
}

#[async_trait::async_trait]
impl Host for ClientKeyHost {
    async fn request_sign(&self, _p: SignParams) -> Result<SignResult, HostError> {
        Ok(SignResult {
            signature: vec![0xde, 0xad, 0xbe, 0xef],
        })
    }
    async fn request_response_encryption_key(
        &self,
        params: engine_ports::ResponseEncryptionKeyParams,
    ) -> Result<engine_ports::ResponseEncryptionKeyResult, HostError> {
        // The pair is generated ON THE HOST: the engine offered nothing,
        // it named the configuration (the #558 pairing) AND the
        // negotiated pair (the §7.3 alg/enc the engine resolved).
        assert_eq!(
            params.credential_configuration_id, "UniversityDegree",
            "the key ask names its configuration (the #558 pairing)"
        );
        assert_eq!(
            params.alg, "ECDH-ES",
            "the key ask carries the negotiated alg"
        );
        assert_eq!(
            params.enc, "A256GCM",
            "the key ask carries the negotiated enc"
        );
        let private = jose_rs::jwk::generate::generate_ec("P-256")
            .map_err(|_| HostError::Cannot("the host cannot generate a pair".to_owned()))?;
        let public: serde_json::Value =
            serde_json::from_str(&private.to_public_jwk().to_json().map_err(|_| {
                HostError::Cannot("the host cannot serialize its public JWK".to_owned())
            })?)
            .map_err(|_| HostError::Cannot("the public JWK is not JSON".to_owned()))?;
        *self.private.lock().expect("lock") = Some(private);
        Ok(engine_ports::ResponseEncryptionKeyResult { public_jwk: public })
    }
    async fn request_decrypt_credential_response(
        &self,
        params: engine_ports::DecryptCredentialResponseParams,
    ) -> Result<engine_ports::DecryptCredentialResponseResult, HostError> {
        self.decrypt_asks.lock().expect("lock").push((
            params.flow_id.clone(),
            params.credential_configuration_id.clone(),
            params.deferred,
            params.jwe.clone(),
        ));
        let private = self
            .private
            .lock()
            .expect("lock")
            .clone()
            .ok_or_else(|| HostError::Cannot("no pair was generated".to_owned()))?;
        let mut private = private;
        private.alg = Some("ECDH-ES".to_owned());
        let plaintext = jose_rs::jwe::compact::decrypt_with_jwk(&private, &params.jwe)
            .map_err(|err| HostError::Cannot(format!("the host decrypt failed: {err}")))?;
        let response: Value = serde_json::from_slice(&plaintext)
            .map_err(|_| HostError::Cannot("the plaintext is not JSON".to_owned()))?;
        Ok(engine_ports::DecryptCredentialResponseResult { response })
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
    async fn request_tx_code(&self, _f: &str) -> Result<String, HostError> {
        Ok("1234".to_owned())
    }
    async fn open_authorization(&self, _f: &str, _u: &str) -> Result<(), HostError> {
        Ok(())
    }
    fn progress(&self, _f: &str, _s: &str, _d: Option<String>) {}
}

/// Issue #59: a host that answers the key ask holds the pair, so the
/// JWE the issuer answers opens ON THE HOST — the engine relays the
/// JWE (one decrypt ask, `deferred: false`, the #558 configuration
/// pairing) and parses the JSON the host returns. The engine never
/// holds the private half; a `to_wallet` secret (the ssc seed) reaches
/// the wallet and only the wallet.
#[tokio::test]
async fn a_client_held_key_opens_the_response_through_the_decrypt_ask() {
    let host = ClientKeyHost {
        private: std::sync::Mutex::new(None),
        decrypt_asks: std::sync::Mutex::new(Vec::new()),
    };
    // The negotiation runs THROUGH the host's key ask (#59):
    // negotiate_with_host falls back to the engine-held pair only when
    // the host refuses — this one answers.
    let encryption = engine_core::oid4vci::encryption::negotiate_with_host(
        &host,
        "flow-1",
        "UniversityDegree",
        &engine_core::oid4vci::encryption::ResponseEncryptionConfig {
            alg_values: vec!["ECDH-ES".to_owned()],
            enc_values: vec!["A256GCM".to_owned()],
            required: true,
        },
    )
    .await
    .expect("negotiate");
    assert!(
        encryption.key.is_client(),
        "the host answered the key ask: the pair is client-held"
    );

    // EncryptingHttp encrypts to whatever public JWK the offer carries
    // — the HOST's, here.
    let response = request_credential(
        &EncryptingHttp,
        &host,
        &test_metadata(),
        &test_token(),
        "UniversityDegree",
        "flow-1",
        Some(&CredentialRequestAux {
            auxiliary_data_to_issuer: &[],
            auxiliary_data_to_wallet: &[],
            encryption: Some(&encryption),
            dpop: None,
            reissuance_kid: None,
            now_unix: 1_000,
        }),
        Some("nonce-1"),
    )
    .await
    .expect("request");
    assert_eq!(
        response.credential.as_deref(),
        Some("encrypted-credential-1")
    );
    assert!(
        response.encrypted,
        "the response's encrypted-arrival flag is set (the completion's #59 relay)"
    );

    // One decrypt ask, relayed to the host, `deferred: false`, the
    // configuration named (#558's pairing) — and the engine never
    // decrypted in-process (the ask carries the issuer's JWE).
    let asks = host.decrypt_asks.lock().expect("lock");
    assert_eq!(asks.len(), 1, "exactly one decrypt ask");
    let (flow, configuration, deferred, jwe) = &asks[0];
    assert_eq!(flow, "flow-1");
    assert_eq!(configuration, "UniversityDegree");
    assert!(!deferred, "the direct response is not deferred");
    assert_eq!(
        jwe.split('.').count(),
        5,
        "the ask relays the issuer's compact JWE"
    );
}

/// Issue #59's legacy fallback: a host that REFUSES the key ask (the
/// pre-#59 hosts, the trait's default) keeps the flow working — the
/// engine-held ephemeral pair decrypts in-process, exactly as before.
#[tokio::test]
async fn a_refusing_host_keeps_the_engine_held_pair() {
    let host = FakeHost;
    let encryption = engine_core::oid4vci::encryption::negotiate_with_host(
        &host,
        "flow-1",
        "UniversityDegree",
        &engine_core::oid4vci::encryption::ResponseEncryptionConfig {
            alg_values: vec!["ECDH-ES".to_owned()],
            enc_values: vec!["A256GCM".to_owned()],
            required: true,
        },
    )
    .await
    .expect("negotiate");
    assert!(
        !encryption.key.is_client(),
        "the refusing host falls back to the engine-held pair"
    );
    // And the engine-held pair still decrypts (the pre-#59 path).
    let response = request_credential(
        &EncryptingHttp,
        &FakeHost,
        &test_metadata(),
        &test_token(),
        "UniversityDegree",
        "flow-1",
        Some(&CredentialRequestAux {
            auxiliary_data_to_issuer: &[],
            auxiliary_data_to_wallet: &[],
            encryption: Some(&encryption),
            dpop: None,
            reissuance_kid: None,
            now_unix: 1_000,
        }),
        Some("nonce-1"),
    )
    .await
    .expect("request");
    assert_eq!(
        response.credential.as_deref(),
        Some("encrypted-credential-1")
    );
}

// ─── §11.3: the Credential Request itself encrypted to the issuer's key ───

/// §11.3: an issuer publishing `credential_request_encryption` gets its
/// Credential Request as a JWE encrypted to the advertised key — Spherity's
/// requirement ("to prevent the response-encryption key from being
/// substituted by an attacker"; their `invalid_encryption_parameters`
/// refusal of the plain request, the 20:13 scan's body log). The request
/// body IS the JWE; the header names the issuer key by its `kid`; the
/// configuration id and the proofs ride the encrypted plaintext.
#[tokio::test]
async fn an_issuer_publishing_request_encryption_gets_an_encrypted_request() {
    let mut metadata = test_metadata();
    metadata.credential_request_encryption = Some(serde_json::json!({
        "jwks": {
            "keys": [{
                "kty": "EC", "crv": "P-256",
                // The issuer's public half; the engine encrypts to it.
                "x": "PrFW9c4Y65Xu5lpKLRCpWs09L-0Ncls6CzjsbLphBeE",
                "y": "pwtQj6DVTT2vH87uqzLmRBhGlVVeK7Pk9iu5liBzttw",
                "kid": "test-issuer-key", "use": "enc", "alg": "ECDH-ES"
            }]
        },
        "enc_values_supported": ["A256GCM", "A128GCM"],
        "encryption_required": false
    }));
    let http = FakeHttp {
        status: 200,
        body: br#"{"credential":"plain-credential-1"}"#.to_vec(),
        sent: std::sync::Mutex::new(Vec::new()),
        last_headers: std::sync::Mutex::new(Vec::new()),
    };
    let response = request_credential(
        &http,
        &FakeHost,
        &metadata,
        &test_token(),
        "UniversityDegree",
        "flow-1",
        None,
        Some("nonce-1"),
    )
    .await
    .expect("request");

    // The sent body: a compact JWE (five dot-separated parts), never
    // plain JSON.
    let sent = String::from_utf8_lossy(&http.last_sent()).into_owned();
    assert_eq!(
        sent.split('.').count(),
        5,
        "the credential request is a compact JWE: {sent}"
    );
    assert!(
        !sent.starts_with('{'),
        "the request body is not plain JSON: {sent}"
    );

    // The wire content type follows the body (§11.3): the JWE rides
    // `application/jwt`, never the plain body's `application/json`.
    let sent_headers = http.last_headers.lock().expect("lock").clone();
    let sent_content_type = sent_headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .map(|(_, value)| value.clone())
        .unwrap_or_default();
    assert_eq!(
        sent_content_type, "application/jwt",
        "the encrypted request rides the JWE content type"
    );

    // The JWE header names the issuer's key by its kid (§11.3): the
    // header is the first base64url part; the kid rides it.
    let header_part = sent.split('.').next().unwrap_or_default();
    let header = base64url_decode(header_part);
    let header_text = String::from_utf8_lossy(&header);
    assert!(
        header_text.contains("test-issuer-key"),
        "the JWE header names the issuer key by kid: {header_text}"
    );
    assert!(
        header_text.contains("ECDH-ES"),
        "the key-management algorithm is ECDH-ES: {header_text}"
    );

    // And the response parses as ever (the plain answer of this fixture).
    assert_eq!(response.credential.as_deref(), Some("plain-credential-1"));
}

/// Minimal base64url decoding (the engine's own helper is private).
fn base64url_decode(encoded: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut values = Vec::new();
    for byte in encoded.bytes() {
        if let Some(position) = ALPHABET.iter().position(|&a| a == byte) {
            values.push(position as u8);
        }
    }
    let mut out = Vec::new();
    for chunk in values.chunks(4) {
        let n = chunk.len();
        let bits: u32 = chunk
            .iter()
            .enumerate()
            .map(|(i, v)| u32::from(*v) << (18 - 6 * i))
            .sum();
        let bytes = [(bits >> 16) as u8, (bits >> 8) as u8, bits as u8];
        out.extend_from_slice(
            &bytes[..match n {
                2 => 1,
                3 => 2,
                _ => 3,
            }],
        );
    }
    out
}

// ─── §11.3's failure modes (the regression guards) ────────────────────────

/// §11.3 `encryption_required: true` with an UNSATISFIABLE config (a key set
/// with no EC encryption key): the request FAILS — never the plain body the
/// issuer's required flag would refuse. A demanded encryption is not
/// negotiable down to plain.
#[tokio::test]
async fn a_required_but_unsatisfiable_request_encryption_fails_the_request() {
    let mut metadata = test_metadata();
    metadata.credential_request_encryption = Some(serde_json::json!({
        "jwks": { "keys": [
            { "kty": "OKP", "crv": "X25519", "kid": "not-an-ec-key" }
        ]},
        "enc_values_supported": ["A256GCM"],
        "encryption_required": true
    }));
    let http = FakeHttp {
        status: 200,
        body: br#"{"credential":"plain-credential-1"}"#.to_vec(),
        sent: std::sync::Mutex::new(Vec::new()),
        last_headers: std::sync::Mutex::new(Vec::new()),
    };
    assert!(
        request_credential(
            &http,
            &FakeHost,
            &metadata,
            &test_token(),
            "UniversityDegree",
            "flow-1",
            None,
            Some("nonce-1"),
        )
        .await
        .is_err(),
        "a required but unsatisfiable §11.3 config fails the request"
    );
    // And NOTHING was sent: no plain body ever reached the issuer.
    assert!(
        http.sent.lock().expect("lock").is_empty(),
        "no request body was sent to the issuer"
    );
}

/// §11.3 `encryption_required: false` with an unsatisfiable config: the
/// plain body rides (the issuer takes it or leaves it) — the optional
/// encryption never blocks the flow. The 200 answer parses as ever.
#[tokio::test]
async fn an_optional_unsatisfiable_request_encryption_rides_plain() {
    let mut metadata = test_metadata();
    metadata.credential_request_encryption = Some(serde_json::json!({
        "jwks": { "keys": [
            { "kty": "OKP", "crv": "X25519", "kid": "not-an-ec-key" }
        ]},
        "enc_values_supported": ["A256GCM"],
        "encryption_required": false
    }));
    let http = FakeHttp {
        status: 200,
        body: br#"{"credential":"plain-credential-1"}"#.to_vec(),
        sent: std::sync::Mutex::new(Vec::new()),
        last_headers: std::sync::Mutex::new(Vec::new()),
    };
    let response = request_credential(
        &http,
        &FakeHost,
        &metadata,
        &test_token(),
        "UniversityDegree",
        "flow-1",
        None,
        Some("nonce-1"),
    )
    .await
    .expect("the optional encryption softens to plain");
    // The body rides PLAIN: JSON, the application/json content type.
    let sent = String::from_utf8_lossy(&http.last_sent()).into_owned();
    assert!(sent.starts_with('{'), "the plain body is JSON: {sent}");
    let headers = http.last_headers.lock().expect("lock").clone();
    let content_type = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .map(|(_, value)| value.clone())
        .unwrap_or_default();
    assert_eq!(content_type, "application/json");
    assert_eq!(response.credential.as_deref(), Some("plain-credential-1"));
}

/// §11.3's `alg_values_supported` GATE: an issuer that advertises ONLY
/// algorithms this stack does not implement (RSA-OAEP say) cannot be
/// negotiated down to an unadvertised ECDH-ES — the request fails under
/// the required flag, plain under the optional one. Never a silent
/// algorithm substitution.
#[tokio::test]
async fn an_unimplemented_alg_list_is_not_negotiated_around() {
    let mut metadata = test_metadata();
    metadata.credential_request_encryption = Some(serde_json::json!({
        "jwks": { "keys": [
            { "kty": "EC", "crv": "P-256",
              "x": "PrFW9c4Y65Xu5lpKLRCpWs09L-0Ncls6CzjsbLphBeE",
              "y": "pwtQj6DVTT2vH87uqzLmRBhGlVVeK7Pk9iu5liBzttw",
              "kid": "alg-gated-key", "use": "enc", "alg": "ECDH-ES" }
        ]},
        "alg_values_supported": ["RSA-OAEP"],
        "enc_values_supported": ["A256GCM"],
        "encryption_required": true
    }));
    let http = FakeHttp {
        status: 200,
        body: br#"{"credential":"plain-credential-1"}"#.to_vec(),
        sent: std::sync::Mutex::new(Vec::new()),
        last_headers: std::sync::Mutex::new(Vec::new()),
    };
    assert!(
        request_credential(
            &http,
            &FakeHost,
            &metadata,
            &test_token(),
            "UniversityDegree",
            "flow-1",
            None,
            Some("nonce-1"),
        )
        .await
        .is_err(),
        "an explicit unimplemented alg list is not negotiated around"
    );
    assert!(
        http.sent.lock().expect("lock").is_empty(),
        "nothing was sent to the issuer"
    );
}
