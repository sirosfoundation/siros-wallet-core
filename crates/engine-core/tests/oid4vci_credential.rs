use engine_core::oid4vci::credential::*;
use engine_core::oid4vci::token::TokenResponse;
use engine_core::oid4vci::types::IssuerMetadata;
use engine_ports::{FetchPurpose, Host, HttpClient, HttpError, HttpRequest};
use engine_ports::{HostError, SignParams, SignResult};
use serde_json::Value;

struct FakeHttp {
    status: u16,
    body: Vec<u8>,
}

#[async_trait::async_trait]
impl HttpClient for FakeHttp {
    async fn send(&self, request: HttpRequest) -> Result<engine_ports::HttpResponse, HttpError> {
        assert_eq!(request.purpose, FetchPurpose::Credential);
        // docs/engine-spec.md §Fetch policy: every request carries a size limit.
        assert!(request.max_response_bytes < usize::MAX);
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
}

#[async_trait::async_trait]
impl Host for KeyHost {
    async fn request_sign(&self, _p: SignParams) -> Result<SignResult, HostError> {
        Ok(SignResult {
            signature: vec![0xde, 0xad, 0xbe, 0xef],
        })
    }
    async fn request_signing_key(
        &self,
        _params: engine_ports::SigningKeyParams,
    ) -> Result<engine_ports::SigningKeyResult, HostError> {
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
        // The 1.0 wire form: jwk + enc only — the key-management
        // algorithm rides the JWE header, not the offer.
        assert!(offer.get("alg").is_none());
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
    assert_eq!(header["jwk"]["key_ops"], serde_json::json!(["verify"]));
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
