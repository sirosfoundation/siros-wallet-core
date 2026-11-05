use engine_core::oid4vci::attestation::*;
use engine_core::oid4vci::types::AsMetadata;
use engine_ports::{AttestationParams, AttestationResult, HttpClient, HttpRequest};
use engine_ports::{HostError, HttpError, HttpResponse, SignParams, SignResult};

struct AttestingHost {
    challenges: std::sync::Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl engine_ports::Host for AttestingHost {
    async fn request_sign(&self, _p: SignParams) -> Result<SignResult, HostError> {
        Ok(SignResult { signature: vec![] })
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
        Err(HostError::Cannot("no tx code".to_owned()))
    }
    async fn open_authorization(&self, _f: &str, _u: &str) -> Result<(), HostError> {
        Ok(())
    }
    fn progress(&self, _f: &str, _s: &str, _d: Option<String>) {}

    async fn request_attestation(
        &self,
        params: AttestationParams,
    ) -> Result<AttestationResult, HostError> {
        let pop = format!("pop-jwt-for-{}", params.challenge);
        self.challenges
            .lock()
            .map(|mut c| c.push(params.challenge))
            .ok();
        Ok(AttestationResult {
            wia: "wia-jwt".to_owned(),
            pop,
        })
    }
}

struct RefusingHost;
#[async_trait::async_trait]
impl engine_ports::Host for RefusingHost {
    async fn request_sign(&self, _p: SignParams) -> Result<SignResult, HostError> {
        Ok(SignResult { signature: vec![] })
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
        Err(HostError::Cannot("no tx code".to_owned()))
    }
    async fn open_authorization(&self, _f: &str, _u: &str) -> Result<(), HostError> {
        Ok(())
    }
    fn progress(&self, _f: &str, _s: &str, _d: Option<String>) {}
}

// ─── the host request ────────────────────────────────────────────

#[tokio::test]
async fn an_answering_host_supplies_the_pair() {
    let host = AttestingHost {
        challenges: std::sync::Mutex::new(Vec::new()),
    };
    let attestation =
        request_client_attestation(&host, "flow-1", "https://as.example", "client-1", "")
            .await
            .expect("attestation");
    assert_eq!(attestation.wia, "wia-jwt");
    assert_eq!(attestation.pop, "pop-jwt-for-");
}

#[tokio::test]
async fn a_refusing_host_proceeds_without_attestation() {
    assert!(
        request_client_attestation(&RefusingHost, "f", "https://as.example", "c", "")
            .await
            .is_none()
    );
    // The default implementation refuses too — an old host keeps
    // working, the flow proceeds unattested.
    struct OldHost;
    #[async_trait::async_trait]
    impl engine_ports::Host for OldHost {
        async fn request_sign(&self, _p: SignParams) -> Result<SignResult, HostError> {
            Ok(SignResult { signature: vec![] })
        }
        async fn request_match(
            &self,
            _params: engine_ports::MatchParams,
        ) -> Result<engine_ports::MatchResult, HostError> {
            Err(HostError::Cannot("no".to_owned()))
        }
        async fn request_consent(
            &self,
            _p: engine_ports::ConsentParams,
        ) -> Result<engine_ports::ConsentResult, HostError> {
            Err(HostError::Cannot("no".to_owned()))
        }
        async fn request_tx_code(&self, _f: &str) -> Result<String, HostError> {
            Err(HostError::Cannot("no".to_owned()))
        }
        async fn open_authorization(&self, _f: &str, _u: &str) -> Result<(), HostError> {
            Ok(())
        }
        fn progress(&self, _f: &str, _s: &str, _d: Option<String>) {}
    }
    assert!(
        request_client_attestation(&OldHost, "f", "https://as.example", "c", "")
            .await
            .is_none()
    );
}

#[tokio::test]
async fn the_headers_come_as_a_pair_or_not_at_all() {
    let attestation = ClientAttestation {
        wia: "wia".to_owned(),
        pop: "pop".to_owned(),
    };
    let headers = attestation_headers(Some(&attestation));
    assert_eq!(headers.len(), 2);
    assert_eq!(headers[0].0, "OAuth-Client-Attestation");
    assert_eq!(headers[1].0, "OAuth-Client-Attestation-PoP");
    assert!(attestation_headers(None).is_empty());

    // A half answer is no answer.
    struct HalfHost;
    #[async_trait::async_trait]
    impl engine_ports::Host for HalfHost {
        async fn request_sign(&self, _p: SignParams) -> Result<SignResult, HostError> {
            Ok(SignResult { signature: vec![] })
        }
        async fn request_match(
            &self,
            _params: engine_ports::MatchParams,
        ) -> Result<engine_ports::MatchResult, HostError> {
            Err(HostError::Cannot("no".to_owned()))
        }
        async fn request_consent(
            &self,
            _p: engine_ports::ConsentParams,
        ) -> Result<engine_ports::ConsentResult, HostError> {
            Err(HostError::Cannot("no".to_owned()))
        }
        async fn request_tx_code(&self, _f: &str) -> Result<String, HostError> {
            Err(HostError::Cannot("no".to_owned()))
        }
        async fn open_authorization(&self, _f: &str, _u: &str) -> Result<(), HostError> {
            Ok(())
        }
        fn progress(&self, _f: &str, _s: &str, _d: Option<String>) {}
        async fn request_attestation(
            &self,
            _params: AttestationParams,
        ) -> Result<AttestationResult, HostError> {
            Ok(AttestationResult {
                wia: "wia".to_owned(),
                pop: String::new(),
            })
        }
    }
    assert!(
        request_client_attestation(&HalfHost, "f", "https://as.example", "c", "")
            .await
            .is_none()
    );
}

// ─── the challenge rejection and resolution ──────────────────────

#[test]
fn the_challenge_rejection_is_recognized() {
    let body = br#"{"error":"use_attestation_challenge"}"#;
    assert!(is_attestation_challenge_error(400, body));
    assert!(is_attestation_challenge_error(401, body));
    assert!(!is_attestation_challenge_error(200, body));
    assert!(!is_attestation_challenge_error(
        400,
        br#"{"error":"invalid_client"}"#
    ));
    assert!(!is_attestation_challenge_error(400, b"not json"));
}

#[test]
fn the_challenge_comes_from_the_response_header() {
    let headers = vec![(
        "OAuth-Client-Attestation-Challenge".to_owned(),
        "challenge-1".to_owned(),
    )];
    assert_eq!(
        challenge_from_headers(&headers),
        Some("challenge-1".to_owned())
    );
    assert_eq!(challenge_from_headers(&[]), None);
    // An empty header is no challenge.
    assert_eq!(
        challenge_from_headers(&[(
            "OAuth-Client-Attestation-Challenge".to_owned(),
            String::new()
        )]),
        None
    );
}

struct FakeHttp {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

#[async_trait::async_trait]
impl HttpClient for FakeHttp {
    async fn send(&self, _request: HttpRequest) -> Result<HttpResponse, HttpError> {
        Ok(HttpResponse {
            status: self.status,
            headers: self.headers.clone(),
            body: self.body.clone(),
        })
    }
}

#[tokio::test]
async fn the_challenge_endpoint_prefers_the_header_then_the_body() {
    let header = FakeHttp {
        status: 200,
        headers: vec![(
            "OAuth-Client-Attestation-Challenge".to_owned(),
            "from-header".to_owned(),
        )],
        body: br#"{"attestation_challenge":"from-body"}"#.to_vec(),
    };
    assert_eq!(
        fetch_attestation_challenge(&header, "https://as.example/challenge")
            .await
            .expect("challenge"),
        "from-header"
    );

    let body = FakeHttp {
        status: 200,
        headers: Vec::new(),
        body: br#"{"attestation_challenge":"from-body"}"#.to_vec(),
    };
    assert_eq!(
        fetch_attestation_challenge(&body, "https://as.example/challenge")
            .await
            .expect("challenge"),
        "from-body"
    );
}

#[tokio::test]
async fn a_failed_challenge_endpoint_refuses() {
    let http = FakeHttp {
        status: 500,
        headers: Vec::new(),
        body: Vec::new(),
    };
    assert!(fetch_attestation_challenge(&http, "https://as.example/c")
        .await
        .is_err());

    // No challenge in the answer at all.
    let empty = FakeHttp {
        status: 200,
        headers: Vec::new(),
        body: b"{}".to_vec(),
    };
    assert!(fetch_attestation_challenge(&empty, "https://as.example/c")
        .await
        .is_err());
}

#[tokio::test]
async fn the_challenge_resolution_prefers_the_header_then_the_endpoint() {
    let as_metadata = AsMetadata {
        issuer: "https://as.example".to_owned(),
        token_endpoint: "https://as.example/token".to_owned(),
        authorization_endpoint: String::new(),
        par_endpoint: String::new(),
        token_endpoint_auth_methods: Vec::new(),
        require_par: false,
        challenge_endpoint: "https://as.example/challenge".to_owned(),
        code_challenge_methods: None,
        grant_types: Vec::new(),
    };

    // The response header wins without touching the endpoint.
    let http = FakeHttp {
        status: 500, // would fail if called
        headers: vec![(
            "OAuth-Client-Attestation-Challenge".to_owned(),
            "from-header".to_owned(),
        )],
        body: Vec::new(),
    };
    assert_eq!(
        resolve_challenge(&http, &as_metadata, &http.headers.clone()).await,
        Some("from-header".to_owned())
    );

    // No header and no endpoint: no challenge.
    let bare = AsMetadata {
        challenge_endpoint: String::new(),
        ..as_metadata
    };
    assert_eq!(resolve_challenge(&http, &bare, &[]).await, None);
}
