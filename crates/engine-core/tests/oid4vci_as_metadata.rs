//! The AS metadata discovery (RFC 8414 §3.1, OIDC discovery).

use engine_core::oid4vci::as_metadata::discover_as_metadata;
use engine_core::oid4vci::types::AsMetadataError;
use engine_ports::{FetchPurpose, HttpClient, HttpError, HttpRequest};

/// The AS-metadata response limit of docs/engine-spec.md §OpenID4VCI issuance.
const AS_METADATA_LIMIT: usize = 1024 * 1024;

struct FakeHttp {
    body: Vec<u8>,
    status: u16,
    calls: std::sync::Mutex<Vec<String>>,
}

impl FakeHttp {
    fn ok(body: serde_json::Value) -> Self {
        Self {
            body: body.to_string().into_bytes(),
            status: 200,
            calls: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn not_found() -> Self {
        Self {
            body: Vec::new(),
            status: 404,
            calls: std::sync::Mutex::new(Vec::new()),
        }
    }
}

#[async_trait::async_trait]
impl HttpClient for FakeHttp {
    async fn send(&self, request: HttpRequest) -> Result<engine_ports::HttpResponse, HttpError> {
        self.calls
            .lock()
            .map(|mut c| c.push(request.url.clone()))
            .ok();
        assert_eq!(request.purpose, FetchPurpose::AsMetadata);
        assert_eq!(request.max_response_bytes, AS_METADATA_LIMIT);
        Ok(engine_ports::HttpResponse {
            status: self.status,
            headers: Vec::new(),
            body: self.body.clone(),
        })
    }
}

fn as_metadata_json(issuer: &str) -> serde_json::Value {
    serde_json::json!({
        "issuer": issuer,
        "token_endpoint": format!("{issuer}/token"),
        "authorization_endpoint": format!("{issuer}/authorize"),
    })
}

#[tokio::test]
async fn resolves_the_rfc8414_form() {
    let http = FakeHttp::ok(as_metadata_json("https://as.example"));
    let metadata = discover_as_metadata(&http, "https://as.example", false)
        .await
        .expect("resolve");
    assert_eq!(metadata.issuer, "https://as.example");
    assert_eq!(metadata.token_endpoint, "https://as.example/token");
}

#[tokio::test]
async fn refuses_an_issuer_mismatch() {
    let http = FakeHttp::ok(as_metadata_json("https://other.example"));
    let err = discover_as_metadata(&http, "https://as.example", false)
        .await
        .expect_err("mismatch refuses");
    assert!(matches!(
        err,
        AsMetadataError::IdentityMismatch { expected, actual }
            if expected == "https://as.example" && actual == "https://other.example"
    ));
}

#[tokio::test]
async fn refuses_a_served_document_without_a_token_endpoint() {
    let http = FakeHttp::ok(serde_json::json!({
        "issuer": "https://as.example",
        // No token_endpoint.
    }));
    assert!(matches!(
        discover_as_metadata(&http, "https://as.example", false).await,
        Err(AsMetadataError::NoTokenEndpoint)
    ));
}

#[tokio::test]
async fn guesses_endpoints_only_when_every_candidate_404s() {
    let http = FakeHttp::not_found();
    let metadata = discover_as_metadata(&http, "https://as.example", false)
        .await
        .expect("guessed");
    assert_eq!(metadata.token_endpoint, "https://as.example/token");
    assert_eq!(
        metadata.authorization_endpoint,
        "https://as.example/authorize"
    );
}

#[tokio::test]
async fn a_5xx_is_terminal_not_a_fallback() {
    struct ServerError;
    #[async_trait::async_trait]
    impl HttpClient for ServerError {
        async fn send(&self, _r: HttpRequest) -> Result<engine_ports::HttpResponse, HttpError> {
            Ok(engine_ports::HttpResponse {
                status: 500,
                headers: Vec::new(),
                body: Vec::new(),
            })
        }
    }
    assert!(matches!(
        discover_as_metadata(&ServerError, "https://as.example", false).await,
        Err(AsMetadataError::Status(500))
    ));
}

#[tokio::test]
async fn builds_candidates_in_order() {
    let http = FakeHttp::not_found();
    discover_as_metadata(&http, "https://as.example/path/", false)
        .await
        .expect("guessed");
    let candidates = http.calls.lock().expect("calls").clone();
    // The RFC 8414 path-insertion form comes first, with the
    // terminating slash removed (the RFC 8414-3.1 expectation);
    // the slash-kept form is the fallback. The OIDC discovery
    // form is appended after.
    assert_eq!(
        candidates[0],
        "https://as.example/.well-known/oauth-authorization-server/path"
    );
    assert!(candidates
        .iter()
        .any(|c| c == "https://as.example/.well-known/oauth-authorization-server/path/"));
    assert!(candidates
        .iter()
        .any(|c| c.contains("openid-configuration")));
}
