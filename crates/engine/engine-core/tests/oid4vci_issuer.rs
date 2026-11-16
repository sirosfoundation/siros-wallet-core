//! The issuer metadata resolution (OpenID4VCI 1.0 §12.2.2).

use engine_core::oid4vci::issuer::resolve_issuer_metadata;
use engine_core::oid4vci::types::{IssuerMetadataError, MetadataType};
use engine_ports::{FetchPurpose, HttpClient, HttpError, HttpRequest};

/// The issuer-metadata response limit of docs/engine-spec.md §OpenID4VCI
/// issuance.
const ISSUER_METADATA_LIMIT: usize = 10 * 1024 * 1024;

struct FakeHttp {
    body: Vec<u8>,
    status: u16,
    content_type: String,
}

#[async_trait::async_trait]
impl HttpClient for FakeHttp {
    async fn send(&self, request: HttpRequest) -> Result<engine_ports::HttpResponse, HttpError> {
        // Verify the declared purpose and size limit.
        assert_eq!(request.purpose, FetchPurpose::IssuerMetadata);
        assert_eq!(request.max_response_bytes, ISSUER_METADATA_LIMIT);
        Ok(engine_ports::HttpResponse {
            status: self.status,
            headers: vec![("content-type".to_owned(), self.content_type.clone())],
            body: self.body.clone(),
        })
    }
}

fn metadata_json() -> Vec<u8> {
    serde_json::json!({
        "credential_issuer": "https://issuer.example",
        "credential_configurations": {
            "UniversityDegree": { "format": "vc+sd-jwt" }
        }
    })
    .to_string()
    .into_bytes()
}

#[tokio::test]
async fn resolves_the_literal_form_with_a_trailing_slash() {
    // The issuer URL has a trailing slash; the path is kept as given.
    let http = FakeHttp {
        body: serde_json::json!({
            "credential_issuer": "https://issuer.example/path/",
            "credential_configurations": {}
        })
        .to_string()
        .into_bytes(),
        status: 200,
        content_type: "application/json".to_owned(),
    };
    let metadata = resolve_issuer_metadata(
        &http,
        "https://issuer.example/path/",
        MetadataType::PreferSigned,
        false,
    )
    .await
    .expect("resolve");
    assert_eq!(metadata.credential_issuer, "https://issuer.example/path/");
    assert!(!metadata.is_signed);
}

#[tokio::test]
async fn refuses_a_credential_issuer_mismatch() {
    let http = FakeHttp {
        body: serde_json::json!({
            "credential_issuer": "https://other.example",
            "credential_configurations": {}
        })
        .to_string()
        .into_bytes(),
        status: 200,
        content_type: "application/json".to_owned(),
    };
    let err = resolve_issuer_metadata(
        &http,
        "https://issuer.example",
        MetadataType::PreferSigned,
        false,
    )
    .await
    .expect_err("mismatch refuses");
    assert!(matches!(
        err,
        IssuerMetadataError::IdentityMismatch { expected, actual }
            if expected == "https://issuer.example" && actual == "https://other.example"
    ));
}

/// Answers 404 to every fetch and records the URLs asked for.
struct NotFoundHttp {
    urls: std::sync::Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl HttpClient for NotFoundHttp {
    async fn send(&self, request: HttpRequest) -> Result<engine_ports::HttpResponse, HttpError> {
        self.urls
            .lock()
            .map(|mut urls| urls.push(request.url.clone()))
            .ok();
        Ok(engine_ports::HttpResponse {
            status: 404,
            headers: Vec::new(),
            body: Vec::new(),
        })
    }
}

/// The URLs the resolution of `credential_issuer` fetches, in order.
async fn urls_fetched_for(credential_issuer: &str) -> Vec<String> {
    let http = NotFoundHttp {
        urls: std::sync::Mutex::new(Vec::new()),
    };
    assert!(matches!(
        resolve_issuer_metadata(&http, credential_issuer, MetadataType::Any, false).await,
        Err(IssuerMetadataError::Status(404))
    ));
    let urls = http.urls.lock().expect("urls").clone();
    urls
}

#[tokio::test]
async fn builds_the_literal_url_correctly() {
    assert_eq!(
        urls_fetched_for("https://issuer.example").await[0],
        "https://issuer.example/.well-known/openid-credential-issuer"
    );
    assert_eq!(
        urls_fetched_for("https://issuer.example/path/").await[0],
        "https://issuer.example/.well-known/openid-credential-issuer/path/"
    );
}

#[tokio::test]
async fn builds_the_fallback_url_with_one_slash_removed() {
    // The fallback removes one terminating slash from the LITERAL form,
    // not from the original credential_issuer URL. The spec says
    // "exactly one terminating slash removed" — from the literal URL.
    assert_eq!(
        urls_fetched_for("https://issuer.example/path/").await[1],
        "https://issuer.example/.well-known/openid-credential-issuer/path"
    );
    // No trailing slash: both forms are the same, fetched once.
    assert_eq!(
        urls_fetched_for("https://issuer.example").await,
        vec!["https://issuer.example/.well-known/openid-credential-issuer".to_owned()]
    );
}

#[tokio::test]
async fn resolves_the_unsigned_form() {
    let http = FakeHttp {
        body: metadata_json(),
        status: 200,
        content_type: "application/json".to_owned(),
    };
    let metadata =
        resolve_issuer_metadata(&http, "https://issuer.example", MetadataType::Any, false)
            .await
            .expect("resolve");
    assert_eq!(metadata.credential_issuer, "https://issuer.example");
    assert!(!metadata.is_signed);
}

#[tokio::test]
async fn refuses_a_non_200_answer() {
    let http = FakeHttp {
        body: Vec::new(),
        status: 500,
        content_type: "application/json".to_owned(),
    };
    assert!(matches!(
        resolve_issuer_metadata(
            &http,
            "https://issuer.example",
            MetadataType::PreferSigned,
            false
        )
        .await,
        Err(IssuerMetadataError::Status(500))
    ));
}
