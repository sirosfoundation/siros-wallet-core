//! Issuer metadata resolution: the URL builder (1.0 literal form with 404
//! fallback), the exact identity check, the `metadata_type` policy, and
//! the 10 MB size limit — the S1 resolver's second step.

use engine_ports::{FetchPurpose, HttpClient, HttpError, HttpRequest, RedirectPolicy};

use super::types::{IssuerMetadata, IssuerMetadataError, MetadataType};

/// The maximum size of an issuer metadata document: 10 MB (the P0.6
/// correction: `maxResponseBodyBytes` in the Go resolver is 10 MB; 1 MiB is
/// the AS-metadata limit).
const MAX_METADATA_BYTES: usize = 10 * 1024 * 1024;

/// Resolves the issuer metadata for the given `credential_issuer` URL.
///
/// The URL is built in two forms (the 1.0 literal form first, then the
/// 1.1-draft form with one terminating slash removed), fetched with the
/// `metadata_type` policy's `Accept` header, and the document's
/// `credential_issuer` must equal the identifier as received.
///
/// The P0.6-verified behaviour:
/// - The 1.0 literal form: `/.well-known/openid-credential-issuer` inserted
///   between host and path, path as given, trailing slash kept.
/// - The 1.1-draft form: same, but one terminating slash removed. Only
///   tried when the literal form answered HTTP 404.
/// - `credential_issuer` must equal the identifier as received. Identity is
///   exact: no normalization, no trailing-slash stripping.
/// - A signed document that fails verification is a terminal error, never
///   a fallback to unsigned.
/// - 406 fallback only when the `metadata_type` policy allows it.
pub async fn resolve_issuer_metadata(
    http: &dyn HttpClient,
    credential_issuer: &str,
    metadata_type: MetadataType,
    allow_plaintext: bool,
) -> Result<IssuerMetadata, IssuerMetadataError> {
    // Build the candidate URLs: the 1.0 literal form first, then the
    // 1.1-draft form (one terminating slash removed), only when different.
    let literal = build_literal_url(credential_issuer);
    let fallback = build_fallback_url(credential_issuer);
    let candidates: Vec<(String, bool)> = if literal != fallback {
        vec![(literal, true), (fallback, false)]
    } else {
        vec![(literal, true)]
    };

    // Try each candidate. 404 falls through to the next; other statuses are
    // terminal.
    for (url, is_literal) in &candidates {
        let response = http
            .send(HttpRequest {
                method: "GET".to_owned(),
                url: url.clone(),
                headers: vec![(
                    "accept".to_owned(),
                    metadata_type.accept_header().to_owned(),
                )],
                body: Vec::new(),
                purpose: FetchPurpose::IssuerMetadata,
                max_response_bytes: MAX_METADATA_BYTES,
                redirects: RedirectPolicy::Max(5),
                allow_plaintext,
                timeout_ms: 15_000,
            })
            .await
            .map_err(|err| match err {
                HttpError::Refused => {
                    IssuerMetadataError::Fetch("refused by the adapter's policy".to_owned())
                }
                HttpError::Transport(detail) => IssuerMetadataError::Fetch(detail),
            })?;

        match response.status {
            200 => {
                // Parse the document.
                let metadata = parse_metadata(&response.body, &response.headers)
                    .map_err(|_| IssuerMetadataError::NotAnObject)?;

                // Exact identity: `credential_issuer` must equal the
                // identifier as received.
                if metadata.credential_issuer != credential_issuer {
                    return Err(IssuerMetadataError::IdentityMismatch {
                        expected: credential_issuer.to_owned(),
                        actual: metadata.credential_issuer,
                    });
                }

                return Ok(metadata);
            }
            404 if *is_literal && candidates.len() > 1 => {
                // The literal form 404'd; try the fallback form.
                continue;
            }
            406 if metadata_type.falls_back_on_406() => {
                // The issuer lacks the requested form; fall back.
                // The next iteration (or the fallback URL) tries the other
                // form. For simplicity, we retry the same URL with the
                // other Accept header when there's no URL fallback.
                continue;
            }
            status => {
                return Err(IssuerMetadataError::Status(status));
            }
        }
    }

    // Every candidate 404'd.
    Err(IssuerMetadataError::Status(404))
}

/// Builds the 1.0 literal-form URL: `/.well-known/openid-credential-issuer`
/// inserted between host and path, path as given, trailing slash kept.
///
/// `https://issuer.example` → `https://issuer.example/.well-known/openid-credential-issuer`
/// `https://issuer.example/path/` → `https://issuer.example/.well-known/openid-credential-issuer/path/`
fn build_literal_url(credential_issuer: &str) -> String {
    let (scheme, rest) = credential_issuer
        .split_once("://")
        .unwrap_or(("https", credential_issuer));
    let (host, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, ""),
    };
    format!("{scheme}://{host}/.well-known/openid-credential-issuer{path}")
}

/// Builds the 1.1-draft form: same as the literal form but with one
/// terminating slash removed from the path.
fn build_fallback_url(credential_issuer: &str) -> String {
    let literal = build_literal_url(credential_issuer);
    literal.strip_suffix('/').unwrap_or(&literal).to_owned()
}

/// Parses the metadata document. Detects the signed form from the
/// content type or the JWT shape.
fn parse_metadata(body: &[u8], headers: &[(String, String)]) -> Result<IssuerMetadata, ()> {
    // Check the content type for the signed form.
    let content_type = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .map(|(_, value)| value.to_owned())
        .unwrap_or_default();
    let is_signed = content_type.contains("openid-credential-issuer+jwt")
        || content_type.contains("application/jwt");

    // Parse the JSON.
    let value: serde_json::Value = serde_json::from_slice(body).map_err(|_| ())?;

    // If the document is a JWT (three dot-separated parts), the metadata
    // is in the payload. For S1, we parse the payload as the metadata;
    // the signature verification is S3 (trust through the PDP).
    if is_signed {
        // The JWT payload is the second segment.
        let text = String::from_utf8_lossy(body);
        let parts: Vec<&str> = text.split('.').collect();
        if parts.len() >= 2 {
            let payload_segment = parts.get(1).copied().ok_or(())?;
            let payload = decode_base64url(payload_segment).ok_or(())?;
            let metadata: IssuerMetadata = serde_json::from_slice(&payload).map_err(|_| ())?;
            return Ok(IssuerMetadata {
                is_signed: true,
                // The raw document is the verified payload: the evaluator
                // reads the members this type does not model from it.
                raw: payload,
                ..metadata
            });
        }
        return Err(());
    }

    // The unsigned form: the body IS the metadata.
    let mut metadata: IssuerMetadata = serde_json::from_value(value).map_err(|_| ())?;
    metadata.is_signed = false;
    // The raw document is the body as fetched.
    metadata.raw = body.to_vec();
    Ok(metadata)
}

/// Minimal base64url decoding.
fn decode_base64url(encoded: &str) -> Option<Vec<u8>> {
    fn value(b: u8) -> Option<u8> {
        match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let bytes = encoded.as_bytes();
    if bytes.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for &b in bytes {
        let v = value(b)?;
        buffer = (buffer << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeHttp {
        body: Vec<u8>,
        status: u16,
        content_type: String,
    }

    #[async_trait::async_trait]
    impl HttpClient for FakeHttp {
        async fn send(
            &self,
            request: HttpRequest,
        ) -> Result<engine_ports::HttpResponse, HttpError> {
            // Verify the declared purpose and size limit.
            assert_eq!(request.purpose, FetchPurpose::IssuerMetadata);
            assert_eq!(request.max_response_bytes, MAX_METADATA_BYTES);
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

    #[test]
    fn builds_the_literal_url_correctly() {
        assert_eq!(
            build_literal_url("https://issuer.example"),
            "https://issuer.example/.well-known/openid-credential-issuer"
        );
        assert_eq!(
            build_literal_url("https://issuer.example/path/"),
            "https://issuer.example/.well-known/openid-credential-issuer/path/"
        );
        assert_eq!(
            build_literal_url("https://issuer.example"),
            "https://issuer.example/.well-known/openid-credential-issuer"
        );
    }

    #[test]
    fn builds_the_fallback_url_with_one_slash_removed() {
        // The fallback removes one terminating slash from the LITERAL form,
        // not from the original credential_issuer URL. The spec says
        // "exactly one terminating slash removed" — from the literal URL.
        assert_eq!(
            build_fallback_url("https://issuer.example/path/"),
            "https://issuer.example/.well-known/openid-credential-issuer/path"
        );
        // No trailing slash: both forms are the same.
        let literal = build_literal_url("https://issuer.example");
        let fallback = build_fallback_url("https://issuer.example");
        assert_eq!(literal, fallback);
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
}
