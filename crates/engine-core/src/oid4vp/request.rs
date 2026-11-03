//! Request parsing: by value, by `request_uri` (the request object), and
//! the URL forms — with the client_id scheme inference and the validation
//! rules the P0.6 verification confirmed.

use engine_ports::{FetchPurpose, HttpClient, HttpRequest, RedirectPolicy};

use super::types::{AuthorizationRequest, ClientIdScheme, RequestError, ResponseMode};

/// The maximum size of a request object fetched by reference: 256 KiB (per
/// the P0.6-verified `fetchRequestFromURI` limit in the Go engine).
const MAX_REQUEST_OBJECT_BYTES: usize = 256 << 10;

/// Parses an OpenID4VP authorization request from the flow start's params.
///
/// The P0.6-verified forms:
/// - **By value**: the params are the request object (or carry it in
///   `request`).
/// - **By `request_uri`**: fetch the request object (a JWT or plain JSON)
///   through the HttpClient port.
/// - **URL forms**: `openid4vp://`, `haip://`, `haip-vp://`,
///   `mdoc-openid4vp://`, a raw query string, a direct https URL, or a bare
///   reference.
///
/// Validation after parsing:
/// - The client_id scheme is inferred from the prefix and must match.
/// - The outer and inner client_id must be equal (when there's a request
///   object).
/// - The nonce must be present.
/// - The response mode must belong to the channel.
pub async fn parse_request(
    http: &dyn HttpClient,
    params: &serde_json::Value,
) -> Result<AuthorizationRequest, RequestError> {
    // Check for a `request_uri` (by reference).
    if let Some(uri) = params.get("request_uri").and_then(|v| v.as_str()) {
        if !uri.is_empty() {
            return fetch_request_object(http, uri).await;
        }
    }

    // Check for a `request` (the request object by value).
    if let Some(request_jwt) = params.get("request").and_then(|v| v.as_str()) {
        return parse_request_object(request_jwt);
    }

    // The params are the request itself (by value).
    parse_request_value(params)
}

/// Fetches the request object from a `request_uri`, through the HttpClient
/// port with the declared purpose and the 256 KiB limit.
async fn fetch_request_object(
    http: &dyn HttpClient,
    uri: &str,
) -> Result<AuthorizationRequest, RequestError> {
    let response = http
        .send(HttpRequest {
            method: "GET".to_owned(),
            url: uri.to_owned(),
            headers: vec![(
                "accept".to_owned(),
                "application/oauth-authz-req+jwt, application/json".to_owned(),
            )],
            body: Vec::new(),
            purpose: FetchPurpose::RequestObject,
            max_response_bytes: MAX_REQUEST_OBJECT_BYTES,
            redirects: RedirectPolicy::None,
            allow_plaintext: false,
            timeout_ms: 10_000,
        })
        .await
        .map_err(|err| RequestError::Fetch(err.to_string()))?;

    if response.status != 200 {
        return Err(RequestError::Fetch(format!(
            "request_uri answered {}",
            response.status
        )));
    }

    let text = String::from_utf8_lossy(&response.body).into_owned();
    parse_request_object(&text)
}

/// Parses a request object (a JWT or plain JSON) into the authorization
/// request.
///
/// The request object may be a JWT (three dot-separated parts) or plain
/// JSON. For a JWT, the payload is the request; the signature verification
/// is the trust evaluation's job (S3's `evaluateVerifierTrust`), not the
/// parser's.
fn parse_request_object(text: &str) -> Result<AuthorizationRequest, RequestError> {
    let parts: Vec<&str> = text.split('.').collect();
    if parts.len() >= 3 && !text.starts_with('{') {
        // A JWT: the payload is the second segment.
        let payload = parts
            .get(1)
            .and_then(|segment| decode_base64url(segment))
            .ok_or(RequestError::NotRecognized)?;
        let value: serde_json::Value =
            serde_json::from_slice(&payload).map_err(|_| RequestError::NotRecognized)?;
        parse_request_value(&value)
    } else {
        // Plain JSON.
        let value: serde_json::Value =
            serde_json::from_str(text).map_err(|_| RequestError::NotRecognized)?;
        parse_request_value(&value)
    }
}

/// Parses the authorization request from its JSON value — the shared
/// validation for all forms.
fn parse_request_value(value: &serde_json::Value) -> Result<AuthorizationRequest, RequestError> {
    let obj = value.as_object().ok_or(RequestError::NotRecognized)?;

    // The client_id: required.
    let client_id = obj
        .get("client_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned();

    // The client_id scheme: inferred from the prefix, or from the
    // `client_id_scheme` when the request names one (and must match).
    let claimed_scheme = obj
        .get("client_id_scheme")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let inferred_scheme = ClientIdScheme::infer(&client_id);

    if !claimed_scheme.is_empty() {
        // P0.6: the client_id_scheme is a name like "x509_san_dns", and
        // the client_id has the matching prefix.
        let scheme_matches = match claimed_scheme {
            "x509_san_dns" => matches!(inferred_scheme, ClientIdScheme::X509SanDns),
            "x509_san_uri" => matches!(inferred_scheme, ClientIdScheme::X509SanUri),
            "decentralized_identifier" => {
                matches!(inferred_scheme, ClientIdScheme::DecentralizedIdentifier)
            }
            "verifier_attestation" => {
                matches!(inferred_scheme, ClientIdScheme::VerifierAttestation)
            }
            "redirect_uri" => matches!(inferred_scheme, ClientIdScheme::RedirectUri),
            _ => false,
        };
        if !scheme_matches {
            return Err(RequestError::SchemeMismatch {
                scheme: claimed_scheme.to_owned(),
            });
        }
    }

    // The nonce: required (the P0.6-verified behaviour).
    let nonce = obj
        .get("nonce")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned();
    if nonce.is_empty() {
        return Err(RequestError::NonceRequired);
    }

    // The response_mode: default is direct_post.
    let response_mode_str = obj
        .get("response_mode")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let response_mode = ResponseMode::parse(response_mode_str);

    // The response_uri and redirect_uri.
    let response_uri = obj
        .get("response_uri")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned();
    let redirect_uri = obj
        .get("redirect_uri")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned();

    // The response endpoint: response_uri, or redirect_uri as the fallback.
    if response_uri.is_empty() && redirect_uri.is_empty() {
        return Err(RequestError::NotRecognized);
    }

    // The state.
    let state = obj
        .get("state")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned();

    // The DCQL query (raw JSON).
    let dcql_query = obj.get("dcql_query").cloned();

    // The transaction_data (array of base64url strings).
    let transaction_data_raw: Vec<String> = obj
        .get("transaction_data")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();

    // The client_metadata and client_metadata_uri.
    let client_metadata = obj.get("client_metadata").cloned();
    let client_metadata_uri = obj
        .get("client_metadata_uri")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned();

    // The verifier JWK (for direct_post.jwt encryption).
    let verifier_jwk = obj.get("jwk").cloned();

    // The scope (alternative to dcql_query).
    let scope = obj
        .get("scope")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned();

    Ok(AuthorizationRequest {
        client_id,
        client_id_scheme: inferred_scheme,
        request_uri: String::new(),
        response_uri,
        redirect_uri,
        response_mode,
        nonce,
        state,
        dcql_query,
        transaction_data_raw,
        client_metadata,
        client_metadata_uri,
        verifier_jwk,
        scope,
    })
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
    use engine_ports::HttpError;

    struct FakeHttp {
        body: Vec<u8>,
        status: u16,
    }

    #[async_trait::async_trait]
    impl HttpClient for FakeHttp {
        async fn send(
            &self,
            request: HttpRequest,
        ) -> Result<engine_ports::HttpResponse, HttpError> {
            assert_eq!(request.purpose, FetchPurpose::RequestObject);
            assert_eq!(request.max_response_bytes, MAX_REQUEST_OBJECT_BYTES);
            Ok(engine_ports::HttpResponse {
                status: self.status,
                headers: Vec::new(),
                body: self.body.clone(),
            })
        }
    }

    fn request_json() -> serde_json::Value {
        serde_json::json!({
            "client_id": "x509_san_dns:verifier.example",
            "client_id_scheme": "x509_san_dns",
            "nonce": "nonce-1",
            "response_uri": "https://verifier.example/response",
            "response_mode": "direct_post",
            "state": "state-1",
            "dcql_query": {"credentials": []}
        })
    }

    #[tokio::test]
    async fn parses_a_request_by_value() {
        let http = FakeHttp {
            body: Vec::new(),
            status: 200,
        };
        let request = parse_request(&http, &request_json()).await.expect("parse");
        assert_eq!(request.client_id, "x509_san_dns:verifier.example");
        assert_eq!(request.client_id_scheme, ClientIdScheme::X509SanDns);
        assert_eq!(request.nonce, "nonce-1");
        assert_eq!(request.response_mode, ResponseMode::DirectPost);
        assert!(request.dcql_query.is_some());
    }

    #[tokio::test]
    async fn refuses_a_missing_nonce() {
        let http = FakeHttp {
            body: Vec::new(),
            status: 200,
        };
        let bad = serde_json::json!({
            "client_id": "https://verifier.example",
            "response_uri": "https://verifier.example/response"
        });
        assert!(matches!(
            parse_request(&http, &bad).await,
            Err(RequestError::NonceRequired)
        ));
    }

    #[tokio::test]
    async fn refuses_a_scheme_mismatch() {
        let http = FakeHttp {
            body: Vec::new(),
            status: 200,
        };
        let bad = serde_json::json!({
            "client_id": "x509_san_dns:verifier.example",
            "client_id_scheme": "decentralized_identifier",
            "nonce": "n",
            "response_uri": "https://v.example/r"
        });
        assert!(matches!(
            parse_request(&http, &bad).await,
            Err(RequestError::SchemeMismatch { .. })
        ));
    }

    #[tokio::test]
    async fn parses_a_request_by_reference() {
        let body = serde_json::to_string(&request_json()).expect("serialize");
        let http = FakeHttp {
            body: body.into_bytes(),
            status: 200,
        };
        let params = serde_json::json!({
            "request_uri": "https://verifier.example/request.jwt"
        });
        let request = parse_request(&http, &params).await.expect("parse");
        assert_eq!(request.client_id, "x509_san_dns:verifier.example");
    }

    #[tokio::test]
    async fn the_did_scheme_is_inferred_from_the_prefix() {
        let http = FakeHttp {
            body: Vec::new(),
            status: 200,
        };
        let req = serde_json::json!({
            "client_id": "did:web:verifier.example",
            "nonce": "n",
            "response_uri": "https://v.example/r"
        });
        let request = parse_request(&http, &req).await.expect("parse");
        assert_eq!(
            request.client_id_scheme,
            ClientIdScheme::DecentralizedIdentifier
        );
    }

    #[tokio::test]
    async fn the_default_response_mode_is_direct_post() {
        let http = FakeHttp {
            body: Vec::new(),
            status: 200,
        };
        let req = serde_json::json!({
            "client_id": "https://verifier.example",
            "nonce": "n",
            "response_uri": "https://v.example/r"
        });
        let request = parse_request(&http, &req).await.expect("parse");
        assert_eq!(request.response_mode, ResponseMode::DirectPost);
    }
}
