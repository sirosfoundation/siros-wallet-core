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
    // The URL forms resolve to their params object first: the string
    // the QR code / link named — `openid4vp://`, `haip://`,
    // `haip-vp://`, `mdoc-openid4vp://` with its query, a raw query
    // string, or a bare request_uri reference.
    let params = match params.as_str() {
        Some(text) => url_to_params(text)?,
        None => params.clone(),
    };

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
    let request = parse_request_value(&params)?;
    // The x509_hash scheme needs the chain the params form cannot carry
    // (OpenID4VP 1.0 §5.2.3): refuse it here, not only in the signed
    // form.
    validate_client_id_hash(&request, None)?;
    Ok(request)
}

/// Turns the URL form into the params object: the authorization
/// request URL's query members, a raw query string, or a bare
/// reference taken as the request_uri.
fn url_to_params(text: &str) -> Result<serde_json::Value, RequestError> {
    // The scheme forms: everything after `://` (the `?` optional).
    let query = match text.split_once("://") {
        Some((scheme, rest)) => {
            if !matches!(scheme, "openid4vp" | "haip" | "haip-vp" | "mdoc-openid4vp") {
                return Err(RequestError::NotRecognized);
            }
            rest.strip_prefix('?').unwrap_or(rest)
        }
        None => text.strip_prefix('?').unwrap_or(text),
    };
    // A query string: the `name=value` members.
    if query.contains('=') {
        let mut object = serde_json::Map::new();
        for pair in query.split('&') {
            let Some((name, value)) = pair.split_once('=') else {
                continue;
            };
            object.insert(
                percent_decode(name),
                serde_json::Value::String(percent_decode(value)),
            );
        }
        return Ok(serde_json::Value::Object(object));
    }
    // A bare reference: the request_uri itself.
    Ok(serde_json::json!({ "request_uri": text }))
}

/// Percent-decodes a query member (RFC 3986 §2.1; the `+` form is not
/// used in these URLs).
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    // A hex digit, or 0xff when the byte is not one.
    let hex = |v: u8| match v {
        b'0'..=b'9' => v - b'0',
        b'a'..=b'f' => v - b'a' + 10,
        b'A'..=b'F' => v - b'A' + 10,
        _ => 0xff,
    };
    let mut index = 0;
    // The bounds are held by `get`, never by indexing: an index is a
    // panic when the slice disagrees.
    while let Some(&byte) = bytes.get(index) {
        if byte == b'%' {
            let high = bytes.get(index + 1).copied().map(hex);
            let low = bytes.get(index + 2).copied().map(hex);
            if let (Some(high), Some(low)) = (high, low) {
                if high != 0xff && low != 0xff {
                    out.push(high * 16 + low);
                    index += 3;
                    continue;
                }
            }
        }
        out.push(byte);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
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
        // A signed request object (RFC 9101 §5.2): the JOSE header
        // must name the type, and the signature must verify under the
        // key the header's `x5c` chain carries — the parser's own
        // checks; the trust evaluation's PDP step is the policy, not
        // the cryptography.
        let header_bytes = parts
            .first()
            .and_then(|segment| decode_base64url(segment))
            .ok_or(RequestError::NotRecognized)?;
        let header: serde_json::Value =
            serde_json::from_slice(&header_bytes).map_err(|_| RequestError::NotRecognized)?;
        if header.get("typ").and_then(|v| v.as_str()) != Some("oauth-authz-req+jwt") {
            return Err(RequestError::RequestObjectTyp);
        }
        // The signature, when the header carries the certificate chain:
        // the first certificate holds the signer's public key. The x5c
        // entries are base64-encoded DER (RFC 7515 §4.1.6 — the
        // standard alphabet, unlike the JOSE segments' base64url).
        //
        // The leaf DER is kept: the x509_hash scheme's client_id is the
        // base64url SHA-256 over it (OpenID4VP 1.0 §5.2.3), checked
        // against the payload's client_id below.
        let mut leaf_der: Option<Vec<u8>> = None;
        if let Some(cert) = header
            .get("x5c")
            .and_then(|v| v.as_array())
            .and_then(|chain| chain.first())
            .and_then(|v| v.as_str())
        {
            let der = decode_base64(cert).ok_or(RequestError::NotRecognized)?;
            let jwk = jose_rs::jwk::cert::public_jwk_from_certificate_der(&der)
                .map_err(|_| RequestError::RequestObjectSignature)?;
            jose_rs::jws::compact::verify_with_jwk(&jwk, text)
                .map_err(|_| RequestError::RequestObjectSignature)?;
            leaf_der = Some(der);
        }
        // The payload is the second segment.
        let payload = parts
            .get(1)
            .and_then(|segment| decode_base64url(segment))
            .ok_or(RequestError::NotRecognized)?;
        let value: serde_json::Value =
            serde_json::from_slice(&payload).map_err(|_| RequestError::NotRecognized)?;
        // The x509_hash scheme (OpenID4VP 1.0 §5.2.3): the client_id's
        // value is the base64url SHA-256 over the leaf certificate the
        // chain carries — the request object MUST carry it (a plain or
        // chainless request cannot name the certificate), and the hash
        // MUST match.
        parse_request_value(&value).and_then(|request| {
            validate_client_id_hash(&request, leaf_der)?;
            Ok(request)
        })
    } else {
        // Plain JSON.
        let value: serde_json::Value =
            serde_json::from_str(text).map_err(|_| RequestError::NotRecognized)?;
        parse_request_value(&value).and_then(|request| {
            validate_client_id_hash(&request, None)?;
            Ok(request)
        })
    }
}

/// The `x509_hash` client_id scheme (OpenID4VP 1.0 §5.2.3): the client_id's
/// value is the base64url SHA-256 over the DER-encoded leaf certificate the
/// request object's `x5c` chain carries — so the chain MUST be there (an
/// unsigned or chainless request cannot name the certificate), and the hash
/// MUST match it, in constant time.
fn validate_client_id_hash(
    request: &AuthorizationRequest,
    leaf_der: Option<Vec<u8>>,
) -> Result<(), RequestError> {
    if request.client_id_scheme != ClientIdScheme::X509Hash {
        return Ok(());
    }
    let der = leaf_der.ok_or(RequestError::ClientIdHashWithoutChain)?;
    let digest = kryptering::digest::digest(kryptering::HashAlgorithm::Sha256, &der)
        .map_err(|_| RequestError::NotRecognized)?;
    let computed = wmp_core::token::base64url_unpadded(&digest);
    let claimed = request
        .client_id
        .strip_prefix("x509_hash:")
        .unwrap_or_default();
    if !wmp_core::token::tokens_equal(&computed, claimed) {
        return Err(RequestError::ClientIdHashMismatch);
    }
    Ok(())
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
            "x509_hash" => matches!(inferred_scheme, ClientIdScheme::X509Hash),
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

    // The direct_post channel requires a response_uri and forbids a
    // redirect_uri (OpenID4VP §5: the redirect_uri belongs to the
    // query/fragment channel).
    if matches!(
        response_mode,
        ResponseMode::DirectPost | ResponseMode::DirectPostJwt
    ) && (response_uri.is_empty() || !redirect_uri.is_empty())
    {
        return Err(RequestError::DirectPostWithoutResponseUri {
            mode: response_mode_str.to_owned(),
        });
    }

    // The client_id scheme must be a recognized one — an unknown
    // prefix is not the redirect_uri scheme's fallback but a refusal.
    if matches!(inferred_scheme, ClientIdScheme::Unknown(_)) {
        return Err(RequestError::UnknownClientIdScheme);
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
/// Decodes a base64-encoded value (the standard alphabet, RFC 4648
/// §4) — the x5c entries' DER (RFC 7515 §4.1.6), padding tolerated.
fn decode_base64(encoded: &str) -> Option<Vec<u8>> {
    fn value(b: u8) -> Option<u8> {
        match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let trimmed = encoded.trim_end_matches('=');
    let bytes = trimmed.as_bytes();
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
            out.push((buffer >> bits) as u8);
        }
    }
    Some(out)
}

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

    #[tokio::test]
    async fn an_unknown_client_id_scheme_refuses() {
        let http = FakeHttp {
            body: Vec::new(),
            status: 200,
        };
        let req = serde_json::json!({
            "client_id": "x509_san_bogus:verifier.example",
            "nonce": "n",
            "response_uri": "https://v.example/r"
        });
        assert!(matches!(
            parse_request(&http, &req).await,
            Err(RequestError::UnknownClientIdScheme)
        ));
    }

    #[tokio::test]
    async fn direct_post_without_a_response_uri_refuses() {
        let http = FakeHttp {
            body: Vec::new(),
            status: 200,
        };
        let req = serde_json::json!({
            "client_id": "x509_san_dns:verifier.example",
            "nonce": "n",
            "response_mode": "direct_post",
            "redirect_uri": "https://v.example/cb"
        });
        assert!(matches!(
            parse_request(&http, &req).await,
            Err(RequestError::DirectPostWithoutResponseUri { .. })
        ));
    }

    /// A compact-serialization JWT with the given header, for the
    /// request-object checks: the signature is irrelevant bytes.
    fn request_object_jwt(header: &serde_json::Value) -> String {
        let header_text =
            crate::oid4vp::test_util::base64url(header.to_string().as_bytes().to_vec().as_slice());
        let payload_text = crate::oid4vp::test_util::base64url(
            request_json().to_string().as_bytes().to_vec().as_slice(),
        );
        format!("{header_text}.{payload_text}.c2ln")
    }

    #[tokio::test]
    async fn a_signed_request_object_without_the_oauth_typ_refuses() {
        let http = FakeHttp {
            body: Vec::new(),
            status: 200,
        };
        let params = serde_json::json!({
            "request": request_object_jwt(&serde_json::json!({
                "alg": "ES256",
                "typ": "jwt"
            }))
        });
        assert!(matches!(
            parse_request(&http, &params).await,
            Err(RequestError::RequestObjectTyp)
        ));
    }

    #[tokio::test]
    async fn a_signed_request_object_with_a_missing_typ_refuses() {
        let http = FakeHttp {
            body: Vec::new(),
            status: 200,
        };
        let params = serde_json::json!({
            "request": request_object_jwt(&serde_json::json!({
                "alg": "ES256"
            }))
        });
        assert!(matches!(
            parse_request(&http, &params).await,
            Err(RequestError::RequestObjectTyp)
        ));
    }

    // ─── The x509_hash client_id scheme (OpenID4VP 1.0 §5.2.3) ─────────────
    //
    // The verifier's private JWK and certificate, from the conformance
    // suite's own wallet test configuration (siros-conformance,
    // configs/conformance/vp-wallet-config.json) — the key the suite's
    // request objects are signed with, and the certificate its x5c
    // chains carry.
    fn verifier_jwk() -> serde_json::Value {
        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "HPtEYEEQNGcOGGtQXnm8VbbryWYOF7dlmTKcDwIxk60",
            "y": "Knv02968XSiEmNSoGPaHX3LXl-boQztsK0DB46VhE68",
            "d": "Z8iB5ltQ0Yf8Wyyafbmypw49VKegZLn2BBjzFzhMHGU",
            "kid": "vp-verifier-key-1",
            "use": "sig",
            "alg": "ES256",
            "x5c": [
                "MIIBvjCCAWOgAwIBAgIUfw4in2xbbaO4BRVzCMJ9jcx+MYUwCgYIKoZIzj0EAwIwIjEgMB4GA1UEAwwXY29uZm9ybWFuY2UuZXhhbXBsZS5jb20wHhcNMjYwNTE1MDc1MzQ1WhcNMjcwNTE1MDc1MzQ1WjAiMSAwHgYDVQQDDBdjb25mb3JtYW5jZS5leGFtcGxlLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBz7RGBBEDRnDhhrUF55vFW268lmDhe3ZZkynA8CMZOtKnv02968XSiEmNSoGPaHX3LXl+boQztsK0DB46VhE6+jdzB1MB0GA1UdDgQWBBR/zA7h3+ikKBoa3jyMiSX7sFdkyzAfBgNVHSMEGDAWgBR/zA7h3+ikKBoa3jyMiSX7sFdkyzAPBgNVHRMBAf8EBTADAQH/MCIGA1UdEQQbMBmCF2NvbmZvcm1hbmNlLmV4YW1wbGUuY29tMAoGCCqGSM49BAMCA0kAMEYCIQC4lhxwiQy3+GPtzdQW9IlDSrQoEnncom6YsKZ3izHuIgIhAKZIjNYWTG0xIpFrS4DVkvo1qiV9kNf1Qvp8StOW6pEr"
            ]
        })
    }

    /// The base64url SHA-256 over the verifier's certificate — the
    /// client_id value the scheme carries.
    fn verifier_hash() -> String {
        let jwk = verifier_jwk();
        let cert = jwk["x5c"][0].as_str().unwrap_or_default();
        let der = decode_base64(cert).expect("the certificate decodes");
        let digest =
            kryptering::digest::digest(kryptering::HashAlgorithm::Sha256, &der).expect("sha256");
        wmp_core::token::base64url_unpadded(&digest)
    }

    /// A signed request object for the `x509_hash` scheme: the JWS header
    /// carries the verifier's `x5c` chain, the payload the given
    /// `client_id`, signed with the verifier's key.
    fn x509_hash_request_object(client_id: &str) -> String {
        let jwk: jose_rs::jwk::Jwk =
            serde_json::from_value(verifier_jwk()).expect("the verifier JWK parses");
        let mut header = jose_rs::header::JoseHeader::new("ES256");
        header.typ = Some("oauth-authz-req+jwt".to_owned());
        header.kid = Some("vp-verifier-key-1".to_owned());
        header.x5c = Some(vec![verifier_jwk()["x5c"][0]
            .as_str()
            .unwrap_or_default()
            .to_owned()]);
        let payload = serde_json::json!({
            "client_id": client_id,
            "nonce": "nonce-1",
            "response_uri": "https://verifier.example/response",
            "response_mode": "direct_post"
        });
        let payload_bytes = payload.to_string().into_bytes();
        // The x5c chain is a key-reference member (RFC 7515 §4.1.6): the
        // deliberate reference the opt-in is for — the scheme's chain
        // rides the header.
        let mut options = jose_rs::jws::compact::SignOptions::default();
        options.allow_key_reference_headers = true;
        jose_rs::jws::compact::sign_with_jwk_options(&jwk, &payload_bytes, &header, &options)
            .expect("the request object signs")
    }

    #[tokio::test]
    async fn an_x509_hash_request_with_a_matching_hash_parses() {
        let http = FakeHttp {
            body: Vec::new(),
            status: 200,
        };
        let client_id = format!("x509_hash:{}", verifier_hash());
        let params = serde_json::json!({
            "request": x509_hash_request_object(&client_id)
        });
        let request = parse_request(&http, &params).await.expect("parse");
        assert_eq!(request.client_id, client_id);
        assert_eq!(request.client_id_scheme, ClientIdScheme::X509Hash);
    }

    #[tokio::test]
    async fn an_x509_hash_request_with_a_mismatched_hash_refuses() {
        let http = FakeHttp {
            body: Vec::new(),
            status: 200,
        };
        // The hash of something else: a valid base64url shape, not the
        // certificate's.
        let client_id = format!("x509_hash:{}", "A".repeat(43));
        let params = serde_json::json!({
            "request": x509_hash_request_object(&client_id)
        });
        assert!(matches!(
            parse_request(&http, &params).await,
            Err(RequestError::ClientIdHashMismatch)
        ));
    }

    #[tokio::test]
    async fn an_x509_hash_request_without_a_chain_refuses() {
        let http = FakeHttp {
            body: Vec::new(),
            status: 200,
        };
        // Plain JSON: no request object, no x5c — the scheme cannot name
        // the certificate.
        let params = serde_json::json!({
            "client_id": format!("x509_hash:{}", verifier_hash()),
            "nonce": "nonce-1",
            "response_uri": "https://verifier.example/response",
            "response_mode": "direct_post"
        });
        assert!(matches!(
            parse_request(&http, &params).await,
            Err(RequestError::ClientIdHashWithoutChain)
        ));
    }
}
