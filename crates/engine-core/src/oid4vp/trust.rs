//! Verifier trust: the client metadata (fetched or inline, raw preserved),
//! the verifier info, the PDP evaluate call with the fail-closed rule, and
//! the §5 validations (the response_uri origin, the outer/inner client_id
//! match) — the OID4VP mirror of S3's issuer trust evaluation.

use engine_ports::{
    EvaluationRequest, FetchPurpose, HttpClient, HttpRequest, Pdp, PdpError, RedirectPolicy,
};

use super::types::{AuthorizationRequest, ClientIdScheme};

/// The maximum size of a client metadata document: 1 MiB. The Go engine
/// reads this stream unbounded (a Go bug class the sans-network core
/// closes); every fetch the core makes declares a bound.
const MAX_CLIENT_METADATA_BYTES: usize = 1 << 20;

/// The client metadata (OpenID4VP §5.2), with the raw document preserved
/// so the host UI can show exactly what the verifier published.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ClientMetadata {
    /// `client_name` — the verifier's display name.
    #[serde(default)]
    pub client_name: String,
    /// `logo_uri` — the verifier's logo.
    #[serde(default)]
    pub logo_uri: String,
    /// The `jwks` object, when the metadata carries one (the JARM
    /// encryption key source for direct_post.jwt).
    #[serde(default)]
    pub jwks: Option<serde_json::Value>,
    /// The whole raw document, exactly as fetched or as received inline.
    pub raw: serde_json::Value,
}

impl ClientMetadata {
    /// Parses the client metadata from its raw JSON document.
    pub fn parse(raw: serde_json::Value) -> Option<Self> {
        if !raw.is_object() {
            return None;
        }
        let client_name = raw
            .get("client_name")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned();
        let logo_uri = raw
            .get("logo_uri")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned();
        let jwks = raw.get("jwks").cloned();
        Some(Self {
            client_name,
            logo_uri,
            jwks,
            raw,
        })
    }
}

/// The verifier info — the wire contract lives in engine-ports.
pub use engine_ports::VerifierInfo;

/// Why the verifier trust evaluation refused.
#[derive(Debug, thiserror::Error)]
pub enum TrustError {
    /// The client metadata fetch failed (the flow continues without the
    /// metadata — the Go behaviour — but the name falls back to the
    /// client_id).
    #[error("oid4vp: client metadata fetch failed: {0}")]
    MetadataFetch(String),
    /// The outer and inner client_id disagree (RFC 9101 §5.2).
    #[error("oid4vp: client_id mismatch: the URL has {url:?} but the request object has {request_object:?}")]
    ClientIdMismatch {
        /// The client_id the request URI carried.
        url: String,
        /// The client_id the request object carried.
        request_object: String,
    },
    /// The response_uri origin does not match the request_uri origin
    /// (OpenID4VP §5, x509_san_dns with direct_post only).
    #[error(
        "oid4vp: response_uri origin {response:?} does not match request_uri origin {request:?}"
    )]
    OriginMismatch {
        /// The response_uri's origin.
        response: String,
        /// The request_uri's origin.
        request: String,
    },
    /// The PDP is unreachable; the engine fails closed.
    #[error("oid4vp: PDP unreachable")]
    PdpUnreachable,
    /// The PDP answered an error; the engine fails closed.
    #[error("oid4vp: PDP error: {0}")]
    PdpError(String),
    /// The PDP answered untrusted; the flow refuses.
    #[error("oid4vp: untrusted verifier {verifier}: {reason}")]
    Untrusted {
        /// The verifier that was refused.
        verifier: String,
        /// The PDP's reason.
        reason: String,
    },
}

/// Fetches the client metadata from a `client_metadata_uri`, bounded, with
/// the raw document preserved.
///
/// A failed fetch is a warning in the Go engine (the flow continues with
/// the client_id as the display name), not a refusal; the caller decides
/// whether to treat it as fatal.
pub async fn fetch_client_metadata(
    http: &dyn HttpClient,
    uri: &str,
) -> Result<ClientMetadata, TrustError> {
    let response = http
        .send(HttpRequest {
            method: "GET".to_owned(),
            url: uri.to_owned(),
            headers: vec![("accept".to_owned(), "application/json".to_owned())],
            body: Vec::new(),
            purpose: FetchPurpose::ClientMetadata,
            max_response_bytes: MAX_CLIENT_METADATA_BYTES,
            redirects: RedirectPolicy::Max(5),
            allow_plaintext: false,
            timeout_ms: 10_000,
        })
        .await
        .map_err(|err| TrustError::MetadataFetch(err.to_string()))?;

    if response.status != 200 {
        return Err(TrustError::MetadataFetch(format!(
            "client_metadata_uri answered {}",
            response.status
        )));
    }

    let raw: serde_json::Value = serde_json::from_slice(&response.body)
        .map_err(|err| TrustError::MetadataFetch(err.to_string()))?;

    ClientMetadata::parse(raw)
        .ok_or_else(|| TrustError::MetadataFetch("not a JSON object".to_owned()))
}

/// Resolves the client metadata: the inline `client_metadata` when the
/// request carries one, else the `client_metadata_uri` fetch. A failed
/// fetch continues without metadata (the P0.6-verified behaviour), so the
/// error is `None`, not a refusal.
pub async fn resolve_client_metadata(
    http: &dyn HttpClient,
    auth_req: &AuthorizationRequest,
) -> Option<ClientMetadata> {
    if let Some(inline) = auth_req.client_metadata.clone() {
        if let Some(parsed) = ClientMetadata::parse(inline) {
            return Some(parsed);
        }
    }
    if !auth_req.client_metadata_uri.is_empty() {
        if let Ok(fetched) = fetch_client_metadata(http, &auth_req.client_metadata_uri).await {
            return Some(fetched);
        }
    }
    None
}

/// Builds the verifier info from the authorization request and the client
/// metadata (when either form was available).
pub fn build_verifier_info(
    auth_req: &AuthorizationRequest,
    client_metadata: Option<&ClientMetadata>,
) -> VerifierInfo {
    let mut info = VerifierInfo {
        name: auth_req.client_id.clone(),
        client_id: auth_req.client_id.clone(),
        client_id_scheme: auth_req.client_id_scheme.clone(),
        domain: extract_domain(&auth_req.client_id),
        logo_uri: String::new(),
        trusted: false,
        framework: String::new(),
        reason: String::new(),
    };
    if let Some(metadata) = client_metadata {
        if !metadata.client_name.is_empty() {
            info.name = metadata.client_name.clone();
        }
        info.logo_uri = metadata.logo_uri.clone();
    }
    info
}

/// Evaluates the verifier's trust through the PDP port — the OID4VP
/// mirror of the issuer trust evaluation, with the same fail-closed rule.
///
/// The key material is the client metadata's `jwks` when the verifier
/// published one, else empty: the PDP decides what an empty key material
/// means (some trust frameworks evaluate on the identifier alone).
///
/// The P0.6-verified behaviour: "Fail closed: a PDP error is never
/// equivalent to 'no PDP configured' and must never fall back to asking
/// the client."
pub async fn evaluate_verifier_trust(
    pdp: &dyn Pdp,
    auth_req: &AuthorizationRequest,
    client_metadata: Option<&ClientMetadata>,
    verifier: &mut VerifierInfo,
) -> Result<(), TrustError> {
    let key_material = client_metadata
        .and_then(|m| m.jwks.as_ref())
        .map(|jwks| jwks.to_string().into_bytes())
        .unwrap_or_default();

    let response = pdp
        .evaluate(EvaluationRequest {
            subject: auth_req.client_id.clone(),
            key_material,
            resource_type: None,
        })
        .await
        .map_err(|err| match err {
            PdpError::Unreachable => TrustError::PdpUnreachable,
            PdpError::Error(detail) => TrustError::PdpError(detail),
            PdpError::NotImplemented => TrustError::PdpError("PDP not implemented".to_owned()),
        })?;

    verifier.trusted = response.trusted;
    verifier.reason = response.decision.clone().unwrap_or_default();

    if !response.trusted {
        let reason = if verifier.reason.is_empty() {
            "verifier not trusted".to_owned()
        } else {
            verifier.reason.clone()
        };
        return Err(TrustError::Untrusted {
            verifier: auth_req.client_id.clone(),
            reason,
        });
    }

    Ok(())
}

/// Extracts the domain from a client_id: the host part of a redirect_uri
/// client_id, the DNS name of an x509_san_dns scheme, the URI authority
/// of an x509_san_uri, else the client_id itself.
pub fn extract_domain(client_id: &str) -> String {
    for prefix in ["x509_san_dns:", "x509_san_uri:"] {
        if let Some(rest) = client_id.strip_prefix(prefix) {
            // The DNS name, or the URI's authority.
            if prefix == "x509_san_dns:" {
                return rest.to_owned();
            }
            if let Some(after) = rest
                .strip_prefix("https://")
                .or_else(|| rest.strip_prefix("http://"))
            {
                return after
                    .split(['/', '?', '#'])
                    .next()
                    .unwrap_or_default()
                    .to_owned();
            }
            return rest.to_owned();
        }
    }
    if let Some(after) = client_id
        .strip_prefix("https://")
        .or_else(|| client_id.strip_prefix("http://"))
    {
        return after
            .split(['/', '?', '#'])
            .next()
            .unwrap_or_default()
            .to_owned();
    }
    client_id.to_owned()
}

// ─── The §5 validations ────────────────────────────────────────────────────

/// Validates that the outer and inner `client_id` agree, when the flow
/// start's request URI carries one (RFC 9101 §5.2) — the request object
/// was fetched from that URI, so its client_id must match the URI's.
pub fn validate_client_id_match(
    auth_req: &AuthorizationRequest,
    outer_request_uri: &str,
) -> Result<(), TrustError> {
    if outer_request_uri.is_empty() {
        return Ok(());
    }
    let Some(url_client_id) = query_param(outer_request_uri, "client_id") else {
        return Ok(());
    };
    if !url_client_id.is_empty() && url_client_id != auth_req.client_id {
        return Err(TrustError::ClientIdMismatch {
            url: url_client_id,
            request_object: auth_req.client_id.clone(),
        });
    }
    Ok(())
}

/// Validates that the `response_uri` origin matches the request URI's
/// origin — **only for `x509_san_dns` with `direct_post`/
/// `direct_post.jwt`**, per OpenID4VP §5 (the P0.6-verified rule: the
/// other schemes are explicitly out of this check's scope).
///
/// The request URI may itself be one of the custom schemes carrying a
/// `request_uri` query parameter; the check resolves to that. A request
/// URI that is not a proper URL (a raw query string) skips the check, as
/// the Go engine does.
pub fn validate_response_uri_origin(
    auth_req: &AuthorizationRequest,
    outer_request_uri: &str,
) -> Result<(), TrustError> {
    if auth_req.client_id_scheme != ClientIdScheme::X509SanDns {
        return Ok(());
    }
    if auth_req.response_uri.is_empty() || outer_request_uri.is_empty() {
        return Ok(());
    }

    // Resolve the custom schemes to their request_uri query parameter.
    let request_url = resolve_request_uri(outer_request_uri);

    let (req_scheme, req_host) = match scheme_and_host(&request_url) {
        Some(parts) => parts,
        None => return Ok(()), // Not a proper URL (a raw query string).
    };

    let Some((resp_scheme, resp_host)) = scheme_and_host(&auth_req.response_uri) else {
        return Ok(());
    };

    // The origin comparison: scheme://host, case-insensitive (the host
    // carries its port when there is one).
    if !req_scheme.eq_ignore_ascii_case(&resp_scheme) || !req_host.eq_ignore_ascii_case(&resp_host)
    {
        return Err(TrustError::OriginMismatch {
            response: format!("{resp_scheme}://{resp_host}"),
            request: format!("{req_scheme}://{req_host}"),
        });
    }

    Ok(())
}

/// Resolves a flow-start request URI to the URL the origin check applies
/// to: the `request_uri` query parameter when the URI uses a custom
/// scheme, else the URI itself.
fn resolve_request_uri(outer: &str) -> String {
    const CUSTOM_SCHEMES: &[&str] = &["openid4vp://", "haip://", "haip-vp://", "mdoc-openid4vp://"];
    if CUSTOM_SCHEMES
        .iter()
        .any(|scheme| outer.starts_with(scheme))
    {
        if let Some(uri) = query_param(outer, "request_uri") {
            if !uri.is_empty() {
                return uri;
            }
        }
    }
    outer.to_owned()
}

/// A URL's scheme and host (the authority), when parseable: the string
/// must have a scheme and a host.
fn scheme_and_host(url: &str) -> Option<(String, String)> {
    let (scheme, rest) = url.split_once("://")?;
    if scheme.is_empty() {
        return None;
    }
    let host = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .rsplit('@')
        .next()
        .unwrap_or_default();
    if host.is_empty() {
        return None;
    }
    Some((scheme.to_owned(), host.to_owned()))
}

/// Extracts a query parameter's value from a URI string, with minimal
/// percent-decoding.
pub fn query_param(url: &str, name: &str) -> Option<String> {
    let query = url.split_once('?')?.1;
    let query = query.split('#').next().unwrap_or(query);
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key == name {
            return Some(percent_decode(value));
        }
    }
    None
}

/// Minimal percent-decoding for query values.
fn percent_decode(value: &str) -> String {
    let mut out = Vec::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '%' {
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            continue;
        }
        // A percent escape: two hex digits, else the '%' emits as is.
        let mut hex = String::with_capacity(2);
        for _ in 0..2 {
            if let Some(h) = chars.next() {
                hex.push(h);
            }
        }
        match u8::from_str_radix(&hex, 16) {
            Ok(byte) if hex.len() == 2 => out.push(byte),
            _ => {
                out.push(b'%');
                out.extend(hex.as_bytes());
            }
        }
    }
    String::from_utf8(out).unwrap_or_default()
}

/// The typed `-31006` data for an untrusted verifier: go-wmp's
/// `NewUntrustedVerifierData` shape — the class reason and the retryable
/// flag — plus the refused verifier and the PDP's detail, which the
/// string form carried and the consent UI shows.
pub fn untrusted_verifier_data(verifier: &str, detail: &str) -> serde_json::Value {
    serde_json::json!({
        "reason": "untrusted_verifier",
        "verifier": verifier,
        "detail": detail,
        "retryable": false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct FakePdp {
        trusted: bool,
        reason: Option<String>,
        unreachable: bool,
        subjects: std::sync::Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl Pdp for FakePdp {
        async fn evaluate(
            &self,
            request: EvaluationRequest,
        ) -> Result<engine_ports::EvaluationResponse, PdpError> {
            if self.unreachable {
                return Err(PdpError::Unreachable);
            }
            self.subjects
                .lock()
                .map(|mut s| s.push(request.subject.clone()))
                .ok();
            Ok(engine_ports::EvaluationResponse {
                trusted: self.trusted,
                decision: self.reason.clone(),
            })
        }

        async fn resolve(
            &self,
            _request: engine_ports::ResolveRequest,
        ) -> Result<engine_ports::ResolveResponse, PdpError> {
            Err(PdpError::NotImplemented)
        }
    }

    struct FakeHttp {
        status: u16,
        body: Vec<u8>,
    }

    #[async_trait::async_trait]
    impl HttpClient for FakeHttp {
        async fn send(
            &self,
            request: HttpRequest,
        ) -> Result<engine_ports::HttpResponse, engine_ports::HttpError> {
            assert_eq!(request.purpose, FetchPurpose::ClientMetadata);
            assert_eq!(request.max_response_bytes, MAX_CLIENT_METADATA_BYTES);
            Ok(engine_ports::HttpResponse {
                status: self.status,
                headers: Vec::new(),
                body: self.body.clone(),
            })
        }
    }

    fn test_request(client_id: &str) -> AuthorizationRequest {
        let scheme = ClientIdScheme::infer(client_id);
        AuthorizationRequest {
            client_id: client_id.to_owned(),
            client_id_scheme: scheme,
            request_uri: String::new(),
            response_uri: "https://verifier.example/response".to_owned(),
            redirect_uri: String::new(),
            response_mode: super::super::types::ResponseMode::DirectPost,
            nonce: "nonce-1".to_owned(),
            state: String::new(),
            dcql_query: None,
            transaction_data_raw: Vec::new(),
            client_metadata: None,
            client_metadata_uri: String::new(),
            verifier_jwk: None,
            scope: String::new(),
        }
    }

    #[test]
    fn the_domain_is_extracted_per_scheme() {
        assert_eq!(
            extract_domain("x509_san_dns:verifier.example"),
            "verifier.example"
        );
        assert_eq!(
            extract_domain("https://verifier.example/cb"),
            "verifier.example"
        );
        assert_eq!(
            extract_domain("did:web:verifier.example"),
            "did:web:verifier.example"
        );
    }

    #[tokio::test]
    async fn a_trusted_verifier_passes_the_pdp() {
        let pdp = FakePdp {
            trusted: true,
            reason: Some("in the registry".to_owned()),
            unreachable: false,
            subjects: std::sync::Mutex::new(Vec::new()),
        };
        let auth_req = test_request("x509_san_dns:verifier.example");
        let mut verifier = build_verifier_info(&auth_req, None);
        evaluate_verifier_trust(&pdp, &auth_req, None, &mut verifier)
            .await
            .expect("trusted");
        assert!(verifier.trusted);
        assert_eq!(verifier.name, "x509_san_dns:verifier.example");
        assert_eq!(verifier.domain, "verifier.example");
        // The PDP saw the full client_id, prefix and all.
        let subjects = pdp.subjects.lock().expect("lock");
        assert_eq!(subjects[0], "x509_san_dns:verifier.example");
    }

    #[tokio::test]
    async fn an_untrusted_verifier_refuses_with_the_reason() {
        let pdp = FakePdp {
            trusted: false,
            reason: Some("not in registry".to_owned()),
            unreachable: false,
            subjects: std::sync::Mutex::new(Vec::new()),
        };
        let auth_req = test_request("x509_san_dns:verifier.example");
        let mut verifier = build_verifier_info(&auth_req, None);
        let err = evaluate_verifier_trust(&pdp, &auth_req, None, &mut verifier)
            .await
            .expect_err("untrusted");
        assert!(matches!(err, TrustError::Untrusted { .. }));
    }

    #[tokio::test]
    async fn a_pdp_error_fails_closed() {
        let pdp = FakePdp {
            trusted: true,
            reason: None,
            unreachable: true,
            subjects: std::sync::Mutex::new(Vec::new()),
        };
        let auth_req = test_request("x509_san_dns:verifier.example");
        let mut verifier = build_verifier_info(&auth_req, None);
        assert!(matches!(
            evaluate_verifier_trust(&pdp, &auth_req, None, &mut verifier).await,
            Err(TrustError::PdpUnreachable)
        ));
    }

    #[tokio::test]
    async fn the_client_metadata_is_fetched_bounded_and_raw_preserved() {
        let http = FakeHttp {
            status: 200,
            body: json!({
                "client_name": "Verifier AB",
                "logo_uri": "https://verifier.example/logo.png",
                "jwks": { "keys": [] },
                "extra": "preserved"
            })
            .to_string()
            .into_bytes(),
        };
        let metadata = fetch_client_metadata(&http, "https://verifier.example/metadata")
            .await
            .expect("fetch");
        assert_eq!(metadata.client_name, "Verifier AB");
        assert_eq!(metadata.logo_uri, "https://verifier.example/logo.png");
        // The raw document is preserved, unknown members and all.
        assert_eq!(metadata.raw["extra"], "preserved");
    }

    #[tokio::test]
    async fn a_failed_metadata_fetch_continues_without_metadata() {
        let http = FakeHttp {
            status: 500,
            body: Vec::new(),
        };
        let mut auth_req = test_request("x509_san_dns:verifier.example");
        auth_req.client_metadata_uri = "https://verifier.example/metadata".to_owned();
        assert!(resolve_client_metadata(&http, &auth_req).await.is_none());
        // The verifier info falls back to the client_id as the name.
        let verifier = build_verifier_info(&auth_req, None);
        assert_eq!(verifier.name, "x509_san_dns:verifier.example");
    }

    #[test]
    fn the_client_id_match_is_checked_against_the_request_uri() {
        let auth_req = test_request("x509_san_dns:verifier.example");
        let matching = "https://verifier.example/request?client_id=x509_san_dns%3Averifier.example";
        assert!(validate_client_id_match(&auth_req, matching).is_ok());
        let mismatching = "https://verifier.example/request?client_id=x509_san_dns%3Asomeone-else";
        assert!(validate_client_id_match(&auth_req, mismatching).is_err());
        // No client_id in the URL: nothing to check.
        assert!(validate_client_id_match(&auth_req, "https://verifier.example/request").is_ok());
    }

    #[test]
    fn the_response_uri_origin_is_checked_for_x509_san_dns_only() {
        let auth_req = test_request("x509_san_dns:verifier.example");
        let same = "https://verifier.example/request.jwt";
        assert!(validate_response_uri_origin(&auth_req, same).is_ok());
        let other = "https://requests.example/request.jwt";
        assert!(validate_response_uri_origin(&auth_req, other).is_err());

        // The other schemes are out of the check's scope (§5).
        let did_req = test_request("did:web:verifier.example");
        assert!(validate_response_uri_origin(&did_req, "https://other.example/r.jwt").is_ok());
    }

    #[test]
    fn the_custom_schemes_resolve_to_their_request_uri() {
        let auth_req = test_request("x509_san_dns:verifier.example");
        let via_scheme = "openid4vp://?request_uri=https%3A%2F%2Fverifier.example%2Frequest.jwt";
        assert!(validate_response_uri_origin(&auth_req, via_scheme).is_ok());
        let via_scheme_other = "haip://?request_uri=https%3A%2F%2Fother.example%2Frequest.jwt";
        assert!(validate_response_uri_origin(&auth_req, via_scheme_other).is_err());
    }

    #[test]
    fn a_non_url_request_uri_skips_the_origin_check() {
        let auth_req = test_request("x509_san_dns:verifier.example");
        // A raw query string: not a proper URL, no origin to compare.
        assert!(validate_response_uri_origin(&auth_req, "client_id=x&nonce=y").is_ok());
    }
}

#[cfg(test)]
mod typed_data_tests {
    //! The typed `-31006` data's own proof: the shape the consumers read
    //! (the class reason, the retryable flag) and the members the consent
    //! UI shows (the refused verifier, the PDP's detail).

    use super::*;

    #[test]
    fn the_untrusted_verifier_data_carries_the_class_reason_and_detail() {
        let data = untrusted_verifier_data("x509_san_dns:verifier.example", "not in registry");
        assert_eq!(
            data.get("reason").and_then(serde_json::Value::as_str),
            Some("untrusted_verifier")
        );
        assert_eq!(
            data.get("verifier").and_then(serde_json::Value::as_str),
            Some("x509_san_dns:verifier.example")
        );
        assert_eq!(
            data.get("detail").and_then(serde_json::Value::as_str),
            Some("not in registry")
        );
        assert_eq!(
            data.get("retryable").and_then(serde_json::Value::as_bool),
            Some(false),
            "an untrusted verdict is never retryable: the wallet never re-asks"
        );
    }
}
