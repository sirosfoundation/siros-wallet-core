//! Verifier trust: the client metadata (fetched or inline, raw preserved),
//! the verifier info, the PDP evaluate call with the fail-closed rule, and
//! the §5 validations (the response_uri origin, the outer/inner client_id
//! match) — the OID4VP mirror of S3's issuer trust evaluation.

use engine_ports::{
    EvaluationRequest, FetchPurpose, HttpClient, HttpRequest, Pdp, PdpError, RedirectPolicy,
    ResolveRequest,
};

use super::types::{AuthorizationRequest, ClientIdScheme};

/// The DID document resource type of the `Pdp::resolve` port (the
/// recorded gap-A2 architecture, docs/engine-parity.md §1): the DID
/// document resolution moves behind the port, and the engine verifies
/// the request JWT against the resolved keys itself — the same split
/// the Go engine makes between resolution (`TrustSvc.ResolveDID`) and
/// trust (`evaluate`).
pub const RESOURCE_TYPE_DID_DOCUMENT: &str = "did_document";

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
    /// The DID-schemed verifier's request could not be verified against
    /// the resolved DID document (gap A2): the client_id names no DID,
    /// the request is not JWT-secured, the document carries no
    /// verification method, or no resolved key verifies the request's
    /// signature — the Go engine's `DID resolution failed` /
    /// `DID request JWT verification failed`.
    #[error("oid4vp: DID request verification failed: {0}")]
    DidVerification(String),
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
/// The key material is the scheme's (the Go engine's
/// `extractVerifierKeyMaterial`): the DID-schemed request's matched
/// resolved key (gap A2), the x.509 schemes' `x5c` chain as the JAR
/// header carried it, the attestation's `cnf.jwk` (§5.9.3.4), else the
/// client metadata's `jwks` — and the PDP decides what an empty key
/// material means (some trust frameworks evaluate on the identifier
/// alone). The evaluation's context (gap C1) carries what the PDP
/// decides on beside it.
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
    let key_material = match auth_req.client_id_scheme {
        // Gap A2: the engine resolves the DID document behind the port
        // and verifies the request JWT against the resolved keys; the
        // matched key is what the PDP evaluates.
        ClientIdScheme::DecentralizedIdentifier => {
            did_key_material(pdp, auth_req, client_metadata).await?
        }
        // The other schemes: the parser has verified the signatures;
        // the key material is the scheme's own.
        _ => best_effort_key_material(auth_req, client_metadata),
    };

    let response = pdp
        .evaluate(EvaluationRequest {
            subject: auth_req.client_id.clone(),
            key_material,
            // The subject's role for the evaluator: the verifier side
            // of the presentation. The backend's proxy maps this to
            // the AuthZEN action name (credential-verifier — one of
            // the default rules' allowed set); a plain PDP ignores
            // it. (The richer mdoc actions — mdoc-reader-auth,
            // mdoc-issuer-auth — are the SDK-side flows' calls, not
            // this engine's single verifier evaluation.)
            resource_type: Some("credential-verifier".to_owned()),
            // Gap C1: the evaluation's context (the Go
            // `buildVerifierEvalContext`).
            context: build_eval_context(auth_req),
        })
        .await
        .map_err(|err| match err {
            PdpError::Unreachable => TrustError::PdpUnreachable,
            PdpError::Error(detail) => TrustError::PdpError(detail),
            PdpError::NotImplemented => TrustError::PdpError("PDP not implemented".to_owned()),
        })?;

    verifier.trusted = response.trusted;
    verifier.reason = response.decision.clone().unwrap_or_default();

    // A registry's own human-facing name for the subject (go-trust's
    // response `context.display_name`, when a registry carries one - most
    // do not, which is why the member is optional): it overrides the
    // verifier's display name, the label a consent UI renders. Rides
    // VerifierInfo.name to the wallet's match ask - the SDK's label chain
    // (client_name → domain → client_id) prefers whatever arrives here
    // when the metadata carried no client_name.
    if let Some(display_name) = response
        .context
        .as_ref()
        .and_then(|c| c.get("display_name"))
        .and_then(|v| v.as_str())
        .filter(|n| !n.is_empty())
    {
        verifier.name = display_name.to_owned();
    }

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

// ─── The key material (the Go extractVerifierKeyMaterial) ─────────────────

/// The DID the client_id names: the `did:` form itself, or the value
/// after the `decentralized_identifier:` alias (the Go
/// `didFromClientID`); `None` when the client_id names no DID.
fn did_of(client_id: &str) -> Option<String> {
    let rest = client_id
        .strip_prefix("decentralized_identifier:")
        .unwrap_or(client_id);
    rest.starts_with("did:").then(|| rest.to_owned())
}

/// The DID-schemed verifier's key material (gap A2, the recorded
/// architecture): the engine resolves the DID document behind the
/// Pdp `resolve` port — the raw document, exactly as the port answers
/// it — and verifies the request JWT against the document's
/// verification methods itself, the matched key being what the PDP
/// evaluates.
///
/// **A PDP that does not implement `did_document` resolutions** answers
/// `NotImplemented`: the engine treats the verifier as best-effort,
/// the documented transition state — the key material falls back to
/// the client metadata's `jwks`, the request JWT unverified, the same
/// way the current behavior did. A PDP that answers an error failed
/// mid-resolution and fails closed, exactly as the Go engine's
/// `ResolveDID` error does.
async fn did_key_material(
    pdp: &dyn Pdp,
    auth_req: &AuthorizationRequest,
    client_metadata: Option<&ClientMetadata>,
) -> Result<Vec<u8>, TrustError> {
    // The DID the client_id names (the Go check: a did: scheme whose
    // client_id is not a DID is a refusal).
    let Some(did) = did_of(&auth_req.client_id) else {
        return Err(TrustError::DidVerification(format!(
            "client_id_scheme={} but the client_id names no DID",
            auth_req.client_id_scheme.name()
        )));
    };
    // The request MUST be JWT-secured (the Go rule).
    let Some(jwt) = auth_req.request_jwt.as_deref() else {
        return Err(TrustError::DidVerification(
            "a did-schemed request must be JWT-secured".to_owned(),
        ));
    };
    match pdp
        .resolve(ResolveRequest {
            uri: did,
            resource_type: RESOURCE_TYPE_DID_DOCUMENT.to_owned(),
        })
        .await
    {
        // The raw document (the recorded decision: the port returns
        // the document, the engine verifies) — the request JWT must
        // verify against at least one verification method.
        Ok(response) => {
            let matched = verify_request_against_did(jwt, &response.metadata)?;
            Ok(matched.to_string().into_bytes())
        }
        // Until a Pdp implementation answers did_document resolutions
        // (the wasm mini host among them), the did-schemed verifier is
        // best-effort: the key material the client metadata published,
        // the request JWT unverified.
        Err(PdpError::NotImplemented) => Ok(metadata_jwks(client_metadata)),
        // The resolution was configured and failed: fail closed, as
        // the evaluate step does.
        Err(PdpError::Unreachable) => Err(TrustError::PdpUnreachable),
        Err(PdpError::Error(detail)) => Err(TrustError::PdpError(detail)),
    }
}

/// Verifies the request JWT against a resolved DID document's
/// verification methods (W3C DID Core §5.3): the first `publicKeyJwk`
/// whose verification succeeds is the matched key the PDP evaluates.
/// No method, no readable document, or no verifying key is a refusal
/// — the Go engine's `resolved but contains no verification method
/// keys` and `DID request JWT verification failed`.
fn verify_request_against_did(jwt: &str, document: &[u8]) -> Result<serde_json::Value, TrustError> {
    let malformed = |reason: &str| {
        TrustError::DidVerification(format!("the DID document is unusable: {reason}"))
    };
    let document: serde_json::Value =
        serde_json::from_slice(document).map_err(|_| malformed("not JSON"))?;
    let methods = document
        .get("verificationMethod")
        .and_then(|value| value.as_array())
        .ok_or_else(|| malformed("no verificationMethod array"))?;
    for method in methods {
        // A verification method's key: the `publicKeyJwk` (RFC 7515's
        // JWK form). The other key forms (multibase and the like) are
        // not JWS keys; a method without a JWK cannot verify.
        let Some(jwk) = method.get("publicKeyJwk") else {
            continue;
        };
        let jwk: jose_rs::jwk::Jwk = serde_json::from_value(jwk.clone())
            .map_err(|_| malformed("a publicKeyJwk is not a JWK"))?;
        if jose_rs::jws::compact::verify_with_jwk(&jwk, jwt).is_ok() {
            return serde_json::to_value(&jwk)
                .map_err(|_| malformed("the matched key does not serialize"));
        }
    }
    Err(TrustError::DidVerification(
        "no resolved key verifies the request signature".to_owned(),
    ))
}

/// The non-DID schemes' key material: the x.509 schemes' `x5c` chain
/// (as the JAR header carried it — the PDP evaluates the chain), the
/// attestation's `cnf.jwk` (§5.9.3.4), else the best-effort chain
/// (the `x5c`, the client metadata's `jwks`, the request JWT header's
/// `jwk` — the Go order) — and empty when none of them is there: the
/// PDP decides what an empty key material means.
fn best_effort_key_material(
    auth_req: &AuthorizationRequest,
    client_metadata: Option<&ClientMetadata>,
) -> Vec<u8> {
    match auth_req.client_id_scheme {
        // The x.509 schemes: the chain is the material (§5.2.3's hash
        // binding and §5's SAN binding are the parser's; the chain's
        // trust is the PDP's).
        ClientIdScheme::X509SanDns | ClientIdScheme::X509SanUri | ClientIdScheme::X509Hash => {
            if let Some(chain) = &auth_req.x5c {
                return serde_json::to_vec(chain).unwrap_or_default();
            }
            Vec::new()
        }
        // The attestation's confirmation key (RFC 7800): the parser
        // verified the request signature under it; the PDP evaluates
        // the attestation it asserts.
        ClientIdScheme::VerifierAttestation => {
            if let Some(jwk) = attestation_cnf_jwk(auth_req) {
                return jwk.to_string().into_bytes();
            }
            Vec::new()
        }
        // The best-effort default: the request's own chain, the
        // metadata's jwks, the request JWT header's jwk.
        _ => {
            if let Some(chain) = &auth_req.x5c {
                return serde_json::to_vec(chain).unwrap_or_default();
            }
            let jwks = metadata_jwks(client_metadata);
            if !jwks.is_empty() {
                return jwks;
            }
            jwt_header_jwk(auth_req)
        }
    }
}

/// The client metadata's `jwks`, as bytes — the key material when
/// nothing scheme-specific applies.
fn metadata_jwks(client_metadata: Option<&ClientMetadata>) -> Vec<u8> {
    client_metadata
        .and_then(|metadata| metadata.jwks.as_ref())
        .map(|jwks| jwks.to_string().into_bytes())
        .unwrap_or_default()
}

/// The `jwk` of an unsigned request JWT's header — the best-effort
/// extraction of last resort (the Go `unverified JWT header
/// extraction`): the header names the key even when nothing verified
/// against it.
fn jwt_header_jwk(auth_req: &AuthorizationRequest) -> Vec<u8> {
    auth_req
        .request_jwt
        .as_deref()
        .and_then(jwt_header)
        .and_then(|header| header.get("jwk").cloned())
        .map(|jwk| jwk.to_string().into_bytes())
        .unwrap_or_default()
}

/// The verifier attestation's `cnf.jwk` (RFC 7800): the confirmation
/// key the attestation asserts, which the request JWT's signature
/// verified under (the parser's §5.9.3.4 check).
fn attestation_cnf_jwk(auth_req: &AuthorizationRequest) -> Option<serde_json::Value> {
    let attestation = auth_req.attestation_jwt.as_deref()?;
    let payload = jwt_payload(attestation)?;
    payload.get("cnf")?.get("jwk").cloned()
}

/// The decoded JOSE header of a JWT.
fn jwt_header(jwt: &str) -> Option<serde_json::Value> {
    let segment = jwt.split('.').next()?;
    let bytes = decode_base64url(segment)?;
    serde_json::from_slice(&bytes).ok()
}

/// The decoded JSON payload of a JWT.
fn jwt_payload(jwt: &str) -> Option<serde_json::Value> {
    let segment = jwt.split('.').nth(1)?;
    let bytes = decode_base64url(segment)?;
    serde_json::from_slice(&bytes).ok()
}

/// Minimal base64url decoding, padding tolerated.
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
    let bytes: Vec<u8> = encoded.bytes().filter(|byte| *byte != b'=').collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let b0 = value(*chunk.first()?)?;
        let b1 = value(*chunk.get(1)?)?;
        out.push((b0 << 2) | (b1 >> 4));
        if let Some(byte) = chunk.get(2) {
            let b2 = value(*byte)?;
            out.push((b1 << 4) | (b2 >> 2));
            if let Some(byte) = chunk.get(3) {
                let b3 = value(*byte)?;
                out.push((b2 << 6) | b3);
            }
        }
    }
    Some(out)
}

// ─── The evaluation's context (gap C1) ────────────────────────────────────

/// The trust evaluation's context (the Go
/// `buildVerifierEvalContext`, carried by `EvaluateVerifierWithContext`):
/// what the PDP decides on beside the key material — the
/// `client_id_scheme` (the claim's name), the `response_uri` and
/// `redirect_uri` the request named, the `trust_chain` from the request
/// object's JAR header (OID4VP §5.9.3.6 — a pre-supplied OIDF trust
/// chain the PDP validates instead of resolving it from scratch), and
/// the verifier attestation's `attestation_issuer`,
/// `attestation_subject` and `attestation_jwt` (§5.9.3.4: the PDP
/// verifies the whole attestation JWT — its signature, issuer chain,
/// expiry and redirect_uris claims — not just the subject and key it
/// asserts).
pub fn build_eval_context(auth_req: &AuthorizationRequest) -> serde_json::Value {
    let mut context = serde_json::json!({
        "client_id_scheme": auth_req.client_id_scheme.name(),
    });
    let Some(object) = context.as_object_mut() else {
        return context;
    };
    if !auth_req.response_uri.is_empty() {
        object.insert(
            "response_uri".to_owned(),
            serde_json::Value::String(auth_req.response_uri.clone()),
        );
    }
    if !auth_req.redirect_uri.is_empty() {
        object.insert(
            "redirect_uri".to_owned(),
            serde_json::Value::String(auth_req.redirect_uri.clone()),
        );
    }
    // The trust chain from the JAR header (§5.9.3.6).
    if let Some(trust_chain) = auth_req
        .request_jwt
        .as_deref()
        .and_then(jwt_header)
        .and_then(|header| header.get("trust_chain").cloned())
    {
        object.insert("trust_chain".to_owned(), trust_chain);
    }
    // The attestation context (§5.9.3.4).
    if let Some(attestation) = auth_req.attestation_jwt.as_deref().and_then(jwt_payload) {
        if let Some(issuer) = attestation.get("iss").and_then(|v| v.as_str()) {
            object.insert(
                "attestation_issuer".to_owned(),
                serde_json::Value::String(issuer.to_owned()),
            );
        }
        if let Some(subject) = attestation.get("sub").and_then(|v| v.as_str()) {
            object.insert(
                "attestation_subject".to_owned(),
                serde_json::Value::String(subject.to_owned()),
            );
        }
        if let Some(attestation_jwt) = auth_req.attestation_jwt.clone() {
            object.insert(
                "attestation_jwt".to_owned(),
                serde_json::Value::String(attestation_jwt),
            );
        }
    }
    context
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
