//! The issuer trust evaluation's key material (go-wallet-backend #540's
//! class, audited into this engine): a document served as `application/jwt`
//! carries its signer's chain in the JWS header (RFC 7515 §4.1.6) — the
//! payload has no `signed_metadata` member and may carry no `jwks` either,
//! so the header's material is the only thing a chain-deciding PDP can
//! read. The whole path is driven through the public API: the metadata
//! resolver fetches the document, the trust evaluation extracts the key
//! material, and a capturing PDP asserts exactly what reached it.

use engine_core::oid4vci::issuer::resolve_issuer_metadata;
use engine_core::oid4vci::trust::evaluate_issuer_trust;
use engine_core::oid4vci::types::{IssuerMetadata, MetadataType};
use engine_ports::{
    EvaluationRequest, EvaluationResponse, Pdp, PdpError, ResolveRequest, ResolveResponse,
};

use std::sync::Mutex;

// ── The fakes ───────────────────────────────────────────────────────────────

/// Serves one fixed response.
struct FixedHttp {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
}

#[async_trait::async_trait]
impl engine_ports::HttpClient for FixedHttp {
    async fn send(
        &self,
        request: engine_ports::HttpRequest,
    ) -> Result<engine_ports::HttpResponse, engine_ports::HttpError> {
        assert_eq!(request.purpose, engine_ports::FetchPurpose::IssuerMetadata);
        Ok(engine_ports::HttpResponse {
            status: self.status,
            headers: vec![("content-type".to_owned(), self.content_type.to_owned())],
            body: self.body.clone(),
        })
    }
}

/// Captures the evaluation request and answers trusted.
struct CapturingPdp {
    request: Mutex<Option<EvaluationRequest>>,
}

#[async_trait::async_trait]
impl Pdp for CapturingPdp {
    async fn evaluate(&self, request: EvaluationRequest) -> Result<EvaluationResponse, PdpError> {
        *self
            .request
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(request);
        Ok(EvaluationResponse {
            trusted: true,
            decision: Some("test".to_owned()),
            context: None,
        })
    }

    async fn resolve(&self, _request: ResolveRequest) -> Result<ResolveResponse, PdpError> {
        Err(PdpError::NotImplemented)
    }
}

fn captured_key_material(pdp: &CapturingPdp) -> EvaluationRequest {
    let guard = pdp
        .request
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.clone().expect("the PDP was called")
}

// ── The JWT fixture builder ──────────────────────────────────────────────────

fn b64url(bytes: &[u8]) -> String {
    b64url_nopad(bytes)
}

/// Minimal unpadded base64url (RFC 7515 §2).
fn b64url_nopad(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[n as usize & 63] as char);
        }
    }
    out
}

/// An `application/jwt` metadata document: header.payload.signature, the
/// header carrying the signer's chain exactly as the #540 issuer serves it
/// (two DER certificates, RFC 7515 §4.1.6).
fn jwt_metadata_document(header_members: &str, payload_members: &str) -> Vec<u8> {
    let header = format!("{{\"alg\":\"ES256\",{header_members}}}");
    let payload = format!("{{\"credential_issuer\":\"https://issuer.example\",{payload_members}}}");
    format!(
        "{}.{}.{}",
        b64url(header.as_bytes()),
        b64url(payload.as_bytes()),
        b64url(b"sig")
    )
    .into_bytes()
}

const TWO_CERTS: &str = "\"x5c\":[\"MIIB1zCCAX2gAwIBAgI\",\"MIIB8DCCAX2gAwIBAgI\"]";

// ── The guarantee: the envelope's chain reaches the PDP ─────────────────────

/// The #540 scenario itself: the issuer serves its metadata as
/// `application/jwt`, the JWS header carries the signer's x5c chain, and
/// the payload carries no key members at all. The trust evaluation must
/// send the PDP that chain — an empty key material is the bug (a
/// chain-deciding PDP can never answer for the issuer, and the flow
/// refuses with "no registry returned positive match").
#[tokio::test]
async fn a_jwt_served_document_sends_the_signer_chain_to_the_pdp() {
    // "Accept: application/json" on this issuer returns a body with no
    // signed_metadata, jwks, jwks_uri or mdoc_iacas_uri — the issue's
    // exact issuer. The JWT form carries everything the PDP needs.
    let document = jwt_metadata_document(TWO_CERTS, "\"credential_endpoint\":\"/credential\"");
    let http = FixedHttp {
        status: 200,
        content_type: "application/jwt",
        body: document,
    };

    let metadata = resolve_issuer_metadata(
        &http,
        "https://issuer.example",
        MetadataType::PreferSigned,
        true,
    )
    .await
    .expect("the JWT document resolves");

    let pdp = CapturingPdp {
        request: Mutex::new(None),
    };
    evaluate_issuer_trust(&pdp, "https://issuer.example", &metadata)
        .await
        .expect("the PDP trusts the chain");

    let request = captured_key_material(&pdp);
    let material: serde_json::Value =
        serde_json::from_slice(&request.key_material).expect("the chain parses as JSON");
    // The x5c array, verbatim — the form the backend's proxy maps to
    // resource.type=x5c, the form go-trust matches against trusted lists.
    assert_eq!(
        material,
        serde_json::json!(["MIIB1zCCAX2gAwIBAgI", "MIIB8DCCAX2gAwIBAgI"]),
        "the JWS header's chain is the key material"
    );
}

/// The priority is the Go fix's exact shape: the payload's own members win,
/// the envelope's signer material is the FALLBACK for when the body
/// extraction returns nothing.
#[tokio::test]
async fn the_payloads_inline_jwks_wins_over_the_envelope_chain() {
    let jwks = "\"credential_configurations\":{\"pid\":{\"jwks\":{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\"}]}}}";
    let document = jwt_metadata_document(TWO_CERTS, jwks);
    let http = FixedHttp {
        status: 200,
        content_type: "application/jwt",
        body: document,
    };

    let metadata = resolve_issuer_metadata(
        &http,
        "https://issuer.example",
        MetadataType::PreferSigned,
        true,
    )
    .await
    .expect("the JWT document resolves");

    let pdp = CapturingPdp {
        request: Mutex::new(None),
    };
    evaluate_issuer_trust(&pdp, "https://issuer.example", &metadata)
        .await
        .expect("trusted");

    let request = captured_key_material(&pdp);
    // The inline jwks (the configurations' member), not the header's chain.
    let material: serde_json::Value =
        serde_json::from_slice(&request.key_material).expect("the jwks parses as JSON");
    assert!(
        material.get("keys").is_some(),
        "the payload's jwks is the key material: {material}"
    );
}

/// The unsigned document without key members keeps the historic behaviour:
/// empty key material — the PDP decides what that means (some frameworks
/// evaluate on the identifier alone). The envelope fallback never fires
/// for a document that was not served as a JWT.
#[tokio::test]
async fn an_unsigned_document_without_key_members_sends_empty_material() {
    let http = FixedHttp {
        status: 200,
        content_type: "application/json",
        body: br#"{"credential_issuer":"https://issuer.example"}"#.to_vec(),
    };

    let metadata = resolve_issuer_metadata(
        &http,
        "https://issuer.example",
        MetadataType::PreferSigned,
        true,
    )
    .await
    .expect("the plain document resolves");

    let pdp = CapturingPdp {
        request: Mutex::new(None),
    };
    evaluate_issuer_trust(&pdp, "https://issuer.example", &metadata)
        .await
        .expect("trusted");

    let request = captured_key_material(&pdp);
    assert!(
        request.key_material.is_empty(),
        "no members, no envelope: empty material"
    );
}

/// The extractor is reachable without a resolver too — a metadata built by
/// hand (the resume path) with the envelope field set answers the same
/// chain, so the field's contract holds outside the parse path.
#[tokio::test]
async fn the_envelope_material_reaches_the_extractor_from_a_built_metadata() {
    let metadata = IssuerMetadata {
        credential_issuer: "https://issuer.example".to_owned(),
        signed_metadata: None,
        envelope_key_material: Some(
            serde_json::to_vec(&serde_json::json!(["MIIB1zCCAX2gAwIBAgI"])).expect("serializes"),
        ),
        is_signed: true,
        raw: Vec::new(),
        ..parse_minimal_metadata()
    };

    let pdp = CapturingPdp {
        request: Mutex::new(None),
    };
    evaluate_issuer_trust(&pdp, "https://issuer.example", &metadata)
        .await
        .expect("trusted");

    let request = captured_key_material(&pdp);
    let material: serde_json::Value =
        serde_json::from_slice(&request.key_material).expect("the chain parses");
    assert_eq!(material, serde_json::json!(["MIIB1zCCAX2gAwIBAgI"]));
}

/// A metadata with the optional members unset — IssuerMetadata has no
/// Default (its `credential_issuer` is never meaningful as a default), so
/// this fills the required rest.
fn parse_minimal_metadata() -> IssuerMetadata {
    serde_json::from_value(serde_json::json!({
        "credential_issuer": "https://issuer.example",
        "credential_endpoint": "",
        "token_endpoint": "",
        "notification_endpoint": "",
        "authorization_servers": [],
        "credential_configurations": {},
    }))
    .expect("the minimal metadata parses")
}
