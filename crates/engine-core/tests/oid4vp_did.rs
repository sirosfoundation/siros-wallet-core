//! The trust plumbing (gap A2, gap C1 — the docs/engine-parity.md §1
//! and §3 alignment): the DID-schemed verifier's resolution behind the
//! Pdp `resolve` port with the request JWT verified engine-side against
//! the resolved keys, the per-scheme key material, and the evaluation's
//! context map.
//!
//! The references are the Go engine (`oid4vp.go`'s
//! `extractVerifierKeyMaterial` DID branch and
//! `buildVerifierEvalContext`), W3C DID Core §5.3 (the verification
//! methods) and OID4VP §5.9.3.6 (the JAR header's trust chain).

use std::sync::Mutex;

use engine_core::oid4vp::trust::{evaluate_verifier_trust, TrustError};
use engine_core::oid4vp::types::{AuthorizationRequest, ClientIdScheme, ResponseMode};
use engine_ports::{
    EntitlementDecision, EvaluationRequest, EvaluationResponse, Pdp, PdpError, ResolveRequest,
    ResolveResponse, VerifierInfo,
};
use serde_json::json;

/// The PDP that records what it was asked, resolves a scripted DID
/// document, and evaluates trusted.
struct RecordingPdp {
    /// The DID document the resolve answers, if any.
    document: Option<Vec<u8>>,
    /// The resolve's answer, when it is not the document.
    resolve_error: Option<PdpError>,
    evaluations: Mutex<Vec<EvaluationRequest>>,
    resolutions: Mutex<Vec<ResolveRequest>>,
}

#[async_trait::async_trait]
impl Pdp for RecordingPdp {
    async fn evaluate(&self, request: EvaluationRequest) -> Result<EvaluationResponse, PdpError> {
        self.evaluations.lock().expect("lock").push(request);
        Ok(EvaluationResponse {
            trusted: true,
            decision: Some("in the registry".to_owned()),
        })
    }

    async fn resolve(&self, request: ResolveRequest) -> Result<ResolveResponse, PdpError> {
        self.resolutions.lock().expect("lock").push(request);
        if let Some(error) = &self.resolve_error {
            return match error {
                PdpError::Unreachable => Err(PdpError::Unreachable),
                PdpError::Error(detail) => Err(PdpError::Error(detail.clone())),
                PdpError::NotImplemented => Err(PdpError::NotImplemented),
            };
        }
        Ok(ResolveResponse {
            metadata: self.document.clone().unwrap_or_default(),
            trust_info: None,
        })
    }

    async fn evaluate_entitlement(
        &self,
        _request: engine_ports::EntitlementRequest,
    ) -> Result<EntitlementDecision, PdpError> {
        Err(PdpError::NotImplemented)
    }
}

/// A did-schemed request, JWT-secured with `request_jwt`, whose
/// resolved document is the caller's.
fn did_request(client_id: &str, request_jwt: Option<String>) -> AuthorizationRequest {
    AuthorizationRequest {
        client_id: client_id.to_owned(),
        client_id_scheme: ClientIdScheme::DecentralizedIdentifier,
        request_uri: String::new(),
        response_uri: "https://verifier.example/response".to_owned(),
        redirect_uri: String::new(),
        response_mode: ResponseMode::DirectPost,
        nonce: "nonce-1".to_owned(),
        state: String::new(),
        dcql_query: None,
        transaction_data_raw: Vec::new(),
        client_metadata: None,
        client_metadata_uri: String::new(),
        verifier_jwk: None,
        scope: String::new(),
        request_jwt,
        x5c: None,
        attestation_jwt: None,
    }
}

/// Signs a request-object JWT over `payload` with a fresh EC key,
/// returning (the compact JWT, the key's public JWK for the DID
/// document).
fn sign_request_object(payload: &serde_json::Value) -> (String, serde_json::Value) {
    let private = jose_rs::jwk::generate::generate_ec("P-256").expect("key");
    let public: serde_json::Value = serde_json::from_str(
        &private
            .to_public_jwk()
            .to_json()
            .expect("the public JWK serializes"),
    )
    .expect("the public JWK is JSON");
    let mut header = jose_rs::header::JoseHeader::new("ES256");
    header.typ = Some("oauth-authz-req+jwt".to_owned());
    let body = serde_json::to_vec(payload).expect("the payload serializes");
    let mut signing = private.clone();
    signing.alg = Some("ES256".to_owned());
    let mut options = jose_rs::jws::compact::SignOptions::default();
    options.allow_key_reference_headers = true;
    let jwt = jose_rs::jws::compact::sign_with_jwk_options(&signing, &body, &header, &options)
        .expect("the request object signs");
    (jwt, public)
}

/// A DID document whose verification method carries the JWK.
fn did_document(jwk: &serde_json::Value) -> Vec<u8> {
    json!({
        "id": "did:web:verifier.example",
        "verificationMethod": [
            {"id": "did:web:verifier.example#key-1", "type": "JsonWebKey", "publicKeyJwk": jwk}
        ]
    })
    .to_string()
    .into_bytes()
}

/// Runs the trust evaluation over a request, returning the verifier
/// info's trusted flag.
async fn run(pdp: &RecordingPdp, request: &AuthorizationRequest) -> Result<bool, TrustError> {
    let mut verifier = VerifierInfo {
        name: request.client_id.clone(),
        client_id: request.client_id.clone(),
        client_id_scheme: request.client_id_scheme.clone(),
        domain: String::new(),
        logo_uri: String::new(),
        trusted: false,
        framework: String::new(),
        reason: String::new(),
    };
    evaluate_verifier_trust(pdp, request, None, &mut verifier).await?;
    Ok(verifier.trusted)
}

// ─── The DID path (gap A2) ───────────────────────────────────────────────

/// A did-schemed request verifies against the resolved document: the
/// engine resolves behind the port (`did_document`), verifies the
/// request JWT against the resolved key itself, and the matched key —
/// not the DID in the abstract — is the key material the PDP evaluates.
#[tokio::test]
async fn the_did_request_verifies_against_the_resolved_document() {
    let (jwt, public) = sign_request_object(&json!({
        "client_id": "did:web:verifier.example",
        "client_id_scheme": "decentralized_identifier",
        "nonce": "nonce-1",
        "response_uri": "https://verifier.example/response",
        "response_mode": "direct_post",
    }));
    let pdp = RecordingPdp {
        document: Some(did_document(&public)),
        resolve_error: None,
        evaluations: Mutex::new(Vec::new()),
        resolutions: Mutex::new(Vec::new()),
    };
    let request = did_request("did:web:verifier.example", Some(jwt));

    assert!(run(&pdp, &request).await.expect("the DID verifies"));

    // The resolution: the DID, behind the port, as a did_document.
    let resolutions = pdp.resolutions.lock().expect("lock");
    assert_eq!(resolutions.len(), 1);
    assert_eq!(resolutions[0].uri, "did:web:verifier.example");
    assert_eq!(resolutions[0].resource_type, "did_document");

    // The evaluation's key material: the MATCHED key (the resolved
    // document's publicKeyJwk that verified the request).
    let evaluations = pdp.evaluations.lock().expect("lock");
    assert_eq!(evaluations.len(), 1);
    let key_material: serde_json::Value =
        serde_json::from_slice(&evaluations[0].key_material).expect("the matched JWK");
    assert_eq!(
        key_material, public,
        "the matched key is what the PDP evaluates"
    );
}

/// The request's signature must verify against a resolved key: a
/// tampered payload (or a document of other keys) is a refusal, and
/// nothing is evaluated (the Go `DID request JWT verification failed`).
#[tokio::test]
async fn a_did_request_no_resolved_key_verifies_refuses() {
    let (jwt, _) = sign_request_object(&json!({
        "client_id": "did:web:verifier.example",
        "client_id_scheme": "decentralized_identifier",
        "nonce": "nonce-1",
        "response_uri": "https://verifier.example/response",
        "response_mode": "direct_post",
    }));
    // The document of ANOTHER key.
    let (_, other) = sign_request_object(&json!({"unrelated": true}));
    let pdp = RecordingPdp {
        document: Some(did_document(&other)),
        resolve_error: None,
        evaluations: Mutex::new(Vec::new()),
        resolutions: Mutex::new(Vec::new()),
    };
    let request = did_request("did:web:verifier.example", Some(jwt));

    let refusal = run(&pdp, &request).await.expect_err("no key verifies");
    assert!(
        matches!(refusal, TrustError::DidVerification(_)),
        "{refusal:?}"
    );
    // Nothing was evaluated: the verification precedes the decision.
    assert!(pdp.evaluations.lock().expect("lock").is_empty());
}

/// The request shapes the Go engine refuses: a did scheme whose
/// client_id names no DID, and a did-schemed request that is not
/// JWT-secured.
#[tokio::test]
async fn a_did_request_without_a_did_or_without_a_signature_refuses() {
    let pdp = RecordingPdp {
        document: None,
        resolve_error: None,
        evaluations: Mutex::new(Vec::new()),
        resolutions: Mutex::new(Vec::new()),
    };
    // Not a DID (the Go check: client_id_scheme but not a did:).
    let not_a_did = did_request("decentralized_identifier:https://verifier.example", None);
    assert!(matches!(
        run(&pdp, &not_a_did).await.expect_err("not a DID refuses"),
        TrustError::DidVerification(_)
    ));
    // A DID, but the request carries no signed JWT.
    let unsigned = did_request("did:web:verifier.example", None);
    assert!(matches!(
        run(&pdp, &unsigned).await.expect_err("unsigned refuses"),
        TrustError::DidVerification(_)
    ));
    // Nothing was resolved for either: the shapes refuse first.
    assert!(pdp.resolutions.lock().expect("lock").is_empty());
}

/// The transition state, as the architecture records it: until a Pdp
/// implementation answers `did_document` resolutions, the did-schemed
/// verifier is best-effort — the client metadata's jwks is the key
/// material, the request JWT unverified, and the flow proceeds.
#[tokio::test]
async fn a_pdp_without_did_resolution_answers_best_effort() {
    let pdp = RecordingPdp {
        document: None,
        resolve_error: Some(PdpError::NotImplemented),
        evaluations: Mutex::new(Vec::new()),
        resolutions: Mutex::new(Vec::new()),
    };
    // The shape check (a did scheme demands a signed request) precedes
    // the resolution, exactly as the Go engine's order does — so the
    // best-effort path still carries one; it just stays unverified.
    let (jwt, _) = sign_request_object(&json!({
        "client_id": "did:web:verifier.example",
        "client_id_scheme": "decentralized_identifier",
        "nonce": "nonce-1",
        "response_uri": "https://verifier.example/response",
        "response_mode": "direct_post",
    }));
    let request = did_request("did:web:verifier.example", Some(jwt));
    assert!(run(&pdp, &request).await.expect("best-effort proceeds"));
    let evaluations = pdp.evaluations.lock().expect("lock");
    assert_eq!(evaluations.len(), 1);
    assert!(
        evaluations[0].key_material.is_empty(),
        "no metadata published a jwks: the PDP decides what empty means"
    );
}

/// A configured resolution that fails mid-flight fails closed, exactly
/// as the evaluate step does (the Go ResolveDID error path).
#[tokio::test]
async fn a_failed_did_resolution_fails_closed() {
    for error in [
        PdpError::Unreachable,
        PdpError::Error("the resolver is down".to_owned()),
    ] {
        let pdp = RecordingPdp {
            document: None,
            resolve_error: Some(error),
            evaluations: Mutex::new(Vec::new()),
            resolutions: Mutex::new(Vec::new()),
        };
        let (jwt, _) = sign_request_object(&json!({
            "client_id": "did:web:verifier.example",
            "client_id_scheme": "decentralized_identifier",
            "nonce": "nonce-1",
            "response_uri": "https://verifier.example/response",
            "response_mode": "direct_post",
        }));
        let request = did_request("did:web:verifier.example", Some(jwt));
        let refusal = run(&pdp, &request).await.expect_err("fails closed");
        assert!(
            matches!(
                refusal,
                TrustError::PdpUnreachable | TrustError::PdpError(_)
            ),
            "{refusal:?}"
        );
        assert!(pdp.evaluations.lock().expect("lock").is_empty());
    }
}

// ─── The evaluation's context (gap C1) ───────────────────────────────────

/// The evaluation's context (the Go `buildVerifierEvalContext`): the
/// client_id scheme's claim name, the response and redirect URIs, the
/// trust chain from the JAR header (OID4VP §5.9.3.6), and the verifier
/// attestation's issuer, subject and whole JWT (§5.9.3.4 — the PDP
/// verifies the attestation itself).
#[tokio::test]
async fn the_evaluation_carries_its_context() {
    let pdp = RecordingPdp {
        document: None,
        resolve_error: None,
        evaluations: Mutex::new(Vec::new()),
        resolutions: Mutex::new(Vec::new()),
    };
    // A request whose JAR header carries a trust chain (§5.9.3.6) and
    // whose scheme is the attestation's.
    let (attestation, _) = sign_request_object(&json!({
        "iss": "https://attest.example",
        "sub": "https://verifier.example",
        "cnf": {"jwk": {"kty": "EC", "crv": "P-256", "x": "bJM", "y": "L0Z"}},
    }));
    let mut request = did_request("x509_san_dns:verifier.example", None);
    request.client_id_scheme = ClientIdScheme::VerifierAttestation;
    request.redirect_uri = "https://verifier.example/cb".to_owned();
    request.attestation_jwt = Some(attestation.clone());
    // A request JWT whose HEADER carries the trust chain (OID4VP
    // §5.9.3.6): nothing verifies it on this path, so the header is
    // handcrafted around the member the context reads.
    let header = serde_json::json!({
        "typ": "oauth-authz-req+jwt",
        "alg": "ES256",
        "trust_chain": ["x5c-entry-1", "x5c-entry-2"],
    })
    .to_string();
    let jwt = format!(
        "{}.{}.forged",
        wmp_core::token::base64url_unpadded(header.as_bytes()),
        wmp_core::token::base64url_unpadded(br#"{}"#.as_slice())
    );
    request.request_jwt = Some(jwt);

    assert!(run(&pdp, &request).await.expect("the attestation passes"));
    let evaluations = pdp.evaluations.lock().expect("lock");
    let context = &evaluations[0].context;
    assert_eq!(context["client_id_scheme"], "verifier_attestation");
    assert_eq!(context["response_uri"], "https://verifier.example/response");
    assert_eq!(context["redirect_uri"], "https://verifier.example/cb");
    assert_eq!(
        context["trust_chain"],
        json!(["x5c-entry-1", "x5c-entry-2"]),
        "the JAR header's trust chain rides the context (§5.9.3.6)"
    );
    assert_eq!(context["attestation_issuer"], "https://attest.example");
    assert_eq!(context["attestation_subject"], "https://verifier.example");
    // The whole attestation JWT: the PDP verifies it, not just the
    // subject and key it asserts.
    assert_eq!(context["attestation_jwt"], attestation);
    // The key material: the attestation's cnf.jwk.
    let key_material: serde_json::Value =
        serde_json::from_slice(&evaluations[0].key_material).expect("the cnf.jwk");
    assert_eq!(key_material["kty"], "EC");
}

// ─── The per-scheme key material ─────────────────────────────────────────

/// The x.509 schemes' key material is the `x5c` chain as the JAR
/// header carried it — the PDP evaluates the chain (the §5.2.3 hash
/// binding and §5's SAN binding are the parser's).
#[tokio::test]
async fn the_x509_schemes_carry_the_chain_as_their_key_material() {
    let pdp = RecordingPdp {
        document: None,
        resolve_error: None,
        evaluations: Mutex::new(Vec::new()),
        resolutions: Mutex::new(Vec::new()),
    };
    let mut request = did_request("x509_hash:verifier.example", None);
    request.client_id_scheme = ClientIdScheme::X509Hash;
    request.x5c = Some(vec!["der-leaf".to_owned(), "der-intermediate".to_owned()]);

    assert!(run(&pdp, &request).await.expect("the chain evaluates"));
    let evaluations = pdp.evaluations.lock().expect("lock");
    let key_material: serde_json::Value =
        serde_json::from_slice(&evaluations[0].key_material).expect("the chain");
    assert_eq!(
        key_material,
        json!(["der-leaf", "der-intermediate"]),
        "the chain, as the header carried it"
    );
}
