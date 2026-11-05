//! The issuer trust evaluation through the PDP port: the key material,
//! the decision, and the fail-closed rule.

use engine_core::oid4vci::trust::*;
use engine_core::oid4vci::types::IssuerMetadata;
use engine_ports::{EvaluationRequest, Pdp, PdpError};

struct FakePdp {
    trusted: bool,
    reason: Option<String>,
    unreachable: bool,
}

#[async_trait::async_trait]
impl Pdp for FakePdp {
    async fn evaluate(
        &self,
        _request: EvaluationRequest,
    ) -> Result<engine_ports::EvaluationResponse, PdpError> {
        if self.unreachable {
            return Err(PdpError::Unreachable);
        }
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

fn test_metadata() -> IssuerMetadata {
    IssuerMetadata {
        nonce_endpoint: None,
        deferred_credential_endpoint: None,
        credential_endpoint: String::new(),
        token_endpoint: String::new(),
        notification_endpoint: String::new(),
        credential_issuer: "https://issuer.example".to_owned(),
        authorization_servers: Vec::new(),
        credential_configurations: serde_json::json!({
            "UniversityDegree": {
                "jwks": { "keys": [{"kty":"EC","crv":"P-256"}] }
            }
        }),
        signed_metadata: None,
        is_signed: false,
        raw: Vec::new(),
    }
}

#[tokio::test]
async fn a_trusted_issuer_passes() {
    let pdp = FakePdp {
        trusted: true,
        reason: Some("trusted by framework X".to_owned()),
        unreachable: false,
    };
    let info = evaluate_issuer_trust(&pdp, "https://issuer.example", &test_metadata())
        .await
        .expect("trusted");
    assert!(info.trusted);
}

#[tokio::test]
async fn an_untrusted_issuer_refuses_with_the_reason() {
    let pdp = FakePdp {
        trusted: false,
        reason: Some("not in registry".to_owned()),
        unreachable: false,
    };
    let err = evaluate_issuer_trust(&pdp, "https://issuer.example", &test_metadata())
        .await
        .expect_err("untrusted");
    assert!(matches!(
        err,
        TrustError::Untrusted { issuer, reason }
            if issuer == "https://issuer.example" && reason == "not in registry"
    ));
}

#[tokio::test]
async fn an_unreachable_pdp_fails_closed() {
    let pdp = FakePdp {
        trusted: true,
        reason: None,
        unreachable: true,
    };
    assert!(matches!(
        evaluate_issuer_trust(&pdp, "https://issuer.example", &test_metadata()).await,
        Err(TrustError::PdpUnreachable)
    ));
}

/// Records the key material the evaluation hands the PDP, and trusts.
struct KeyMaterialPdp {
    key_material: std::sync::Mutex<Vec<u8>>,
}

#[async_trait::async_trait]
impl Pdp for KeyMaterialPdp {
    async fn evaluate(
        &self,
        request: EvaluationRequest,
    ) -> Result<engine_ports::EvaluationResponse, PdpError> {
        self.key_material
            .lock()
            .map(|mut material| *material = request.key_material)
            .ok();
        Ok(engine_ports::EvaluationResponse {
            trusted: true,
            decision: None,
        })
    }

    async fn resolve(
        &self,
        _request: engine_ports::ResolveRequest,
    ) -> Result<engine_ports::ResolveResponse, PdpError> {
        Err(PdpError::NotImplemented)
    }
}

/// The key material the issuer trust evaluation of `metadata` sends.
async fn key_material_of(metadata: &IssuerMetadata) -> Vec<u8> {
    let pdp = KeyMaterialPdp {
        key_material: std::sync::Mutex::new(Vec::new()),
    };
    evaluate_issuer_trust(&pdp, "https://issuer.example", metadata)
        .await
        .expect("trusted");
    let material = pdp.key_material.lock().expect("key material").clone();
    material
}

#[tokio::test]
async fn the_signed_metadata_is_the_key_material() {
    let metadata = IssuerMetadata {
        signed_metadata: Some("eyJhbGciOiJFUzI1NiJ9.payload.sig".to_owned()),
        ..test_metadata()
    };
    let material = key_material_of(&metadata).await;
    assert!(!material.is_empty());
}

#[tokio::test]
async fn the_jwks_from_the_configurations_is_the_key_material() {
    let material = key_material_of(&test_metadata()).await;
    assert!(!material.is_empty());
    let text = String::from_utf8_lossy(&material);
    assert!(text.contains("keys"));
}

#[tokio::test]
async fn no_key_material_is_an_empty_vector_not_an_error() {
    let metadata = IssuerMetadata {
        credential_configurations: serde_json::json!({}),
        ..test_metadata()
    };
    assert!(key_material_of(&metadata).await.is_empty());
}
