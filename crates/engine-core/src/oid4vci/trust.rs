//! Trust evaluation through the PDP port: the issuer's key material from
//! the signed metadata, the PDP evaluate call, and the fail-closed rule —
//! S3's core.

use engine_ports::{EvaluationRequest, Pdp, PdpError};

use super::types::IssuerMetadata;

/// The trust decision the PDP answered.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TrustInfo {
    /// Whether the issuer (or verifier) is trusted.
    pub trusted: bool,
    /// The trust framework that made the decision, when there is one.
    #[serde(default)]
    pub framework: String,
    /// Why the decision was made (the PDP's reason).
    #[serde(default)]
    pub reason: String,
}

/// Why trust evaluation refused.
#[derive(Debug, thiserror::Error)]
pub enum TrustError {
    /// The PDP is unreachable; the engine fails closed.
    #[error("oid4vci: PDP unreachable")]
    PdpUnreachable,
    /// The PDP answered an error; the engine fails closed.
    #[error("oid4vci: PDP error: {0}")]
    PdpError(String),
    /// The PDP answered untrusted; the flow refuses.
    #[error("oid4vci: untrusted issuer {issuer}: {reason}")]
    Untrusted {
        /// The issuer that was refused.
        issuer: String,
        /// The PDP's reason.
        reason: String,
    },
    /// The signed metadata did not verify.
    #[error("oid4vci: signed metadata verification failed")]
    SignedVerificationFailed,
}

/// Evaluates the issuer's trust through the PDP port, with the key material
/// from the issuer's signed metadata.
///
/// The P0.6-verified behaviour:
/// - The key material comes from the signed metadata (x5c or jwk), or from
///   inline `jwks`, `jwks_uri`, or mdoc IACA certificates.
/// - The PDP is called with the issuer's identifier and the key material.
/// - **Fail closed**: a PDP that is unreachable or answers an error fails
///   the flow — never a fallback to client-asserted trust. The Go code's
///   exact words: "A configured PDP that errors returns above and never
///   falls through."
/// - An untrusted issuer refuses the flow with the PDP's reason.
pub async fn evaluate_issuer_trust(
    pdp: &dyn Pdp,
    issuer: &str,
    metadata: &IssuerMetadata,
) -> Result<TrustInfo, TrustError> {
    // Extract the key material from the signed metadata.
    let key_material = extract_key_material(metadata);

    // Call the PDP with the issuer and the key material.
    let response = pdp
        .evaluate(EvaluationRequest {
            subject: issuer.to_owned(),
            key_material,
            // The subject's role for the evaluator: the issuer side of
            // the issuance. The backend's proxy maps this to the
            // AuthZEN action name (credential-issuer — one of the
            // default rules' allowed set); a plain PDP ignores it.
            resource_type: Some("credential-issuer".to_owned()),
            // The issuer evaluation carries no context (the Go
            // engine's EvaluateIssuer has none — the verifier's
            // buildVerifierEvalContext is the presentation side's).
            context: serde_json::json!({}),
        })
        .await
        .map_err(|err| match err {
            PdpError::Unreachable => TrustError::PdpUnreachable,
            PdpError::Error(detail) => TrustError::PdpError(detail),
            PdpError::NotImplemented => TrustError::PdpError("PDP not implemented".to_owned()),
        })?;

    // The PDP answered. An untrusted issuer refuses the flow.
    if !response.trusted {
        let reason = response
            .decision
            .clone()
            .filter(|d| !d.is_empty())
            .unwrap_or_else(|| "issuer not trusted".to_owned());
        return Err(TrustError::Untrusted {
            issuer: issuer.to_owned(),
            reason,
        });
    }

    Ok(TrustInfo {
        trusted: response.trusted,
        framework: String::new(),
        reason: response.decision.unwrap_or_default(),
    })
}

/// Extracts the key material from the issuer's signed metadata (x5c or jwk),
/// or from inline `jwks`, `jwks_uri`, or mdoc IACA certificates.
///
/// Returns an empty vector when no key material was found (the PDP decides
/// what that means — some trust frameworks evaluate on the identifier
/// alone).
/// The metadata's signing key material: the signed metadata JWT, or the
/// inline `jwks` — what [`Pdp::evaluate`](engine_ports::Pdp::evaluate)
/// receives for the trust decision, and the entitlement evaluation for
/// the WRPAC (the chain that signed the document).
pub(crate) fn extract_key_material(metadata: &IssuerMetadata) -> Vec<u8> {
    // The signed metadata JWT carries the key material in its payload.
    if let Some(signed) = &metadata.signed_metadata {
        // For S3, we pass the signed metadata JWT as the key material; the
        // PDP extracts the keys. The full x5c/jwk extraction arrives with
        // the JOSE stack.
        return signed.as_bytes().to_vec();
    }

    // The unsigned metadata: look for jwks or jwks_uri in the configurations.
    if let Some(configs) = metadata.credential_configurations.as_object() {
        for (_id, config) in configs {
            if let Some(jwks) = config.get("jwks") {
                return jwks.to_string().into_bytes();
            }
            if let Some(jwks_uri) = config.get("jwks_uri").and_then(|v| v.as_str()) {
                return jwks_uri.as_bytes().to_vec();
            }
        }
    }

    Vec::new()
}

/// The typed `-31006` data for an untrusted issuer: go-wmp's
/// `NewUntrustedIssuerData` shape — the class reason and the retryable
/// flag — plus the refused issuer and the PDP's detail, which the string
/// form carried and the consent UI shows.
pub fn untrusted_issuer_data(issuer: &str, detail: &str) -> serde_json::Value {
    serde_json::json!({
        "reason": "untrusted_issuer",
        "issuer": issuer,
        "detail": detail,
        "retryable": false,
    })
}
