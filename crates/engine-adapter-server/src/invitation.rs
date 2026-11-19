//! The engine's invitation service (issue #77): the provider-delegate key,
//! the create endpoint's signing, and the consume-path verifier.
//!
//! The provider (this engine's deployment) signs its own invitations with
//! a **generated-at-startup ES256 key** — wmp-invitation.md §1.2.5
//! ("signature-bound: signed by the sender's key or a delegate authorized
//! by the sender"): the engine IS the provider's delegate here (the
//! standalone server has no upstream wallet to ask), so the key it holds
//! is the provider's signing key for invitations. The public half goes in
//! the JWKS the counterparty fetches (the discovery path); the private
//! half signs.
//!
//! The `signature` field's shape: a **full JWS compact serialization**
//! (`header.payload.signature`) over the invitation's signing payload —
//! every field except the signature itself, JSON-serialized. The
//! counterparty verifies with the provider's JWKS entry.

use std::sync::Arc;

use wmp_core::handler::HandlerError;
use wmp_core::invitation::{Invitation, InvitationError};

/// The engine's invitation key pair: ES256, generated at startup, never
/// persisted (a restart invalidates outstanding unsigned invitations —
/// the store's nonces live as long as the process).
pub struct InvitationKey {
    /// The private JWK (signing).
    private: jose_rs::jwk::Jwk,
    /// The public JWK (verification / the JWKS entry).
    public: jose_rs::jwk::Jwk,
}

impl InvitationKey {
    /// Generates a fresh ES256 pair.
    pub fn generate() -> Result<Self, String> {
        let mut private = jose_rs::jwk::generate::generate_ec("P-256")
            .map_err(|err| format!("the invitation key generation failed: {err}"))?;
        private.alg = Some("ES256".to_owned());
        let public_json = private
            .to_public_jwk()
            .to_json()
            .map_err(|err| format!("the invitation public JWK failed: {err}"))?;
        let public: jose_rs::jwk::Jwk = serde_json::from_str(&public_json)
            .map_err(|err| format!("the invitation public JWK parse failed: {err}"))?;
        Ok(Self { private, public })
    }

    /// Signs an invitation, setting its `signature` to the full JWS
    /// compact serialization over the signing payload.
    pub fn sign(&self, invitation: &mut Invitation) -> Result<(), InvitationError> {
        let payload = invitation.signing_payload()?;
        let mut header = jose_rs::header::JoseHeader::new("ES256");
        header.kid = Some(self.kid());
        let signature = jose_rs::jws::compact::sign_with_jwk(&self.private, &payload, &header)
            .map_err(|err| InvitationError::Unmarshal(err.to_string()))?;
        invitation.signature = signature;
        Ok(())
    }

    /// Verifies an invitation's `signature` against this key.
    pub fn verify(&self, invitation: &Invitation) -> Result<(), InvitationError> {
        if invitation.signature.is_empty() {
            return Err(InvitationError::Signature);
        }
        jose_rs::jws::compact::verify_with_jwk(&self.public, &invitation.signature)
            .map(|_| ())
            .map_err(|_| InvitationError::Signature)
    }

    /// The kid: the public JWK's thumbprint (the discovery path resolves
    /// by it).
    pub fn kid(&self) -> String {
        jose_rs::jwk::thumbprint::thumbprint_sha256(&self.public)
            .unwrap_or_else(|_| "invitation-key".to_owned())
    }

    /// The public JWK as JSON (the JWKS entry).
    pub fn public_jwk_json(&self) -> String {
        self.public.to_json().unwrap_or_default()
    }
}

/// The consume-path verifier: the engine's own key verifies the
/// invitation (the provider-delegate model — the standalone server has no
/// other trust root for its own provider's invitations).
pub struct EngineInvitationVerifier {
    key: Arc<InvitationKey>,
}

impl EngineInvitationVerifier {
    /// The verifier over the engine's invitation key.
    pub fn new(key: Arc<InvitationKey>) -> Self {
        Self { key }
    }
}

impl wmp_core::invitation::InvitationVerifier for EngineInvitationVerifier {
    fn verify_invitation(&self, inv: &Invitation) -> Result<(), HandlerError> {
        self.key.verify(inv).map_err(|_| {
            wmp_core::error::RpcError::new(
                wmp_core::error::ERR_NOT_AUTHORIZED,
                Some(serde_json::json!({
                    "reason": "invitation signature verification failed",
                })),
            )
            .into()
        })
    }
}
