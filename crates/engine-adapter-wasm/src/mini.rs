//! The mini host: a built-in Host implementation for driving the raw
//! engine against the OIDF certification suites — the wallet side of the
//! conformance harness (`docs/oidf-conformance.md`).
//!
//! The suites judge the wallet by its wire traffic; the host answers the
//! sub-flows so the engine's protocol is the only thing under test. The
//! mini host holds one generated P-256 key (the proofs' signing key),
//! auto-consents, answers the transaction code from configuration, and
//! forwards the authorization step to the page so Playwright can drive
//! the suite's AS login. It refuses everything it does not implement —
//! attestation and client-held DPoP fall back to the engine's own
//! behaviours, exactly as an SDK host without those capabilities would.

use engine_ports::{
    AttestationParams, AttestationResult, ConsentParams, ConsentResult, DpopProofParams,
    DpopProofResult, Host, HostError, MatchParams, MatchResult, SignParams, SignResult, VpParams,
    VpResult,
};

use wasm_bindgen::prelude::*;

/// The built-in mini host: `{"host": "mini"}` in the engine config
/// selects it.
pub struct MiniHost {
    /// The proof-signing key: one generated P-256 pair per engine
    /// instance, the wallet's device key for the run.
    key: jose_rs::jwk::Jwk,
    /// The software key behind it — kryptering's `Signer` signs the raw
    /// to-be-signed bytes.
    signer: kryptering::SoftwareSigner,
    /// The transaction code the plan's issuer expects (the OIDF suite
    /// publishes it in the plan configuration).
    tx_code: String,
    /// The page's authorization callback: `(url) => Promise<void>` —
    /// navigate, and the suite's AS redirects back to the page.
    open_authorization: Option<js_sys::Function>,
}

impl MiniHost {
    /// Generates the device key and binds the configuration.
    pub fn new(
        tx_code: String,
        open_authorization: Option<js_sys::Function>,
    ) -> Result<Self, String> {
        let key = jose_rs::jwk::generate::generate_ec("P-256")
            .map_err(|err| format!("the device key generation failed: {err}"))?;
        let software = jose_rs::jwk::jwk_to_software_key(&key)
            .map_err(|err| format!("the device key does not convert: {err}"))?;
        let signer = kryptering::SoftwareSigner::new(
            kryptering::SignatureAlgorithm::Ecdsa(
                kryptering::EcCurve::P256,
                kryptering::HashAlgorithm::Sha256,
            ),
            software,
        )
        .map_err(|err| format!("the device key does not sign: {err}"))?;
        Ok(Self {
            key,
            signer,
            tx_code,
            open_authorization,
        })
    }

    /// The device key's public JWK — for the plan's key registration, if
    /// the suite asks for it.
    pub fn public_jwk(&self) -> serde_json::Value {
        let public = self.key.to_public_jwk();
        let text = public.to_json().unwrap_or_default();
        serde_json::from_str(&text).unwrap_or_default()
    }
}

#[async_trait::async_trait]
impl Host for MiniHost {
    /// Signs the proof: the engine builds the JWT's to-be-signed bytes,
    /// the mini host signs with the device key — the same division the
    /// real SDK has, with the keystore replaced by a generated pair.
    async fn request_sign(&self, params: SignParams) -> Result<SignResult, HostError> {
        let signature = kryptering::Signer::sign(&self.signer, &params.to_sign)
            .map_err(|err| HostError::Cannot(format!("the device key refused: {err}")))?;
        Ok(SignResult { signature })
    }

    /// The match: not asked by the issuance flows; refused rather than
    /// faked.
    async fn request_match(&self, _params: MatchParams) -> Result<MatchResult, HostError> {
        Err(HostError::Cannot(
            "the mini host answers no match (the issuance flows do not ask)".to_owned(),
        ))
    }

    /// Consent: automatic. The suites test the wallet's protocol, not a
    /// person's judgement; a decline variant would come from the page's
    /// own callback.
    async fn request_consent(&self, _params: ConsentParams) -> Result<ConsentResult, HostError> {
        Ok(ConsentResult { consented: true })
    }

    /// The transaction code from configuration — the plan's issuer
    /// publishes the code it will accept.
    async fn request_tx_code(&self, _flow_id: &str) -> Result<String, HostError> {
        if self.tx_code.is_empty() {
            return Err(HostError::Cannot(
                "the mini host has no transaction code configured".to_owned(),
            ));
        }
        Ok(self.tx_code.clone())
    }

    /// The authorization step: forwarded to the page, whose callback
    /// navigates — the suite's AS shows its login, Playwright answers
    /// it, and the redirect returns to the page with the code.
    async fn open_authorization(&self, _flow_id: &str, url: &str) -> Result<(), HostError> {
        let Some(callback) = &self.open_authorization else {
            return Err(HostError::Cannot(
                "the mini host has no authorization callback".to_owned(),
            ));
        };
        let callback = callback.clone();
        let url = url.to_owned();
        let navigated = crate::ports::await_js(crate::ports::spawn_js(async move {
            let value = serde_wasm_bindgen::to_value(&url)
                .map_err(|err| format!("serialize the url: {err}"))?;
            let promise = callback
                .call1(&JsValue::NULL, &value)
                .map_err(|err| format!("the callback refused: {err:?}"))?;
            wasm_bindgen_futures::JsFuture::from(js_sys::Promise::from(promise))
                .await
                .map(|_| ())
                .map_err(|err| format!("the navigation failed: {err:?}"))
        }))
        .await
        .and_then(|inner| inner)
        .map_err(HostError::Cannot);

        navigated
    }

    /// The VP construction: Phase 2 of the conformance plan wires the
    /// presentation crates; refused for now, and the issuance flows
    /// never ask.
    async fn request_vp(&self, _params: VpParams) -> Result<VpResult, HostError> {
        Err(HostError::Cannot(
            "the mini host builds no VP yet (Phase 2 of the conformance plan)".to_owned(),
        ))
    }

    /// Client-held DPoP: refused — the engine falls back to its own
    /// ephemeral key, which the suites accept.
    async fn request_dpop_proof(
        &self,
        _params: DpopProofParams,
    ) -> Result<DpopProofResult, HostError> {
        Err(HostError::Cannot(
            "the mini host holds no DPoP key".to_owned(),
        ))
    }

    /// Attestation: refused — the flow proceeds without, and an issuer
    /// that requires it rejects on its own (the suites' test issuers do
    /// not).
    async fn request_attestation(
        &self,
        _params: AttestationParams,
    ) -> Result<AttestationResult, HostError> {
        Err(HostError::Cannot(
            "the mini host carries no wallet instance attestation".to_owned(),
        ))
    }

    /// Progress: swallowed. The page observes the flow through the
    /// resolved request promises; the suites see only the wire.
    fn progress(&self, _flow_id: &str, _step: &str, _detail: Option<String>) {}
}

/// The Arc helper the dispatcher's ports need.
pub fn arc(host: MiniHost) -> std::sync::Arc<dyn engine_ports::Host> {
    std::sync::Arc::new(host)
}
