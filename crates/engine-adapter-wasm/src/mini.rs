//! The mini host: a built-in Host implementation for driving the raw
//! engine against the OIDF certification suites — the wallet side of the
//! conformance harness (`docs/oidf-conformance.md`).
//!
//! The suites judge the wallet by its wire traffic; the host answers the
//! sub-flows so the engine's protocol is the only thing under test. The
//! mini host holds two keys: a generated P-256 device key (the OID4VCI
//! proof's signing key) and, when the plan's configuration registered
//! one, the wallet's client key (the RFC 7523 private_key_jwt
//! assertion's signing key). It auto-consents, answers the transaction
//! code from configuration, and forwards the authorization step to the
//! page so Playwright can drive the suite's AS login. It refuses
//! everything it does not implement — attestation and client-held DPoP
//! fall back to the engine's own behaviours, exactly as an SDK host
//! without those capabilities would.

use engine_ports::{
    AttestationParams, AttestationResult, ConsentParams, ConsentResult, DpopProofParams,
    DpopProofResult, Host, HostError, MatchParams, MatchResult, SignParams, SignResult, VpParams,
    VpResult,
};

use wasm_bindgen::prelude::*;

/// The ES256 P-256 software signer shape both keys use.
type Signer = kryptering::SoftwareSigner;

fn p256_signer(jwk: &jose_rs::jwk::Jwk) -> Result<Signer, String> {
    let software = jose_rs::jwk::jwk_to_software_key(jwk)
        .map_err(|err| format!("the key does not convert: {err}"))?;
    kryptering::SoftwareSigner::new(
        kryptering::SignatureAlgorithm::Ecdsa(
            kryptering::EcCurve::P256,
            kryptering::HashAlgorithm::Sha256,
        ),
        software,
    )
    .map_err(|err| format!("the key does not sign: {err}"))
}

/// The built-in mini host: `{"host": "mini"}` in the engine config
/// selects it.
pub struct MiniHost {
    /// The device key's public JWK (the plan's key registration and the
    /// tests' verification).
    key: jose_rs::jwk::Jwk,
    /// The device key's signer — the OID4VCI proof's signing key.
    signer: Signer,
    /// The wallet's registered client key, when the plan's
    /// configuration supplies one: the private_key_jwt assertion's
    /// signing key.
    client_signer: Option<Signer>,
    /// The client key's kid — how the assertion's sign ask names the
    /// key (the registered kid, e.g. `client-key-1`).
    client_key_kid: Option<String>,
    /// The client key's public JWK — the signing-key ask's answer when
    /// the engine identifies the client key in a proof header.
    client_key: Option<serde_json::Value>,
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
        client_key_jwk: Option<String>,
        open_authorization: Option<js_sys::Function>,
    ) -> Result<Self, String> {
        let key = jose_rs::jwk::generate::generate_ec("P-256")
            .map_err(|err| format!("the device key generation failed: {err}"))?;
        let signer = p256_signer(&key)?;

        let (client_signer, client_key_kid, client_key) = match client_key_jwk {
            Some(jwk) => {
                let jwk: jose_rs::jwk::Jwk = serde_json::from_str(&jwk)
                    .map_err(|err| format!("the client key does not parse: {err}"))?;
                let kid = jwk.kid.clone();
                // The public form: the private member never leaves the
                // host (the engine only ever sees the public JWK).
                let public = jwk.to_public_jwk();
                let text = public.to_json().unwrap_or_default();
                let value: serde_json::Value =
                    serde_json::from_str(&text).unwrap_or_default();
                (Some(p256_signer(&jwk)?), kid, Some(value))
            }
            None => (None, None, None),
        };

        Ok(Self {
            key,
            signer,
            client_signer,
            client_key_kid,
            client_key,
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
    /// Signs what the engine built: the OID4VCI proof's TBS with the
    /// device key, the RFC 7523 client assertion's TBS (key id
    /// `client-auth`) with the registered client key — the same
    /// division the real SDK has, with the keystore replaced by the
    /// mini host's pairs.
    async fn request_sign(&self, params: SignParams) -> Result<SignResult, HostError> {
        // The key id routes: the engine asks for the registered kid
        // (or the conventional client-auth name) when the client
        // assertion needs the client key; anything else is the device
        // key (the OID4VCI proof).
        let use_client = params
            .key_id
            .as_deref()
            .is_some_and(|id| match self.client_key_kid.as_deref() {
                Some(kid) => id == kid,
                None => id == engine_core::oid4vci::token::CLIENT_AUTH_KEY_ID,
            });
        let signer = if use_client {
            self.client_signer.as_ref().ok_or_else(|| {
                HostError::Cannot("the mini host carries no client key".to_owned())
            })?
        } else {
            &self.signer
        };
        let signature = kryptering::Signer::sign(signer, &params.to_sign)
            .map_err(|err| HostError::Cannot(format!("the key refused: {err}")))?;
        Ok(SignResult { signature })
    }

    /// The signing-key ask: the public JWK of the key the engine is
    /// about to sign with, so the proof header can identify it (the
    /// public JWK + the RFC 7638 thumbprint kid). The key routes the
    /// same way request_sign routes — the registered client kid or
    /// the conventional client-auth name answers the client key,
    /// anything else the device key.
    async fn request_signing_key(
        &self,
        params: engine_ports::SigningKeyParams,
    ) -> Result<engine_ports::SigningKeyResult, HostError> {
        let use_client = params
            .key_id
            .as_deref()
            .is_some_and(|id| match self.client_key_kid.as_deref() {
                Some(kid) => id == kid,
                None => id == engine_core::oid4vci::token::CLIENT_AUTH_KEY_ID,
            });
        let jwk = if use_client {
            self.client_key.clone().ok_or_else(|| {
                HostError::Cannot("the mini host carries no client key".to_owned())
            })?
        } else {
            self.public_jwk()
        };
        Ok(engine_ports::SigningKeyResult { jwk })
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
        crate::ports::await_js(crate::ports::spawn_js(async move {
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
        .map_err(HostError::Cannot)
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
        Err(HostError::Cannot("the mini host holds no DPoP key".to_owned()))
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

#[cfg(all(test, target_arch = "wasm32"))]
mod tests {
    use super::*;

    /// The client key the plan registers (the OIDF suite's fixture
    /// shape): the host must sign the assertion with THIS key when
    /// the ask names the registered kid, and the signature must
    /// verify against the key's public members.
    #[wasm_bindgen_test::wasm_bindgen_test]
    async fn the_client_key_signs_the_assertion_ask() {
        let jwk = r#"{"kty": "EC", "x": "ktT77AqMntawPyU772lBg8nd7cwENrYyOL_KWbYN8Jc", "y": "67lPXEq5gJdimDYD0AacxLfRfIm2-fSNd3HBqyXXvBI", "crv": "P-256", "d": "KJEKZo2PQq6E40P6HMenViCVBRXoWD2FDyevRsJnlG0", "kid": "client-key-1", "use": "sig", "alg": "ES256"}"#;
        let host = MiniHost::new("123456".to_owned(), Some(jwk.to_owned()), None)
            .expect("the mini host builds");
        let tbs = "header.payload";
        let sign = host
            .request_sign(SignParams {
                flow_id: "flow-1".to_owned(),
                to_sign: tbs.as_bytes().to_vec(),
                key_id: Some("client-key-1".to_owned()),
                algorithm: "ES256".to_owned(),
            })
            .await
            .expect("the client key signs");
        assert_eq!(sign.signature.len(), 64, "the raw JOSE signature");

        // The signature must verify with the client key's public half.
        let public: jose_rs::jwk::Jwk = serde_json::from_value(serde_json::json!({
            "kty": "EC",
            "x": "ktT77AqMntawPyU772lBg8nd7cwENrYyOL_KWbYN8Jc",
            "y": "67lPXEq5gJdimDYD0AacxLfRfIm2-fSNd3HBqyXXvBI",
            "crv": "P-256",
            "kid": "client-key-1",
        }))
        .expect("the public JWK");
        let key = jose_rs::jwk::jwk_to_software_key(&public).expect("the public converts");
        let verifier = kryptering::SoftwareVerifier::new(
            kryptering::SignatureAlgorithm::Ecdsa(
                kryptering::EcCurve::P256,
                kryptering::HashAlgorithm::Sha256,
            ),
            key,
        )
        .expect("the verifier");
        let ok = kryptering::Verifier::verify(&verifier, tbs.as_bytes(), &sign.signature)
            .expect("verify runs");
        assert!(ok, "the assertion signature verifies with the client key");
    }
}
