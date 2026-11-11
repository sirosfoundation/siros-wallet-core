//! The SDK callback interfaces bridged to the engine's ports (the gap-F2
//! wiring): the Kotlin/Swift implementations of this crate's
//! [`Host`](crate::Host), [`HttpClient`](crate::HttpClient) and
//! [`Pdp`](crate::Pdp) callback interfaces, wrapped as the
//! `engine-ports` traits the engine core runs on — plus the built-ins
//! the adapter supplies itself (the system clock, the OS randomness,
//! the in-memory persistence, the no-op telemetry).
//!
//! The engine core sees only `engine-ports`; the SDK sees only the
//! UniFFI types; the adapter maps between them.

use std::sync::Mutex;

use crate::{
    AttestationParams, ConsentParams, ConsentResult, CredentialSelectionParams, DpopProofParams,
    EvaluationRequest, Host, HttpClient, MatchParams, MatchResult, Pdp, ResolveRequest, SdkError,
    SignParams, SignResult, SigningKeyParams, VpParams,
};

/// The SDK's `Host` callback as the engine's port: every sub-flow ask
/// crosses the UniFFI boundary through here.
pub struct HostBridge(pub(crate) Box<dyn Host>);

/// The SDK's `HttpClient` callback as the engine's port: every fetch
/// the engine makes goes through the app's platform stack.
pub struct HttpClientBridge(pub(crate) Box<dyn HttpClient>);

/// The SDK's `Pdp` callback as the engine's trust port — `None` is the
/// unconfigured PDP, whose every operation answers `NotImplemented`
/// (the engine's trust evaluation fails closed on it).
pub struct PdpBridge(pub(crate) Option<Box<dyn Pdp>>);

/// The foreign error to the host error: a decline is the user's, the
/// rest the host cannot answer.
fn host_error(err: SdkError) -> engine_ports::HostError {
    match err {
        SdkError::Declined => engine_ports::HostError::Declined,
        SdkError::Cannot(detail) => engine_ports::HostError::Cannot(detail),
        // A transport failure on the host's side is not a decline: the
        // host could not answer.
        SdkError::NetworkRefused => {
            engine_ports::HostError::Cannot("the host's network refused".to_owned())
        }
        SdkError::Transport(detail) => engine_ports::HostError::Cannot(detail),
        SdkError::Internal => engine_ports::HostError::Cannot("the host failed".to_owned()),
    }
}

/// The foreign error to the PDP error: an unreachable evaluator is
/// never "no PDP configured".
fn pdp_error(err: SdkError) -> engine_ports::PdpError {
    match err {
        SdkError::NetworkRefused | SdkError::Transport(_) => engine_ports::PdpError::Unreachable,
        SdkError::Declined => engine_ports::PdpError::Error("the PDP declined".to_owned()),
        SdkError::Cannot(detail) => engine_ports::PdpError::Error(detail),
        SdkError::Internal => engine_ports::PdpError::Error("the PDP failed".to_owned()),
    }
}

#[async_trait::async_trait]
impl engine_ports::HttpClient for HttpClientBridge {
    async fn send(
        &self,
        request: engine_ports::HttpRequest,
    ) -> Result<engine_ports::HttpResponse, engine_ports::HttpError> {
        self.0
            .send(request.into())
            .await
            .map(Into::into)
            .map_err(|err| match err {
                SdkError::NetworkRefused => engine_ports::HttpError::Refused,
                SdkError::Transport(detail) => engine_ports::HttpError::Transport(detail),
                other => engine_ports::HttpError::Transport(other.to_string()),
            })
    }
}

impl From<engine_ports::HttpRequest> for crate::HttpRequest {
    fn from(r: engine_ports::HttpRequest) -> Self {
        Self {
            method: r.method,
            url: r.url,
            headers: r
                .headers
                .into_iter()
                .map(|(name, value)| crate::HeaderPair { name, value })
                .collect(),
            body: r.body,
            purpose: r.purpose.into(),
            max_response_bytes: r.max_response_bytes as u64,
            redirects: match r.redirects {
                engine_ports::RedirectPolicy::None => crate::RedirectPolicy::None,
                engine_ports::RedirectPolicy::Max(hops) => crate::RedirectPolicy::Max(hops as u32),
            },
            allow_plaintext: r.allow_plaintext,
            timeout_ms: r.timeout_ms,
        }
    }
}

impl From<crate::HttpResponse> for engine_ports::HttpResponse {
    fn from(r: crate::HttpResponse) -> Self {
        Self {
            status: r.status,
            headers: Vec::new(),
            body: r.body,
        }
    }
}

impl From<engine_ports::FetchPurpose> for crate::FetchPurpose {
    fn from(p: engine_ports::FetchPurpose) -> Self {
        match p {
            engine_ports::FetchPurpose::IssuerMetadata => Self::IssuerMetadata,
            engine_ports::FetchPurpose::AsMetadata => Self::AsMetadata,
            engine_ports::FetchPurpose::Offer => Self::Offer,
            engine_ports::FetchPurpose::Nonce => Self::Nonce,
            engine_ports::FetchPurpose::Token => Self::Token,
            engine_ports::FetchPurpose::Credential => Self::Credential,
            engine_ports::FetchPurpose::Deferred => Self::Deferred,
            engine_ports::FetchPurpose::Notification => Self::Notification,
            engine_ports::FetchPurpose::RequestObject => Self::RequestObject,
            engine_ports::FetchPurpose::ClientMetadata => Self::ClientMetadata,
            engine_ports::FetchPurpose::DirectPost => Self::DirectPost,
            engine_ports::FetchPurpose::Jwks => Self::Jwks,
            engine_ports::FetchPurpose::Logo => Self::Logo,
            engine_ports::FetchPurpose::Pdp => Self::Pdp,
            engine_ports::FetchPurpose::AsJwks => Self::AsJwks,
        }
    }
}

#[async_trait::async_trait]
impl engine_ports::Host for HostBridge {
    async fn request_sign(
        &self,
        params: engine_ports::SignParams,
    ) -> Result<engine_ports::SignResult, engine_ports::HostError> {
        let params: SignParams = params.into();
        self.0
            .request_sign(params)
            .await
            .map(Into::into)
            .map_err(host_error)
    }

    async fn request_signing_key(
        &self,
        params: engine_ports::SigningKeyParams,
    ) -> Result<engine_ports::SigningKeyResult, engine_ports::HostError> {
        let params = SigningKeyParams {
            flow_id: params.flow_id,
            key_id: params.key_id,
            fresh: params.fresh,
        };
        let answer = self
            .0
            .request_signing_key(params)
            .await
            .map_err(host_error)?;
        Ok(engine_ports::SigningKeyResult {
            jwk: serde_json::from_str(&answer.jwk).unwrap_or_default(),
        })
    }

    async fn request_match(
        &self,
        params: engine_ports::MatchParams,
    ) -> Result<engine_ports::MatchResult, engine_ports::HostError> {
        let params: MatchParams = params.into();
        self.0
            .request_match(params)
            .await
            .map(Into::into)
            .map_err(host_error)
    }

    async fn request_vp(
        &self,
        params: engine_ports::VpParams,
    ) -> Result<engine_ports::VpResult, engine_ports::HostError> {
        let params: VpParams = params.into();
        self.0
            .request_vp(params)
            .await
            .map(Into::into)
            .map_err(host_error)
    }

    async fn request_dpop_proof(
        &self,
        params: engine_ports::DpopProofParams,
    ) -> Result<engine_ports::DpopProofResult, engine_ports::HostError> {
        let params: DpopProofParams = params.into();
        self.0
            .request_dpop_proof(params)
            .await
            .map(Into::into)
            .map_err(host_error)
    }

    async fn request_consent(
        &self,
        params: engine_ports::ConsentParams,
    ) -> Result<engine_ports::ConsentResult, engine_ports::HostError> {
        let params = ConsentParams {
            flow_id: params.flow_id,
            purpose: params.purpose,
            requested_claims: params.requested_claims,
            transaction_data: params.transaction_data,
        };
        self.0
            .request_consent(params)
            .await
            .map(|ConsentResult { consented }| engine_ports::ConsentResult { consented })
            .map_err(host_error)
    }

    async fn request_tx_code(&self, flow_id: &str) -> Result<String, engine_ports::HostError> {
        self.0
            .request_tx_code(flow_id.to_owned())
            .await
            .map_err(host_error)
    }

    async fn open_authorization(
        &self,
        flow_id: &str,
        url: &str,
    ) -> Result<(), engine_ports::HostError> {
        self.0
            .open_authorization(flow_id.to_owned(), url.to_owned())
            .await
            .map_err(host_error)
    }

    async fn request_attestation(
        &self,
        params: engine_ports::AttestationParams,
    ) -> Result<engine_ports::AttestationResult, engine_ports::HostError> {
        let params = AttestationParams {
            flow_id: params.flow_id,
            audience: params.audience,
            client_id: params.client_id,
            challenge: params.challenge,
        };
        let answer = self
            .0
            .request_attestation(params)
            .await
            .map_err(host_error)?;
        Ok(engine_ports::AttestationResult {
            wia: answer.wia,
            pop: answer.pop,
        })
    }

    async fn request_credential_selection(
        &self,
        params: engine_ports::CredentialSelectionParams,
    ) -> Result<engine_ports::CredentialSelectionResult, engine_ports::HostError> {
        let params = CredentialSelectionParams {
            flow_id: params.flow_id,
            available: params.available.into_iter().map(Into::into).collect(),
        };
        let answer = self
            .0
            .request_credential_selection(params)
            .await
            .map_err(host_error)?;
        Ok(engine_ports::CredentialSelectionResult {
            credential_configuration_id: answer.credential_configuration_id,
        })
    }

    fn progress(&self, flow_id: &str, step: &str, detail: Option<String>) {
        self.0.progress(flow_id.to_owned(), step.to_owned(), detail);
    }
}

impl From<engine_ports::SignParams> for SignParams {
    fn from(p: engine_ports::SignParams) -> Self {
        Self {
            flow_id: p.flow_id,
            to_sign: p.to_sign,
            key_id: p.key_id,
            algorithm: p.algorithm,
        }
    }
}

impl From<SignResult> for engine_ports::SignResult {
    fn from(r: SignResult) -> Self {
        Self {
            signature: r.signature,
        }
    }
}

impl From<MatchResult> for engine_ports::MatchResult {
    fn from(r: MatchResult) -> Self {
        Self {
            selections: r.selections.into_iter().map(Into::into).collect(),
            handle: r.handle,
        }
    }
}

#[async_trait::async_trait]
impl engine_ports::Pdp for PdpBridge {
    async fn evaluate(
        &self,
        request: engine_ports::EvaluationRequest,
    ) -> Result<engine_ports::EvaluationResponse, engine_ports::PdpError> {
        let Some(pdp) = self.0.as_ref() else {
            return Err(engine_ports::PdpError::NotImplemented);
        };
        let request: EvaluationRequest = request.into();
        pdp.evaluate(request)
            .await
            .map(|answer| engine_ports::EvaluationResponse {
                trusted: answer.trusted,
                decision: answer.decision,
                // The FFI record carries the context as JSON text (the
                // UniFFI convention): parse it into the ports' Value here.
                context: answer
                    .context
                    .and_then(|text| serde_json::from_str(&text).ok()),
            })
            .map_err(pdp_error)
    }

    async fn resolve(
        &self,
        request: engine_ports::ResolveRequest,
    ) -> Result<engine_ports::ResolveResponse, engine_ports::PdpError> {
        let Some(pdp) = self.0.as_ref() else {
            return Err(engine_ports::PdpError::NotImplemented);
        };
        let request = ResolveRequest {
            uri: request.uri,
            resource_type: request.resource_type,
        };
        pdp.resolve(request)
            .await
            .map(|answer| engine_ports::ResolveResponse {
                metadata: answer.metadata,
                trust_info: answer.trust_info,
            })
            .map_err(pdp_error)
    }

    async fn evaluate_entitlement(
        &self,
        request: engine_ports::EntitlementRequest,
    ) -> Result<engine_ports::EntitlementDecision, engine_ports::PdpError> {
        let Some(pdp) = self.0.as_ref() else {
            return Err(engine_ports::PdpError::NotImplemented);
        };
        let request = crate::EntitlementRequest {
            issuer: request.issuer,
            metadata: request.metadata,
            key_material: request.key_material,
            offers: request
                .offers
                .into_iter()
                .map(|offer| crate::EntitlementOffer {
                    format: offer.format,
                    credential_type: offer.credential_type,
                })
                .collect(),
        };
        let answer = pdp.evaluate_entitlement(request).await.map_err(pdp_error)?;
        Ok(engine_ports::EntitlementDecision {
            allowed: answer.allowed,
            mode: answer.mode.into(),
            evaluated: answer.evaluated,
            findings: answer
                .findings
                .into_iter()
                .map(|finding| engine_ports::EntitlementFinding {
                    code: finding.code.into(),
                    message: finding.message,
                    credential_type: finding.credential_type,
                })
                .collect(),
            findings_truncated: answer.findings_truncated,
        })
    }
}

// ─── The built-ins ───────────────────────────────────────────────────────

/// The system clock: the OS's own time, what a mobile app has.
pub struct SystemClock;

#[async_trait::async_trait]
impl engine_ports::Clock for SystemClock {
    fn now_unix(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or_default()
    }

    async fn sleep(&self, duration_ms: u64) {
        tokio::time::sleep(std::time::Duration::from_millis(duration_ms)).await;
    }
}

/// The OS randomness: the device's secure entropy.
pub struct OsRng;

impl engine_ports::Rng for OsRng {
    fn fill(&self, buf: &mut [u8]) -> bool {
        use std::io::Read;
        match std::fs::File::open("/dev/urandom") {
            Ok(mut file) => file.read_exact(buf).is_ok(),
            Err(_) => false,
        }
    }
}

/// One stored entry: the value and its TTL.
type StoredEntry = (Vec<u8>, Option<i64>);

/// The in-memory persistence: the default; nothing the SDK persists
/// through this port survives the process.
pub struct InMemoryKv(Mutex<rustc_hash::FxHashMap<String, StoredEntry>>);

impl Default for InMemoryKv {
    fn default() -> Self {
        Self(Mutex::new(rustc_hash::FxHashMap::default()))
    }
}

#[async_trait::async_trait]
impl engine_ports::KeyValue for InMemoryKv {
    async fn get(&self, key: &str) -> Option<engine_ports::KeyValueEntry> {
        self.0
            .lock()
            .ok()?
            .get(key)
            .map(|(value, _)| engine_ports::KeyValueEntry {
                value: value.clone(),
                ttl_secs: None,
            })
    }

    async fn put(&self, key: &str, entry: engine_ports::KeyValueEntry) {
        if let Ok(mut map) = self.0.lock() {
            map.insert(
                key.to_owned(),
                (entry.value, entry.ttl_secs.map(|secs| secs as i64)),
            );
        }
    }

    async fn delete(&self, key: &str) {
        if let Ok(mut map) = self.0.lock() {
            map.remove(key);
        }
    }
}

/// The no-op telemetry.
pub struct NoopTelemetry;

impl engine_ports::Telemetry for NoopTelemetry {
    fn event(&self, _event: engine_ports::TelemetryEvent) {}
}

// ─── The unused stubs (the fallback engine's) ────────────────────────────

/// The HTTP port that refuses everything — the fallback engine's.
pub struct UnusedHttp;

#[async_trait::async_trait]
impl engine_ports::HttpClient for UnusedHttp {
    async fn send(
        &self,
        _request: engine_ports::HttpRequest,
    ) -> Result<engine_ports::HttpResponse, engine_ports::HttpError> {
        Err(engine_ports::HttpError::Refused)
    }
}

/// The host that answers nothing — the fallback engine's.
pub struct UnusedHost;

#[async_trait::async_trait]
impl engine_ports::Host for UnusedHost {
    async fn request_sign(
        &self,
        _params: engine_ports::SignParams,
    ) -> Result<engine_ports::SignResult, engine_ports::HostError> {
        Err(engine_ports::HostError::Cannot(
            "the engine is not wired".to_owned(),
        ))
    }

    async fn request_match(
        &self,
        _params: engine_ports::MatchParams,
    ) -> Result<engine_ports::MatchResult, engine_ports::HostError> {
        Err(engine_ports::HostError::Cannot(
            "the engine is not wired".to_owned(),
        ))
    }

    async fn request_consent(
        &self,
        _params: engine_ports::ConsentParams,
    ) -> Result<engine_ports::ConsentResult, engine_ports::HostError> {
        Err(engine_ports::HostError::Cannot(
            "the engine is not wired".to_owned(),
        ))
    }

    async fn request_tx_code(&self, _flow_id: &str) -> Result<String, engine_ports::HostError> {
        Err(engine_ports::HostError::Cannot(
            "the engine is not wired".to_owned(),
        ))
    }

    async fn open_authorization(
        &self,
        _flow_id: &str,
        _url: &str,
    ) -> Result<(), engine_ports::HostError> {
        Err(engine_ports::HostError::Cannot(
            "the engine is not wired".to_owned(),
        ))
    }

    fn progress(&self, _flow_id: &str, _step: &str, _detail: Option<String>) {}
}
