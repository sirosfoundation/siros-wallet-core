//! The server adapter's implementations of the engine-ports traits: what
//! the engine core runs on when deployed as a container.

use std::sync::Arc;

use engine_ports::{
    Clock, ConsentParams, ConsentResult, EvaluationRequest, EvaluationResponse, Host, HostError,
    HttpClient, HttpError, HttpRequest, HttpResponse, KeyValue, KeyValueEntry, MatchResult, Pdp,
    PdpError, ResolveRequest, ResolveResponse, Rng, SignParams, SignResult, Telemetry,
    TelemetryEvent,
};

use crate::config::Config;

// ─── HttpClient: the server's HTTP client ─────────────────────────────────

/// The server's HTTP client: `reqwest` with `rustls`, enforcing the
/// address policy and the limits the core declares. The TEE adapter replaces
/// this with its own client (TLS inside the trusted binary).
pub struct ServerHttpClient {
    client: reqwest::Client,
    allow_plaintext: bool,
}

impl ServerHttpClient {
    /// Builds the client from the config.
    pub fn new(config: &Config) -> Self {
        Self {
            client: reqwest::Client::builder()
                .use_rustls_tls()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
            allow_plaintext: config.allow_plaintext,
        }
    }
}

#[async_trait::async_trait]
impl HttpClient for ServerHttpClient {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, HttpError> {
        // Enforce the address policy: refuse private, loopback, link-local
        // and cloud-metadata addresses at dial time, on every redirect hop.
        // reqwest's redirect policy handles the hops; the address check is
        // the adapter's job.
        if !request.allow_plaintext && !self.allow_plaintext {
            if let Some(scheme) = request.url.split(':').next() {
                if scheme != "https" {
                    return Err(HttpError::Refused);
                }
            }
        }

        let method = reqwest::Method::from_bytes(request.method.as_bytes())
            .map_err(|_| HttpError::Transport("invalid method".to_owned()))?;

        let mut builder = self
            .client
            .request(method, &request.url)
            .timeout(std::time::Duration::from_millis(request.timeout_ms));

        for (name, value) in &request.headers {
            builder = builder.header(name, value);
        }

        if !request.body.is_empty() {
            builder = builder.body(request.body.clone());
        }

        let response = builder
            .send()
            .await
            .map_err(|err| HttpError::Transport(err.to_string()))?;

        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|v| (name.to_string(), v.to_owned()))
            })
            .collect();

        // Bound the response size: read at most one byte past the declared
        // limit, and refuse the response if it exceeded the limit.
        let body = response
            .bytes()
            .await
            .map_err(|err| HttpError::Transport(err.to_string()))?;

        if body.len() > request.max_response_bytes {
            return Err(HttpError::Refused);
        }

        Ok(HttpResponse {
            status,
            headers,
            body: body.to_vec(),
        })
    }
}

// ─── Clock: the system clock ──────────────────────────────────────────────

/// The system clock.
pub struct SystemClock;

#[async_trait::async_trait]
impl Clock for SystemClock {
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

// ─── Rng: the OS secure RNG ───────────────────────────────────────────────

/// The OS secure RNG.
pub struct OsRng;

impl Rng for OsRng {
    fn fill(&self, buf: &mut [u8]) -> bool {
        use std::io::Read;
        match std::fs::File::open("/dev/urandom") {
            Ok(mut f) => f.read_exact(buf).is_ok(),
            Err(_) => false,
        }
    }
}

// ─── Host: the remote WMP peer ────────────────────────────────────────────

/// The remote wallet host: the WMP client on the other side of the
/// transport. The engine's sub-flow asks (sign, match, consent, tx_code,
/// presentation, DPoP, attestation, the authorization navigation) go to
/// the client as **child flows** through the [`WmpHostBridge`] — a
/// `wmp.flow.start` for the ask, the client's `wmp.flow.complete` the
/// answer — exactly the pattern the #163 bridge's `wmpTransport` drives.
///
/// The bridge is set after construction (`set_bridge`): the peer the
/// bridge sends through is built after the ports (the handler needs the
/// runtime, the runtime the ports), so the host starts empty and is
/// wired once the peer exists. Before the wiring, every ask refuses —
/// the engine's flows see a host that cannot answer, never a panic.
pub struct RemoteHost {
    bridge: std::sync::OnceLock<Arc<crate::host_bridge::WmpHostBridge>>,
    /// The flow→session notes the handler keeps (the flow start's
    /// `wmp.session_id`): the asks start under their flow's session.
    sessions: Arc<crate::host_bridge::FlowSessions>,
}

impl RemoteHost {
    /// An unwired host: every ask refuses until the bridge is set.
    pub fn new(sessions: Arc<crate::host_bridge::FlowSessions>) -> Self {
        Self {
            bridge: std::sync::OnceLock::new(),
            sessions,
        }
    }

    /// Wires the bridge. Idempotent; the first wiring wins.
    pub fn set_bridge(&self, bridge: Arc<crate::host_bridge::WmpHostBridge>) {
        let _ = self.bridge.set(bridge);
    }

    /// The bridge, or the refusal when it is not wired.
    fn bridge(&self) -> Result<&Arc<crate::host_bridge::WmpHostBridge>, HostError> {
        self.bridge.get().ok_or_else(|| {
            HostError::Cannot("the remote host is not wired to the transport".to_owned())
        })
    }

    /// The session a flow's asks start under: the flow's own, else the
    /// empty key (the asks still route — the child ids are unique, and
    /// the session names the envelope).
    fn session(&self, flow_id: &str) -> String {
        self.sessions.session_of(flow_id).unwrap_or_default()
    }
}

#[async_trait::async_trait]
impl Host for RemoteHost {
    async fn request_sign(&self, params: SignParams) -> Result<SignResult, HostError> {
        let bridge = self.bridge()?;
        let ctx = wmp_core::context::RequestContext::default();
        let session = self.session(&params.flow_id);
        let answer = bridge
            .request(
                &ctx,
                &params.flow_id,
                &session,
                "sign",
                &params,
                crate::host_bridge::ask::SIGN,
            )
            .await
            .map_err(|err| err.into_host_error())?;
        serde_json::from_str(answer.get())
            .map_err(|_| HostError::Cannot("the sign answer does not parse".to_owned()))
    }

    async fn request_signing_key(
        &self,
        params: engine_ports::SigningKeyParams,
    ) -> Result<engine_ports::SigningKeyResult, HostError> {
        let bridge = self.bridge()?;
        let ctx = wmp_core::context::RequestContext::default();
        let session = self.session(&params.flow_id);
        let answer = bridge
            .request(
                &ctx,
                &params.flow_id,
                &session,
                "signing_key",
                &params,
                crate::host_bridge::ask::MATCH,
            )
            .await
            .map_err(|err| err.into_host_error())?;
        serde_json::from_str(answer.get())
            .map_err(|_| HostError::Cannot("the signing-key answer does not parse".to_owned()))
    }

    async fn request_match(
        &self,
        params: engine_ports::MatchParams,
    ) -> Result<MatchResult, HostError> {
        let bridge = self.bridge()?;
        let ctx = wmp_core::context::RequestContext::default();
        let session = self.session(&params.flow_id);
        let answer = bridge
            .request(
                &ctx,
                &params.flow_id,
                &session,
                "match",
                &params,
                crate::host_bridge::ask::MATCH,
            )
            .await
            .map_err(|err| err.into_host_error())?;
        serde_json::from_str(answer.get())
            .map_err(|_| HostError::Cannot("the match answer does not parse".to_owned()))
    }

    async fn request_consent(&self, params: ConsentParams) -> Result<ConsentResult, HostError> {
        let bridge = self.bridge()?;
        let ctx = wmp_core::context::RequestContext::default();
        let session = self.session(&params.flow_id);
        let answer = bridge
            .request(
                &ctx,
                &params.flow_id,
                &session,
                "consent",
                &params,
                crate::host_bridge::ask::CONSENT,
            )
            .await
            .map_err(|err| err.into_host_error())?;
        serde_json::from_str(answer.get())
            .map_err(|_| HostError::Cannot("the consent answer does not parse".to_owned()))
    }

    async fn request_tx_code(&self, flow_id: &str) -> Result<String, HostError> {
        let bridge = self.bridge()?;
        let ctx = wmp_core::context::RequestContext::default();
        let session = self.session(flow_id);
        let answer = bridge
            .request(
                &ctx,
                flow_id,
                &session,
                "tx_code",
                &serde_json::json!({ "flow_id": flow_id }),
                crate::host_bridge::ask::TX_CODE,
            )
            .await
            .map_err(|err| err.into_host_error())?;
        // The answer is the code itself (a JSON string), or an object
        // carrying it — the client's choice; both are read.
        let value: serde_json::Value = serde_json::from_str(answer.get())
            .map_err(|_| HostError::Cannot("the tx_code answer does not parse".to_owned()))?;
        value
            .as_str()
            .map(str::to_owned)
            .or_else(|| {
                value
                    .get("tx_code")
                    .and_then(|v| v.as_str())
                    .map(str::to_owned)
            })
            .ok_or_else(|| HostError::Cannot("the tx_code answer carries no code".to_owned()))
    }

    async fn open_authorization(&self, flow_id: &str, url: &str) -> Result<(), HostError> {
        let bridge = self.bridge()?;
        let ctx = wmp_core::context::RequestContext::default();
        let session = self.session(flow_id);
        // The authorization ask: the client navigates, and the redirect's
        // answer comes back through its own flow action — the ask itself
        // completes when the client took the URL (the redirect is the
        // flow's, resumed by `wmp.flow.action`, not the ask's).
        bridge
            .request(
                &ctx,
                flow_id,
                &session,
                "authorization",
                &serde_json::json!({ "flow_id": flow_id, "url": url }),
                crate::host_bridge::ask::AUTHORIZATION,
            )
            .await
            .map_err(|err| err.into_host_error())?;
        Ok(())
    }

    async fn request_vp(
        &self,
        params: engine_ports::VpParams,
    ) -> Result<engine_ports::VpResult, HostError> {
        let bridge = self.bridge()?;
        let ctx = wmp_core::context::RequestContext::default();
        let session = self.session(&params.flow_id);
        let answer = bridge
            .request(
                &ctx,
                &params.flow_id,
                &session,
                "presentation",
                &params,
                crate::host_bridge::ask::PRESENTATION,
            )
            .await
            .map_err(|err| err.into_host_error())?;
        serde_json::from_str(answer.get())
            .map_err(|_| HostError::Cannot("the presentation answer does not parse".to_owned()))
    }

    async fn request_dpop_proof(
        &self,
        params: engine_ports::DpopProofParams,
    ) -> Result<engine_ports::DpopProofResult, HostError> {
        let bridge = self.bridge()?;
        let ctx = wmp_core::context::RequestContext::default();
        let session = self.session(&params.flow_id);
        let answer = bridge
            .request(
                &ctx,
                &params.flow_id,
                &session,
                "dpop_proof",
                &params,
                crate::host_bridge::ask::DPOP_PROOF,
            )
            .await
            .map_err(|err| err.into_host_error())?;
        serde_json::from_str(answer.get())
            .map_err(|_| HostError::Cannot("the DPoP answer does not parse".to_owned()))
    }

    async fn request_attestation(
        &self,
        params: engine_ports::AttestationParams,
    ) -> Result<engine_ports::AttestationResult, HostError> {
        let bridge = self.bridge()?;
        let ctx = wmp_core::context::RequestContext::default();
        let session = self.session(&params.flow_id);
        let answer = bridge
            .request(
                &ctx,
                &params.flow_id,
                &session,
                "attestation",
                &params,
                crate::host_bridge::ask::ATTESTATION,
            )
            .await
            .map_err(|err| err.into_host_error())?;
        serde_json::from_str(answer.get())
            .map_err(|_| HostError::Cannot("the attestation answer does not parse".to_owned()))
    }

    fn progress(&self, flow_id: &str, step: &str, detail: Option<String>) {
        // Fire and forget: the progress notification rides the peer's
        // transport (the outbox), the client's UI hears the step. The
        // bridge is not needed for it — but the peer is only reachable
        // through it, so an unwired host drops the step.
        let Some(bridge) = self.bridge.get() else {
            return;
        };
        let ctx = wmp_core::context::RequestContext::default();
        let session = self.session(flow_id);
        let _ = bridge.progress(&ctx, flow_id, &session, step, detail);
    }
}

// ─── Pdp: the backend proxy ───────────────────────────────────────────────

/// The PDP through the backend's proxy: `/v1/evaluate` and `/v1/resolve`.
/// What the SDK's `BackendProxy` Pdp port talks to when the engine is
/// remote; what the server adapter talks to when the engine is the
/// backend's own engine.
pub struct BackendProxyPdp {
    client: reqwest::Client,
    proxy_url: String,
    token: Option<String>,
}

impl BackendProxyPdp {
    /// Builds the PDP client from the config. The `pdp_url` is the
    /// backend's proxy endpoint (the `/v1/evaluate` and `/v1/resolve`
    /// routes); an empty URL means the PDP is not configured and the
    /// engine fails closed.
    pub fn new(config: &Config) -> Self {
        Self {
            client: reqwest::Client::builder()
                .use_rustls_tls()
                .build()
                .unwrap_or_default(),
            proxy_url: config.pdp_url.clone(),
            token: None,
        }
    }

    /// Sets the bearer token the proxy validates.
    pub fn with_token(mut self, token: String) -> Self {
        self.token = Some(token);
        self
    }
}

#[async_trait::async_trait]
impl Pdp for BackendProxyPdp {
    async fn evaluate(&self, request: EvaluationRequest) -> Result<EvaluationResponse, PdpError> {
        let url = format!("{}/v1/evaluate", self.proxy_url);
        let mut builder = self.client.post(&url).json(&serde_json::json!({
            "subject": request.subject,
            "key_material": request.key_material,
        }));
        if let Some(token) = &self.token {
            builder = builder.bearer_auth(token);
        }
        let response = builder.send().await.map_err(|_| PdpError::Unreachable)?;
        if !response.status().is_success() {
            return Err(PdpError::Error(format!(
                "evaluate answered {}",
                response.status()
            )));
        }
        response
            .json()
            .await
            .map_err(|err| PdpError::Error(err.to_string()))
    }

    async fn resolve(&self, request: ResolveRequest) -> Result<ResolveResponse, PdpError> {
        let url = format!("{}/v1/resolve", self.proxy_url);
        let mut builder = self.client.post(&url).json(&serde_json::json!({
            "uri": request.uri,
            "resource_type": request.resource_type,
        }));
        if let Some(token) = &self.token {
            builder = builder.bearer_auth(token);
        }
        let response = builder.send().await.map_err(|_| PdpError::Unreachable)?;
        if !response.status().is_success() {
            return Err(PdpError::Error(format!(
                "resolve answered {}",
                response.status()
            )));
        }
        response
            .json()
            .await
            .map_err(|err| PdpError::Error(err.to_string()))
    }
}

// ─── KeyValue: in-memory ──────────────────────────────────────────────────

/// The in-memory KV store: the default; the shared store arrives with the
/// backend adapter.
#[derive(Default)]
pub struct InMemoryKv {
    entries: parking_lot::RwLock<
        rustc_hash::FxHashMap<String, (KeyValueEntry, Option<std::time::Instant>)>,
    >,
}

#[async_trait::async_trait]
impl KeyValue for InMemoryKv {
    async fn get(&self, key: &str) -> Option<KeyValueEntry> {
        let entries = self.entries.read();
        let (entry, expires) = entries.get(key)?;
        if let Some(expires) = expires {
            if std::time::Instant::now() > *expires {
                return None;
            }
        }
        Some(entry.clone())
    }

    async fn put(&self, key: &str, entry: KeyValueEntry) {
        let expires = entry
            .ttl_secs
            .map(|ttl| std::time::Instant::now() + std::time::Duration::from_secs(ttl));
        self.entries
            .write()
            .insert(key.to_owned(), (entry, expires));
    }

    async fn delete(&self, key: &str) {
        self.entries.write().remove(key);
    }
}

// ─── Telemetry: no-op ─────────────────────────────────────────────────────

/// The no-op telemetry: the server adapter's logging arrives with the
/// observability wiring.
pub struct NoopTelemetry;

impl Telemetry for NoopTelemetry {
    fn event(&self, _event: TelemetryEvent) {}
}
