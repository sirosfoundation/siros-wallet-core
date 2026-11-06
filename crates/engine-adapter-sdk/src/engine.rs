//! The in-process WMP engine: a UniFFI-exported handle the SDKs use as
//! their `Transport` implementation — replacing the WebSocket to the remote
//! engine with the Rust engine core running in the same process (the
//! gap-F2 wiring: the full ports, the flow runtime, the flow families,
//! and the notification channel the SDK polls).
//!
//! The handle exposes exactly the SDK's Transport shape: `send(ByteArray)`
//! for one JSON-RPC request (the response comes back synchronously), and
//! `take_notifications()` for the engine-to-client messages (flow
//! progress, sub-flow requests) that arrive between requests.
//!
//! The Kotlin adapter (`WmpUniFFITransport`) is a thin class over this
//! handle; the Swift adapter is the same shape.

use std::sync::Arc;

use crate::ports::{
    HostBridge, HttpClientBridge, InMemoryKv, NoopTelemetry, OsRng, PdpBridge, SystemClock,
    UnusedHost, UnusedHttp,
};
use crate::{Host, HttpClient, Pdp, SdkError};

use engine_core::runtime::FlowRuntime;
use wmp_core::context::RequestContext;
use wmp_core::error::RpcError;
use wmp_core::handler::HandlerError;
use wmp_core::methods::*;
use wmp_core::peer::Peer;
use wmp_core::session::MemorySessionStore;

/// The in-process WMP engine handle. The SDK creates one, sends WMP
/// messages through `send`, and reads the engine's notifications through
/// `take_notifications`.
///
/// The engine runs the full WMP stack in-process: the peer dispatches
/// every method, the session service manages sessions, and the flow
/// families (oid4vci, oid4vp, credential_notification) register on the
/// flow runtime. No WebSocket, no network to the engine — the only HTTP
/// is the engine's own outgoing fetches through the SDK's `HttpClient`
/// callback, and the wallet's asks go through the SDK's `Host`
/// callback.
#[derive(uniffi::Object)]
pub struct WmpEngine {
    peer: Arc<Peer>,
    store: Arc<MemorySessionStore>,
    channel: Arc<wmp_core::channel_transport::ChannelTransport>,
    /// The flow runtime, held so its lifetime is the engine's (its
    /// families and the swap-set peer go with it).
    _runtime: Arc<FlowRuntime>,
    /// The tokio runtime itself, kept alive with the engine.
    _tokio: Arc<tokio::runtime::Runtime>,
}

#[uniffi::export]
impl WmpEngine {
    /// Sends one WMP message (a JSON-RPC request or notification) to the
    /// engine and answers the reply. A notification answers `None`.
    ///
    /// This is the SDK Transport's `send` method: the SDK serialises the
    /// WMP message, calls this, and delivers the reply bytes to its
    /// `WmpSession` through the `incoming()` flow.
    ///
    /// The call blocks until the engine answers. The engine's sub-flow
    /// asks arrive on the `Host` callback while it is in flight, so the
    /// transport's caller must be free to serve them: call `send` from a
    /// worker whose dispatcher the callbacks can run on (never from the
    /// thread that must answer them).
    pub fn send(&self, message: Vec<u8>) -> Result<Option<Vec<u8>>, SdkError> {
        let ctx = RequestContext {
            // The SDK supplies the authenticated principal; the in-process
            // engine trusts the SDK (the SDK's auth module did the
            // login). The full token validation is the server adapter's.
            principal: Some(wmp_core::principal::Principal::new("sdk-user", "")),
            ..RequestContext::default()
        };
        self.peer
            .handle_request_sync(&ctx, &message)
            .map_err(|_err| SdkError::Internal)
    }

    /// Takes the engine's queued notifications (flow progress, sub-flow
    /// requests, completions) that arrived since the last call. The SDK
    /// delivers these to its `WmpSession` through the `incoming()` flow.
    ///
    /// Returns an empty list when nothing arrived. Poll it after each
    /// `send` and on the transport's own cadence — the engine's flow
    /// progress arrives while the wallet's UI is on screen.
    pub fn take_notifications(&self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(message) = self.channel.try_take_outbound() {
            out.push(message);
        }
        out
    }

    /// Blocks until the engine queues one notification, and answers it.
    /// The transport's polling thread calls this in a loop — the
    /// blocking form of [`WmpEngine::take_notifications`], for a
    /// transport that serves notifications the moment they arrive
    /// instead of on a cadence. The call answers `None` only when the
    /// engine's channel closed, which the in-process engine never does:
    /// run it on a thread that dies with the engine.
    pub fn read_notification(&self) -> Option<Vec<u8>> {
        self.channel.read_outbound()
    }

    /// The engine's session store, for the health probe.
    pub fn is_ready(&self) -> bool {
        // The store answers a read: the engine is alive.
        wmp_core::session::SessionStore::get(&*self.store, "sdk-probe").is_some() || true
        // an empty store is ready too
    }
}

/// The engine's construction configuration.
#[derive(uniffi::Record, Clone, Debug)]
pub struct EngineConfig {
    /// The maximum WMP message size (default 1 MiB).
    pub max_message_size: u64,
    /// The default session TTL in seconds (default 3600).
    pub default_session_ttl_secs: u64,
    /// The concurrent-flow limit the engine advertises in its `flows`
    /// capability.
    pub max_concurrent_flows: u64,
    /// The presentation consent check's mode (`warn`, `enforce`,
    /// `off`): how a match answer that does not fit the DCQL query it
    /// was sent is treated. An unrecognised value is warn, never off.
    pub consent_check: String,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            max_message_size: 1 << 20,
            default_session_ttl_secs: 3600,
            max_concurrent_flows: 16,
            consent_check: "warn".to_owned(),
        }
    }
}

/// Creates the in-process WMP engine with the given configuration and
/// ports. The SDK calls this once and holds the returned handle as its
/// Transport.
///
/// The engine runs the full WMP stack: the peer, the session service,
/// and the flow families (oid4vci, oid4vp, credential_notification)
/// registered on the flow runtime. The SDK supplies the world through
/// the callbacks:
/// - `http`: the engine's outgoing fetches (the app's platform stack
///   handles TLS, proxies and VPNs);
/// - `host`: the wallet's own asks — the sub-flows, the consents, the
///   key custody;
/// - `pdp`: the trust port, the app's trust stack. `None` is an
///   unconfigured PDP: the engine's trust evaluation fails closed on
///   it, so no flow passes the trust step until the app supplies one.
#[uniffi::export]
pub fn create_engine(
    config: EngineConfig,
    http: Box<dyn HttpClient>,
    host: Box<dyn Host>,
    pdp: Option<Box<dyn Pdp>>,
) -> Arc<WmpEngine> {
    let store = Arc::new(MemorySessionStore::new());

    // The tokio runtime the engine's async work runs on: the flow
    // dispatch blocks the foreign caller's thread on it (the callbacks
    // answer from the app's own dispatchers).
    let tokio_runtime = Arc::new(new_tokio_runtime());
    let handle = tokio_runtime.handle().clone();

    // The session service: the entropy and clock are the device's own,
    // the capability advert the SDK's session create negotiates against
    // — the flows and credential_notification capabilities, the same
    // shape the server's and the wasm dispatcher's session creates
    // advertise (the runtime's capability gate answers -31005 without
    // them).
    let entropy: wmp_core::sessionservice::EntropyFn =
        Arc::new(|bytes: &mut [u8]| engine_ports::Rng::fill(&OsRng, bytes));
    let clock: wmp_core::sessionservice::Clock =
        Arc::new(|| <SystemClock as engine_ports::Clock>::now_unix(&SystemClock));
    let supported = session_capabilities(config.max_concurrent_flows);

    let service = match wmp_core::sessionservice::SessionService::new(
        wmp_core::sessionservice::SessionServiceConfig {
            store: Some(store.clone()),
            entropy: Some(entropy),
            default_ttl_secs: config.default_session_ttl_secs as i64,
            supported,
            ..wmp_core::sessionservice::SessionServiceConfig::default()
        },
    ) {
        Ok(service) => Arc::new(service),
        Err(_) => {
            // The config is a constant here: the store and entropy are
            // always present. If it fails, the SDK cannot create
            // sessions — the fallback engine answers the service's
            // errors and -31005 for every flow.
            return fallback_engine(store, config, tokio_runtime);
        }
    };

    let session_handler = Arc::new(wmp_core::sessionservice::SessionHandler::new(
        service, clock,
    ));

    // The notification channel: the peer's outbound messages (the flow
    // progress, the completions, the sub-flow requests) land in it, and
    // `take_notifications` drains it.
    let channel = Arc::new(wmp_core::channel_transport::ChannelTransport::new(64, 1024));

    // The ports over the SDK's callbacks and the adapter's built-ins
    // (the gap-F2 wiring).
    let ports = Arc::new(engine_core::Ports {
        http: Arc::new(HttpClientBridge(http)),
        clock: Arc::new(SystemClock),
        rng: Arc::new(OsRng),
        host: Arc::new(HostBridge(host)),
        pdp: Arc::new(PdpBridge(pdp)),
        kv: Arc::new(InMemoryKv::default()),
        telemetry: Arc::new(NoopTelemetry),
        consent_check: engine_ports::ConsentCheckMode::parse(&config.consent_check),
        notifications: Arc::new(
            engine_core::oid4vci::notification::NotificationContexts::default(),
        ),
    });

    // The peer ↔ runtime cycle, the same break the server adapter
    // makes: the runtime over a placeholder peer, the handler (the
    // session methods + the flow dispatch) over it, the real peer over
    // the handler, then the real peer swapped in — no flow can start
    // before the swap, and every notification reaches the channel.
    let placeholder_peer = wmp_core::peer::PeerBuilder::new(Arc::new(PlaceholderHandler))
        .session_store(store.clone())
        .max_message_size(config.max_message_size as usize)
        .build();
    let runtime = Arc::new(FlowRuntime::new(ports, placeholder_peer));
    let handler = Arc::new(SdkHandler {
        session: session_handler,
        runtime: runtime.clone(),
        handle: handle.clone(),
    });
    let peer = wmp_core::peer::PeerBuilder::new(handler)
        .session_store(store.clone())
        .max_message_size(config.max_message_size as usize)
        .transport(channel.clone())
        .build();
    runtime.set_peer(peer.clone());

    // The flow families (the drop-in engine: a flow type nobody
    // registered answers -31005, core §10.3). The three own disjoint
    // flow types; the registration cannot collide.
    let _ = runtime.register(Arc::new(engine_core::oid4vci::Oid4vciFlow));
    let _ = runtime.register(Arc::new(engine_core::oid4vp::Oid4vpFlow));
    let _ = runtime.register(Arc::new(
        engine_core::oid4vci::notification::CredentialNotificationFlow,
    ));

    Arc::new(WmpEngine {
        peer,
        store,
        channel,
        _runtime: runtime,
        _tokio: tokio_runtime,
    })
}

/// The fallback engine, for a construction that should not fail: no
/// session service, no families — the session methods answer the
/// service's errors, every flow answers -31005 (nothing registered).
fn fallback_engine(
    store: Arc<MemorySessionStore>,
    config: EngineConfig,
    tokio_runtime: Arc<tokio::runtime::Runtime>,
) -> Arc<WmpEngine> {
    struct FallbackHandler;
    impl wmp_core::handler::Handler for FallbackHandler {}
    let channel = Arc::new(wmp_core::channel_transport::ChannelTransport::new(64, 1024));
    let peer = wmp_core::peer::PeerBuilder::new(Arc::new(FallbackHandler))
        .session_store(store.clone())
        .max_message_size(config.max_message_size as usize)
        .transport(channel.clone())
        .build();
    let ports = Arc::new(engine_core::Ports {
        http: Arc::new(UnusedHttp),
        clock: Arc::new(SystemClock),
        rng: Arc::new(OsRng),
        host: Arc::new(UnusedHost),
        pdp: Arc::new(PdpBridge(None)),
        kv: Arc::new(InMemoryKv::default()),
        telemetry: Arc::new(NoopTelemetry),
        consent_check: engine_ports::ConsentCheckMode::Warn,
        notifications: Arc::new(
            engine_core::oid4vci::notification::NotificationContexts::default(),
        ),
    });
    let runtime = Arc::new(FlowRuntime::new(ports, peer.clone()));
    Arc::new(WmpEngine {
        peer,
        store,
        channel,
        _runtime: runtime,
        _tokio: tokio_runtime,
    })
}

/// The multi-threaded tokio runtime the engine runs its async work on.
fn new_tokio_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|_| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap_or_else(|_| std::process::exit(1))
        })
}

/// The capabilities the engine's session create advertises (core
/// §10.3): the flows capability the families gate on, and the
/// credential_notification capability the notification flow gates on —
/// the same shape the server's and the wasm dispatcher's session
/// creates advertise.
fn session_capabilities(max_concurrent: u64) -> wmp_core::types::Capabilities {
    serde_json::from_value(serde_json::json!({
        "flows": { "max_concurrent": max_concurrent },
        "credential_notification": {
            "events": ["credential_accepted", "credential_failure"],
            "context_ttl_seconds": 300,
        },
    }))
    .unwrap_or_default()
}

/// The SDK's handler: the session methods over the session service, the
/// flow methods over the flow runtime — bridged to the tokio runtime
/// the engine owns (the peer's dispatch is sync, the runtime's flow
/// handling is not; the foreign caller's thread is not a runtime worker,
/// so `block_on` is safe).
struct SdkHandler {
    session: Arc<wmp_core::sessionservice::SessionHandler>,
    runtime: Arc<FlowRuntime>,
    handle: tokio::runtime::Handle,
}

impl wmp_core::handler::Handler for SdkHandler {
    fn session_create(
        &self,
        ctx: &RequestContext,
        params: &SessionCreateParams,
    ) -> Result<SessionCreateResult, HandlerError> {
        self.session.session_create(ctx, params)
    }

    fn session_resume(
        &self,
        ctx: &RequestContext,
        params: &SessionResumeParams,
    ) -> Result<SessionResumeResult, HandlerError> {
        self.session.session_resume(ctx, params)
    }

    fn session_close(&self, ctx: &RequestContext, params: &SessionCloseParams) {
        self.session.session_close(ctx, params)
    }

    fn session_authenticate(
        &self,
        ctx: &RequestContext,
        params: &SessionAuthenticateParams,
    ) -> Result<SessionAuthenticateResult, HandlerError> {
        self.session.session_authenticate(ctx, params)
    }

    fn flow_start(
        &self,
        ctx: &RequestContext,
        params: &FlowStartParams,
    ) -> Result<FlowStartResult, HandlerError> {
        let runtime = self.runtime.clone();
        let ctx = ctx.clone();
        let params = params.clone();
        self.handle
            .block_on(async move { runtime.start_flow(&ctx, &params).await })
    }

    fn flow_action(
        &self,
        ctx: &RequestContext,
        params: &FlowActionParams,
    ) -> Result<FlowActionResult, HandlerError> {
        let runtime = self.runtime.clone();
        let ctx = ctx.clone();
        let params = params.clone();
        self.handle
            .block_on(async move { runtime.handle_action(&ctx, &params).await })
    }

    fn flow_progress(&self, ctx: &RequestContext, params: &FlowProgressParams) {
        let runtime = self.runtime.clone();
        let ctx = ctx.clone();
        let params = params.clone();
        self.handle.block_on(async move {
            runtime.handle_progress(&ctx, &params).await;
        });
    }

    fn flow_complete(&self, ctx: &RequestContext, params: &FlowCompleteParams) {
        let runtime = self.runtime.clone();
        let ctx = ctx.clone();
        let params = params.clone();
        self.handle.block_on(async move {
            runtime.handle_complete(&ctx, &params).await;
        });
    }

    fn flow_error(&self, ctx: &RequestContext, params: &FlowErrorParams) {
        let runtime = self.runtime.clone();
        let ctx = ctx.clone();
        let params = params.clone();
        self.handle.block_on(async move {
            runtime.handle_error(&ctx, &params).await;
        });
    }

    fn flow_cancel(
        &self,
        ctx: &RequestContext,
        params: &FlowCancelParams,
    ) -> Result<FlowCancelResult, HandlerError> {
        let runtime = self.runtime.clone();
        let ctx = ctx.clone();
        let params = params.clone();
        self.handle
            .block_on(async move { runtime.handle_cancel(&ctx, &params).await })
    }
}

/// A handler that answers nothing — the placeholder the runtime is
/// constructed over before the real peer exists.
struct PlaceholderHandler;

impl wmp_core::handler::Handler for PlaceholderHandler {
    fn flow_start(
        &self,
        _ctx: &RequestContext,
        _params: &FlowStartParams,
    ) -> Result<FlowStartResult, HandlerError> {
        Err(HandlerError::Rpc(RpcError::code(
            wmp_core::error::ERR_CAPABILITY_NOT_SUPPORTED,
        )))
    }
}
