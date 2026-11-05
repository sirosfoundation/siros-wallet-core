//! The engine's WMP handler: session management through the session
//! service, and the flow methods delegated to the engine core's
//! `FlowRuntime` — the wiring that makes the server serve what the runtime
//! has registered, so the flow families (S0–S3) plug in without further
//! adapter work.

use std::sync::Arc;

use wmp_core::context::RequestContext;
use wmp_core::error::{RpcError, ERR_INVALID_PARAMS, ERR_METHOD_NOT_FOUND};
use wmp_core::handler::Handler;
use wmp_core::handler::HandlerError;
use wmp_core::methods::*;
use wmp_core::resolve::new_vctm_resolve_result;
use wmp_core::session::MemorySessionStore;
use wmp_core::sessionservice::{Clock, SessionHandler, SessionService, SessionServiceConfig};

use crate::config::Config;
use crate::outbox::{Outbox, OutboxReplayer};

/// The engine's handler: a `SessionHandler` for the session methods, and
/// the `FlowRuntime` for the flow methods. Every WMP method the engine
/// serves dispatches here; the session methods work today, and the flow
/// methods serve what the runtime's families have registered.
///
/// The flow families register on the runtime at startup
/// (the server calls `FlowRuntime::register` for each); a flow type nobody
/// registered answers `-31005` (capability not supported, core §10.3).
pub struct EngineHandler {
    session: Arc<SessionHandler>,
    runtime: Arc<engine_core::runtime::FlowRuntime>,
}

impl EngineHandler {
    /// Builds the handler from the config, the store, the runtime, and the
    /// outbound event log: the `wmp.session.resume` result's
    /// `missed_messages` counts from the same log the SSE route replays
    /// (go-wmp's replayer contract — one log, one truth).
    pub fn new(
        config: &Config,
        store: &Arc<MemorySessionStore>,
        runtime: Arc<engine_core::runtime::FlowRuntime>,
        outbox: Arc<Outbox>,
    ) -> Arc<Self> {
        let service = Arc::new(
            SessionService::new(SessionServiceConfig {
                store: Some(store.clone()),
                default_ttl_secs: config.default_session_ttl_secs,
                entropy: Some(os_entropy()),
                replay: Some(Arc::new(OutboxReplayer { outbox })),
                ..SessionServiceConfig::default()
            })
            .unwrap_or_else(|err| {
                eprintln!("engine-server: invalid session service config: {err}");
                std::process::exit(1);
            }),
        );
        Arc::new(Self {
            session: Arc::new(SessionHandler::new(service, system_clock())),
            runtime,
        })
    }
}

impl Handler for EngineHandler {
    // ── Session methods: the SessionHandler ──────────────────────────────

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

    // ── Resolve: the vctm lookup (WMP Core 5.8) ─────────────────────────

    /// `wmp.resolve` (WMP Core 5.8): the `vctm` lookup. The uri names a
    /// fetchable type metadata document (the Go engine's direct-URL path
    /// — its registry is the backend's, which the standalone engine does
    /// not carry) — fetched through the engine's own `HttpClient` port,
    /// with the port's transport rules, and projected to the six members
    /// a vctm resolution carries (Core 5.8.1).
    ///
    /// An empty uri answers `-32602`; a lookup that cannot produce a
    /// document — the fetch refused, a non-200, a document that cannot be
    /// carried — answers `-32603` with `reason: metadata_fetch_error`,
    /// never the raw body. A resolution type the engine does not serve
    /// answers `-32601`.
    fn resolve(
        &self,
        _ctx: &RequestContext,
        params: &ResolveParams,
    ) -> Result<ResolveResult, HandlerError> {
        if params.r#type != RESOLVE_TYPE_VCTM {
            return Err(RpcError::code(ERR_METHOD_NOT_FOUND).into());
        }
        if params.uri.is_empty() {
            return Err(RpcError::code(ERR_INVALID_PARAMS).into());
        }
        let fetch_error = || {
            HandlerError::Rpc(RpcError::new(
                wmp_core::error::ERR_INTERNAL_ERROR,
                Some(serde_json::json!({
                    "reason": wmp_core::resolve::RESOLVE_REASON_METADATA_FETCH_ERROR,
                })),
            ))
        };
        // The vctm fetch: bounded, the port's transport rules
        // (allow_plaintext refused). A 410-style per-fetch SSE route does
        // not apply here: the document is the engine's own answer.
        let response = tokio::task::block_in_place(|| {
            let ports = self.runtime.ports();
            let uri = params.uri.clone();
            tokio::runtime::Handle::current().block_on(async move {
                engine_ports::HttpClient::send(
                    ports.http.as_ref(),
                    engine_ports::HttpRequest {
                        method: "GET".to_owned(),
                        url: uri,
                        headers: vec![("accept".to_owned(), "application/json".to_owned())],
                        body: Vec::new(),
                        purpose: engine_ports::FetchPurpose::IssuerMetadata,
                        max_response_bytes: 1 << 20,
                        redirects: engine_ports::RedirectPolicy::Max(5),
                        allow_plaintext: false,
                        timeout_ms: 10_000,
                    },
                )
                .await
            })
        })
        .map_err(|_| fetch_error())?;
        if response.status != 200 {
            return Err(fetch_error());
        }
        // The projection to the carried members (the vct, name,
        // description, display, claims, schema), else the fetch error.
        new_vctm_resolve_result(&params.wmp.session_id, &params.uri, &response.body)
    }

    // ── Flow methods: the FlowRuntime ───────────────────────────────────
    //
    // The wmp-core peer checks its registry for a profile-registered flow
    // handler first; when none is found (the families are engine-core
    // FlowHandlers, not wmp-core Profiles), the peer falls through to
    // these methods, which delegate to the runtime. A flow type nobody
    // registered answers -31005 from the runtime directly.

    fn flow_start(
        &self,
        ctx: &RequestContext,
        params: &FlowStartParams,
    ) -> Result<FlowStartResult, HandlerError> {
        // The runtime's start_flow is async; the peer's dispatch is sync.
        // Bridge through the current runtime: block_in_place tells the
        // multi-threaded runtime this thread is going to block, so it can
        // schedule other workers. (The server always runs multi-threaded.)
        tokio::task::block_in_place(|| {
            let runtime = self.runtime.clone();
            let ctx = ctx.clone();
            let params = params.clone();
            tokio::runtime::Handle::current()
                .block_on(async move { runtime.start_flow(&ctx, &params).await })
        })
    }

    fn flow_action(
        &self,
        ctx: &RequestContext,
        params: &FlowActionParams,
    ) -> Result<FlowActionResult, HandlerError> {
        tokio::task::block_in_place(|| {
            let runtime = self.runtime.clone();
            let ctx = ctx.clone();
            let params = params.clone();
            tokio::runtime::Handle::current()
                .block_on(async move { runtime.handle_action(&ctx, &params).await })
        })
    }

    fn flow_cancel(
        &self,
        ctx: &RequestContext,
        params: &FlowCancelParams,
    ) -> Result<FlowCancelResult, HandlerError> {
        tokio::task::block_in_place(|| {
            let runtime = self.runtime.clone();
            let ctx = ctx.clone();
            let params = params.clone();
            tokio::runtime::Handle::current()
                .block_on(async move { runtime.handle_cancel(&ctx, &params).await })
        })
    }

    // ── Everything else: the SessionHandler's defaults (which answer
    // -32601 for unimplemented methods, which the peer converts to -31005
    // for flow types) ────────────────────────────────────────────────────
}

/// The system clock, unix seconds.
fn system_clock() -> Clock {
    Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or_default()
    })
}

/// The OS entropy source.
fn os_entropy() -> wmp_core::sessionservice::EntropyFn {
    Arc::new(|bytes: &mut [u8]| {
        use std::io::Read;
        match std::fs::File::open("/dev/urandom") {
            Ok(mut f) => f.read_exact(bytes).is_ok(),
            Err(_) => false,
        }
    })
}
