//! The engine's WMP handler: session management through the session
//! service, and the flow methods delegated to the engine core's
//! `FlowRuntime` — the wiring that makes the server serve what the runtime
//! has registered, so the flow families (S0–S3) plug in without further
//! adapter work.

use std::sync::Arc;

use wmp_core::context::RequestContext;
use wmp_core::handler::Handler;
use wmp_core::handler::HandlerError;
use wmp_core::methods::*;
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
