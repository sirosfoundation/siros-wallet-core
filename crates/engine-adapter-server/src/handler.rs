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
    /// The flow→session notes: each flow's start records the session it
    /// runs in, so the host bridge starts the flow's asks under it.
    flows: Arc<crate::host_bridge::FlowSessions>,
    /// The #319 lifecycle gate: the user's token cut-off, consulted at
    /// each flow start (an instance revoked mid-token must not start
    /// new flows). The standalone default answers nothing; the backend
    /// adapter implements it against the user store.
    gate: Arc<crate::token::NoTokenGate>,
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
        flows: Arc<crate::host_bridge::FlowSessions>,
    ) -> Arc<Self> {
        let service = Arc::new(
            SessionService::new(SessionServiceConfig {
                store: Some(store.clone()),
                default_ttl_secs: config.default_session_ttl_secs,
                entropy: Some(os_entropy()),
                replay: Some(Arc::new(OutboxReplayer { outbox })),
                // The flows capability the engine's families gate on
                // (core §10.3): the session create advertises it, so a
                // client that did not offer it refuses at the session,
                // not at the first flow start. The wasm dispatcher
                // advertises the same shape.
                supported: flows_capability(config.max_concurrent_flows).unwrap_or_else(|err| {
                    eprintln!("engine-server: invalid flows capability: {err}");
                    std::process::exit(1);
                }),
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
            flows,
            gate: Arc::new(crate::token::NoTokenGate),
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
        // The #319 lifecycle gate, the flow-start half: a principal whose
        // token was cut off (the wallet instance revoked mid-token)
        // starts no new flows. The Go engine consults
        // `User.AuthInvalidBefore` at the WS handshake AND each flow
        // start; the transport covers the handshake half
        // (`bearer_principal`), this covers the flow-start half. The
        // anonymous principal (no token) is the engine's own decision:
        // the standalone deployment requires a token for engine flows,
        // so it refuses here rather than starting an unowned flow.
        let principal = ctx
            .principal
            .as_ref()
            .filter(|p| p.is_authenticated())
            .ok_or_else(|| {
                flow_not_authorized("an engine flow start requires an authenticated principal")
            })?;
        if crate::token::principal_token_is_stale(principal, self.gate.as_ref()) {
            return Err(flow_not_authorized(
                "the principal's token was cut off; resume with a fresh token",
            ));
        }
        // The TAC gate (the Go engine's requiredTACForProtocol): each
        // flow type's action semantically requires one permission —
        // OID4VP shares an existing credential (read), OID4VCI receives
        // a new one (insert. Enforced ONLY when the principal carries a
        // TAC: an empty one is the legacy-auth shape, which has no TAC
        // concept (not "no permissions"), exactly as the Go engine
        // treats the HMAC path.
        if !principal.tac.is_empty() {
            if let Some(required) = required_tac(&params.flow_type) {
                if !principal.tac_has_all(required) {
                    return Err(flow_not_authorized(&format!(
                        "insufficient permissions for flow type {}: the principal's TAC lacks {}",
                        params.flow_type, required
                    )));
                }
            }
        }

        // The flow's session: the host bridge starts this flow's asks
        // under it (the child flows' wmp envelopes name the same
        // session, so the client's answers route back).
        self.flows.note(&params.flow_id, &params.wmp.session_id);
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
        // The OpenID4x action translation (3.1.2/3.2.2): the client's
        // user-response actions arrive under their OpenID4x names; the
        // engine's flow families answer the engine names. Translated
        // here, at the adapter, so the flow families stay on one
        // vocabulary (the #163 bridge's wmp_translate.go shape).
        let mut params = params.clone();
        params.action = translate_action(&params.action);
        let params = &params;
        tokio::task::block_in_place(|| {
            let runtime = self.runtime.clone();
            let ctx = ctx.clone();
            tokio::runtime::Handle::current()
                .block_on(async move { runtime.handle_action(&ctx, params).await })
        })
    }

    fn flow_cancel(
        &self,
        ctx: &RequestContext,
        params: &FlowCancelParams,
    ) -> Result<FlowCancelResult, HandlerError> {
        // The flow is off: its session note goes with it.
        self.flows.forget(&params.flow_id);
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

/// The flows capability the session create advertises (core §10.3): the
/// same shape the wasm dispatcher offers.
fn flows_capability(max_concurrent: i64) -> Result<wmp_core::types::Capabilities, String> {
    // The credential_notification capability (WMP OpenID4x 2.4): the
    // events the engine forwards and the TTL of the context it
    // retains. A wallet that wants to run the flow offers it; a
    // session that did not negotiate it refuses the flow (-31005,
    // core 10.3).
    serde_json::from_value(serde_json::json!({
        "flows": { "max_concurrent": max_concurrent },
        "credential_notification": {
            "events": ["credential_accepted", "credential_failure"],
            "context_ttl_seconds": 300,
        },
    }))
    .map_err(|err| format!("the flows capability does not serialize: {err}"))
}

// ─── The gates and the translation ───────────────────────────────────────────

/// The TAC permission a flow type's action semantically requires (the Go
/// engine's `requiredTACForProtocol`): OID4VP shares an existing
/// credential (read `r`), OID4VCI receives a new one (insert `i`). Other
/// flow types require nothing.
fn required_tac(flow_type: &str) -> Option<&'static str> {
    match flow_type {
        "oid4vp" => Some("r"),
        "oid4vci" => Some("i"),
        _ => None,
    }
}

/// The `-31002` flow refusal: the principal may not start this flow.
fn flow_not_authorized(reason: &str) -> HandlerError {
    HandlerError::Rpc(RpcError::new(
        wmp_core::error::ERR_NOT_AUTHORIZED,
        Some(serde_json::json!({ "reason": reason })),
    ))
}

/// The OpenID4x action translation (3.1.2/3.2.2): the client's
/// user-response action names, mapped to the engine's flow-action names.
/// Unknown actions pass through untouched — the flow families decide
/// what they answer (a family that answers an OpenID4x name directly
/// keeps it; a family that answers the engine name gets the translation).
///
/// | OpenID4x (the client sends) | The engine's flow action |
/// | --- | --- |
/// | `authorize` | `authorization_complete` |
/// | `select_credentials` | `select_credential` |
/// | `provide_tx_code` | `provide_pin` |
/// | `accept_offer` | `consent` (the offer consented) |
/// | `cancel` | (passed through: the flow cancel is its own method) |
fn translate_action(action: &str) -> String {
    match action {
        "authorize" => "authorization_complete".to_owned(),
        "select_credentials" => "select_credential".to_owned(),
        "provide_tx_code" => "provide_pin".to_owned(),
        "accept_offer" => "consent".to_owned(),
        other => other.to_owned(),
    }
}

#[cfg(test)]
mod translation_tests {
    //! The OpenID4x action translation's own proof (3.1.2/3.2.2): the
    //! client's user-response names map to the engine's flow-action
    //! names, unknown actions pass through.

    use super::*;

    #[test]
    fn the_openid4x_actions_map_to_the_engine_actions() {
        assert_eq!(translate_action("authorize"), "authorization_complete");
        assert_eq!(translate_action("select_credentials"), "select_credential");
        assert_eq!(translate_action("provide_tx_code"), "provide_pin");
        assert_eq!(translate_action("accept_offer"), "consent");
        // Unknown actions pass through: the flow families decide what
        // they answer (consent/decline stay, an engine-native name
        // stays).
        assert_eq!(translate_action("consent"), "consent");
        assert_eq!(translate_action("decline"), "decline");
        assert_eq!(
            translate_action("credentials_matched"),
            "credentials_matched"
        );
    }

    #[test]
    fn the_flow_types_carry_their_required_tacs() {
        // The Go engine's requiredTACForProtocol: OID4VP shares an
        // existing credential (read), OID4VCI receives a new one
        // (insert).
        assert_eq!(required_tac("oid4vp"), Some("r"));
        assert_eq!(required_tac("oid4vci"), Some("i"));
        assert_eq!(required_tac("vctm"), None);
        assert_eq!(required_tac("anything-else"), None);
    }

    #[test]
    fn the_principal_tac_gates_the_flow_types() {
        // The TAC-carrying principal: `ri` grants both engine flows;
        // `r` alone grants only the presentation.
        let both = wmp_core::principal::Principal::with_token("alice", "acme", "jti", "ri");
        assert!(both.tac_has_all(required_tac("oid4vp").unwrap_or("")));
        assert!(both.tac_has_all(required_tac("oid4vci").unwrap_or("")));
        let read_only = wmp_core::principal::Principal::with_token("alice", "acme", "jti", "r");
        assert!(read_only.tac_has_all(required_tac("oid4vp").unwrap_or("")));
        assert!(!read_only.tac_has_all(required_tac("oid4vci").unwrap_or("")));
        // The empty-TAC principal (the legacy shape): grants nothing,
        // and the gate does not enforce it at all.
        let legacy = wmp_core::principal::Principal::new("alice", "acme");
        assert!(legacy.tac.is_empty());
    }
}
