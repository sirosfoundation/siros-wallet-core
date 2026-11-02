//! The registry: registered profiles, and the routing state machine that
//! delivers each flow's messages to the instance that owns it.

use std::sync::{Arc, RwLock};

use crate::context::RequestContext;
use crate::handler::HandlerError;
use crate::methods::*;
use crate::profile::{ChainStep, DispatchResult, Middleware, Profile};
use crate::session::Session;
use rustc_hash::FxHashMap;

/// The registry: profiles, middleware, session hooks, and the routes of
/// active flows.
pub struct Registry {
    inner: RwLock<Inner>,
}

struct Inner {
    profiles: Vec<Arc<dyn Profile>>,
    flow_handlers: FxHashMap<String, Arc<dyn Profile>>,
    methods: FxHashMap<String, Arc<dyn Profile>>,
    resolvers: FxHashMap<String, Arc<dyn Profile>>,
    id_resolvers: Vec<Arc<dyn Profile>>,
    middleware: Vec<Middleware>,
    session_hooks: Vec<Arc<dyn Profile>>,
    resume_hooks: Vec<Arc<dyn Profile>>,

    /// Each active flow_id's route. Entries are told apart by a generation,
    /// never by comparing profiles (a profile need not be comparable).
    flows: FxHashMap<String, FlowEntry>,
    /// The `wmp.flow.start`s whose handler is still running.
    starting: FxHashMap<String, StartState>,
    next_gen: u64,
}

/// The route of one flow instance. `gen` identifies the instance: a flow_id
/// reused after the flow ended gets a new generation, so a message or a
/// cleanup that belongs to the old instance cannot touch the new one.
#[derive(Clone)]
pub(crate) struct FlowEntry {
    pub(crate) flow_id: String,
    pub(crate) handler: Arc<dyn Profile>,
    /// The one session whose messages are routed to the handler; empty
    /// accepts any session.
    pub(crate) session: String,
    pub(crate) claimed: bool,
    /// The handler ends the route of each flow itself
    /// ([`Profile::manages_flow_routes`]). The route of any other handler's
    /// flow may be replaced by a start of the same flow_id from the same
    /// session.
    pub(crate) managed: bool,
    pub(crate) gen: u64,
    /// The flow has ended — its terminal notification went out or came in,
    /// or it was cancelled — though its worker may still be winding down.
    /// Its flow_id stays reserved, and a repeated start is not acknowledged.
    pub(crate) terminal: bool,
    /// Identifies the `wmp.flow.start` the flow was started by (type and
    /// params), so the same start sent again is recognised.
    pub(crate) start_id: [u8; 32],
    /// The dispatches using this route; a route released meanwhile (ended)
    /// goes away when the last one is done.
    inflight: usize,
    ended: bool,
}

/// Limits of what is held for a flow whose start is still running: a few
/// progress notifications, at most one terminal notification and one cancel.
const MAX_DEFERRED_PROGRESS: usize = 16;

/// A `wmp.flow.start` whose handler is running. Messages for the flow that
/// arrive meanwhile are held, in arrival order and within the limits, and
/// applied once the handler has returned and the flow exists.
struct StartState {
    session: String,
    queue: Vec<DeferredOp>,
    progress: usize,
    terminal: usize,
    cancel: usize,
}

/// A message held while a flow starts.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeferKind {
    /// A `wmp.flow.progress`.
    Progress,
    /// A `wmp.flow.complete` or `wmp.flow.error`.
    Terminal,
    /// A `wmp.flow.cancel`.
    Cancel,
}

/// One held operation, with the route's generation baked in.
struct DeferredOp {
    #[allow(dead_code)]
    kind: DeferKind,
    op: Box<dyn FnOnce() + Send + Sync>,
}

/// What [`Registry::begin_start`] decided.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum StartOutcome {
    /// Go ahead and start the flow.
    Reserved,
    /// The flow_id is not available.
    Refused,
    /// The same start was already accepted: acknowledge it again.
    Duplicate,
}

impl Registry {
    /// An empty registry.
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(Inner {
                profiles: Vec::new(),
                flow_handlers: FxHashMap::default(),
                methods: FxHashMap::default(),
                resolvers: FxHashMap::default(),
                id_resolvers: Vec::new(),
                middleware: Vec::new(),
                session_hooks: Vec::new(),
                resume_hooks: Vec::new(),
                flows: FxHashMap::default(),
                starting: FxHashMap::default(),
                next_gen: 0,
            }),
        }
    }

    /// Adds a profile and registers its handlers. Conflicts with
    /// already-registered handlers are errors.
    pub fn register(&self, profile: Arc<dyn Profile>) -> Result<(), HandlerError> {
        let mut inner = self
            .inner
            .write()
            .map_err(|_| HandlerError::Internal("registry lock".into()))?;
        for flow_type in profile.flow_types() {
            if inner.flow_handlers.contains_key(&flow_type) {
                return Err(HandlerError::Internal(
                    format!("flow type {flow_type:?} already registered").into(),
                ));
            }
        }
        for method in profile.methods() {
            if inner.methods.contains_key(&method) {
                return Err(HandlerError::Internal(
                    format!("method {method:?} already registered").into(),
                ));
            }
        }
        for resolve_type in profile.resolve_types() {
            if inner.resolvers.contains_key(&resolve_type) {
                return Err(HandlerError::Internal(
                    format!("resolve type {resolve_type:?} already registered").into(),
                ));
            }
        }
        for flow_type in profile.flow_types() {
            inner.flow_handlers.insert(flow_type, profile.clone());
        }
        for method in profile.methods() {
            inner.methods.insert(method, profile.clone());
        }
        for resolve_type in profile.resolve_types() {
            inner.resolvers.insert(resolve_type, profile.clone());
        }
        if !profile.identifier_schemes().is_empty() {
            inner.id_resolvers.push(profile.clone());
        }
        if profile.has_session_hooks() {
            inner.session_hooks.push(profile.clone());
        }
        if profile.has_resume_hooks() {
            inner.resume_hooks.push(profile.clone());
        }
        inner.profiles.push(profile);
        Ok(())
    }

    /// Appends middleware to the chain.
    pub fn add_middleware(&self, mw: Middleware) {
        if let Ok(mut inner) = self.inner.write() {
            inner.middleware.push(mw);
        }
    }

    /// The flow handler for a flow type.
    pub(crate) fn lookup_flow_handler(&self, flow_type: &str) -> Option<Arc<dyn Profile>> {
        self.inner
            .read()
            .ok()?
            .flow_handlers
            .get(flow_type)
            .cloned()
    }

    /// A snapshot of the route of `flow_id`.
    pub(crate) fn lookup_flow(&self, flow_id: &str) -> Option<FlowEntry> {
        let entry = self.inner.read().ok()?.flows.get(flow_id).cloned()?;
        if entry.ended {
            return None;
        }
        Some(entry)
    }

    /// Marks one dispatch as using generation `gen` of `flow_id`'s route;
    /// fails when that route is gone, so a message for an old instance is
    /// dropped. Every successful acquire is paired with [`Registry::done`].
    pub(crate) fn acquire(&self, flow_id: &str, gen: u64) -> Option<FlowEntry> {
        let mut inner = self.inner.write().ok()?;
        let entry = inner.flows.get_mut(flow_id)?;
        if entry.gen != gen || entry.ended {
            return None;
        }
        entry.inflight += 1;
        Some(entry.clone())
    }

    /// Ends the use [`Registry::acquire`] began.
    pub(crate) fn done(&self, flow_id: &str, gen: u64) {
        let Ok(mut inner) = self.inner.write() else {
            return;
        };
        if let Some(entry) = inner.flows.get_mut(flow_id) {
            if entry.gen == gen {
                entry.inflight -= 1;
                if entry.ended && entry.inflight == 0 {
                    inner.flows.remove(flow_id);
                }
            }
        }
    }

    /// Reserves `flow_id`, for messages of `session_id`, for a
    /// `wmp.flow.start` (identified by `start_id`) about to run a handler.
    ///
    /// Refuses when another start of the flow_id is running, when it is
    /// routed to a claim, to another session's flow, or to a route still in
    /// use, and when it is routed to a flow whose handler manages its own
    /// routes — unless the very same start is repeated, which is
    /// acknowledged again without a second worker. An ordinary handler's
    /// flow is replaced by a start of the same flow_id from the same
    /// session, but only once the route replaces it: a failed start leaves
    /// it routed.
    pub(crate) fn begin_start(
        &self,
        flow_id: &str,
        session_id: &str,
        start_id: [u8; 32],
    ) -> StartOutcome {
        let Ok(mut inner) = self.inner.write() else {
            return StartOutcome::Refused;
        };
        if inner.starting.contains_key(flow_id) {
            return StartOutcome::Refused;
        }
        if let Some(entry) = inner.flows.get(flow_id) {
            if entry.claimed || entry.session != session_id || entry.inflight > 0 || entry.ended {
                return StartOutcome::Refused;
            }
            if entry.managed {
                if entry.start_id == start_id && !entry.terminal {
                    return StartOutcome::Duplicate;
                }
                return StartOutcome::Refused;
            }
        }
        inner.starting.insert(
            flow_id.to_owned(),
            StartState {
                session: session_id.to_owned(),
                queue: Vec::new(),
                progress: 0,
                terminal: 0,
                cancel: 0,
            },
        );
        StartOutcome::Reserved
    }

    /// Publishes the flow of a start that [`Registry::begin_start`]
    /// reserved, for messages of `session_id`, and returns its generation
    /// and the route it replaced.
    pub(crate) fn route(
        &self,
        flow_id: &str,
        session_id: &str,
        handler: Arc<dyn Profile>,
        start_id: [u8; 32],
    ) -> Option<(u64, Option<FlowEntry>)> {
        let mut inner = self.inner.write().ok()?;
        inner.next_gen += 1;
        let gen = inner.next_gen;
        let managed = handler.manages_flow_routes();
        let replaced = inner.flows.get(flow_id).cloned();
        inner.flows.insert(
            flow_id.to_owned(),
            FlowEntry {
                flow_id: flow_id.to_owned(),
                handler,
                session: session_id.to_owned(),
                claimed: false,
                managed,
                gen,
                terminal: false,
                start_id,
                inflight: 0,
                ended: false,
            },
        );
        Some((gen, replaced))
    }

    /// Undoes [`Registry::route`] for a start that failed: generation `gen`
    /// is removed and the route it replaced, if any, is put back.
    pub(crate) fn abandon_route(&self, flow_id: &str, gen: u64, replaced: Option<FlowEntry>) {
        let Ok(mut inner) = self.inner.write() else {
            return;
        };
        let matches = inner.flows.get(flow_id).is_some_and(|e| e.gen == gen);
        if !matches {
            return;
        }
        match replaced {
            Some(replaced) => {
                inner.flows.insert(flow_id.to_owned(), replaced);
            }
            None => {
                inner.flows.remove(flow_id);
            }
        }
    }

    /// The session a running start of `flow_id` is for.
    pub(crate) fn starting_session(&self, flow_id: &str) -> Option<String> {
        self.inner
            .read()
            .ok()?
            .starting
            .get(flow_id)
            .map(|st| st.session.clone())
    }

    /// Holds `op` until the start of `flow_id` has returned, when one is
    /// running, and reports whether it did. Held messages keep their arrival
    /// order and are bounded: progress beyond [`MAX_DEFERRED_PROGRESS`] is
    /// dropped, and of terminal notifications (and of cancels) the first is
    /// kept.
    pub(crate) fn defer_while_starting(
        &self,
        flow_id: &str,
        kind: DeferKind,
        op: Box<dyn FnOnce() + Send + Sync>,
    ) -> bool {
        let Ok(mut inner) = self.inner.write() else {
            return false;
        };
        let Some(state) = inner.starting.get_mut(flow_id) else {
            return false;
        };
        match kind {
            DeferKind::Progress => {
                if state.progress >= MAX_DEFERRED_PROGRESS {
                    return true;
                }
                state.progress += 1;
            }
            DeferKind::Terminal => {
                if state.terminal > 0 {
                    return true;
                }
                state.terminal += 1;
            }
            DeferKind::Cancel => {
                if state.cancel > 0 {
                    return true;
                }
                state.cancel += 1;
            }
        }
        state.queue.push(DeferredOp { kind, op });
        true
    }

    /// The messages held for `flow_id` in arrival order; with none left it
    /// ends the reservation (`done` is true), so nothing is applied out of
    /// order.
    pub(crate) fn take_deferred(
        &self,
        flow_id: &str,
    ) -> (Vec<Box<dyn FnOnce() + Send + Sync>>, bool) {
        let Ok(mut inner) = self.inner.write() else {
            return (Vec::new(), true);
        };
        let Some(state) = inner.starting.get_mut(flow_id) else {
            return (Vec::new(), true);
        };
        if state.queue.is_empty() {
            inner.starting.remove(flow_id);
            return (Vec::new(), true);
        }
        let ops: Vec<Box<dyn FnOnce() + Send + Sync>> = std::mem::take(&mut state.queue)
            .into_iter()
            .map(|op| op.op)
            .collect();
        (ops, false)
    }

    /// Ends the reservation of a start that failed, dropping what was held
    /// for it.
    pub(crate) fn discard_start(&self, flow_id: &str) {
        if let Ok(mut inner) = self.inner.write() {
            inner.starting.remove(flow_id);
        }
    }

    /// Routes `flow_id` to `handler` for messages of `session_id`, unless
    /// the flow_id is routed or being started. The returned claim ends only
    /// with [`crate::profile::Claim::release`]; a claim is not ended by a
    /// completion or error.
    pub(crate) fn claim_flow(
        self: &Arc<Self>,
        flow_id: &str,
        session_id: &str,
        handler: Arc<dyn Profile>,
    ) -> Option<crate::profile::Claim> {
        let mut inner = self.inner.write().ok()?;
        if inner.flows.contains_key(flow_id) || inner.starting.contains_key(flow_id) {
            return None;
        }
        inner.next_gen += 1;
        let gen = inner.next_gen;
        inner.flows.insert(
            flow_id.to_owned(),
            FlowEntry {
                flow_id: flow_id.to_owned(),
                handler,
                session: session_id.to_owned(),
                claimed: true,
                managed: false,
                gen,
                terminal: false,
                start_id: [0; 32],
                inflight: 0,
                ended: false,
            },
        );
        Some(crate::profile::Claim::new(
            self.clone(),
            flow_id.to_owned(),
            gen,
        ))
    }

    /// Records that the flow routed under `flow_id` has ended; with `gen`
    /// zero it applies to whichever instance is routed (the flow's own
    /// outgoing terminal notification names no generation, and its
    /// identifier is reserved until its worker has exited, so there is only
    /// that instance).
    ///
    /// This is the terminal half of the flow-route seam a profile's
    /// start-flow receives from the peer; the async flow machinery
    /// (`docs/wmp-core-port.md`, stage 2) drives it.
    pub fn mark_terminal(&self, flow_id: &str, gen: u64) {
        if let Ok(mut inner) = self.inner.write() {
            if let Some(entry) = inner.flows.get_mut(flow_id) {
                if gen == 0 || entry.gen == gen {
                    entry.terminal = true;
                }
            }
        }
    }

    /// Ends the route of generation `gen` of `flow_id`; a later instance of
    /// the same flow_id is untouched. A route a dispatch is still using goes
    /// away when that dispatch is done.
    pub(crate) fn release(&self, flow_id: &str, gen: u64) {
        let Ok(mut inner) = self.inner.write() else {
            return;
        };
        let Some(entry) = inner.flows.get_mut(flow_id) else {
            return;
        };
        if entry.gen != gen {
            return;
        }
        if entry.inflight > 0 {
            entry.ended = true;
            return;
        }
        inner.flows.remove(flow_id);
    }

    /// The profile handling a custom method.
    pub(crate) fn lookup_method(&self, method: &str) -> Option<Arc<dyn Profile>> {
        self.inner.read().ok()?.methods.get(method).cloned()
    }

    /// The profile handling a resolution type.
    pub(crate) fn lookup_resolver(&self, resolve_type: &str) -> Option<Arc<dyn Profile>> {
        self.inner.read().ok()?.resolvers.get(resolve_type).cloned()
    }

    /// Executes the middleware chain, then calls the final handler.
    pub(crate) fn run_middleware(
        &self,
        ctx: &RequestContext,
        method: &str,
        params: &serde_json::Value,
        final_step: ChainStep,
    ) -> DispatchResult {
        let middleware = match self.inner.read() {
            Ok(inner) => inner.middleware.clone(),
            Err(_) => return final_step(ctx, method, params),
        };
        // Build the chain from the inside out.
        let mut chain = final_step;
        for mw in middleware.iter().rev() {
            let next = chain.clone();
            let mw = mw.clone();
            chain = Arc::new(
                move |ctx: &RequestContext, method: &str, params: &serde_json::Value| {
                    mw(ctx, method, params, &next)
                },
            );
        }
        chain(ctx, method, params)
    }

    /// Calls the session-create hooks of every registered profile.
    pub(crate) fn run_session_create_hooks(
        &self,
        ctx: &RequestContext,
        session: &mut Session,
        params: &SessionCreateParams,
    ) -> Result<(), HandlerError> {
        let hooks = match self.inner.read() {
            Ok(inner) => inner.session_hooks.clone(),
            Err(_) => return Ok(()),
        };
        for hook in hooks {
            hook.on_session_create(ctx, session, params)?;
        }
        Ok(())
    }

    /// Whether any resume hook is registered.
    pub(crate) fn has_resumers(&self) -> bool {
        self.inner
            .read()
            .is_ok_and(|inner| !inner.resume_hooks.is_empty())
    }

    /// Calls the registered resume hooks, stopping at the first error.
    pub(crate) fn run_session_resumers(
        &self,
        ctx: &RequestContext,
        session: &Session,
        params: &SessionResumeParams,
    ) -> Result<(), HandlerError> {
        let hooks = match self.inner.read() {
            Ok(inner) => inner.resume_hooks.clone(),
            Err(_) => return Ok(()),
        };
        for hook in hooks {
            hook.on_session_resume(ctx, session, params)?;
        }
        Ok(())
    }

    /// Calls the session-close hooks of every registered profile.
    pub(crate) fn run_session_close_hooks(
        &self,
        ctx: &RequestContext,
        session: &Session,
        params: &SessionCloseParams,
    ) {
        if let Ok(inner) = self.inner.read() {
            for hook in &inner.session_hooks {
                hook.on_session_close(ctx, session, params);
            }
        }
    }

    /// Resolves a WMP identifier to an endpoint using the registered
    /// resolvers, tried in registration order; the first `Some` result wins.
    pub(crate) fn resolve_identifier(
        &self,
        ctx: &RequestContext,
        identifier: &str,
    ) -> Result<Option<crate::profile::DiscoveredEndpoint>, HandlerError> {
        let resolvers = match self.inner.read() {
            Ok(inner) => inner.id_resolvers.clone(),
            Err(_) => return Ok(None),
        };
        for resolver in resolvers {
            for scheme in resolver.identifier_schemes() {
                if identifier.len() >= scheme.len() && identifier.starts_with(&scheme) {
                    return resolver.resolve_identifier(ctx, identifier);
                }
            }
        }
        Ok(None)
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}
