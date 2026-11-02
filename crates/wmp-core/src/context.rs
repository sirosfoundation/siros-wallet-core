//! The per-request context: what go-wmp threads through `context.Context`
//! as typed values, carried here as one explicit struct.

use std::sync::Arc;

use crate::principal::Principal;
use crate::session::Session;

/// The handle the peer gives a profile's start-flow: the generation of the
/// route and the functions that end exactly that route — go-wmp's
/// `flowRoute`, carried there by `context.Context`.
#[derive(Clone)]
pub struct FlowRouteHandle {
    /// The generation of the flow's route.
    pub gen: u64,
    /// Ends the route of this generation.
    pub release: Arc<dyn Fn() + Send + Sync>,
    /// Marks the flow terminal; its route stays until release.
    pub terminal: Arc<dyn Fn() + Send + Sync>,
}

/// What the peer knows about the dispatch in flight.
///
/// go-wmp attaches the session, the sender identity, whether the dispatch is
/// a notification and the authenticated principal to the request context, and
/// handlers read them back with `SessionFromContext` and friends. Rust has no
/// implicit context; the peer passes this struct to every handler call.
#[derive(Clone, Default)]
pub struct RequestContext {
    /// The session the request belongs to, resolved from the store by the
    /// peer. `None` when the store holds no such session (or there is no
    /// store) — a handler that needs a session must fail closed.
    pub session: Option<Session>,
    /// The sender identity from the `wmp` envelope.
    pub sender: String,
    /// Whether the in-flight dispatch is for a JSON-RPC notification (no
    /// `id`) rather than a request.
    ///
    /// A notification can never deliver a synchronous JSON-RPC error back to
    /// its sender — the peer discards any dispatch error once
    /// [`RequestContext::is_notification`] is true — so a dispatch case that
    /// returns an error early for a notification is not reporting anything to
    /// the caller: it is silently dropping the message before the registered
    /// handler ever sees it. A handler with its own way to surface a
    /// rejection needs that chance; this flag lets a dispatch case tell the
    /// two situations apart and only fail fast for a real request.
    pub is_notification: bool,
    /// The authenticated principal the transport or embedding application
    /// established — never taken from client-supplied WMP parameters.
    pub principal: Option<Principal>,
    /// The generation of the flow a message is dispatched for; `None` when
    /// the dispatch names none (go-wmp's `withFlowGen`).
    pub flow_gen: Option<u64>,
    /// The route of the flow a start is starting, given to the profile's
    /// start-flow (go-wmp's `contextWithFlowRoute`).
    pub flow_route: Option<FlowRouteHandle>,
}

impl RequestContext {
    /// The generation of the flow a message is dispatched for; zero when the
    /// dispatch names none.
    pub fn generation(&self) -> u64 {
        self.flow_gen.unwrap_or(0)
    }
}
