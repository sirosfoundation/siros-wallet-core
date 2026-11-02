//! The per-request context: what go-wmp threads through `context.Context`
//! as typed values, carried here as one explicit struct.

use crate::principal::Principal;
use crate::session::Session;

/// What the peer knows about the dispatch in flight.
///
/// go-wmp attaches the session, the sender identity, whether the dispatch is
/// a notification and the authenticated principal to the request context, and
/// handlers read them back with `SessionFromContext` and friends. Rust has no
/// implicit context; the peer passes this struct to every handler call.
#[derive(Debug, Clone, Default)]
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
}
