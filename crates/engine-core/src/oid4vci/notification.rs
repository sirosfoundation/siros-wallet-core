//! The credential_notification flow (WMP OpenID4x 3.4) and the
//! notification context store (#527/#528): after an issuance has
//! completed, the wallet reports an OID4VCI §10 notification event and
//! the engine forwards it to the issuer from the ephemeral context it
//! retained at the completion.
//!
//! The context is the issuance's own, minimal and ephemeral: the
//! endpoint, the access token (the notification is authorized with the
//! issuance's own token), the DPoP signing means, and the
//! `notification_id` the issuer returned. **Nothing is persisted** —
//! the store is in-process memory, bounded by the context TTL (5
//! minutes, [`CONTEXT_TTL_SECS`]): notifications are sent by the
//! client immediately after a flow completes, while the issuance token
//! is still valid (the Go engine's
//! `notificationContextTTL`, whose comment this mirrors), and the
//! engine stays zero-knowledge about the credential itself.
//!
//! **Each `notification_id` is single use** (an issuance can end in
//! several Credential Responses, each with its own id): the claim marks
//! it, the other ids of the issuance stay usable. A context that knows
//! no id (an encrypted response the engine read blind) accepts the ids
//! the wallet names, once each, up to
//! [`MAX_BLIND_NOTIFICATION_IDS`]. The id is **spent only once the
//! issuer was contacted** (#528): a DPoP proof that could not be
//! obtained sent nothing, so the id and the context go back with their
//! original expiry, and the wallet may retry the same notification
//! until the TTL.
//!
//! The context is bound to the session that ran the issuance: a
//! notification flow in another session cannot claim it (the Go
//! principal binding; a flow without a session — the wasm dispatcher,
//! where the wallet is the engine's only principal — binds
//! trivially). A superseding registration for the same flow id owns
//! it: a put-back (`restore`) never revives a superseded context.
//!
//! The events the engine forwards (OpenID4x 3.4.1): `credential_accepted`
//! and `credential_failure`. `credential_deleted` is deliberately not
//! forwarded: it occurs long after issuance, when the access token has
//! expired and the notification can no longer be authenticated.

use std::sync::atomic::{AtomicUsize, Ordering};

use parking_lot::Mutex;
use rustc_hash::{FxHashMap, FxHashSet};

use crate::runtime::{FlowContext, FlowHandler};

use super::credential::CredentialResponse;
use super::dpop;
use super::token::TokenResponse;
use super::types::IssuerMetadata;
use engine_ports::{FetchPurpose, HttpRequest};
use wmp_core::error::{RpcError, ERR_FLOW_ERROR, ERR_INVALID_PARAMS};
use wmp_core::methods::{
    FlowActionParams, FlowCancelParams, FlowCompleteParams, FlowErrorParams, FlowProgressParams,
    FlowStartParams,
};

// ─── The flow's identifiers and bounds (OpenID4x 2.4, 3.4) ────────────────

/// The flow type of the credential_notification flow (OpenID4x 3.4) —
/// and the capability it requires (§2.4).
pub const FLOW_TYPE: &str = "credential_notification";
/// The capability a credential_notification flow needs negotiated
/// (§2.4): the server's session create advertises it (with the events
/// and the context TTL), a wallet that wants to run the flow offers
/// it.
pub const CAPABILITY: &str = "credential_notification";

/// How long the engine retains the ephemeral issuance context: 5
/// minutes (the Go `notificationContextTTL`).
pub const CONTEXT_TTL_SECS: i64 = 300;

/// How many credential notifications may be forwarded concurrently
/// across all sessions (the Go `maxConcurrentNotifications`): the
/// backpressure so a client cannot spawn an unbounded number of
/// outbound requests by flooding notification flows. A notification
/// turned away as busy keeps the context and the id, for the wallet's
/// retry.
pub const MAX_CONCURRENT_FORWARDS: usize = 32;

/// The bound on an `issuance_flow_id` and a `notification_id`, in
/// Unicode scalar values (the schema's `maxLength`, OpenID4x 3.4.1).
pub const MAX_ID_LEN: usize = 256;
/// The bound on an `event_description` (the schema's `maxLength`).
pub const MAX_EVENT_DESCRIPTION_LEN: usize = 512;
/// The bound on an `event` name.
pub const MAX_EVENT_LEN: usize = 64;
/// The bound on the ids a context that knows none accepts
/// (OpenID4x 3.4.2: 256 per issuance).
pub const MAX_BLIND_NOTIFICATION_IDS: usize = 256;

/// The event of a credential the wallet accepted (OID4VCI §10).
pub const EVENT_ACCEPTED: &str = "credential_accepted";
/// The event of a credential that failed on the wallet's side.
pub const EVENT_FAILURE: &str = "credential_failure";

/// The events the engine forwards, in the capability advert's `events`
/// member (§2.4) and the start's validation (§3.4.1).
pub const EVENTS: [&str; 2] = [EVENT_ACCEPTED, EVENT_FAILURE];

/// The status of a forwarded notification (OpenID4x 3.4.2's result).
pub const STATUS_FORWARDED: &str = "forwarded";

// ─── The reasons (OpenID4x 3.4.2) ─────────────────────────────────────────

/// No usable context: absent, expired, consumed, another session's, or
/// an id that does not match. It does not say which.
pub const REASON_CONTEXT_UNAVAILABLE: &str = "context_unavailable";
/// The engine is at its forwarding limit and kept the context.
pub const REASON_BUSY: &str = "busy";
/// The wallet did not provide a DPoP proof.
pub const REASON_SIGNING_FAILED: &str = "signing_failed";
/// The issuer refused or the transport failed.
pub const REASON_FORWARD_FAILED: &str = "forward_failed";
/// The flow's own timeout expired (core 6.2).
pub const REASON_TIMEOUT: &str = "timeout";

/// The flow error of a refused notification: `-31006` with the reason
/// class and the retryable flag, never the wallet's or the issuer's
/// text (OpenID4x 3.4.2).
fn flow_error(reason: &str, retryable: bool) -> wmp_core::handler::HandlerError {
    wmp_core::handler::HandlerError::Rpc(RpcError::new(
        ERR_FLOW_ERROR,
        Some(serde_json::json!({
            "reason": reason,
            "retryable": retryable,
        })),
    ))
}

// ─── The context ────────────────────────────────────────────────────────

/// The ephemeral issuance context a notification is forwarded from
/// (the Go `notificationContext`): captured at the issuance flow's
/// completion, claimed (spent) by the notification flow, never
/// persisted.
#[derive(Clone)]
pub struct NotificationContext {
    /// The issuer's notification endpoint (the metadata's
    /// `notification_endpoint`, OID4VCI §10).
    pub endpoint: String,
    /// The issuance access token: the notification is authorized with
    /// the issuance's own token, as any other resource request.
    pub access_token: String,
    /// The token type (`DPoP` or `Bearer`): which authorization
    /// scheme the notification carries.
    pub token_type: String,
    /// The issuer's identifier (the DPoP proof's audience).
    pub issuer: String,
    /// The engine-held DPoP key (the legacy mode), when the issuance
    /// signed with one: the notification's proofs sign with the same
    /// key, which is what makes the DPoP binding hold past the flow.
    pub dpop_key: Option<dpop::DpopKey>,
    /// The client-held DPoP key id, when the issuance asked the host
    /// with one: the notification's proofs ask the host with the same
    /// id.
    pub dpop_key_id: Option<String>,
    /// The DPoP nonce captured at the token exchange (RFC 9449 §8):
    /// the notification proof carries it until the issuer demands a
    /// fresh one.
    pub dpop_nonce: Option<String>,
    /// The `notification_id` the issuer returned for this Credential
    /// Response (OID4VCI §8.3/§11): exactly one per response. Empty
    /// when the engine could not read it (an encrypted response read
    /// blind) — such a context accepts the ids the wallet names.
    pub notification_id: Option<String>,
    /// The session that ran the issuance (empty when the flow ran
    /// without one): the binding a notification flow must match.
    pub session_id: String,
    /// When the context expires (the Clock's now at registration +
    /// [`CONTEXT_TTL_SECS`]).
    expires_at_unix: i64,
    /// The ids already claimed over this context (each single use).
    notified: FxHashSet<String>,
    /// The registration's sequence number, so an unspend can tell a
    /// superseded context from the live one.
    seq: u64,
}

impl NotificationContext {
    /// The context from its public members. The expiry, the notified
    /// set and the sequence number are the store's — [`NotificationContexts::put`]
    /// sets them at registration.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        endpoint: String,
        access_token: String,
        token_type: String,
        issuer: String,
        dpop_key: Option<dpop::DpopKey>,
        dpop_key_id: Option<String>,
        dpop_nonce: Option<String>,
        notification_id: Option<String>,
        session_id: String,
    ) -> Self {
        Self {
            endpoint,
            access_token,
            token_type,
            issuer,
            dpop_key,
            dpop_key_id,
            dpop_nonce,
            notification_id,
            session_id,
            expires_at_unix: 0,
            notified: FxHashSet::default(),
            seq: 0,
        }
    }
}

// ─── The store ───────────────────────────────────────────────────────────

/// The in-process registry of [`NotificationContext`]s, keyed by the
/// issuance flow id (the Go `notificationContextStore`): ephemeral,
/// TTL-bounded, never persisted. One instance spans the engine's
/// sessions (the contexts bind their own), supplied by the adapter on
/// [`Ports`](crate::Ports).
pub struct NotificationContexts {
    inner: Mutex<Inner>,
    /// The notifications in flight (the backpressure).
    in_flight: AtomicUsize,
}

struct Inner {
    contexts: FxHashMap<String, NotificationContext>,
    /// The newest registration per flow id (seq + time), so an unspend
    /// never revives a superseded context.
    latest: FxHashMap<String, (u64, i64)>,
    seq: u64,
}

impl Default for NotificationContexts {
    fn default() -> Self {
        Self {
            inner: Mutex::new(Inner {
                contexts: FxHashMap::default(),
                latest: FxHashMap::default(),
                seq: 0,
            }),
            in_flight: AtomicUsize::new(0),
        }
    }
}

impl NotificationContexts {
    /// Registers a context for the issuance flow, with the TTL from
    /// `now_unix`. An empty flow id or endpoint registers nothing.
    pub fn put(&self, flow_id: &str, context: NotificationContext, now_unix: i64) {
        if flow_id.is_empty() || context.endpoint.is_empty() {
            return;
        }
        let mut inner = self.inner.lock();
        inner.prune(now_unix);
        inner.seq += 1;
        let mut context = context;
        context.expires_at_unix = now_unix + CONTEXT_TTL_SECS;
        context.seq = inner.seq;
        context.notified.clear();
        inner
            .latest
            .insert(flow_id.to_owned(), (context.seq, now_unix));
        inner.contexts.insert(flow_id.to_owned(), context);
    }

    /// Claims the context of the issuance flow for `notification_id`,
    /// bound to `session_id`, and marks the id used — the single
    /// consumption record both the flow and any adapter-side legacy
    /// path go through. Returns the context to forward with (its
    /// `notified` set stays behind), or `None` when there is nothing
    /// to use: the context is absent, expired, retained for another
    /// session, the id is not one it knows or was already used, or a
    /// context that knows no id has accepted its maximum. The reasons
    /// are not told apart (the Go `useLocked`, whose list this
    /// mirrors). The context stays for the issuance's other ids until
    /// its TTL.
    pub fn claim(
        &self,
        flow_id: &str,
        session_id: &str,
        notification_id: &str,
        now_unix: i64,
    ) -> Option<NotificationContext> {
        let mut inner = self.inner.lock();
        let context = inner.contexts.get_mut(flow_id)?;
        if now_unix > context.expires_at_unix || context.session_id != session_id {
            return None;
        }
        if notification_id.is_empty() || notification_id.chars().count() > MAX_ID_LEN {
            // An id beyond the bound is never recorded: a context that
            // knows no id would otherwise hold up to 256 of them,
            // however long.
            return None;
        }
        if context.notified.contains(notification_id) {
            return None;
        }
        match &context.notification_id {
            Some(known) if known == notification_id => {
                // Its one known id is used: the context is gone.
                let used = inner.contexts.remove(flow_id)?;
                Some(used)
            }
            Some(_) => None,
            None => {
                // A context that knows no id accepts the wallet's, once
                // each, up to the bound.
                if context.notified.len() >= MAX_BLIND_NOTIFICATION_IDS {
                    return None;
                }
                context.notified.insert(notification_id.to_owned());
                let mut used = context.clone();
                used.notified.clear();
                Some(used)
            }
        }
    }

    /// Takes back the use of `notification_id` of a context `claim`
    /// handed out, whose notification never reached the issuer (#528):
    /// the id is freed (a context that knows its one id was deleted at
    /// the claim is put back whole; a blind context loses the id from
    /// its set, freeing the slot). The original expiry is kept — a
    /// retry cannot extend the context's life — and nothing is revived
    /// once the context expired or the issuance registered a newer
    /// one (the seq check).
    pub fn unspend(
        &self,
        flow_id: &str,
        context: &NotificationContext,
        notification_id: &str,
        now_unix: i64,
    ) {
        if flow_id.is_empty() {
            return;
        }
        let mut inner = self.inner.lock();
        if now_unix > context.expires_at_unix {
            return;
        }
        // Superseded by a newer registration, which owns the flow id
        // now.
        if inner
            .latest
            .get(flow_id)
            .is_none_or(|(seq, _)| *seq != context.seq)
        {
            return;
        }
        if context.notification_id.is_some() {
            if !inner.contexts.contains_key(flow_id) {
                let mut back = context.clone();
                back.notified.clear();
                inner.contexts.insert(flow_id.to_owned(), back);
            }
            return;
        }
        if let Some(live) = inner.contexts.get_mut(flow_id) {
            if live.seq == context.seq {
                live.notified.remove(notification_id);
            }
        }
    }

    /// The notification endpoint of the issuance flow's live context —
    /// what the issuance completion tells the wallet to record (the Go
    /// `wmpEndpointFor`), or empty when there is none.
    pub fn endpoint_for(&self, flow_id: &str, now_unix: i64) -> String {
        let inner = self.inner.lock();
        inner
            .contexts
            .get(flow_id)
            .filter(|context| now_unix <= context.expires_at_unix)
            .map(|context| context.endpoint.clone())
            .unwrap_or_default()
    }

    /// Takes a forwarding slot (the backpressure): `false` when the
    /// engine is at [`MAX_CONCURRENT_FORWARDS`]. A notification turned
    /// away keeps its context and id, for the wallet's retry.
    pub fn try_begin_forward(&self) -> bool {
        let before = self.in_flight.fetch_add(1, Ordering::AcqRel);
        if before >= MAX_CONCURRENT_FORWARDS {
            self.in_flight.fetch_sub(1, Ordering::AcqRel);
            return false;
        }
        true
    }

    /// Releases a forwarding slot.
    pub fn end_forward(&self) {
        self.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Inner {
    /// Removes the expired entries.
    fn prune(&mut self, now_unix: i64) {
        self.contexts
            .retain(|_, context| now_unix <= context.expires_at_unix);
        self.latest
            .retain(|_, (_, at)| now_unix - *at <= CONTEXT_TTL_SECS);
    }
}

// ─── The registration (the issuance completion) ─────────────────────────

/// Registers the notification context of an issuance that just
/// delivered: the context the wallet's later credential_notification
/// flow forwards from. Returns the completion's notification members
/// (the `notification_endpoint` — what the wallet records — and the
/// `notification_id` the issuer returned), or an empty object when
/// nothing is retained.
///
/// Nothing is retained unless the issuer advertises a notification
/// endpoint and the response carries a `notification_id` (the §11.1
/// contract: the id is present exactly when the issuer expects the
/// notification). A response the engine reads blind (an encrypted
/// response whose id it cannot read) would register a context with no
/// id — the wallet's ids are accepted then; that path arrives with the
/// encrypted-response relay.
pub fn register(
    ctx: &FlowContext,
    flow_id: &str,
    metadata: &IssuerMetadata,
    token: &TokenResponse,
    response: &CredentialResponse,
    dpop_key: Option<&dpop::DpopKey>,
    dpop_key_id: Option<&str>,
) -> serde_json::Value {
    let mut members = serde_json::json!({});
    let notification_id = response.notification_id.clone().filter(|id| !id.is_empty());
    if metadata.notification_endpoint.is_empty() || notification_id.is_none() {
        return members;
    }
    let session_id = ctx
        .session
        .as_ref()
        .map(|session| session.id.clone())
        .unwrap_or_default();
    ctx.ports.notifications.put(
        flow_id,
        NotificationContext::new(
            metadata.notification_endpoint.clone(),
            token.access_token.clone(),
            token.token_type.clone(),
            metadata.credential_issuer.clone(),
            dpop_key.cloned(),
            dpop_key_id.map(str::to_owned),
            token.dpop_nonce.clone(),
            notification_id.clone(),
            session_id,
        ),
        ctx.clock().now_unix(),
    );
    if let Some(object) = members.as_object_mut() {
        object.insert(
            "notification_endpoint".to_owned(),
            serde_json::Value::String(metadata.notification_endpoint.clone()),
        );
        object.insert(
            "notification_id".to_owned(),
            serde_json::Value::String(notification_id.unwrap_or_default()),
        );
    }
    members
}

// ─── The flow (OpenID4x 3.4.1) ────────────────────────────────────────────

/// The validated start of a credential_notification flow
/// (OpenID4x 3.4.1).
#[derive(Debug, Clone)]
pub struct NotificationStart {
    /// The oid4vci flow whose retained context the engine forwards
    /// from.
    pub issuance_flow_id: String,
    /// The `notification_id` the issuer returned (OID4VCI §11.1):
    /// the wallet's notification MUST echo this exact value.
    pub notification_id: String,
    /// The event (`credential_accepted`, `credential_failure`).
    pub event: String,
    /// The event's description, when the wallet carries one.
    pub event_description: Option<String>,
}

/// Parses and validates the start's params (§3.4.1): `issuance_flow_id`,
/// `notification_id` and `event` are required strings within their
/// bounds, `event` one of [`EVENTS`]; `event_description` is an
/// optional printable-ASCII string within
/// [`MAX_EVENT_DESCRIPTION_LEN`]. The `Err` is the first offending
/// member's name — the `-32602` data, never a value from the params
/// (the go-wmp `notificationMemberError`).
pub fn parse_start(
    params: &Option<Box<serde_json::value::RawValue>>,
) -> Result<NotificationStart, String> {
    let raw = params.as_ref().map(|raw| raw.get()).unwrap_or_default();
    let value: serde_json::Value = serde_json::from_str(raw).unwrap_or(serde_json::Value::Null);
    // A required member: a string, non-empty, within the bound. The
    // empty or absent description is fine.
    let member = |name: &str, limit: usize| -> Option<String> {
        match value.get(name) {
            Some(serde_json::Value::String(text))
                if !text.is_empty() && text.chars().count() <= limit =>
            {
                Some(text.clone())
            }
            _ => None,
        }
    };
    let issuance_flow_id =
        member("issuance_flow_id", MAX_ID_LEN).ok_or_else(|| "issuance_flow_id".to_owned())?;
    let notification_id =
        member("notification_id", MAX_ID_LEN).ok_or_else(|| "notification_id".to_owned())?;
    let event = member("event", MAX_EVENT_LEN)
        .filter(|event| EVENTS.contains(&event.as_str()))
        .ok_or_else(|| "event".to_owned())?;
    let event_description = match value.get("event_description") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(text)) if text.is_empty() => None,
        Some(serde_json::Value::String(text)) => {
            if text.chars().count() > MAX_EVENT_DESCRIPTION_LEN
                || !text.bytes().all(|byte| (0x20..0x7f).contains(&byte))
            {
                return Err("event_description".to_owned());
            }
            Some(text.clone())
        }
        Some(_) => return Err("event_description".to_owned()),
    };
    Ok(NotificationStart {
        issuance_flow_id,
        notification_id,
        event,
        event_description,
    })
}

/// The credential_notification flow (OpenID4x 3.4): the wallet reports
/// a OID4VCI §10 notification event after an issuance flow completed,
/// and the engine forwards it to the issuer from the context the
/// issuance retained.
pub struct CredentialNotificationFlow;

#[async_trait::async_trait]
impl FlowHandler for CredentialNotificationFlow {
    fn flow_types(&self) -> Vec<String> {
        vec![FLOW_TYPE.to_owned()]
    }

    fn required_capability(&self, _flow_type: &str) -> String {
        CAPABILITY.to_owned()
    }

    async fn start_flow(
        &self,
        ctx: &FlowContext,
        params: &FlowStartParams,
    ) -> Result<wmp_core::methods::FlowStartResult, wmp_core::handler::HandlerError> {
        let start = parse_start(&params.params).map_err(|member| {
            // The first offending member (§3.4.1): the -32602 data, a
            // name from the fixed set, never a value from the params.
            wmp_core::handler::HandlerError::Rpc(RpcError::new(
                ERR_INVALID_PARAMS,
                Some(serde_json::json!({ "member": member })),
            ))
        })?;

        // The forwarding limit (the backpressure), checked BEFORE the
        // context is used: a notification turned away keeps the
        // context and the id for the wallet's retry (the Go rule, in
        // ForwardNotification).
        if !ctx.ports.notifications.try_begin_forward() {
            return Err(flow_error(REASON_BUSY, true));
        }

        // The context: the issuance's own, in this session, the id
        // single use (the claim marks it).
        let session_id = ctx
            .session
            .as_ref()
            .map(|session| session.id.clone())
            .unwrap_or_default();
        let now_unix = ctx.clock().now_unix();
        let context = match ctx.ports.notifications.claim(
            &start.issuance_flow_id,
            &session_id,
            &start.notification_id,
            now_unix,
        ) {
            Some(context) => context,
            None => {
                ctx.ports.notifications.end_forward();
                return Err(flow_error(REASON_CONTEXT_UNAVAILABLE, false));
            }
        };

        let outcome = forward(ctx, &params.flow_id, &context, &start).await;
        ctx.ports.notifications.end_forward();

        match outcome {
            ForwardOutcome::Sent => {
                // OpenID4x 3.4.2's result.
                let _ = ctx
                    .complete(&serde_json::json!({
                        "status": STATUS_FORWARDED,
                        "notification_id": start.notification_id,
                    }))
                    .await;
                Ok(wmp_core::methods::FlowStartResult {
                    wmp: wmp_core::types::Metadata::default(),
                    flow_id: params.flow_id.clone(),
                    flow_type: params.flow_type.clone(),
                })
            }
            // #528: nothing reached the issuer — the DPoP proof could
            // not be obtained — so the id and the context go back,
            // with their original expiry, and the wallet may retry the
            // same notification. The reason is signing_failed (the
            // wallet's side), not forward_failed.
            ForwardOutcome::NotSent => {
                ctx.ports.notifications.unspend(
                    &start.issuance_flow_id,
                    &context,
                    &start.notification_id,
                    now_unix,
                );
                Err(flow_error(REASON_SIGNING_FAILED, false))
            }
            // The issuer was contacted: the id stays spent, whatever
            // it answered.
            ForwardOutcome::Failed => Err(flow_error(REASON_FORWARD_FAILED, false)),
        }
    }

    async fn handle_action(
        &self,
        _ctx: &FlowContext,
        _params: &FlowActionParams,
    ) -> Result<wmp_core::methods::FlowActionResult, wmp_core::handler::HandlerError> {
        // The flow completes inside its start (nothing to ask, nothing
        // to resume): no action is defined.
        Err(flow_error(
            "no action on a credential_notification flow",
            false,
        ))
    }

    async fn handle_progress(&self, _ctx: &FlowContext, _params: &FlowProgressParams) {}
    async fn handle_complete(&self, _ctx: &FlowContext, _params: &FlowCompleteParams) {}
    async fn handle_error(&self, _ctx: &FlowContext, _params: &FlowErrorParams) {}

    async fn handle_cancel(
        &self,
        _ctx: &FlowContext,
        _params: &FlowCancelParams,
    ) -> Result<bool, wmp_core::handler::HandlerError> {
        // The flow is a single HTTP forwarding: there is nothing to
        // stop between the start and the completion.
        Ok(true)
    }
}

/// The outcome of a forwarding attempt: sent and accepted, nothing
/// sent (#528 — the context goes back), or sent and refused.
enum ForwardOutcome {
    /// The issuer accepted (204 or 200, OID4VCI §10).
    Sent,
    /// Nothing reached the issuer: the DPoP proof could not be
    /// obtained. The id is not spent.
    NotSent,
    /// The issuer was contacted and refused (or the transport failed
    /// after the request left): the id stays spent.
    Failed,
}

/// Forwards the notification to the issuer (the Go `sendNotification` +
/// `newNotificationRequest`): the OID4VCI §10 Notification Request to
/// the **full** endpoint, authorized with the retained issuance token,
/// and — when the token is DPoP-bound — proofed with a DPoP proof over
/// the endpoint **without query and fragment** (RFC 9449 §4.2, the only
/// htu a wallet signs for a notification, OpenID4x 3.4.3), the nonce
/// retry included (§8.1).
async fn forward(
    ctx: &FlowContext,
    flow_id: &str,
    context: &NotificationContext,
    start: &NotificationStart,
) -> ForwardOutcome {
    let mut body = serde_json::json!({
        "notification_id": start.notification_id,
        "event": start.event,
    });
    if let Some(description) = &start.event_description {
        if let Some(object) = body.as_object_mut() {
            object.insert(
                "event_description".to_owned(),
                serde_json::Value::String(description.clone()),
            );
        }
    }
    let body = serde_json::to_vec(&body).unwrap_or_default();

    let dpop_bound = context.token_type.eq_ignore_ascii_case("DPoP");
    let mut nonce = context.dpop_nonce.clone();
    for attempt in 0..2 {
        let mut headers = vec![("content-type".to_owned(), "application/json".to_owned())];
        if dpop_bound {
            headers.push((
                "authorization".to_owned(),
                format!("DPoP {}", context.access_token),
            ));
            // The proof over the endpoint without query and fragment
            // (RFC 9449 §4.2): the wallet signs exactly this, whatever
            // the request itself goes to.
            let htu = strip_query_fragment(&context.endpoint);
            let proof = dpop::proof_for(
                ctx.host().as_ref(),
                context.dpop_key.as_ref(),
                dpop::ProofRequest {
                    flow_id,
                    key_id: context.dpop_key_id.as_deref(),
                    htm: "POST",
                    htu: &htu,
                    access_token: Some(&context.access_token),
                    nonce: nonce.as_deref(),
                    rng: ctx.rng().as_ref(),
                    now_unix: ctx.clock().now_unix(),
                },
            )
            .await;
            match proof {
                Some(proof) => headers.push(("DPoP".to_owned(), proof)),
                None => {
                    // Nothing has reached the issuer (the DPoP proof
                    // could not be obtained). On the nonce retry
                    // something has, so the context stays spent.
                    return if attempt == 0 {
                        ForwardOutcome::NotSent
                    } else {
                        ForwardOutcome::Failed
                    };
                }
            }
        } else {
            headers.push((
                "authorization".to_owned(),
                format!("Bearer {}", context.access_token),
            ));
        }

        let response = ctx
            .http()
            .send(HttpRequest {
                method: "POST".to_owned(),
                url: context.endpoint.clone(),
                headers,
                body: body.clone(),
                purpose: FetchPurpose::Notification,
                max_response_bytes: 1024,
                redirects: engine_ports::RedirectPolicy::None,
                allow_plaintext: false,
                timeout_ms: 10_000,
            })
            .await;

        match response {
            Ok(response) => {
                // The nonce demand (RFC 9449 §8.1): one retry with the
                // fresh nonce.
                if attempt == 0 && dpop::is_dpop_nonce_error(&response) {
                    nonce = dpop::dpop_nonce_from_response(&response);
                    continue;
                }
                // OID4VCI §10: the issuer answers 204 No Content.
                if response.status == 204 || response.status == 200 {
                    return ForwardOutcome::Sent;
                }
                return ForwardOutcome::Failed;
            }
            // A transport failure: the request may have left, so the
            // id stays spent (the Go rule: only a proof that could not
            // be obtained puts the context back).
            Err(_) => return ForwardOutcome::Failed,
        }
    }
    ForwardOutcome::Failed
}

/// The DPoP `htu` of a request to `endpoint`: the endpoint without
/// its query and fragment (RFC 9449 §4.2, OpenID4x 3.4.3). The request
/// itself goes to the full endpoint.
#[must_use]
pub fn strip_query_fragment(endpoint: &str) -> String {
    let cut = endpoint.find(['?', '#']).unwrap_or(endpoint.len());
    endpoint[..cut].to_owned()
}
