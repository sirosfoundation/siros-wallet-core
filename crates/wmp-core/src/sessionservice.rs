//! `wmp.session.create`, `resume` and `close` on top of a
//! [`SessionStore`]: server-assigned unguessable session identifiers, owner
//! binding to the authenticated principal, and single-use rotating
//! resumption tokens.

use std::sync::{Arc, Mutex};

use crate::context::RequestContext;
use crate::error::{
    RpcError, ERR_INTERNAL_ERROR, ERR_INVALID_PARAMS, ERR_NOT_AUTHORIZED, ERR_SESSION_EXPIRED,
    ERR_SESSION_NOT_FOUND,
};
use crate::handler::HandlerError;
use crate::methods::{
    SessionCloseParams, SessionCreateParams, SessionCreateResult, SessionResumeParams,
    SessionResumeResult,
};
use crate::session::{Session, SessionStore, StoreError};
use crate::token::{new_resumption_token, tokens_equal, RESUMPTION_TOKEN_BYTES};
use crate::types::{Capabilities, Metadata, SecurityMode, SUPPORTED_VERSIONS};
use crate::version::{negotiate_version, version_rejection};

/// Session metadata key holding the protocol version negotiated at create.
pub const METADATA_KEY_VERSION: &str = "wmp.version";
/// Session metadata key holding `wmp.sender` from the create request. It is
/// an unauthenticated claim; the authenticated identity is [`Session::owner`].
pub const METADATA_KEY_SENDER: &str = "wmp.sender";

/// The session lifetime applied when the request carries no `ttl`: one hour.
pub const DEFAULT_SESSION_TTL_SECS: i64 = 3600;

/// The upper bound on requested session lifetimes: twenty-four hours.
pub const MAX_SESSION_TTL_SECS: i64 = 24 * 60 * 60;

/// The number of per-session lock stripes the fallback paths serialise on.
/// A power of two: the stripe index is a mask, not a modulo, so it cannot
/// divide by zero.
const SESSION_LOCK_STRIPES: usize = 64;

/// The stripe mask, `SESSION_LOCK_STRIPES - 1`.
const SESSION_LOCK_STRIPE_MASK: u32 = (SESSION_LOCK_STRIPES - 1) as u32;

/// Tells the service how many messages a resuming client missed, for the
/// result's `missed_messages`. Without one the count is 0.
pub trait MessageReplayer: Send + Sync {
    /// The number of messages queued for the session after
    /// `last_received_id` — all of them when it is empty.
    fn missed_since(&self, session_id: &str, last_received_id: &str) -> i64;
}

/// A hook that runs after a resume is validated and the token rotated.
///
/// It sees a private copy of the session: the store may hand out its live
/// record, and hooks are for authorisation and observation, not for changing
/// the session.
pub trait SessionResumer: Send + Sync {
    /// Observes or authorises the resume; an error fails the call.
    fn on_session_resume(
        &self,
        session: &Session,
        params: &SessionResumeParams,
    ) -> Result<(), HandlerError>;
}

/// A hook that runs when an expired session is discovered — on a resume
/// attempt, or in [`SessionService::sweep`] — **after** the record has been
/// deleted: the session passed in is the last copy, and the store no longer
/// holds it.
pub trait SessionExpirer: Send + Sync {
    /// Observes the expired session.
    fn on_session_expire(&self, session: &Session);
}

/// Why a [`SessionServiceConfig`] could not become a service. go-wmp panics
/// on a missing store, a programming error; the mirror returns an error
/// instead, because nothing here panics.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ConfigError {
    /// `store` is required.
    #[error("wmp: SessionServiceConfig.store is required")]
    MissingStore,
}

/// A capability-negotiation override.
pub type CapabilitiesFn = Arc<dyn Fn(&Capabilities) -> Capabilities + Send + Sync>;
/// An entropy source: fills a buffer, reporting `false` when it cannot.
pub type EntropyFn = Arc<dyn Fn(&mut [u8]) -> bool + Send + Sync>;
/// A session-identifier generator.
pub type SessionIdFn = Arc<dyn Fn() -> Option<String> + Send + Sync>;

/// The configuration of a [`SessionService`].
///
/// Zero values select defaults, as in go-wmp; the two differences from the
/// Go shape are deliberate: lifetimes are seconds rather than
/// `time.Duration`, and randomness is injected — `entropy` fills bytes and
/// reports failure instead of `crypto/rand` panicking, and `new_session_id`
/// replaces the default `ses-` generator.
#[derive(Default)]
pub struct SessionServiceConfig {
    /// Persists sessions. Required.
    pub store: Option<Arc<dyn SessionStore>>,
    /// The protocol versions offered; empty means [`SUPPORTED_VERSIONS`].
    pub versions: Vec<String>,
    /// The capability set the default negotiation grants: the result is the
    /// offered capabilities that appear here, with these parameters. Ignored
    /// when [`SessionServiceConfig::capabilities`] is set.
    pub supported: Capabilities,
    /// Overrides capability negotiation. Default: the intersection of the
    /// offered capabilities with [`SessionServiceConfig::supported`].
    pub capabilities: Option<CapabilitiesFn>,
    /// The accepted security modes. An empty requested mode selects the
    /// first entry; any mode not listed is rejected with `-32602` (core
    /// §4.1). Default: `["tls"]`.
    pub security_modes: Vec<String>,
    /// The session lifetime applied when the request carries no `ttl`
    /// (default: one hour, clamped to the maximum).
    pub default_ttl_secs: i64,
    /// The upper bound on requested lifetimes (default: twenty-four hours).
    pub max_ttl_secs: i64,
    /// The lifetime of each resumption token, capped by the session expiry
    /// (default: the session expiry, as core §4.5.2 recommends).
    pub resumption_ttl_secs: i64,
    /// Fills a buffer with entropy, returning `false` when it cannot.
    /// Required for create and resume: this crate has no ambient randomness.
    /// Production adapters use the operating system's generator; the test
    /// harness uses a counter.
    pub entropy: Option<EntropyFn>,
    /// Generates session identifiers. Default: `ses-` plus the hex of
    /// sixteen entropy bytes (`wmp-metadata.json` requires
    /// `^ses-[a-zA-Z0-9]+$`). It must be unguessable.
    pub new_session_id: Option<SessionIdFn>,
    /// Supplies `missed_messages` on resume. Optional.
    pub replay: Option<Arc<dyn MessageReplayer>>,
    /// Hooks that run after a resume is validated and the token rotated.
    pub resume_hooks: Vec<Arc<dyn SessionResumer>>,
    /// Hooks that run when an expired session is discovered.
    pub expire_hooks: Vec<Arc<dyn SessionExpirer>>,
}

/// Implements `wmp.session.create`, `resume` and `close` on top of a
/// [`SessionStore`].
///
/// Resumption-token rotation is atomic when the store implements it
/// natively; otherwise the service serialises per session within this
/// process, which is not enough across replicas sharing a store.
pub struct SessionService {
    cfg: NormalizedConfig,
    locks: Vec<Mutex<()>>,
    /// The lock `lock_for` falls back to; unreachable while the stripes exist.
    zero: Mutex<()>,
}

struct NormalizedConfig {
    store: Arc<dyn SessionStore>,
    versions: Vec<String>,
    supported: Capabilities,
    capabilities: Option<CapabilitiesFn>,
    security_modes: Vec<String>,
    default_ttl_secs: i64,
    max_ttl_secs: i64,
    resumption_ttl_secs: i64,
    entropy: EntropyFn,
    new_session_id: Option<SessionIdFn>,
    replay: Option<Arc<dyn MessageReplayer>>,
    resume_hooks: Vec<Arc<dyn SessionResumer>>,
    expire_hooks: Vec<Arc<dyn SessionExpirer>>,
}

impl SessionService {
    /// Validates `cfg`, applies the defaults and returns the service.
    pub fn new(cfg: SessionServiceConfig) -> Result<Self, ConfigError> {
        let store = cfg.store.ok_or(ConfigError::MissingStore)?;
        let versions = if cfg.versions.is_empty() {
            SUPPORTED_VERSIONS.iter().map(|v| v.to_string()).collect()
        } else {
            cfg.versions
        };
        let security_modes = if cfg.security_modes.is_empty() {
            vec!["tls".to_owned()]
        } else {
            cfg.security_modes
        };
        let mut default_ttl_secs = if cfg.default_ttl_secs <= 0 {
            DEFAULT_SESSION_TTL_SECS
        } else {
            cfg.default_ttl_secs
        };
        let max_ttl_secs = if cfg.max_ttl_secs <= 0 {
            MAX_SESSION_TTL_SECS
        } else {
            cfg.max_ttl_secs
        };
        default_ttl_secs = default_ttl_secs.min(max_ttl_secs);
        Ok(Self {
            cfg: NormalizedConfig {
                store,
                versions,
                supported: cfg.supported,
                capabilities: cfg.capabilities,
                security_modes,
                default_ttl_secs,
                max_ttl_secs,
                resumption_ttl_secs: cfg.resumption_ttl_secs,
                entropy: cfg.entropy.ok_or(ConfigError::MissingStore)?,
                new_session_id: cfg.new_session_id,
                replay: cfg.replay,
                resume_hooks: cfg.resume_hooks,
                expire_hooks: cfg.expire_hooks,
            },
            locks: (0..SESSION_LOCK_STRIPES).map(|_| Mutex::new(())).collect(),
            zero: Mutex::new(()),
        })
    }

    /// The store the service persists to.
    pub fn store(&self) -> &Arc<dyn SessionStore> {
        &self.cfg.store
    }

    /// The protocol versions this service offers — what a peer negotiates
    /// against when the handler is a [`SessionHandler`].
    pub fn supported_versions(&self) -> Vec<String> {
        self.cfg.versions.clone()
    }

    fn versions(&self) -> Vec<&str> {
        self.cfg.versions.iter().map(String::as_str).collect()
    }

    /// Implements `wmp.session.create`.
    ///
    /// The caller must be authenticated (in [`RequestContext::principal`]);
    /// the session is owned by it, and the client never chooses the session
    /// identifier.
    pub fn session_create(
        &self,
        now: i64,
        ctx: &RequestContext,
        p: &SessionCreateParams,
    ) -> Result<SessionCreateResult, HandlerError> {
        let principal = ctx
            .principal
            .as_ref()
            .filter(|p| p.is_authenticated())
            .ok_or_else(|| RpcError::code(ERR_NOT_AUTHORIZED))?;
        let versions = self.versions();
        let selected = negotiate_version(&p.wmp.version, &versions)
            .ok_or_else(|| version_rejection(Some(&p.wmp.version), &versions))?;
        let mode = if p.security.mode.is_empty() {
            self.cfg.security_modes.first().cloned().unwrap_or_default()
        } else {
            p.security.mode.clone()
        };
        if !self.cfg.security_modes.contains(&mode) {
            return Err(RpcError::new(
                ERR_INVALID_PARAMS,
                Some(serde_json::json!({
                    "reason": "unsupported security mode",
                    "security_modes": self.cfg.security_modes,
                })),
            )
            .into());
        }
        let ttl = match p.ttl {
            Some(ttl) if ttl < 0 => {
                return Err(RpcError::new(
                    ERR_INVALID_PARAMS,
                    Some(serde_json::json!({ "reason": "negative ttl" })),
                )
                .into())
            }
            Some(ttl) if ttl > 0 => ttl.min(self.cfg.max_ttl_secs),
            _ => self.cfg.default_ttl_secs,
        };

        let id = self.new_session_id()?;
        let token = self.new_resumption_token()?;
        let expires = now + ttl;
        let mut meta = crate::types::OrderedMap::new();
        meta.insert(METADATA_KEY_VERSION.to_owned(), selected.to_owned());
        if !p.wmp.sender.is_empty() {
            meta.insert(METADATA_KEY_SENDER.to_owned(), p.wmp.sender.clone());
        }
        let mut session = Session {
            id: id.clone(),
            participants: p.participants.clone(),
            capabilities: self.negotiate_capabilities(p.capabilities_offered.as_ref()),
            security: SecurityMode {
                mode,
                ..SecurityMode::default()
            },
            metadata: meta,
            resumption_token: token.clone(),
            created_at: now,
            expires_at: Some(expires),
            owner: principal.key(),
            ..Session::default()
        };
        session.resumption_token_expires_at = self.token_expiry(now, session.expires_at);
        self.insert(session.clone())
            .map_err(|_| RpcError::code(ERR_INTERNAL_ERROR))?;
        Ok(SessionCreateResult {
            wmp: Metadata {
                version: selected.to_owned(),
                session_id: id,
                ..Metadata::default()
            },
            capabilities: session.capabilities.clone(),
            security: session.security.clone(),
            resumption_token: token,
            ..SessionCreateResult::default()
        })
    }

    /// Implements `wmp.session.resume` (core §4.5).
    ///
    /// An unknown session and one owned by another principal are
    /// indistinguishable (`-31000`), so the call is not an existence oracle.
    /// Expired sessions answer `-31001` and a spent, wrong or expired token
    /// `-31000`/`-31001`. On success the token is rotated and the new one
    /// returned.
    pub fn session_resume(
        &self,
        now: i64,
        ctx: &RequestContext,
        p: &SessionResumeParams,
    ) -> Result<SessionResumeResult, HandlerError> {
        let principal = ctx
            .principal
            .as_ref()
            .filter(|p| p.is_authenticated())
            .ok_or_else(|| RpcError::code(ERR_NOT_AUTHORIZED))?;
        let versions = self.versions();
        if negotiate_version(&p.wmp.version, &versions).is_none() {
            return Err(version_rejection(Some(&p.wmp.version), &versions).into());
        }
        let session = match self.cfg.store.get(&p.session_id) {
            Some(session) if session.owned_by(&principal.key()) => session,
            _ => return Err(RpcError::code(ERR_SESSION_NOT_FOUND).into()),
        };
        if session.is_expired(now) {
            self.expire(now, &session);
            return Err(RpcError::code(ERR_SESSION_EXPIRED).into());
        }
        // All messages of a session use the version negotiated at create.
        let version = self.session_version(&session, &p.wmp.version, &versions)?;

        let new_token = self.new_resumption_token()?;
        let rotated = match self.rotate(
            now,
            &p.session_id,
            &p.resumption_token,
            &new_token,
            self.token_expiry(now, session.expires_at),
        ) {
            Ok(rotated) => rotated,
            Err(StoreError::TokenExpired) => return Err(RpcError::code(ERR_SESSION_EXPIRED).into()),
            Err(StoreError::NoSuchSession) => {
                return Err(self.lost_rotation(now, principal, &p.session_id))
            }
            Err(StoreError::TokenMismatch) => {
                return Err(RpcError::code(ERR_SESSION_NOT_FOUND).into())
            }
            Err(_) => return Err(RpcError::code(ERR_INTERNAL_ERROR).into()),
        };

        for hook in &self.cfg.resume_hooks {
            // A private copy: the store may hand out its live record, and
            // hooks are for authorisation and observation, not for changing
            // the session.
            hook.on_session_resume(&rotated, p)?;
        }
        let missed = self
            .cfg
            .replay
            .as_ref()
            .map_or(0, |r| r.missed_since(&p.session_id, &p.last_received_id));
        Ok(SessionResumeResult {
            wmp: Metadata {
                version,
                session_id: p.session_id.clone(),
                ..Metadata::default()
            },
            resumed: true,
            resumption_token: new_token,
            missed_messages: missed,
            capabilities: Some(rotated.capabilities.clone()),
            security: rotated.security.clone(),
        })
    }

    /// Implements `wmp.session.close`: deletes the session when the caller
    /// owns it. Anything else — no principal, an unknown session, not the
    /// owner — is silently ignored, as a notification has no response.
    pub fn session_close(&self, _now: i64, ctx: &RequestContext, p: &SessionCloseParams) {
        let Some(principal) = ctx.principal.as_ref().filter(|p| p.is_authenticated()) else {
            return;
        };
        // Serialise with the fallback token rotation so a concurrent resume
        // cannot write the session back after it was closed.
        let Ok(_guard) = self.lock_for(&p.wmp.session_id) else {
            return;
        };
        let Some(session) = self.cfg.store.get(&p.wmp.session_id) else {
            return;
        };
        if !session.owned_by(&principal.key()) {
            return;
        }
        let _ = self.cfg.store.delete(&session.id);
    }

    /// Removes expired sessions and returns how many were removed.
    ///
    /// With a store that lists expired sessions, the expire hooks run for
    /// each removed session, and sessions that expire while the sweep runs
    /// are left for the next one so none is removed without its hooks;
    /// otherwise the sweep only cleans up. Safe for concurrent use.
    pub fn sweep(&self, now: i64) -> Result<usize, HandlerError> {
        let expired = match self.cfg.store.list_expired(now) {
            Ok(expired) => expired,
            Err(StoreError::Unsupported) => {
                // Cleanup must not run between a fallback rotation's read
                // and write, so hold every stripe.
                let guards: Vec<_> = self
                    .locks
                    .iter()
                    .filter_map(|lock| lock.lock().ok())
                    .collect();
                let count = self
                    .cfg
                    .store
                    .cleanup(now)
                    .map_err(|_| RpcError::code(ERR_INTERNAL_ERROR))?;
                drop(guards);
                return Ok(count);
            }
            Err(_) => return Err(RpcError::code(ERR_INTERNAL_ERROR).into()),
        };
        let mut removed = 0;
        for session in expired {
            if self.expire(now, &session) {
                removed += 1;
            }
        }
        Ok(removed)
    }

    /// Removes `session` and, only if this call removed it, runs the expire
    /// hooks. The record is re-read under the per-session stripe lock and
    /// deleted before the hooks run, so concurrent sweeps and resume attempts
    /// in this process run the hooks at most once per session. Reports
    /// whether this call expired the session.
    fn expire(&self, now: i64, session: &Session) -> bool {
        let current = {
            let Ok(_guard) = self.lock_for(&session.id) else {
                return false;
            };
            let Some(current) = self.cfg.store.get(&session.id) else {
                return false;
            };
            if !current.is_expired(now) {
                return false;
            }
            if self.cfg.store.delete(&session.id).is_err() {
                return false;
            }
            current
        };
        // The stripe is released before the hooks run, as in go-wmp.
        for hook in &self.cfg.expire_hooks {
            hook.on_session_expire(&current);
        }
        true
    }

    /// Maps a rotation that found no live session. If the caller's own
    /// session expired between the expiry check and the rotation, it is
    /// expired properly (hooks run, record removed) and the caller gets
    /// `-31001`; anything else is `-31000`.
    fn lost_rotation(
        &self,
        now: i64,
        principal: &crate::principal::Principal,
        id: &str,
    ) -> HandlerError {
        let Some(session) = self.cfg.store.get(id) else {
            return RpcError::code(ERR_SESSION_NOT_FOUND).into();
        };
        if !session.owned_by(&principal.key()) || !session.is_expired(now) {
            return RpcError::code(ERR_SESSION_NOT_FOUND).into();
        }
        if !self.expire(now, &session) {
            return RpcError::code(ERR_INTERNAL_ERROR).into();
        }
        RpcError::code(ERR_SESSION_EXPIRED).into()
    }

    /// The version to use on resume: the one stored at create, provided the
    /// client still offers at least that. Sessions without a stored version
    /// (not created by this service) fall back to negotiation.
    fn session_version(
        &self,
        session: &Session,
        offered: &str,
        versions: &[&str],
    ) -> Result<String, HandlerError> {
        let stored = session
            .metadata
            .get(METADATA_KEY_VERSION)
            .cloned()
            .unwrap_or_default();
        if stored.is_empty() {
            let selected = negotiate_version(offered, versions)
                .ok_or_else(|| version_rejection(Some(offered), versions))?;
            return Ok(selected.to_owned());
        }
        // The pinned version must still be one this service supports.
        if !versions.contains(&stored.as_str()) {
            return Err(version_rejection(Some(offered), versions).into());
        }
        let pinned = [stored.as_str()];
        let selected = negotiate_version(offered, &pinned)
            .ok_or_else(|| version_rejection(Some(offered), &pinned))?;
        Ok(selected.to_owned())
    }

    /// Stores a new session, refusing an identifier that is already taken
    /// instead of overwriting that session. Atomic through the store's
    /// create-if-absent; else serialised per identifier within this process.
    fn insert(&self, session: Session) -> Result<(), StoreError> {
        match self.cfg.store.create_if_absent(session.clone()) {
            Err(StoreError::Unsupported) => {}
            other => return other,
        }
        let Ok(_guard) = self.lock_for(&session.id) else {
            return Err(StoreError::Unsupported);
        };
        if self.cfg.store.get(&session.id).is_some() {
            return Err(StoreError::SessionExists);
        }
        self.cfg.store.create(session)
    }

    /// Swaps the resumption token atomically through the store's rotation;
    /// for a store without one, under a per-session stripe lock, which is
    /// not enough across replicas sharing the store.
    fn rotate(
        &self,
        now: i64,
        id: &str,
        old_token: &str,
        new_token: &str,
        expires_at: Option<i64>,
    ) -> Result<Session, StoreError> {
        match self
            .cfg
            .store
            .rotate_resumption_token(now, id, old_token, new_token, expires_at)
        {
            Err(StoreError::Unsupported) => {}
            other => return other,
        }
        let Ok(_guard) = self.lock_for(id) else {
            return Err(StoreError::Unsupported);
        };
        let session = self.cfg.store.get(id).ok_or(StoreError::NoSuchSession)?;
        if session.is_expired(now) {
            return Err(StoreError::NoSuchSession);
        }
        if old_token.is_empty() || !tokens_equal(&session.resumption_token, old_token) {
            return Err(StoreError::TokenMismatch);
        }
        if session
            .resumption_token_expires_at
            .is_some_and(|expires| now > expires)
        {
            return Err(StoreError::TokenExpired);
        }
        let mut updated = session;
        updated.resumption_token = new_token.to_owned();
        updated.resumption_token_expires_at = expires_at;
        self.cfg.store.update(updated.clone())?;
        Ok(updated)
    }

    fn negotiate_capabilities(&self, offered: Option<&Capabilities>) -> Capabilities {
        static EMPTY: Capabilities = Capabilities(crate::types::OrderedMap::new());
        let offered = offered.unwrap_or(&EMPTY);
        if let Some(custom) = &self.cfg.capabilities {
            return custom(offered);
        }
        // The negotiated value is always the supported side's parameters,
        // never the offered ones — mirroring go-wmp's negotiation.
        let mut out = Capabilities::default();
        for name in offered.0.keys() {
            if let Some(supported) = self.cfg.supported.0.get(name) {
                out.0.insert(name.clone(), supported.clone());
            }
        }
        out
    }

    /// `now` plus the resumption lifetime, never later than the session
    /// expiry. A zero resumption lifetime means the token dies with the
    /// session; a session that does not expire gives the plain resumption
    /// lifetime, or no expiry when that is unset too.
    fn token_expiry(&self, now: i64, session_expiry: Option<i64>) -> Option<i64> {
        if self.cfg.resumption_ttl_secs <= 0 {
            return session_expiry;
        }
        let exp = now + self.cfg.resumption_ttl_secs;
        match session_expiry {
            None => Some(exp),
            Some(session_expiry) if exp < session_expiry => Some(exp),
            Some(session_expiry) => Some(session_expiry),
        }
    }

    fn lock_for(&self, id: &str) -> Result<std::sync::MutexGuard<'_, ()>, StoreError> {
        // FNV-1a, as in go-wmp's stripe selection. The stripes are always all
        // present; `unwrap_or` on the dedicated lock keeps the impossible
        // case honest instead of indexing. A poisoned stripe is unreachable
        // — nothing panics while holding one — and surfaces as an error.
        let mut hash = 0x811c9dc5u32;
        for &b in id.as_bytes() {
            hash ^= b as u32;
            hash = hash.wrapping_mul(0x01000193);
        }
        let stripe = (hash & SESSION_LOCK_STRIPE_MASK) as usize;
        self.locks
            .get(stripe)
            .unwrap_or(&self.zero)
            .lock()
            .map_err(|_| StoreError::Unsupported)
    }

    fn new_session_id(&self) -> Result<String, HandlerError> {
        if let Some(custom) = &self.cfg.new_session_id {
            return custom().ok_or_else(|| HandlerError::Rpc(RpcError::code(ERR_INTERNAL_ERROR)));
        }
        let mut bytes = [0u8; 16];
        (self.cfg.entropy)(&mut bytes)
            .then(|| format!("ses-{}", hex_lower(&bytes)))
            .ok_or_else(|| HandlerError::Rpc(RpcError::code(ERR_INTERNAL_ERROR)))
    }

    fn new_resumption_token(&self) -> Result<String, HandlerError> {
        let mut bytes = [0u8; RESUMPTION_TOKEN_BYTES];
        (self.cfg.entropy)(&mut bytes)
            .then(|| new_resumption_token(bytes))
            .ok_or_else(|| HandlerError::Rpc(RpcError::code(ERR_INTERNAL_ERROR)))
    }
}

/// Lower-case hex, for the default session identifier.
fn hex_lower(bytes: &[u8]) -> String {
    /// The lower-case hex digit for a value below 16.
    fn hex_digit(v: u8) -> char {
        if v < 10 {
            (b'0' + v) as char
        } else {
            (b'a' + (v - 10)) as char
        }
    }
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(hex_digit(b >> 4));
        out.push(hex_digit(b & 0x0f));
    }
    out
}

/// A clock: the current time, unix seconds. go-wmp reads `time.Now` inside
/// the service; the mirror injects the clock so tests are deterministic.
pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

/// A [`Handler`](crate::Handler) whose session methods run a
/// [`SessionService`].
///
/// go-wmp embeds this in an application handler so the other methods come
/// from `BaseHandler`; in Rust an application implements
/// [`Handler`](crate::Handler) for itself and delegates the three session
/// methods to a clone of this handler, or holds it and calls its methods
/// directly.
#[derive(Clone)]
pub struct SessionHandler {
    service: Arc<SessionService>,
    clock: Clock,
}

impl SessionHandler {
    /// A handler backed by `service`, reading the time from `clock`.
    pub fn new(service: Arc<SessionService>, clock: Clock) -> Self {
        Self { service, clock }
    }

    /// The service behind this handler.
    pub fn service(&self) -> &Arc<SessionService> {
        &self.service
    }

    /// Delegates `wmp.session.create`.
    pub fn create(
        &self,
        now: i64,
        ctx: &RequestContext,
        params: &SessionCreateParams,
    ) -> Result<SessionCreateResult, HandlerError> {
        self.service.session_create(now, ctx, params)
    }

    /// Delegates `wmp.session.resume`.
    pub fn resume(
        &self,
        now: i64,
        ctx: &RequestContext,
        params: &SessionResumeParams,
    ) -> Result<SessionResumeResult, HandlerError> {
        self.service.session_resume(now, ctx, params)
    }

    /// Delegates `wmp.session.close`.
    pub fn close(&self, now: i64, ctx: &RequestContext, params: &SessionCloseParams) {
        self.service.session_close(now, ctx, params)
    }
}

impl crate::handler::Handler for SessionHandler {
    fn session_create(
        &self,
        ctx: &RequestContext,
        params: &SessionCreateParams,
    ) -> Result<SessionCreateResult, HandlerError> {
        self.service.session_create((self.clock)(), ctx, params)
    }

    fn session_resume(
        &self,
        ctx: &RequestContext,
        params: &SessionResumeParams,
    ) -> Result<SessionResumeResult, HandlerError> {
        self.service.session_resume((self.clock)(), ctx, params)
    }

    fn session_close(&self, ctx: &RequestContext, params: &SessionCloseParams) {
        self.service.session_close((self.clock)(), ctx, params)
    }

    fn session_store(&self) -> Option<Arc<dyn SessionStore>> {
        Some(self.service.store().clone())
    }

    fn supported_versions(&self) -> Vec<String> {
        self.service.supported_versions()
    }
}
