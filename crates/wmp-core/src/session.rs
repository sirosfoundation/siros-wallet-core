//! The session state, the store that persists it, and the in-memory store.

use std::collections::BTreeMap;
use std::sync::RwLock;

use rustc_hash::FxHashMap;

use crate::token::tokens_equal;
use crate::types::{Capabilities, SecurityMode};

/// Why a store operation failed — the analogue of go-wmp's sentinel errors,
/// distinct from the numeric JSON-RPC codes.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum StoreError {
    /// The session does not exist or has expired.
    #[error("wmp: no such session")]
    NoSuchSession,
    /// The presented resumption token is not the session's current token
    /// (never issued, already rotated, or empty).
    #[error("wmp: resumption token mismatch")]
    TokenMismatch,
    /// The replacement token is empty or equal to the presented token,
    /// which would leave the old token usable and break single-use.
    #[error("wmp: invalid replacement resumption token")]
    InvalidNewToken,
    /// A session with the same identifier is already stored.
    #[error("wmp: session already exists")]
    SessionExists,
    /// The presented token is current but its own expiry has passed.
    #[error("wmp: resumption token expired")]
    TokenExpired,
    /// The store does not implement this optional operation.
    #[error("wmp: store does not support this operation")]
    Unsupported,
}

/// The state of an active WMP session.
///
/// Timestamps are unix seconds. go-wmp reads the wall clock through
/// `time.Now`; this crate takes the current time as an argument, so expiry
/// is decided by the caller's clock and tests are deterministic.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Session {
    /// The session identifier.
    pub id: String,
    /// The session participants.
    pub participants: Vec<String>,
    /// The negotiated capabilities.
    pub capabilities: Capabilities,
    /// The session security configuration.
    pub security: SecurityMode,
    /// Free-form session metadata.
    pub metadata: BTreeMap<String, String>,
    /// The session's current single-use resumption token.
    pub resumption_token: String,
    /// When the session was created, unix seconds.
    pub created_at: i64,
    /// When the session expires, unix seconds; absent for a session that
    /// does not expire on its own.
    pub expires_at: Option<i64>,
    /// The opaque owner key of the authenticated principal that created the
    /// session ([`crate::principal::Principal::key`]). Empty means unowned, which is
    /// the behaviour of sessions created before owner binding existed.
    pub owner: String,
    /// When [`Session::resumption_token`] expires, unix seconds; absent
    /// when the token does not expire on its own (it still dies with the
    /// session).
    pub resumption_token_expires_at: Option<i64>,
}

impl Session {
    /// Whether the session is bound to `owner_key`. An empty key never
    /// matches, so an unauthenticated caller cannot claim an unowned session
    /// by presenting an empty owner.
    pub fn owned_by(&self, owner_key: &str) -> bool {
        !owner_key.is_empty() && self.owner == owner_key
    }

    /// Whether the session has exceeded its TTL at `now` (unix seconds).
    pub fn is_expired(&self, now: i64) -> bool {
        self.expires_at.is_some_and(|expires| now > expires)
    }

    /// Whether the named capability was negotiated.
    pub fn has_capability(&self, name: &str) -> bool {
        self.capabilities.0.contains_key(name)
    }

    /// Whether the named capability requires encryption.
    pub fn requires_encryption(&self, capability: &str) -> bool {
        self.security
            .encrypted_capabilities
            .iter()
            .any(|c| c == capability)
    }
}

/// The store that persists sessions.
///
/// go-wmp splits optional capabilities (token rotation, create-if-absent,
/// update-if-present, expired listing) into separate interfaces the peer
/// discovers by type assertion. Rust has no cross-trait downcast, so they are
/// default methods here: a store overrides the ones it supports, and the
/// default returns [`StoreError::Unsupported`].
///
/// Stores hand out owned copies of sessions; nothing held by a caller is
/// mutated by a later store operation.
pub trait SessionStore: Send + Sync {
    /// Stores `session`, overwriting any session with the same identifier.
    fn create(&self, session: Session) -> Result<(), StoreError>;

    /// Returns a copy of the session with this identifier, if stored.
    /// Expiry is not checked here; the caller decides with
    /// [`Session::is_expired`].
    fn get(&self, id: &str) -> Option<Session>;

    /// Replaces the stored session with `session`.
    fn update(&self, session: Session) -> Result<(), StoreError>;

    /// Removes the session with this identifier.
    fn delete(&self, id: &str) -> Result<(), StoreError>;

    /// Returns the non-expired sessions whose metadata maps `key` to
    /// `value`, at `now` (unix seconds).
    fn get_by_metadata(&self, now: i64, key: &str, value: &str)
        -> Result<Vec<Session>, StoreError>;

    /// Returns all non-expired sessions at `now` (unix seconds).
    fn list(&self, now: i64) -> Result<Vec<Session>, StoreError>;

    /// Removes all expired sessions at `now` (unix seconds) and returns how
    /// many were removed.
    fn cleanup(&self, now: i64) -> Result<usize, StoreError>;

    /// Rotates the resumption token atomically: succeeds for at most one of
    /// any number of concurrent callers presenting the same old token.
    ///
    /// Returns the updated session, [`StoreError::NoSuchSession`] if the
    /// session is absent or expired, [`StoreError::TokenMismatch`] if
    /// `old_token` is empty or not the current token,
    /// [`StoreError::TokenExpired`] if it is current but past its expiry, or
    /// [`StoreError::InvalidNewToken`] if `new_token` is empty or equals
    /// `old_token`. The comparison must be constant-time
    /// ([`crate::token::tokens_equal`]).
    fn rotate_resumption_token(
        &self,
        now: i64,
        id: &str,
        old_token: &str,
        new_token: &str,
        expires_at: Option<i64>,
    ) -> Result<Session, StoreError> {
        let _ = (now, id, old_token, new_token, expires_at);
        Err(StoreError::Unsupported)
    }

    /// Stores `session` only if its identifier is free, atomically.
    /// [`SessionStore::create`] alone overwrites, so a colliding identifier
    /// would silently replace another session's owner and token.
    fn create_if_absent(&self, session: Session) -> Result<(), StoreError> {
        let _ = session;
        Err(StoreError::Unsupported)
    }

    /// Replaces the stored session only if one with that identifier exists.
    fn update_if_present(&self, session: Session) -> Result<(), StoreError> {
        let _ = session;
        Err(StoreError::Unsupported)
    }

    /// Returns the expired sessions at `now` (unix seconds).
    fn list_expired(&self, now: i64) -> Result<Vec<Session>, StoreError> {
        let _ = now;
        Err(StoreError::Unsupported)
    }
}

/// A thread-safe in-memory [`SessionStore`] that implements every optional
/// operation.
#[derive(Debug, Default)]
pub struct MemorySessionStore {
    sessions: RwLock<FxHashMap<String, Session>>,
}

impl MemorySessionStore {
    /// Creates an empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl SessionStore for MemorySessionStore {
    fn create(&self, session: Session) -> Result<(), StoreError> {
        self.sessions
            .write()
            .map_err(|_| StoreError::Unsupported)?
            .insert(session.id.clone(), session);
        Ok(())
    }

    fn get(&self, id: &str) -> Option<Session> {
        self.sessions.read().ok()?.get(id).cloned()
    }

    fn update(&self, session: Session) -> Result<(), StoreError> {
        self.sessions
            .write()
            .map_err(|_| StoreError::Unsupported)?
            .insert(session.id.clone(), session);
        Ok(())
    }

    fn delete(&self, id: &str) -> Result<(), StoreError> {
        self.sessions
            .write()
            .map_err(|_| StoreError::Unsupported)?
            .remove(id);
        Ok(())
    }

    fn get_by_metadata(
        &self,
        now: i64,
        key: &str,
        value: &str,
    ) -> Result<Vec<Session>, StoreError> {
        let sessions = self.sessions.read().map_err(|_| StoreError::Unsupported)?;
        Ok(sessions
            .values()
            .filter(|sess| {
                !sess.is_expired(now) && sess.metadata.get(key).is_some_and(|v| v == value)
            })
            .cloned()
            .collect())
    }

    fn list(&self, now: i64) -> Result<Vec<Session>, StoreError> {
        let sessions = self.sessions.read().map_err(|_| StoreError::Unsupported)?;
        Ok(sessions
            .values()
            .filter(|sess| !sess.is_expired(now))
            .cloned()
            .collect())
    }

    fn cleanup(&self, now: i64) -> Result<usize, StoreError> {
        let mut sessions = self.sessions.write().map_err(|_| StoreError::Unsupported)?;
        let expired: Vec<String> = sessions
            .iter()
            .filter(|(_, sess)| sess.is_expired(now))
            .map(|(id, _)| id.clone())
            .collect();
        let count = expired.len();
        for id in expired {
            sessions.remove(&id);
        }
        Ok(count)
    }

    fn rotate_resumption_token(
        &self,
        now: i64,
        id: &str,
        old_token: &str,
        new_token: &str,
        expires_at: Option<i64>,
    ) -> Result<Session, StoreError> {
        if new_token.is_empty() || tokens_equal(new_token, old_token) {
            return Err(StoreError::InvalidNewToken);
        }
        let mut sessions = self.sessions.write().map_err(|_| StoreError::Unsupported)?;
        let sess = sessions.get(id).ok_or(StoreError::NoSuchSession)?;
        if sess.is_expired(now) {
            return Err(StoreError::NoSuchSession);
        }
        if old_token.is_empty() || !tokens_equal(&sess.resumption_token, old_token) {
            return Err(StoreError::TokenMismatch);
        }
        if sess
            .resumption_token_expires_at
            .is_some_and(|expires| now > expires)
        {
            return Err(StoreError::TokenExpired);
        }
        let mut updated = sess.clone();
        updated.resumption_token = new_token.to_owned();
        updated.resumption_token_expires_at = expires_at;
        sessions.insert(id.to_owned(), updated.clone());
        Ok(updated)
    }

    fn create_if_absent(&self, session: Session) -> Result<(), StoreError> {
        let mut sessions = self.sessions.write().map_err(|_| StoreError::Unsupported)?;
        if sessions.contains_key(&session.id) {
            return Err(StoreError::SessionExists);
        }
        sessions.insert(session.id.clone(), session);
        Ok(())
    }

    fn update_if_present(&self, session: Session) -> Result<(), StoreError> {
        let mut sessions = self.sessions.write().map_err(|_| StoreError::Unsupported)?;
        if !sessions.contains_key(&session.id) {
            return Err(StoreError::NoSuchSession);
        }
        sessions.insert(session.id.clone(), session);
        Ok(())
    }

    fn list_expired(&self, now: i64) -> Result<Vec<Session>, StoreError> {
        let sessions = self.sessions.read().map_err(|_| StoreError::Unsupported)?;
        Ok(sessions
            .values()
            .filter(|sess| sess.is_expired(now))
            .cloned()
            .collect())
    }
}
