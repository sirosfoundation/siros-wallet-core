//! The Valkey-backed session and invitation stores (#109): the production
//! persistence for multi-replica deployments. The same `fred` client the
//! shared outbox uses (issue #65), behind the same `valkey` feature.
//!
//! The [`SessionStore`] and [`InvitationStore`] traits are the boundary;
//! this module provides the Valkey implementation. Sessions live at
//! `engine:sessions:<id>`, nonces at `engine:invitations:<nonce>`, each
//! with Valkey TTLs matching their expiry. A SET index (`engine:session-ids`)
//! tracks the live session ids for listing — the standard Redis pattern,
//! no SCAN needed. The store's `cleanup` sweeps the index for sessions
//! whose Valkey TTL has already expired (the skew-tolerance catch).

use wmp_core::invitation::{Invitation, InvitationError, InvitationStore};
use wmp_core::session::{Session, SessionStore, StoreError};

use fred::prelude::*;
use std::sync::Arc;

const SESSION_PREFIX: &str = "engine:sessions:";
const SESSION_INDEX: &str = "engine:session-ids";
const INVITATION_PREFIX: &str = "engine:invitations:";

/// The shared Valkey runtime + client (the same pattern as the outbox: a
/// dedicated tokio runtime the sync trait methods drive through `block_on`).
struct Valkey {
    client: Client,
    runtime: tokio::runtime::Handle,
}

impl Valkey {
    fn new(url: &str) -> Result<Self, String> {
        let config =
            Config::from_url(url).map_err(|err| format!("the valkey url does not parse: {err}"))?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|err| format!("the valkey runtime failed: {err}"))?;
        let handle = runtime.handle().clone();
        let client = handle
            .block_on(async {
                let client = Client::new(config, None, None, None);
                client.init().await?;
                Ok::<Client, fred::error::Error>(client)
            })
            .map_err(|err| format!("the valkey connection failed: {err}"))?;
        std::mem::forget(runtime);
        Ok(Self {
            client,
            runtime: handle,
        })
    }
}

fn session_key(id: &str) -> String {
    format!("{SESSION_PREFIX}{id}")
}

/// The Valkey-backed [`SessionStore`]: sessions as JSON at
/// `engine:sessions:<id>` with Valkey TTLs, a SET index for listing.
pub struct ValkeySessionStore {
    valkey: Arc<Valkey>,
}

impl ValkeySessionStore {
    /// Connects to the Valkey store at `url` (a RESP URL: `valkey://` or
    /// `redis://`), starting the shared runtime.
    pub fn new(url: &str) -> Result<Self, String> {
        Ok(Self {
            valkey: Arc::new(Valkey::new(url)?),
        })
    }

    fn session_ttl(session: &Session) -> Option<Expiration> {
        session
            .expires_at
            .map(|exp| Expiration::EX((exp - session.created_at).max(0)))
    }

    fn read(&self, key: &str) -> Option<Session> {
        let value: Option<Vec<u8>> = self
            .valkey
            .runtime
            .block_on(async { self.valkey.client.get(key).await })
            .ok()?;
        serde_json::from_slice(&value?).ok()
    }

    fn ids(&self) -> Result<Vec<String>, StoreError> {
        self.valkey
            .runtime
            .block_on(async { self.valkey.client.smembers(SESSION_INDEX).await })
            .map_err(|_| StoreError::Unsupported)
    }
}

impl SessionStore for ValkeySessionStore {
    fn create(&self, session: Session) -> Result<(), StoreError> {
        let key = session_key(&session.id);
        let value = serde_json::to_vec(&session).map_err(|_| StoreError::Unsupported)?;
        let expire = Self::session_ttl(&session);
        self.valkey
            .runtime
            .block_on(async {
                let _: () = self
                    .valkey
                    .client
                    .set(&key, value, expire, None, false)
                    .await?;
                let _: () = self.valkey.client.sadd(SESSION_INDEX, &key).await?;
                Ok::<(), fred::error::Error>(())
            })
            .map_err(|_| StoreError::Unsupported)
    }

    fn get(&self, id: &str) -> Option<Session> {
        self.read(&session_key(id))
    }

    fn update(&self, session: Session) -> Result<(), StoreError> {
        self.create(session)
    }

    fn delete(&self, id: &str) -> Result<(), StoreError> {
        let key = session_key(id);
        self.valkey
            .runtime
            .block_on(async {
                let _: () = self.valkey.client.del(&key).await?;
                let _: () = self.valkey.client.srem(SESSION_INDEX, &key).await?;
                Ok::<(), fred::error::Error>(())
            })
            .map_err(|_| StoreError::Unsupported)
    }

    fn get_by_metadata(
        &self,
        now: i64,
        key: &str,
        value: &str,
    ) -> Result<Vec<Session>, StoreError> {
        let all = self.list(now)?;
        Ok(all
            .into_iter()
            .filter(|sess| sess.metadata.get(key).is_some_and(|v| v == value))
            .collect())
    }

    fn list(&self, now: i64) -> Result<Vec<Session>, StoreError> {
        let keys = self.ids()?;
        let mut sessions = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some(session) = self.read(&key) {
                if !session.is_expired(now) {
                    sessions.push(session);
                }
            }
        }
        Ok(sessions)
    }

    fn cleanup(&self, now: i64) -> Result<usize, StoreError> {
        // Valkey's TTL expired most sessions; this sweep catches the skew
        // cases and cleans the index of dead keys.
        let keys = self.ids()?;
        let mut dead = Vec::new();
        for key in keys {
            let value: Option<Vec<u8>> = self
                .valkey
                .runtime
                .block_on(async { self.valkey.client.get(key.clone()).await })
                .map_err(|_| StoreError::Unsupported)?;
            match value {
                None => dead.push(key), // the TTL expired the key; the index is stale
                Some(bytes) => {
                    if let Ok(session) = serde_json::from_slice::<Session>(&bytes) {
                        if session.is_expired(now) {
                            dead.push(key);
                        }
                    }
                }
            }
        }
        for key in &dead {
            let _ = self.valkey.runtime.block_on(async {
                let _: () = self.valkey.client.del(key).await?;
                let _: () = self.valkey.client.srem(SESSION_INDEX, key).await?;
                Ok::<(), fred::error::Error>(())
            });
        }
        Ok(dead.len())
    }

    fn rotate_resumption_token(
        &self,
        _now: i64,
        id: &str,
        old_token: &str,
        new_token: &str,
        expires_at: Option<i64>,
    ) -> Result<Session, StoreError> {
        let mut session = self.get(id).ok_or(StoreError::Unsupported)?;
        if session.resumption_token != old_token {
            return Err(StoreError::InvalidNewToken);
        }
        session.resumption_token = new_token.to_owned();
        session.resumption_token_expires_at = expires_at;
        self.update(session.clone())?;
        Ok(session)
    }
}

/// The Valkey-backed [`InvitationStore`]: nonces as keys with TTLs.
pub struct ValkeyInvitationStore {
    valkey: Arc<Valkey>,
}

impl ValkeyInvitationStore {
    /// Connects to the Valkey store at `url` (the same URL as the session
    /// store; the two share the client's protocol but not the connection).
    pub fn new(url: &str) -> Result<Self, String> {
        Ok(Self {
            valkey: Arc::new(Valkey::new(url)?),
        })
    }

    fn key(nonce: &str) -> String {
        format!("{INVITATION_PREFIX}{nonce}")
    }

    fn ttl_secs(inv: &Invitation) -> i64 {
        inv.expires_at
            .as_deref()
            .and_then(wmp_core::invitation::rfc3339_to_unix)
            .map(|exp| exp.max(0))
            .unwrap_or(3600)
            .min(86400)
    }
}

impl InvitationStore for ValkeyInvitationStore {
    fn put(&self, nonce: &str, inv: &Invitation) -> Result<(), InvitationError> {
        let key = Self::key(nonce);
        let value =
            serde_json::to_vec(inv).map_err(|_| InvitationError::Nonce("serialize".to_owned()))?;
        let expire = Expiration::EX(Self::ttl_secs(inv));
        self.valkey
            .runtime
            .block_on(async {
                let _: () = self
                    .valkey
                    .client
                    .set(key, value, Some(expire), None, false)
                    .await?;
                Ok::<(), fred::error::Error>(())
            })
            .map_err(|e| InvitationError::Nonce(format!("write: {e}")))
    }

    fn consume(&self, now: i64, nonce: &str) -> Option<Invitation> {
        let key = Self::key(nonce);
        // GETDEL: the atomic single-use consume.
        let value: Option<Vec<u8>> = self
            .valkey
            .runtime
            .block_on(async { self.valkey.client.getdel(key).await })
            .ok()?;
        let inv: Invitation = serde_json::from_slice(&value?).ok()?;
        if inv.is_expired(now) {
            return None;
        }
        Some(inv)
    }

    fn cleanup(&self, now: i64) -> Result<usize, InvitationError> {
        // The skew-tolerance sweep: Valkey's TTL did most of the work.
        // Without a SCAN, we accept that expired-but-unconsumed nonces
        // whose Valkey TTL hasn't fired yet are simply not swept here —
        // the `is_expired(now)` check in `consume` catches them, and
        // Valkey's TTL eventually does. The count is a best-effort 0
        // (the TTL is the primary cleanup).
        let _ = now;
        Ok(0)
    }
}
