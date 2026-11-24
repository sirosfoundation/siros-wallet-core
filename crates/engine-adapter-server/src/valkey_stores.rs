//! The Valkey-backed session and invitation stores (#109): the production
//! persistence for multi-replica deployments. The same `fred` client the
//! shared outbox uses (issue #65), behind the same `valkey` feature.
//!
//! The [`SessionStore`] and [`InvitationStore`] traits are the boundary;
//! this module provides the Valkey implementation. Sessions live at
//! `engine:sessions:<id>`, nonces at `engine:invitations:<nonce>`, each
//! with Valkey TTLs matching their expiry — the store's `cleanup` is the
//! skew-tolerance sweep (Valkey's TTL already did most of the work).

use wmp_core::invitation::{Invitation, InvitationError, InvitationStore};
use wmp_core::session::{Session, SessionStore, StoreError};

use fred::prelude::*;
use std::sync::Arc;

const SESSION_PREFIX: &str = "engine:sessions:";
const INVITATION_PREFIX: &str = "engine:invitations:";

/// The shared Valkey runtime + client for the stores (the same pattern
/// as the outbox: a dedicated tokio runtime the sync trait methods drive
/// through `block_on`).
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
        Ok(Self { client, runtime })
    }
}

/// The Valkey-backed [`SessionStore`]: sessions as JSON values keyed by
/// id, expiry by the session's own TTL as a Valkey `EX`.
pub struct ValkeySessionStore {
    valkey: Arc<Valkey>,
}

impl ValkeySessionStore {
    pub fn new(url: &str) -> Result<Self, String> {
        Ok(Self { valkey: Arc::new(Valkey::new(url)?) })
    }

    /// The session's remaining TTL in seconds (None = no Valkey TTL).
    fn session_ttl(session: &Session) -> Option<i64> {
        session
            .expires_at
            .map(|exp| (exp - session.created_at).max(0))
    }

    /// Reads and deserializes one session.
    fn read(&self, key: &str) -> Option<Session> {
        let value: Option<Vec<u8>> = self
            .valkey
            .runtime
            .block_on(async { self.valkey.client.get(key).await })
            .ok()?;
        serde_json::from_slice(&value?).ok()
    }
}

fn session_key(id: &str) -> String {
    format!("{SESSION_PREFIX}{id}")
}

impl SessionStore for ValkeySessionStore {
    fn create(&self, session: Session) -> Result<(), StoreError> {
        let key = session_key(&session.id);
        let value = serde_json::to_vec(&session).map_err(|_| StoreError::Unsupported)?;
        let expire = Self::session_ttl(&session)
            .map(Expiration::EX);
        self.valkey
            .runtime
            .block_on(async {
                let _: () = self.valkey.client.set(key, value, expire, None, false).await?;
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
                let _: () = self.valkey.client.del(key).await?;
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
        // SCAN (not KEYS): the session store can be large, and KEYS
        // blocks the server. The page size is the batch; the cursor
        // walks.
        let mut cursor: u64 = 0;
        let mut sessions = Vec::new();
        loop {
            let page: (u64, Vec<String>) = self
                .valkey
                .runtime
                .block_on(async {
                    self.valkey.client.scan_page(cursor, Some(format!("{SESSION_PREFIX}*")), None).await
                })
                .map_err(|_| StoreError::Unsupported)?;
            cursor = page.0;
            for key in page.1 {
                if let Some(session) = self.read(&key) {
                    if !session.is_expired(now) {
                        sessions.push(session);
                    }
                }
            }
            if cursor == 0 {
                break;
            }
        }
        Ok(sessions)
    }

    fn cleanup(&self, now: i64) -> Result<usize, StoreError> {
        // Valkey's TTL expired most; this sweep catches the skew cases.
        let all = self.list(now)?;
        let expired: Vec<String> = all
            .iter()
            .filter(|sess| sess.is_expired(now))
            .map(|sess| session_key(&sess.id))
            .collect();
        for key in &expired {
            let _ = self
                .valkey
                .runtime
                .block_on(async {
                    let _: () = self.valkey.client.del(key).await?;
                    Ok::<(), fred::error::Error>(())
                });
        }
        Ok(expired.len())
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
    pub fn new(url: &str) -> Result<Self, String> {
        Ok(Self { valkey: Arc::new(Valkey::new(url)?) })
    }

    fn key(nonce: &str) -> String {
        format!("{INVITATION_PREFIX}{nonce}")
    }

    fn ttl_secs(inv: &Invitation) -> i64 {
        inv.expires_at
            .map(|exp| exp.max(0))
            .unwrap_or(3600)
            .min(86400)
    }
}

impl InvitationStore for ValkeyInvitationStore {
    fn put(&self, nonce: &str, inv: &Invitation) -> Result<(), InvitationError> {
        let key = Self::key(nonce);
        let value = serde_json::to_vec(inv)
            .map_err(|_| InvitationError::Nonce("serialize".to_owned()))?;
        let expire = Expiration::EX(Self::ttl_secs(inv));
        self.valkey
            .runtime
            .block_on(async {
                let _: () = self.valkey.client.set(key, value, Some(expire), None, false).await?;
                Ok::<(), fred::error::Error>(())
            })
            .map_err(|e| InvitationError::Nonce(format!("write: {e}")))
    }

    fn consume(&self, now: i64, nonce: &str) -> Option<Invitation> {
        let key = Self::key(nonce);
        // GETDEL: atomic consume.
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
        // The skew-tolerance sweep (Valkey's TTL did most of the work).
        let mut cursor: u64 = 0;
        let mut expired = Vec::new();
        loop {
            let page: (u64, Vec<String>) = self
                .valkey
                .runtime
                .block_on(async {
                    self.valkey.client.scan_page(cursor, Some(format!("{INVITATION_PREFIX}*")), None).await
                })
                .map_err(|e| InvitationError::Nonce(format!("scan: {e}")))?;
            cursor = page.0;
            for key in page.1 {
                let value: Option<Vec<u8>> = self
                    .valkey
                    .runtime
                    .block_on(async { self.valkey.client.get(key.clone()).await })
                    .map_err(|e| InvitationError::Nonce(format!("read: {e}")))?;
                if let Some(bytes) = value {
                    if let Ok(inv) = serde_json::from_slice::<Invitation>(&bytes) {
                        if inv.is_expired(now) {
                            expired.push(key);
                        }
                    }
                }
            }
            if cursor == 0 {
                break;
            }
        }
        for key in &expired {
            let _ = self
                .valkey
                .runtime
                .block_on(async {
                    let _: () = self.valkey.client.del(key).await?;
                    Ok::<(), fred::error::Error>(())
                });
        }
        Ok(expired.len())
    }
}
