//! The group registry (issue #77 — the `join` invitation's other half):
//! which sessions joined which group sessions.
//!
//! A `join` invitation names the group session ([`wmp_core::invitation::
//! INVITATION_PURPOSE_JOIN`]); the invitation's consume (`wmp.session.create`
//! with the `invitation_nonce`) registers the joining session as a member
//! here. In-group message passing (the mailbox's `deliver`) fans a delivery
//! naming a group out to every member's box; the SSE outbox pushes per
//! member, so the live stream and the replay both see it.
//!
//! [`GroupRegistry::leave`] drops every membership a session holds —
//! `wmp.session.close` calls it, so a member that leaves the group stops
//! receiving its deliveries.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

/// The group memberships: group session id → the member session ids that
/// joined it (the group's own session is NOT a member of itself — the
/// fan-out unions it in).
pub struct GroupRegistry {
    groups: Mutex<BTreeMap<String, BTreeSet<String>>>,
}

impl GroupRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self {
            groups: Mutex::new(BTreeMap::new()),
        }
    }

    /// Registers `member` as a member of `group`. Idempotent: a session
    /// that joins twice (two invitations, two consumes) holds one
    /// membership.
    pub fn join(&self, group: &str, member: &str) {
        if group.is_empty() || member.is_empty() {
            return;
        }
        self.groups
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry(group.to_owned())
            .or_default()
            .insert(member.to_owned());
    }

    /// Drops every membership `session` holds (its `wmp.session.close`):
    /// the leaving member's group deliveries stop here.
    pub fn leave(&self, session: &str) {
        if session.is_empty() {
            return;
        }
        let mut groups = self.groups.lock().unwrap_or_else(|p| p.into_inner());
        for members in groups.values_mut() {
            members.remove(session);
        }
        groups.retain(|_, members| !members.is_empty());
    }

    /// The members of `group` (empty when nobody joined): the mailbox's
    /// fan-out source.
    pub fn members(&self, group: &str) -> Vec<String> {
        self.groups
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(group)
            .map(|members| members.iter().cloned().collect())
            .unwrap_or_default()
    }
}

impl Default for GroupRegistry {
    fn default() -> Self {
        Self::new()
    }
}
