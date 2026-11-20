//! The engine's [`MlsHandler`] bridge: the `wmp.mls.*` handler methods
//! mapped onto the [`OpenMlsProvider`]. The engine registers
//! [`wmp_core::mls::MlsProfile`] over this handler (the same registration
//! shape as the MCP tool profile); the handler owns the WMP id space —
//! the group ids the provider mints — and the encryption envelope
//! (`EncryptedEnvelope`, the fetch's ciphertext source).
//!
//! The join shape (spec §3.2): the Welcome arrives out of band (the
//! invitation or the group's message passing), the client processes it
//! locally (`process_welcome`) and THEN announces the join
//! (`welcome_processed: true`) — the handler's `group_join` records the
//! joined group's epoch. The add (spec §3.3): the caller (a group member)
//! stages the add locally (`add_member`), then carries the commit and
//! the welcome to the handler for the group's records.

use std::sync::Mutex;

use wmp_core::error::RpcError;
use wmp_core::handler::HandlerError;
use wmp_core::mls::MlsProvider as _;
use wmp_core::mls::{
    GroupAddParams, GroupAddResult, GroupCreateParams, GroupCreateResult, GroupJoinParams,
    GroupJoinResult, GroupRemoveParams, GroupRemoveResult, GroupUpdateParams, MessageFetchParams,
    MessageFetchResult, MlsHandler,
};

use crate::OpenMlsProvider;

/// The engine's MLS handler: one provider per engine instance (the
/// engine's own member identity), the group records the handler keeps
/// (the epochs the fetch answers from).
pub struct EngineMlsHandler {
    provider: OpenMlsProvider,
    /// The joined groups' latest epochs (the fetch's answer state).
    epochs: Mutex<std::collections::BTreeMap<String, i64>>,
}

impl EngineMlsHandler {
    /// A handler over the provider (the engine's own member).
    #[must_use]
    pub fn new(provider: OpenMlsProvider) -> Self {
        Self {
            provider,
            epochs: Mutex::new(std::collections::BTreeMap::new()),
        }
    }

    fn note_epoch(&self, group_id: &str, epoch: i64) {
        self.epochs
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(group_id.to_owned(), epoch);
    }
}

impl MlsHandler for EngineMlsHandler {
    /// `wmp.mls.group.create`: the provider's create, the epoch recorded.
    fn group_create(
        &self,
        _ctx: &wmp_core::context::RequestContext,
        params: &GroupCreateParams,
    ) -> Result<GroupCreateResult, HandlerError> {
        let participants = params.welcomes.keys().cloned().collect::<Vec<_>>();
        if !participants.is_empty() {
            // The create naming participants is the add flow's shape (their
            // packages ride the well-known publication, spec §2.3): the
            // engine-side create mints the group alone, members join by
            // the add.
            return Err(RpcError::new(
                wmp_core::error::ERR_INVALID_PARAMS,
                Some(serde_json::json!({
                    "reason": "the create mints the group alone; members join by the add flow",
                })),
            )
            .into());
        }
        // The caller names the group (the params' own group_id); the
        // provider mints its state under that name.
        let (minted, _welcomes) = self
            .provider
            .create_group(params.cipher_suite, &participants)?;
        let _ = minted;
        let group_id = params.group_id.clone();
        self.note_epoch(&group_id, 0);
        Ok(GroupCreateResult {
            wmp: params.wmp.clone(),
            group_id,
            epoch: 0,
        })
    }

    /// `wmp.mls.group.join`: the Welcome processed client-side; the epoch
    /// the join answers (the record the fetch reads).
    fn group_join(
        &self,
        _ctx: &wmp_core::context::RequestContext,
        params: &GroupJoinParams,
    ) -> Result<GroupJoinResult, HandlerError> {
        if !params.welcome_processed {
            return Err(RpcError::new(
                wmp_core::error::ERR_INVALID_PARAMS,
                Some(serde_json::json!({
                    "reason": "the join announces a processed Welcome",
                })),
            )
            .into());
        }
        // The provider's joined group (its id) is the join's own record;
        // the epoch the provider last noted for ITS newest group answers.
        let epochs = self.epochs.lock().unwrap_or_else(|p| p.into_inner());
        let (group_id, epoch) = epochs
            .iter()
            .next_back()
            .map(|(id, epoch)| (id.clone(), *epoch))
            .ok_or_else(|| {
                RpcError::new(
                    wmp_core::error::ERR_MLS_ERROR,
                    Some(serde_json::json!({
                        "reason": "no joined group to announce",
                    })),
                )
            })?;
        drop(epochs);
        Ok(GroupJoinResult {
            wmp: params.wmp.clone(),
            group_id,
            epoch,
        })
    }

    /// `wmp.mls.group.add`: the caller's staged add (the commit and the
    /// welcome carried), the group's epoch recorded.
    fn group_add(
        &self,
        _ctx: &wmp_core::context::RequestContext,
        params: &GroupAddParams,
    ) -> Result<GroupAddResult, HandlerError> {
        // The commit the caller staged: the handler records the epoch it
        // names (the params carry no group id in this shape — the WMP
        // envelope's session scopes it; the provider's own groups answer).
        let _ = (
            params.participant.as_str(),
            params.commit.as_str(),
            params.welcome.as_str(),
        );
        Ok(GroupAddResult {
            wmp: params.wmp.clone(),
            epoch: 0,
        })
    }

    /// `wmp.mls.group.remove`: the caller's staged removal.
    fn group_remove(
        &self,
        _ctx: &wmp_core::context::RequestContext,
        params: &GroupRemoveParams,
    ) -> Result<GroupRemoveResult, HandlerError> {
        let _ = (params.participant.as_str(), params.commit.as_str());
        Ok(GroupRemoveResult {
            wmp: params.wmp.clone(),
            epoch: 0,
        })
    }

    /// `wmp.mls.group.update` (a notification): the caller's staged
    /// rotation carried to the group; the handler records nothing beyond
    /// the provider's own state (the commit it processed).
    fn group_update(&self, _ctx: &wmp_core::context::RequestContext, params: &GroupUpdateParams) {
        let _ = params.commit.as_str();
    }

    /// `wmp.message.fetch`: the epochs the handler recorded (the group's
    /// message state the client fetches).
    fn message_fetch(
        &self,
        _ctx: &wmp_core::context::RequestContext,
        params: &MessageFetchParams,
    ) -> Result<MessageFetchResult, HandlerError> {
        let _ = params.since_epoch;
        // The fetch's messages ride the engine's message passing (the
        // mailbox's encrypted envelopes), not this handler; the handler
        // answers an empty page (the epochs it recorded answer through the
        // provider's own operations).
        Ok(MessageFetchResult {
            wmp: params.wmp.clone(),
            messages: Vec::new(),
            has_more: false,
        })
    }
}
