//! WMP MLS: types, method constants, the handler and provider traits, and
//! the no-op implementations for TLS-only sessions — the mirror of go-wmp's
//! `pkg/wmp/mls`.
//!
//! This module provides the protocol-level types and handler traits. Actual
//! MLS cryptographic operations are delegated to an [`MlsProvider`]
//! implementation backed by an MLS library.

use rustc_hash::FxHashMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::context::RequestContext;
use crate::error::{
    RpcError, ERR_CAPABILITY_NOT_SUPPORTED, ERR_INTERNAL_ERROR, ERR_INVALID_PARAMS, ERR_MLS_ERROR,
};
use crate::handler::HandlerError;
use crate::profile::{DispatchResult, Profile};
use crate::types::{Metadata, OrderedMap};

// --- Method names ---

/// `wmp.mls.group.create`
pub const METHOD_GROUP_CREATE: &str = "wmp.mls.group.create";
/// `wmp.mls.group.join`
pub const METHOD_GROUP_JOIN: &str = "wmp.mls.group.join";
/// `wmp.mls.group.add`
pub const METHOD_GROUP_ADD: &str = "wmp.mls.group.add";
/// `wmp.mls.group.remove`
pub const METHOD_GROUP_REMOVE: &str = "wmp.mls.group.remove";
/// `wmp.mls.group.update`
pub const METHOD_GROUP_UPDATE: &str = "wmp.mls.group.update";
/// `wmp.message.fetch`
pub const METHOD_MESSAGE_FETCH: &str = "wmp.message.fetch";

// --- Cipher suites ---

/// `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (0x0001). MUST be
/// supported per the WMP MLS spec.
pub const CIPHER_SUITE_X25519_AES128_GCM: i64 = 0x0001;
/// `MLS_128_DHKEMP256_AES128GCM_SHA256_P256` (0x0002). SHOULD be supported.
pub const CIPHER_SUITE_P256_AES128_GCM: i64 = 0x0002;

// --- Credential types ---

/// The basic MLS credential type.
pub const CREDENTIAL_TYPE_BASIC: &str = "basic";
/// The X.509 MLS credential type.
pub const CREDENTIAL_TYPE_X509: &str = "x509";

/// The params of [`METHOD_GROUP_CREATE`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupCreateParams {
    /// The `wmp` envelope.
    pub wmp: Metadata,
    /// The group's identifier.
    pub group_id: String,
    /// The cipher suite, by its number.
    pub cipher_suite: i64,
    /// The credential types the group accepts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted_credential_types: Vec<String>,
    /// The identity schemes the group accepts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted_identity_schemes: Vec<String>,
    /// The group's GroupInfo.
    pub group_info: String,
    /// The Welcome messages, base64url-encoded, keyed by participant.
    pub welcomes: OrderedMap<String, String>,
}

/// The result of [`METHOD_GROUP_CREATE`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupCreateResult {
    /// The `wmp` envelope.
    pub wmp: Metadata,
    /// The group's identifier.
    pub group_id: String,
    /// The group's epoch.
    pub epoch: i64,
}

/// The params of [`METHOD_GROUP_JOIN`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupJoinParams {
    /// The `wmp` envelope.
    pub wmp: Metadata,
    /// Whether the Welcome was processed.
    pub welcome_processed: bool,
}

/// The result of [`METHOD_GROUP_JOIN`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupJoinResult {
    /// The `wmp` envelope.
    pub wmp: Metadata,
    /// The group's identifier.
    pub group_id: String,
    /// The group's epoch.
    pub epoch: i64,
}

/// The params of [`METHOD_GROUP_ADD`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupAddParams {
    /// The `wmp` envelope.
    pub wmp: Metadata,
    /// The participant being added.
    pub participant: String,
    /// The Commit message.
    pub commit: String,
    /// The Welcome message.
    pub welcome: String,
}

/// The result of [`METHOD_GROUP_ADD`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupAddResult {
    /// The `wmp` envelope.
    pub wmp: Metadata,
    /// The group's epoch after the add.
    pub epoch: i64,
}

/// The params of [`METHOD_GROUP_REMOVE`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupRemoveParams {
    /// The `wmp` envelope.
    pub wmp: Metadata,
    /// The participant being removed.
    pub participant: String,
    /// The Commit message.
    pub commit: String,
}

/// The result of [`METHOD_GROUP_REMOVE`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupRemoveResult {
    /// The `wmp` envelope.
    pub wmp: Metadata,
    /// The group's epoch after the removal.
    pub epoch: i64,
}

/// The params of [`METHOD_GROUP_UPDATE`] (a notification).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupUpdateParams {
    /// The `wmp` envelope.
    pub wmp: Metadata,
    /// The Commit message.
    pub commit: String,
}

/// The params of [`METHOD_MESSAGE_FETCH`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageFetchParams {
    /// The `wmp` envelope.
    pub wmp: Metadata,
    /// Fetch messages after this epoch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since_epoch: Option<i64>,
    /// The sessions to fetch from.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sessions: Vec<String>,
}

/// The result of [`METHOD_MESSAGE_FETCH`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageFetchResult {
    /// The `wmp` envelope.
    pub wmp: Metadata,
    /// The fetched messages.
    pub messages: Vec<Box<RawValue>>,
    /// Whether more messages remain.
    pub has_more: bool,
}

/// A published MLS KeyPackage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPackage {
    /// The KeyPackage's identifier.
    pub id: String,
    /// The cipher suite, by its number.
    pub cipher_suite: i64,
    /// The KeyPackage itself, base64url-encoded.
    pub key_package: String,
    /// When the KeyPackage expires, RFC 3339.
    pub expires: String,
}

/// The response from `/.well-known/mls-key-packages`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPackagesResponse {
    /// The published KeyPackages.
    pub key_packages: Vec<KeyPackage>,
}

/// An MLS-encrypted message carried in the standard JSON-RPC envelope: the
/// method stays in plaintext, the content is in the ciphertext.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    /// The `wmp` envelope.
    pub wmp: Metadata,
    /// The base64url-encoded MLSMessage.
    pub ciphertext: String,
}

/// Processes MLS group lifecycle operations. Implement this to manage MLS
/// groups; every method has a default that answers "MLS not supported", as
/// go-wmp's `BaseMLSHandler` does.
pub trait MlsHandler: Send + Sync {
    /// `wmp.mls.group.create`
    fn group_create(
        &self,
        _ctx: &RequestContext,
        _params: &GroupCreateParams,
    ) -> Result<GroupCreateResult, HandlerError> {
        Err(RpcError::new(
            ERR_CAPABILITY_NOT_SUPPORTED,
            Some(serde_json::json!({ "message": "MLS not supported" })),
        )
        .into())
    }

    /// `wmp.mls.group.join`
    fn group_join(
        &self,
        _ctx: &RequestContext,
        _params: &GroupJoinParams,
    ) -> Result<GroupJoinResult, HandlerError> {
        Err(RpcError::code(ERR_CAPABILITY_NOT_SUPPORTED).into())
    }

    /// `wmp.mls.group.add`
    fn group_add(
        &self,
        _ctx: &RequestContext,
        _params: &GroupAddParams,
    ) -> Result<GroupAddResult, HandlerError> {
        Err(RpcError::code(ERR_CAPABILITY_NOT_SUPPORTED).into())
    }

    /// `wmp.mls.group.remove`
    fn group_remove(
        &self,
        _ctx: &RequestContext,
        _params: &GroupRemoveParams,
    ) -> Result<GroupRemoveResult, HandlerError> {
        Err(RpcError::code(ERR_CAPABILITY_NOT_SUPPORTED).into())
    }

    /// `wmp.mls.group.update` (a notification).
    fn group_update(&self, _ctx: &RequestContext, _params: &GroupUpdateParams) {}

    /// `wmp.message.fetch`
    fn message_fetch(
        &self,
        _ctx: &RequestContext,
        _params: &MessageFetchParams,
    ) -> Result<MessageFetchResult, HandlerError> {
        Err(RpcError::code(ERR_CAPABILITY_NOT_SUPPORTED).into())
    }
}

/// Abstracts the MLS cryptographic engine: key packages, group creation and
/// welcomes, commits and proposals, message encryption and decryption.
pub trait MlsProvider: Send + Sync {
    /// Creates a new KeyPackage for the cipher suite.
    fn generate_key_package(&self, cipher_suite: i64) -> Result<KeyPackage, HandlerError>;

    /// Creates a new group, returning the GroupInfo and the base64url
    /// Welcomes keyed by participant.
    fn create_group(
        &self,
        cipher_suite: i64,
        participants: &[String],
    ) -> Result<(String, OrderedMap<String, String>), HandlerError>;

    /// Processes an incoming Welcome, joining the group.
    fn process_welcome(&self, welcome: &str) -> Result<(String, i64), HandlerError>;

    /// Generates a Commit and Welcome for adding a member.
    fn add_member(
        &self,
        group_id: &str,
        key_package: &str,
    ) -> Result<(String, String), HandlerError>;

    /// Generates a Commit for removing a member.
    fn remove_member(&self, group_id: &str, participant: &str) -> Result<String, HandlerError>;

    /// Processes an incoming Commit, advancing the epoch.
    fn process_commit(&self, group_id: &str, commit: &str) -> Result<i64, HandlerError>;

    /// Generates a Commit with a self-update proposal.
    fn self_update(&self, group_id: &str) -> Result<String, HandlerError>;

    /// Encrypts plaintext for the group, returning base64url ciphertext and
    /// the epoch.
    fn encrypt(&self, group_id: &str, plaintext: &[u8]) -> Result<(String, i64), HandlerError>;

    /// Decrypts base64url ciphertext from the group.
    fn decrypt(&self, group_id: &str, ciphertext: &str) -> Result<(Vec<u8>, i64), HandlerError>;
}

/// A [`Profile`] that dispatches the `wmp.mls.*` methods to an
/// [`MlsHandler`], registered with the peer to enable MLS support.
pub struct MlsProfile {
    handler: Arc<dyn MlsHandler>,
}

impl MlsProfile {
    /// A profile wrapping `handler`.
    pub fn new(handler: Arc<dyn MlsHandler>) -> Arc<Self> {
        Arc::new(Self { handler })
    }
}

impl Profile for MlsProfile {
    fn name(&self) -> String {
        "mls".to_owned()
    }

    fn capabilities(&self) -> Vec<String> {
        vec!["mls".to_owned()]
    }

    fn init(&self, _ctx: Arc<dyn crate::profile::PeerContext>) -> Result<(), HandlerError> {
        Ok(())
    }

    fn methods(&self) -> Vec<String> {
        METHODS.iter().map(|m| String::from(*m)).collect()
    }

    fn handle_method(
        &self,
        ctx: &RequestContext,
        method: &str,
        params: &serde_json::Value,
    ) -> DispatchResult {
        fn value(result: &impl Serialize) -> DispatchResult {
            Ok(Some(serde_json::to_value(result).map_err(|_| {
                HandlerError::Rpc(RpcError::code(ERR_INTERNAL_ERROR))
            })?))
        }
        match method {
            METHOD_GROUP_CREATE => {
                let ps: GroupCreateParams = serde_json::from_value(params.clone())
                    .map_err(|_| HandlerError::Rpc(RpcError::code(ERR_INVALID_PARAMS)))?;
                value(&self.handler.group_create(ctx, &ps)?)
            }
            METHOD_GROUP_JOIN => {
                let ps: GroupJoinParams = serde_json::from_value(params.clone())
                    .map_err(|_| HandlerError::Rpc(RpcError::code(ERR_INVALID_PARAMS)))?;
                value(&self.handler.group_join(ctx, &ps)?)
            }
            METHOD_GROUP_ADD => {
                let ps: GroupAddParams = serde_json::from_value(params.clone())
                    .map_err(|_| HandlerError::Rpc(RpcError::code(ERR_INVALID_PARAMS)))?;
                value(&self.handler.group_add(ctx, &ps)?)
            }
            METHOD_GROUP_REMOVE => {
                let ps: GroupRemoveParams = serde_json::from_value(params.clone())
                    .map_err(|_| HandlerError::Rpc(RpcError::code(ERR_INVALID_PARAMS)))?;
                value(&self.handler.group_remove(ctx, &ps)?)
            }
            METHOD_GROUP_UPDATE => {
                let ps: GroupUpdateParams = serde_json::from_value(params.clone())
                    .map_err(|_| HandlerError::Rpc(RpcError::code(ERR_INVALID_PARAMS)))?;
                self.handler.group_update(ctx, &ps);
                Ok(None)
            }
            METHOD_MESSAGE_FETCH => {
                let ps: MessageFetchParams = serde_json::from_value(params.clone())
                    .map_err(|_| HandlerError::Rpc(RpcError::code(ERR_INVALID_PARAMS)))?;
                value(&self.handler.message_fetch(ctx, &ps)?)
            }
            _ => Err(HandlerError::Rpc(RpcError::code(
                crate::error::ERR_METHOD_NOT_FOUND,
            ))),
        }
    }
}

/// The `wmp.mls.*` method names, for registration.
pub const METHODS: &[&str] = &[
    METHOD_GROUP_CREATE,
    METHOD_GROUP_JOIN,
    METHOD_GROUP_ADD,
    METHOD_GROUP_REMOVE,
    METHOD_GROUP_UPDATE,
    METHOD_MESSAGE_FETCH,
];

// --- The no-op implementations for TLS-only sessions ---

/// An [`MlsHandler`] for TLS-only sessions: it accepts group lifecycle
/// operations but performs no MLS cryptographic operations — messages pass
/// through unencrypted, relying on transport-level TLS.
pub struct NoopMlsHandler {
    groups: Mutex<FxHashMap<String, NoopGroup>>,
}

struct NoopGroup {
    epoch: i64,
    members: Vec<String>,
}

impl Default for NoopMlsHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl NoopMlsHandler {
    /// A handler suitable for TLS-only sessions.
    pub fn new() -> Self {
        Self {
            groups: Mutex::new(FxHashMap::default()),
        }
    }
}

impl MlsHandler for NoopMlsHandler {
    fn group_create(
        &self,
        _ctx: &RequestContext,
        params: &GroupCreateParams,
    ) -> Result<GroupCreateResult, HandlerError> {
        if params.group_id.is_empty() {
            return Err(RpcError::new(
                ERR_INVALID_PARAMS,
                Some(serde_json::json!({ "reason": "group_id is required" })),
            )
            .into());
        }
        let Ok(mut groups) = self.groups.lock() else {
            return Err(HandlerError::Rpc(RpcError::code(ERR_INTERNAL_ERROR)));
        };
        if groups.contains_key(&params.group_id) {
            return Err(RpcError::new(
                ERR_MLS_ERROR,
                Some(serde_json::json!({ "reason": "group already exists" })),
            )
            .into());
        }
        let mut members: Vec<String> = params.welcomes.keys().cloned().collect();
        // Include the creator.
        if !params.wmp.sender.is_empty() {
            members.push(params.wmp.sender.clone());
        }
        groups.insert(params.group_id.clone(), NoopGroup { epoch: 0, members });
        Ok(GroupCreateResult {
            wmp: params.wmp.clone(),
            group_id: params.group_id.clone(),
            epoch: 0,
        })
    }

    fn group_join(
        &self,
        _ctx: &RequestContext,
        params: &GroupJoinParams,
    ) -> Result<GroupJoinResult, HandlerError> {
        // In noop mode, the join is accepted without checking a Welcome.
        Ok(GroupJoinResult {
            wmp: params.wmp.clone(),
            group_id: String::new(),
            epoch: 0,
        })
    }

    fn group_add(
        &self,
        _ctx: &RequestContext,
        params: &GroupAddParams,
    ) -> Result<GroupAddResult, HandlerError> {
        let Ok(mut groups) = self.groups.lock() else {
            return Err(HandlerError::Rpc(RpcError::code(ERR_INTERNAL_ERROR)));
        };
        let Some((_, group)) = groups.iter_mut().next() else {
            return Err(RpcError::new(
                ERR_MLS_ERROR,
                Some(serde_json::json!({ "reason": "no group found" })),
            )
            .into());
        };
        if !params.participant.is_empty() {
            group.members.push(params.participant.clone());
        }
        group.epoch += 1;
        Ok(GroupAddResult {
            wmp: params.wmp.clone(),
            epoch: group.epoch,
        })
    }

    fn group_remove(
        &self,
        _ctx: &RequestContext,
        params: &GroupRemoveParams,
    ) -> Result<GroupRemoveResult, HandlerError> {
        let Ok(mut groups) = self.groups.lock() else {
            return Err(HandlerError::Rpc(RpcError::code(ERR_INTERNAL_ERROR)));
        };
        let Some((_, group)) = groups.iter_mut().next() else {
            return Err(RpcError::new(
                ERR_MLS_ERROR,
                Some(serde_json::json!({ "reason": "no group found" })),
            )
            .into());
        };
        group.members.retain(|member| *member != params.participant);
        group.epoch += 1;
        Ok(GroupRemoveResult {
            wmp: params.wmp.clone(),
            epoch: group.epoch,
        })
    }

    fn message_fetch(
        &self,
        _ctx: &RequestContext,
        params: &MessageFetchParams,
    ) -> Result<MessageFetchResult, HandlerError> {
        Ok(MessageFetchResult {
            wmp: params.wmp.clone(),
            messages: Vec::new(),
            has_more: false,
        })
    }
}

/// An [`MlsProvider`] for TLS-only sessions: it performs no actual MLS
/// cryptographic operations — messages pass through unencrypted, relying on
/// transport-level TLS for confidentiality.
///
/// Because this provider intentionally disables end-to-end encryption, it
/// must be enabled explicitly with [`NoopMlsProvider::allow_insecure`].
/// Code that accidentally creates one without the opt-in gets errors from
/// encrypt and decrypt rather than silently leaking plaintext.
pub struct NoopMlsProvider {
    epochs: Mutex<FxHashMap<String, i64>>,
    allow_insecure: bool,
}

impl Default for NoopMlsProvider {
    fn default() -> Self {
        Self::new(false)
    }
}

impl NoopMlsProvider {
    /// A no-op provider. With `allow_insecure` false (the default), encrypt
    /// and decrypt answer errors; enable passthrough only when the transport
    /// channel already provides confidentiality and integrity, such as
    /// mutually authenticated TLS.
    pub fn new(allow_insecure: bool) -> Self {
        Self {
            epochs: Mutex::new(FxHashMap::default()),
            allow_insecure,
        }
    }

    /// Explicitly enables the plaintext passthrough mode.
    pub fn allow_insecure(self, allow: bool) -> Self {
        Self {
            allow_insecure: allow,
            ..self
        }
    }

    fn bump(&self, group_id: &str) -> i64 {
        let Ok(mut epochs) = self.epochs.lock() else {
            return 0;
        };
        let epoch = epochs.entry(group_id.to_owned()).or_insert(0);
        *epoch += 1;
        *epoch
    }
}

impl MlsProvider for NoopMlsProvider {
    fn generate_key_package(&self, cipher_suite: i64) -> Result<KeyPackage, HandlerError> {
        Ok(KeyPackage {
            id: "noop-kp-1".to_owned(),
            cipher_suite,
            key_package: String::new(),
            expires: "2099-12-31T23:59:59Z".to_owned(),
        })
    }

    fn create_group(
        &self,
        _cipher_suite: i64,
        participants: &[String],
    ) -> Result<(String, OrderedMap<String, String>), HandlerError> {
        // Empty group info and empty welcomes, as in go-wmp.
        let welcomes: OrderedMap<String, String> = participants
            .iter()
            .map(|p| (p.clone(), String::new()))
            .collect();
        Ok((String::new(), welcomes))
    }

    fn process_welcome(&self, _welcome: &str) -> Result<(String, i64), HandlerError> {
        Ok(("noop-group".to_owned(), 0))
    }

    fn add_member(
        &self,
        group_id: &str,
        _key_package: &str,
    ) -> Result<(String, String), HandlerError> {
        let _ = self.bump(group_id);
        Ok((String::new(), String::new()))
    }

    fn remove_member(&self, group_id: &str, _participant: &str) -> Result<String, HandlerError> {
        let _ = self.bump(group_id);
        Ok(String::new())
    }

    fn process_commit(&self, group_id: &str, _commit: &str) -> Result<i64, HandlerError> {
        Ok(self.bump(group_id))
    }

    fn self_update(&self, group_id: &str) -> Result<String, HandlerError> {
        let _ = self.bump(group_id);
        Ok(String::new())
    }

    fn encrypt(&self, _group_id: &str, plaintext: &[u8]) -> Result<(String, i64), HandlerError> {
        if !self.allow_insecure {
            return Err(RpcError::new(
                ERR_MLS_ERROR,
                Some(serde_json::json!({
                    "reason": "NoopMLSProvider plaintext mode is not enabled; use allow_insecure(true) only when transport security is sufficient",
                })),
            )
            .into());
        }
        // Passthrough: the plaintext is returned as-is (base64url is the
        // caller's concern).
        let _ = plaintext;
        Ok((String::new(), 0))
    }

    fn decrypt(&self, _group_id: &str, ciphertext: &str) -> Result<(Vec<u8>, i64), HandlerError> {
        if !self.allow_insecure {
            return Err(RpcError::new(
                ERR_MLS_ERROR,
                Some(serde_json::json!({
                    "reason": "NoopMLSProvider plaintext mode is not enabled; use allow_insecure(true) only when transport security is sufficient",
                })),
            )
            .into());
        }
        Ok((ciphertext.as_bytes().to_vec(), 0))
    }
}
