//! The WMP method names and the parameter and result types of every
//! method.

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::types::{null_default, Capabilities, Metadata, SecurityMode};

// --- Method names ---

/// `wmp.session.create`
pub const METHOD_SESSION_CREATE: &str = "wmp.session.create";
/// `wmp.session.resume`
pub const METHOD_SESSION_RESUME: &str = "wmp.session.resume";
/// `wmp.session.close`
pub const METHOD_SESSION_CLOSE: &str = "wmp.session.close";
/// `wmp.session.authenticate`
pub const METHOD_SESSION_AUTHENTICATE: &str = "wmp.session.authenticate";
/// `wmp.message.deliver`
pub const METHOD_MESSAGE_DELIVER: &str = "wmp.message.deliver";
/// `wmp.message.ack`
pub const METHOD_MESSAGE_ACK: &str = "wmp.message.ack";
/// `wmp.message.poll`
pub const METHOD_MESSAGE_POLL: &str = "wmp.message.poll";
/// `wmp.message.status`
pub const METHOD_MESSAGE_STATUS: &str = "wmp.message.status";
/// `wmp.capability.update`
pub const METHOD_CAPABILITY_UPDATE: &str = "wmp.capability.update";
/// `wmp.capability.list`
pub const METHOD_CAPABILITY_LIST: &str = "wmp.capability.list";
/// `wmp.flow.start`
pub const METHOD_FLOW_START: &str = "wmp.flow.start";
/// `wmp.flow.progress`
pub const METHOD_FLOW_PROGRESS: &str = "wmp.flow.progress";
/// `wmp.flow.action`
pub const METHOD_FLOW_ACTION: &str = "wmp.flow.action";
/// `wmp.flow.complete`
pub const METHOD_FLOW_COMPLETE: &str = "wmp.flow.complete";
/// `wmp.flow.error`
pub const METHOD_FLOW_ERROR: &str = "wmp.flow.error";
/// `wmp.flow.cancel`
pub const METHOD_FLOW_CANCEL: &str = "wmp.flow.cancel";
/// `wmp.credential.notification` — not defined by the WMP specification; it
/// has no result and cannot ask the client for the DPoP proof an issuer may
/// require. The credential_notification flow (OpenID4x profile §3.4)
/// replaces it. The method keeps working.
pub const METHOD_CREDENTIAL_NOTIFICATION: &str = "wmp.credential.notification";
/// `wmp.resolve`
pub const METHOD_RESOLVE: &str = "wmp.resolve";
/// `wmp.relay.register`
pub const METHOD_RELAY_REGISTER: &str = "wmp.relay.register";

// --- Session ---

/// The params of [`METHOD_SESSION_CREATE`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionCreateParams {
    /// The `wmp` envelope.
    pub wmp: Metadata,
    /// The session participants.
    #[serde(
        default,
        deserialize_with = "null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub participants: Vec<String>,
    /// The capabilities the caller offers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities_offered: Option<Capabilities>,
    /// The session security configuration.
    #[serde(default, deserialize_with = "null_default")]
    pub security: SecurityMode,
    /// The session's time to live, in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<i64>,
    /// Authentication material for the session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<AuthObject>,
    /// The nonce of the invitation this create answers, if any.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub invitation_nonce: String,
}

/// The result of [`METHOD_SESSION_CREATE`]. `capabilities` is always present
/// on the wire — `{}` when nothing was negotiated — because
/// `session-create-response.json` requires the member and an omit-empty
/// would drop an empty map.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionCreateResult {
    /// The `wmp` envelope.
    pub wmp: Metadata,
    /// The negotiated capabilities; always emitted.
    pub capabilities: Capabilities,
    /// The session security configuration.
    pub security: SecurityMode,
    /// The challenge for identity-assertion replay protection.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub challenge: String,
    /// The single-use resumption token.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub resumption_token: String,
}

/// The params of [`METHOD_SESSION_RESUME`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionResumeParams {
    /// The `wmp` envelope.
    pub wmp: Metadata,
    /// The session to resume.
    #[serde(default, deserialize_with = "null_default")]
    pub session_id: String,
    /// The session's current resumption token.
    #[serde(default, deserialize_with = "null_default")]
    pub resumption_token: String,
    /// The last message identifier the caller received.
    #[serde(
        default,
        deserialize_with = "null_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub last_received_id: String,
}

/// The result of [`METHOD_SESSION_RESUME`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionResumeResult {
    /// The `wmp` envelope.
    pub wmp: Metadata,
    /// Whether the session was resumed.
    pub resumed: bool,
    /// The rotated resumption token.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub resumption_token: String,
    /// How many messages the caller missed while away.
    pub missed_messages: i64,
    /// The negotiated capabilities.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Capabilities>,
    /// The session security configuration.
    pub security: SecurityMode,
}

/// The params of [`METHOD_SESSION_CLOSE`] (a notification).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionCloseParams {
    /// The `wmp` envelope.
    pub wmp: Metadata,
    /// Why the session is closing.
    #[serde(default, deserialize_with = "null_default")]
    pub reason: String,
}

/// Close reason: the flow completed.
pub const REASON_COMPLETE: &str = "complete";
/// Close reason: the session timed out.
pub const REASON_TIMEOUT: &str = "timeout";
/// Close reason: an error ended the session.
pub const REASON_ERROR: &str = "error";
/// Close reason: the user cancelled.
pub const REASON_USER_CANCELLED: &str = "user_cancelled";

// --- Message ---

/// The params of [`METHOD_MESSAGE_DELIVER`] (a notification).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageDeliverParams {
    /// The `wmp` envelope.
    pub wmp: Metadata,
    /// The recipients.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub to: Vec<String>,
    /// The content type of the body.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub content_type: String,
    /// The message body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<Box<RawValue>>,
    /// The encrypted body, when the capability requires encryption.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ciphertext: String,
    /// ERDS delivery metadata: where replies go.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reply_to: String,
    /// ERDS delivery metadata: the message this replies to.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub in_reply_to: String,
    /// ERDS delivery metadata: the message type.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub message_type: String,
    /// ERDS delivery metadata: the consignment mode.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub consignment_mode: String,
    /// ERDS delivery metadata: the recipient's assurance level.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub recipient_assurance_level: String,
    /// ERDS delivery metadata: the applicable policies.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applicable_policies: Vec<String>,
}

/// The params of [`METHOD_MESSAGE_ACK`] (a notification).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageAckParams {
    /// The `wmp` envelope.
    pub wmp: Metadata,
    /// The acknowledged message identifiers.
    pub message_ids: Vec<String>,
    /// The acknowledgement status.
    pub status: String,
}

/// Ack status: the message was received.
pub const ACK_RECEIVED: &str = "received";
/// Ack status: the message was read.
pub const ACK_READ: &str = "read";
/// Ack status: the message was processed.
pub const ACK_PROCESSED: &str = "processed";
/// Ack status: processing failed.
pub const ACK_FAILED: &str = "failed";

/// The params of [`METHOD_MESSAGE_POLL`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagePollParams {
    /// The `wmp` envelope.
    pub wmp: Metadata,
    /// Poll messages after this identifier.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub since: String,
    /// The maximum number of messages to return.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<i64>,
}

/// The result of [`METHOD_MESSAGE_POLL`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagePollResult {
    /// The `wmp` envelope.
    pub wmp: Metadata,
    /// The messages, in order.
    pub messages: Vec<Box<RawValue>>,
}

// --- Capability ---

/// The params of [`METHOD_CAPABILITY_UPDATE`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityUpdateParams {
    /// The `wmp` envelope.
    pub wmp: Metadata,
    /// The capabilities to add.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub add: Option<Capabilities>,
    /// The capability names to remove.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remove: Vec<String>,
    /// The new security configuration, when it changes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<SecurityMode>,
}

/// The result of [`METHOD_CAPABILITY_UPDATE`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityUpdateResult {
    /// The `wmp` envelope.
    pub wmp: Metadata,
    /// The capabilities after the update.
    pub capabilities: Capabilities,
    /// The security configuration after the update.
    pub security: SecurityMode,
}

/// The params of [`METHOD_CAPABILITY_LIST`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityListParams {
    /// The `wmp` envelope.
    pub wmp: Metadata,
}

/// The result of [`METHOD_CAPABILITY_LIST`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityListResult {
    /// The `wmp` envelope.
    pub wmp: Metadata,
    /// The negotiated capabilities.
    pub capabilities: Capabilities,
    /// The session security configuration.
    pub security: SecurityMode,
}

// --- Flow ---

/// The params of [`METHOD_FLOW_START`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowStartParams {
    /// The `wmp` envelope.
    pub wmp: Metadata,
    /// The flow type.
    #[serde(default, deserialize_with = "null_default")]
    pub flow_type: String,
    /// The caller's identifier for the flow.
    #[serde(default, deserialize_with = "null_default")]
    pub flow_id: String,
    /// The flow-type-specific parameters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Box<RawValue>>,
    /// The flow's timeout, in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<i64>,
}

/// The result of [`METHOD_FLOW_START`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowStartResult {
    /// The `wmp` envelope.
    pub wmp: Metadata,
    /// The flow identifier.
    pub flow_id: String,
    /// The flow type.
    pub flow_type: String,
}

/// The params of [`METHOD_FLOW_PROGRESS`] (a notification).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FlowProgressParams {
    /// The `wmp` envelope.
    pub wmp: Metadata,
    /// The flow.
    pub flow_id: String,
    /// The step the flow reached.
    pub step: String,
    /// Step payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Box<RawValue>>,
}

/// The params of [`METHOD_FLOW_ACTION`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowActionParams {
    /// The `wmp` envelope.
    pub wmp: Metadata,
    /// The flow.
    #[serde(default, deserialize_with = "null_default")]
    pub flow_id: String,
    /// The action the caller takes.
    #[serde(default, deserialize_with = "null_default")]
    pub action: String,
    /// The action's parameters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Box<RawValue>>,
}

/// The result of [`METHOD_FLOW_ACTION`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowActionResult {
    /// The `wmp` envelope.
    pub wmp: Metadata,
    /// The flow.
    pub flow_id: String,
    /// The action.
    pub action: String,
    /// The flow's status after the action.
    pub status: String,
}

/// The params of [`METHOD_FLOW_COMPLETE`] (a notification).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FlowCompleteParams {
    /// The `wmp` envelope.
    pub wmp: Metadata,
    /// The flow.
    pub flow_id: String,
    /// The flow's result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Box<RawValue>>,
}

/// The params of [`METHOD_FLOW_ERROR`] (a notification).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FlowErrorParams {
    /// The `wmp` envelope.
    pub wmp: Metadata,
    /// The flow.
    pub flow_id: String,
    /// The error code.
    pub code: i64,
    /// The error message.
    pub message: String,
    /// Structured error data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Box<RawValue>>,
}

/// Built-in flow type: an approval flow.
pub const FLOW_TYPE_APPROVAL: &str = "approval";
/// Built-in flow type: a signing flow.
pub const FLOW_TYPE_SIGN: &str = "sign";
/// Built-in flow type: a message flow.
pub const FLOW_TYPE_MESSAGE: &str = "message";

// --- Credential notification ---

/// OID4VCI §10 lifecycle event: the credential was accepted.
pub const CREDENTIAL_EVENT_ACCEPTED: &str = "credential_accepted";
/// OID4VCI §10 lifecycle event: issuance failed.
pub const CREDENTIAL_EVENT_FAILURE: &str = "credential_failure";

/// The params of [`METHOD_CREDENTIAL_NOTIFICATION`]: an OID4VCI §10
/// credential lifecycle event carried from the client to the server, which
/// forwards it to the issuer's notification endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialNotificationParams {
    /// The `wmp` envelope.
    pub wmp: Metadata,
    /// The flow the notification belongs to.
    pub flow_id: String,
    /// The notification's identifier.
    pub notification_id: String,
    /// The lifecycle event.
    pub event: String,
    /// A human-readable description of the event.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub event_description: String,
}

/// The error for a [`CredentialNotificationParams`] that is missing a
/// required identifier or carries an unknown lifecycle event.
pub fn validate_credential_notification(
    params: &CredentialNotificationParams,
) -> Result<(), crate::error::RpcError> {
    use crate::error::{RpcError, ERR_INVALID_PARAMS};
    if params.flow_id.is_empty() {
        return Err(RpcError::new(
            ERR_INVALID_PARAMS,
            Some(serde_json::json!({ "reason": "flow_id is required" })),
        ));
    }
    if params.notification_id.is_empty() {
        return Err(RpcError::new(
            ERR_INVALID_PARAMS,
            Some(serde_json::json!({ "reason": "notification_id is required" })),
        ));
    }
    if !is_valid_credential_event(&params.event) {
        return Err(RpcError::new(
            ERR_INVALID_PARAMS,
            Some(serde_json::json!({
                "reason": format!("unsupported credential event: {}", params.event),
            })),
        ));
    }
    Ok(())
}

/// Whether `event` is a known OID4VCI credential lifecycle event.
pub fn is_valid_credential_event(event: &str) -> bool {
    matches!(event, CREDENTIAL_EVENT_ACCEPTED | CREDENTIAL_EVENT_FAILURE)
}

// --- Resolve ---

/// The params of [`METHOD_RESOLVE`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveParams {
    /// The `wmp` envelope.
    pub wmp: Metadata,
    /// What `uri` resolves.
    pub r#type: String,
    /// What to resolve.
    pub uri: String,
    /// Resolve options.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<Box<RawValue>>,
}

/// The result of [`METHOD_RESOLVE`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveResult {
    /// The `wmp` envelope.
    pub wmp: Metadata,
    /// What was resolved.
    pub r#type: String,
    /// What was resolved.
    pub uri: String,
    /// The resolved metadata.
    pub metadata: Box<RawValue>,
    /// Trust information for the resolved document.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_info: Option<Box<RawValue>>,
}

/// Resolve type: a verifiable credential type metadata document.
pub const RESOLVE_TYPE_VCTM: &str = "vctm";
/// Resolve type: an issuer's metadata.
pub const RESOLVE_TYPE_ISSUER_METADATA: &str = "issuer_metadata";
/// Resolve type: trust information.
pub const RESOLVE_TYPE_TRUST: &str = "trust";
/// Resolve type: an endpoint.
pub const RESOLVE_TYPE_ENDPOINT: &str = "endpoint";
/// Resolve type: an OpenID Federation entity.
pub const RESOLVE_TYPE_OPENID_FEDERATION: &str = "openid_federation";

// --- Flow cancel ---

/// The params of [`METHOD_FLOW_CANCEL`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowCancelParams {
    /// The `wmp` envelope.
    pub wmp: Metadata,
    /// The flow.
    pub flow_id: String,
    /// Why the flow is cancelled.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
}

/// The result of [`METHOD_FLOW_CANCEL`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowCancelResult {
    /// The `wmp` envelope.
    pub wmp: Metadata,
    /// The flow.
    pub flow_id: String,
    /// The flow's status after the cancellation.
    pub status: String,
}

/// Cancel reason: the user cancelled.
pub const CANCEL_REASON_USER_CANCELLED: &str = "user_cancelled";
/// Cancel reason: a newer flow superseded this one.
pub const CANCEL_REASON_SUPERSEDED: &str = "superseded";
/// Cancel reason: the flow is no longer needed.
pub const CANCEL_REASON_NO_LONGER_NEEDED: &str = "no_longer_needed";

// --- Message status ---

/// The params of [`METHOD_MESSAGE_STATUS`] (a notification).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageStatusParams {
    /// The `wmp` envelope.
    pub wmp: Metadata,
    /// The message.
    pub message_id: String,
    /// The message's status.
    pub status: String,
    /// Why the status changed.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
}

/// Message status: queued for delivery.
pub const MESSAGE_STATUS_QUEUED: &str = "queued";
/// Message status: delivered.
pub const MESSAGE_STATUS_DELIVERED: &str = "delivered";
/// Message status: expired before delivery.
pub const MESSAGE_STATUS_EXPIRED: &str = "expired";
/// Message status: dropped.
pub const MESSAGE_STATUS_DROPPED: &str = "dropped";

// --- Session authentication ---

/// The `auth` object of [`METHOD_SESSION_CREATE`] and
/// [`METHOD_SESSION_AUTHENTICATE`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthObject {
    /// The authentication type.
    pub r#type: String,
    /// The bearer token, for bearer authentication.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub token: String,
    /// The proof of possession.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub proof: String,
    /// The challenge to sign.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub challenge: String,
    /// The signature over the challenge.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature: String,
    /// The certificate chain.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub x5c: Vec<String>,
    /// DID authentication material.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did_auth: Option<Box<RawValue>>,
}

/// The params of [`METHOD_SESSION_AUTHENTICATE`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionAuthenticateParams {
    /// The `wmp` envelope.
    pub wmp: Metadata,
    /// The authentication material.
    pub auth: AuthObject,
}

/// The result of [`METHOD_SESSION_AUTHENTICATE`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionAuthenticateResult {
    /// The `wmp` envelope.
    pub wmp: Metadata,
    /// Whether the caller authenticated.
    pub authenticated: bool,
    /// The authenticated identity.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub identity: String,
}

/// Authentication type: bearer token.
pub const AUTH_TYPE_BEARER: &str = "bearer";
/// Authentication type: DPoP.
pub const AUTH_TYPE_DPOP: &str = "dpop";
/// Authentication type: mutual TLS.
pub const AUTH_TYPE_MTLS: &str = "mtls";
/// Authentication type: a signed challenge.
pub const AUTH_TYPE_SIGNED_CHALLENGE: &str = "signed_challenge";
/// Authentication type: an X.509 chain.
pub const AUTH_TYPE_X5C: &str = "x5c";
/// Authentication type: DID authentication. Deprecated; use
/// [`AUTH_TYPE_SIGNED_CHALLENGE`].
pub const AUTH_TYPE_DID_AUTH: &str = "did_auth";

// --- Relay registration ---

/// The params of [`METHOD_RELAY_REGISTER`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayRegisterParams {
    /// The `wmp` envelope.
    pub wmp: Metadata,
    /// Authentication material for the relay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<AuthObject>,
}

/// The result of [`METHOD_RELAY_REGISTER`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayRegisterResult {
    /// The `wmp` envelope.
    pub wmp: Metadata,
    /// Whether the relay registered the caller.
    pub registered: bool,
    /// The registration's time to live, in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<i64>,
}

/// Relay service class: best effort.
pub const SERVICE_CLASS_BEST_EFFORT: &str = "best_effort";
/// Relay service class: standard.
pub const SERVICE_CLASS_STANDARD: &str = "standard";
/// Relay service class: registered delivery.
pub const SERVICE_CLASS_REGISTERED: &str = "registered";
/// Relay service class: certified.
pub const SERVICE_CLASS_CERTIFIED: &str = "certified";
