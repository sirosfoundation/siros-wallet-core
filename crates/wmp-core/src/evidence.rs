//! Evidence event types — the ETSI EN 319 522 (QERDS) alignment of the
//! WMP evidence specification.

use serde::{Deserialize, Serialize};

// --- Event types ---

/// The evidence was submitted.
pub const EVIDENCE_SUBMITTED: &str = "submitted";
/// The submission was accepted.
pub const EVIDENCE_SUBMISSION_ACCEPTED: &str = "submission_accepted";
/// The submission was rejected.
pub const EVIDENCE_SUBMISSION_REJECTED: &str = "submission_rejected";
/// A relay accepted the message.
pub const EVIDENCE_RELAY_ACCEPTED: &str = "relay_accepted";
/// A relay failed.
pub const EVIDENCE_RELAY_FAILED: &str = "relay_failed";
/// The message was delivered.
pub const EVIDENCE_DELIVERED: &str = "delivered";
/// Delivery failed.
pub const EVIDENCE_DELIVERY_FAILED: &str = "delivery_failed";
/// The evidence was retrieved.
pub const EVIDENCE_RETRIEVED: &str = "retrieved";
/// Retrieval failed.
pub const EVIDENCE_RETRIEVAL_FAILED: &str = "retrieval_failed";
/// Content access was tracked.
pub const EVIDENCE_CONTENT_ACCESS_TRACKED: &str = "content_access_tracked";
/// The evidence was accepted.
pub const EVIDENCE_ACCEPTED: &str = "accepted";
/// The evidence was rejected.
pub const EVIDENCE_REJECTED: &str = "rejected";
/// The acceptance expired.
pub const EVIDENCE_ACCEPTANCE_EXPIRED: &str = "acceptance_expired";
/// Content handover happened.
pub const EVIDENCE_CONTENT_HANDOVER: &str = "content_handover";
/// Content handover failed.
pub const EVIDENCE_CONTENT_HANDOVER_FAILED: &str = "content_handover_failed";
/// A notification was sent.
pub const EVIDENCE_NOTIFICATION_SENT: &str = "notification_sent";
/// A notification failed.
pub const EVIDENCE_NOTIFICATION_FAILED: &str = "notification_failed";
/// A notification was delivered.
pub const EVIDENCE_NOTIFICATION_DELIVERED: &str = "notification_delivered";
/// The message was relayed to an external system.
pub const EVIDENCE_RELAY_TO_EXTERNAL: &str = "relay_to_external";
/// Relaying to an external system failed.
pub const EVIDENCE_RELAY_TO_EXTERNAL_FAILED: &str = "relay_to_external_failed";
/// The message was received from an external system.
pub const EVIDENCE_RECEIVED_FROM_EXTERNAL: &str = "received_from_external";

// --- Reason codes ---

/// A policy was violated.
pub const EVENT_REASON_POLICY_VIOLATION: &str = "policy_violation";
/// A quota was exceeded.
pub const EVENT_REASON_QUOTA_EXCEEDED: &str = "quota_exceeded";
/// The format was invalid.
pub const EVENT_REASON_INVALID_FORMAT: &str = "invalid_format";
/// The recipient was invalid.
pub const EVENT_REASON_INVALID_RECIPIENT: &str = "invalid_recipient";
/// The assurance level was insufficient.
pub const EVENT_REASON_INSUFFICIENT_ASSURANCE: &str = "insufficient_assurance";
/// The consignment mode is unsupported.
pub const EVENT_REASON_CONSIGNMENT_MODE_UNSUPPORTED: &str = "consignment_mode_unsupported";
/// The policy is unsupported.
pub const EVENT_REASON_POLICY_UNSUPPORTED: &str = "policy_unsupported";
/// The recipient rejected the message.
pub const EVENT_REASON_RECIPIENT_REJECTED: &str = "recipient_rejected";
/// A timeout.
pub const EVENT_REASON_TIMEOUT: &str = "timeout";
/// A system error.
pub const EVENT_REASON_SYSTEM_ERROR: &str = "system_error";
/// A delegation was invalid.
pub const EVENT_REASON_DELEGATION_INVALID: &str = "delegation_invalid";

// --- Consignment modes ---

/// Basic consignment.
pub const CONSIGNMENT_BASIC: &str = "basic";
/// Consented consignment.
pub const CONSIGNMENT_CONSENTED: &str = "consented";
/// Consented, signed consignment.
pub const CONSIGNMENT_CONSENTED_SIGNED: &str = "consented_signed";

// --- Assurance levels ---

/// Low assurance.
pub const ASSURANCE_LOW: &str = "low";
/// Substantial assurance.
pub const ASSURANCE_SUBSTANTIAL: &str = "substantial";
/// High assurance.
pub const ASSURANCE_HIGH: &str = "high";

/// Why an evidence event occurred.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EvidenceEventReason {
    /// The reason's code.
    pub code: String,
    /// The reason's human-readable text.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub text: String,
    /// Structured details.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

/// The entity that issued the evidence.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EvidenceIssuer {
    /// The issuer's identifier.
    pub id: String,
    /// The issuer's name.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    /// The issuer's country.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub country: String,
}

/// An external system referenced by evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalSystem {
    /// The system's type.
    pub r#type: String,
    /// The system's identifier.
    pub id: String,
}

/// An external ERDS referenced by evidence.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExternalErds {
    /// The ERDS's identifier.
    pub id: String,
    /// The ERDS's name.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    /// The ERDS's policy.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub policy: String,
}

/// A delegate's identity in evidence records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegateIdentity {
    /// The delegate's identifier.
    pub id: String,
    /// The delegate's identity attributes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_attributes: Option<serde_json::Value>,
}

/// The params of `wmp.evidence.notify`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EvidenceNotifyParams {
    /// The `wmp` envelope.
    pub wmp: crate::types::Metadata,
    /// The evidence's identifier.
    pub evidence_id: String,
    /// The event's type.
    pub event_type: String,
    /// The evidence's version.
    pub evidence_version: String,
    /// When the event happened, RFC 3339.
    pub timestamp: String,
    /// The message the evidence is about.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub message_id: String,
    /// The session the evidence belongs to.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub session_id: String,
    /// The sender.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sender: String,
    /// The recipient.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub recipient: String,
    /// Why the event occurred.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_reason: Option<EvidenceEventReason>,
    /// The original sender's delegate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_sender_delegate: Option<DelegateIdentity>,
    /// The original recipient's delegate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_recipient_delegate: Option<DelegateIdentity>,
    /// When the evidence was submitted, RFC 3339.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub submission_time: String,
    /// The evidence issuer's policies.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_issuer_policy: Vec<String>,
    /// The evidence issuer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_issuer: Option<EvidenceIssuer>,
    /// The sender's assurance level.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sender_assurance_level: String,
    /// The recipient's assurance level.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub recipient_assurance_level: String,
    /// The sender's identity attributes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_identity_attributes: Option<serde_json::Value>,
    /// The recipient's identity attributes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_identity_attributes: Option<serde_json::Value>,
    /// The recipient the evidence refers to.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub evidence_refers_to_recipient: String,
    /// An external system.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_system: Option<ExternalSystem>,
    /// An external ERDS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_erds: Option<ExternalErds>,
    /// The transaction log.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub transaction_log: String,
    /// Extensions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}
