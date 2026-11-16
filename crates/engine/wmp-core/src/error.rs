//! WMP and JSON-RPC error codes, their standard messages, and the
//! [`RpcError`] wire type.

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

/// The session does not exist (or is unknown to this peer).
pub const ERR_SESSION_NOT_FOUND: i32 = -31000;
/// The session exists but its TTL has passed.
pub const ERR_SESSION_EXPIRED: i32 = -31001;
/// The caller is not authorized for the request.
pub const ERR_NOT_AUTHORIZED: i32 = -31002;
/// The capability requires encryption and the message is plaintext.
pub const ERR_ENCRYPTION_REQUIRED: i32 = -31003;
/// The MLS layer refused the operation.
pub const ERR_MLS_ERROR: i32 = -31004;
/// The capability is not negotiated on the session.
pub const ERR_CAPABILITY_NOT_SUPPORTED: i32 = -31005;
/// A flow reported an error.
pub const ERR_FLOW_ERROR: i32 = -31006;
/// The peer is rate-limiting the caller.
pub const ERR_RATE_LIMITED: i32 = -31007;
/// A participant named by the request is not in the session.
pub const ERR_PARTICIPANT_NOT_FOUND: i32 = -31008;
/// The request must carry evidence.
pub const ERR_EVIDENCE_REQUIRED: i32 = -31009;
/// A signature is missing or does not verify.
pub const ERR_SIGNATURE_INVALID: i32 = -31010;
/// A timestamp is missing, malformed or outside its window.
pub const ERR_TIMESTAMP_INVALID: i32 = -31011;
/// An identity assertion is missing or does not verify.
pub const ERR_IDENTITY_ASSERTION_INVALID: i32 = -31012;
/// No supported version matches the offered one.
pub const ERR_VERSION_NOT_SUPPORTED: i32 = -31013;
/// The receiver's queue is full.
pub const ERR_QUEUE_FULL: i32 = -31014;
/// A delegation is missing or invalid.
pub const ERR_DELEGATION_INVALID: i32 = -31015;
/// The consignment mode is not supported.
pub const ERR_CONSIGNMENT_MODE_UNSUPPORTED: i32 = -31016;
/// The assurance level is not supported.
pub const ERR_ASSURANCE_LEVEL_UNSUPPORTED: i32 = -31017;
/// The policy is not supported.
pub const ERR_POLICY_UNSUPPORTED: i32 = -31018;
/// The plaintext hash does not match the encrypted message.
pub const ERR_PLAINTEXT_HASH_MISMATCH: i32 = -31019;
/// The issuer is not entitled to the operation.
pub const ERR_ISSUER_NOT_ENTITLED: i32 = -31020;

/// JSON-RPC 2.0: the message is not valid JSON.
pub const ERR_PARSE_ERROR: i32 = -32700;
/// JSON-RPC 2.0: the message is not a valid request object.
pub const ERR_INVALID_REQUEST: i32 = -32600;
/// JSON-RPC 2.0: the method does not exist.
pub const ERR_METHOD_NOT_FOUND: i32 = -32601;
/// JSON-RPC 2.0: the params are invalid for the method.
pub const ERR_INVALID_PARAMS: i32 = -32602;
/// JSON-RPC 2.0: an internal error occurred.
pub const ERR_INTERNAL_ERROR: i32 = -32603;

/// The standard message for a WMP or JSON-RPC error code, or `"Unknown
/// error"` for any other code — mirroring `wmp.ErrorMessage` in go-wmp.
pub fn error_message(code: i32) -> &'static str {
    match code {
        ERR_SESSION_NOT_FOUND => "Session not found",
        ERR_SESSION_EXPIRED => "Session expired",
        ERR_NOT_AUTHORIZED => "Not authorized",
        ERR_ENCRYPTION_REQUIRED => "Encryption required",
        ERR_MLS_ERROR => "MLS error",
        ERR_CAPABILITY_NOT_SUPPORTED => "Capability not supported",
        ERR_FLOW_ERROR => "Flow error",
        ERR_RATE_LIMITED => "Rate limited",
        ERR_PARTICIPANT_NOT_FOUND => "Participant not found",
        ERR_EVIDENCE_REQUIRED => "Evidence required",
        ERR_SIGNATURE_INVALID => "Signature invalid",
        ERR_TIMESTAMP_INVALID => "Timestamp invalid",
        ERR_IDENTITY_ASSERTION_INVALID => "Identity assertion invalid",
        ERR_VERSION_NOT_SUPPORTED => "Version not supported",
        ERR_QUEUE_FULL => "Queue full",
        ERR_DELEGATION_INVALID => "Delegation invalid",
        ERR_CONSIGNMENT_MODE_UNSUPPORTED => "Consignment mode unsupported",
        ERR_ASSURANCE_LEVEL_UNSUPPORTED => "Assurance level unsupported",
        ERR_POLICY_UNSUPPORTED => "Policy unsupported",
        ERR_PLAINTEXT_HASH_MISMATCH => "Plaintext hash mismatch",
        ERR_ISSUER_NOT_ENTITLED => "Issuer not entitled",
        ERR_PARSE_ERROR => "Parse error",
        ERR_INVALID_REQUEST => "Invalid Request",
        ERR_METHOD_NOT_FOUND => "Method not found",
        ERR_INVALID_PARAMS => "Invalid params",
        ERR_INTERNAL_ERROR => "Internal error",
        _ => "Unknown error",
    }
}

/// A JSON-RPC 2.0 error object: the code, the standard message for that code,
/// and optional machine-readable data.
///
/// Construct it with [`RpcError::new`] (the message is looked up from the
/// code, exactly as `wmp.NewRPCError` does) so the wire form of every WMP
/// error is uniform.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcError {
    /// The error code.
    pub code: i32,
    /// The standard message for the code.
    pub message: String,
    /// Optional structured data (for example `supported_versions`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Box<RawValue>>,
}

impl RpcError {
    /// Creates the error for `code` with the standard message and optional
    /// data. The data is any JSON value; it is stored in its serialized form.
    pub fn new(code: i32, data: Option<serde_json::Value>) -> Self {
        let data = data
            .and_then(|v| serde_json::to_string(&v).ok())
            .and_then(|s| RawValue::from_string(s).ok());
        Self {
            code,
            message: error_message(code).to_owned(),
            data,
        }
    }

    /// Creates the error for `code` with the standard message and no data.
    pub fn code(code: i32) -> Self {
        Self {
            code,
            message: error_message(code).to_owned(),
            data: None,
        }
    }
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "wmp: rpc error {}: {}", self.code, self.message)
    }
}

impl std::error::Error for RpcError {}
