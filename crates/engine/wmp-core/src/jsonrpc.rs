//! JSON-RPC 2.0 framing: requests, notifications, responses, and the strict
//! decoder with its size and depth limits.

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::error::RpcError;

/// The default maximum message size: 1 MiB.
pub const DEFAULT_MAX_MESSAGE_SIZE: usize = 1 << 20;

/// The default maximum nesting depth for arrays and objects.
pub const DEFAULT_MAX_DEPTH: usize = 32;

/// The safety limits for JSON-RPC decoding.
///
/// `None` selects the default ([`DEFAULT_MAX_MESSAGE_SIZE`],
/// [`DEFAULT_MAX_DEPTH`]), mirroring go-wmp, where a zero value means the
/// same.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DecodeOptions {
    /// The maximum message size in bytes.
    pub max_size: Option<usize>,
    /// The maximum nesting depth for arrays and objects.
    pub max_depth: Option<usize>,
}

impl DecodeOptions {
    /// The effective size limit.
    fn size(self) -> usize {
        self.max_size.unwrap_or(DEFAULT_MAX_MESSAGE_SIZE)
    }

    /// The effective depth limit.
    fn depth(self) -> usize {
        self.max_depth.unwrap_or(DEFAULT_MAX_DEPTH)
    }
}

/// A JSON-RPC 2.0 request or notification. Notifications carry no `id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    /// The protocol string, always `2.0`.
    pub jsonrpc: String,
    /// The request identifier; absent on a notification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Box<RawValue>>,
    /// The method name.
    pub method: String,
    /// The method parameters. Always present on the wire; `None` is `null`.
    #[serde(default)]
    pub params: Option<Box<RawValue>>,
}

impl Request {
    /// Whether this is a notification: no `id`, or an explicit `null` id.
    pub fn is_notification(&self) -> bool {
        match &self.id {
            None => true,
            Some(id) => id.get() == "null",
        }
    }
}

/// A JSON-RPC 2.0 response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    /// The protocol string, always `2.0`.
    pub jsonrpc: String,
    /// The identifier of the request being answered.
    #[serde(default)]
    pub id: Option<Box<RawValue>>,
    /// The result, present on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Box<RawValue>>,
    /// The error, present on failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

/// A message read from a transport, where the kind is not yet known: a
/// request/notification (`method` present) or a response (`result` or
/// `error` present).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// The protocol string, always `2.0`.
    pub jsonrpc: String,
    /// The message identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Box<RawValue>>,
    /// The method name, present on a request or notification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// The method parameters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Box<RawValue>>,
    /// The result, present on a response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Box<RawValue>>,
    /// The error, present on an error response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

impl Message {
    /// Whether this is a request or notification (a method is present).
    pub fn is_request(&self) -> bool {
        self.method.as_deref().is_some_and(|m| !m.is_empty())
    }

    /// Whether this is a response (a result or an error is present).
    pub fn is_response(&self) -> bool {
        self.result.is_some() || self.error.is_some()
    }

    /// The message as a [`Request`].
    pub fn as_request(&self) -> Request {
        Request {
            jsonrpc: self.jsonrpc.clone(),
            id: self.id.clone(),
            method: self.method.clone().unwrap_or_default(),
            params: self.params.clone(),
        }
    }

    /// The message as a [`Response`].
    pub fn as_response(&self) -> Response {
        Response {
            jsonrpc: self.jsonrpc.clone(),
            id: self.id.clone(),
            result: self.result.clone(),
            error: self.error.clone(),
        }
    }
}

/// Creates a JSON-RPC 2.0 request. An empty `id` makes a notification.
pub fn new_request(
    id: Option<&str>,
    method: &str,
    params: &impl Serialize,
) -> Result<Request, serde_json::Error> {
    let params = serde_json::to_string(params)?;
    let id = match id {
        Some(id) if !id.is_empty() => Some(serde_json::to_string(id)?),
        _ => None,
    };
    Ok(Request {
        jsonrpc: "2.0".to_owned(),
        id: id.and_then(|s| RawValue::from_string(s).ok()),
        method: method.to_owned(),
        params: RawValue::from_string(params).ok(),
    })
}

/// Creates a JSON-RPC 2.0 notification (no id).
pub fn new_notification(
    method: &str,
    params: &impl Serialize,
) -> Result<Request, serde_json::Error> {
    new_request(None, method, params)
}

/// Creates a successful JSON-RPC 2.0 response for `id`.
pub fn new_response(
    id: Option<Box<RawValue>>,
    result: &impl Serialize,
) -> Result<Response, serde_json::Error> {
    let result = serde_json::to_string(result)?;
    Ok(Response {
        jsonrpc: "2.0".to_owned(),
        id,
        result: RawValue::from_string(result).ok(),
        error: None,
    })
}

/// Creates an error response for `id`.
pub fn new_error_response(id: Option<Box<RawValue>>, error: RpcError) -> Response {
    Response {
        jsonrpc: "2.0".to_owned(),
        id,
        result: None,
        error: Some(error),
    }
}

/// Why a message could not be decoded.
#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    /// The message exceeds the configured size limit.
    #[error("message exceeds maximum size of {max} bytes")]
    TooLarge {
        /// The configured limit.
        max: usize,
    },
    /// The message is not valid JSON.
    #[error("decode message: {0}")]
    Json(#[from] serde_json::Error),
    /// Data followed the JSON-RPC message.
    #[error("trailing data after JSON-RPC message")]
    Trailing,
    /// The `jsonrpc` member is not `2.0`.
    #[error("unsupported jsonrpc version: {0:?}")]
    UnsupportedVersion(String),
    /// A payload exceeds the configured nesting depth.
    #[error("message exceeds maximum nesting depth of {max}")]
    DepthExceeded {
        /// The configured limit.
        max: usize,
    },
}

/// Decodes raw JSON into a [`Message`].
///
/// The input must be a single JSON value with nothing after it; the `jsonrpc`
/// member must be `2.0`; and `params`, `result` and `error.data` must respect
/// the depth limit. A payload that does not parse is left for the method-level
/// decoder to report — mirroring go-wmp.
pub fn decode_message(data: &[u8], options: DecodeOptions) -> Result<Message, DecodeError> {
    if data.len() > options.size() {
        return Err(DecodeError::TooLarge {
            max: options.size(),
        });
    }
    let mut de = serde_json::Deserializer::from_slice(data);
    let msg = Message::deserialize(&mut de)?;
    // Nothing but whitespace may follow the message — the analogue of
    // go-wmp's requireEOF, checked on the stream rather than re-parsed.
    de.end().map_err(|_| DecodeError::Trailing)?;
    if msg.jsonrpc != "2.0" {
        return Err(DecodeError::UnsupportedVersion(msg.jsonrpc));
    }
    check_depth(&msg.params, options.depth())?;
    check_depth(&msg.result, options.depth())?;
    if let Some(error) = &msg.error {
        check_depth(&error.data, options.depth())?;
    }
    Ok(msg)
}

/// Decodes a JSON array as a batch of messages.
///
/// Returns `None` when the data is not a JSON array (the single-message
/// caller then decodes it as one message); an array that is empty, has a
/// member with the wrong `jsonrpc` version, or exceeds a limit is an error.
pub fn decode_batch(
    data: &[u8],
    options: DecodeOptions,
) -> Result<Option<Vec<Message>>, DecodeError> {
    if data.len() > options.size() {
        return Err(DecodeError::TooLarge {
            max: options.size(),
        });
    }
    let trimmed = trim_leading_whitespace(data);
    if trimmed.first() != Some(&b'[') {
        return Ok(None);
    }
    let msgs: Vec<Message> = serde_json::from_slice(data)?;
    for msg in &msgs {
        if msg.jsonrpc != "2.0" {
            return Err(DecodeError::UnsupportedVersion(msg.jsonrpc.clone()));
        }
        check_depth(&msg.params, options.depth())?;
        check_depth(&msg.result, options.depth())?;
        if let Some(error) = &msg.error {
            check_depth(&error.data, options.depth())?;
        }
    }
    Ok(Some(msgs))
}

fn trim_leading_whitespace(mut data: &[u8]) -> &[u8] {
    while let Some((&first, rest)) = data.split_first() {
        if matches!(first, b' ' | b'\t' | b'\n' | b'\r') {
            data = rest;
        } else {
            break;
        }
    }
    data
}

/// Checks one raw payload against the depth limit. A payload that does not
/// parse is skipped: the method-level decoder reports it with the context the
/// caller can act on.
fn check_depth(raw: &Option<Box<RawValue>>, max: usize) -> Result<(), DecodeError> {
    let raw = match raw {
        Some(raw) => raw,
        None => return Ok(()),
    };
    let value: serde_json::Value = match serde_json::from_str(raw.get()) {
        Ok(value) => value,
        Err(_) => return Ok(()),
    };
    if depth(&value) > max {
        return Err(DecodeError::DepthExceeded { max });
    }
    Ok(())
}

/// The nesting depth of a JSON value: containers are one more than their
/// deepest child, scalars are one.
fn depth(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::Object(map) => map.values().map(depth).max().map_or(1, |d| d + 1),
        serde_json::Value::Array(items) => items.iter().map(depth).max().map_or(1, |d| d + 1),
        _ => 1,
    }
}
