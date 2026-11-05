//! The vctm resolution helpers — the mirror of go-wmp's `resolve.go`.

use serde_json::value::RawValue;

use crate::error::{RpcError, ERR_INTERNAL_ERROR, ERR_INVALID_PARAMS};
use crate::handler::HandlerError;
use crate::methods::{ResolveParams, ResolveResult};
use crate::types::{Metadata, VERSION};

/// The `data.reason` of the error a vctm lookup answers with when it cannot
/// produce a document (WMP Core 5.8.1).
pub const RESOLVE_REASON_METADATA_FETCH_ERROR: &str = "metadata_fetch_error";

/// One member of a type metadata document that a vctm resolution carries
/// (WMP Core 5.8.1), in the order it is written. `string_member` marks the
/// two that must be strings: a null there is treated as absent, while
/// display, claims and schema are carried verbatim, null included (Core 9.5
/// rule 4).
const VCTM_MEMBERS: &[(&str, bool)] = &[
    ("name", true),
    ("description", true),
    ("display", false),
    ("claims", false),
    ("schema", false),
];

/// Why a type metadata document cannot be carried.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum VctmError {
    /// The document is not a JSON object, its `vct`, `name` or
    /// `description` is not a string, or it names no `vct` and the uri is
    /// empty.
    #[error("wmp: invalid type metadata document")]
    Invalid,
}

/// Reduces a type metadata document to the members a vctm resolution
/// carries: `vct` (set to the uri when the document has none), and `name`,
/// `description`, `display`, `claims` and `schema` when present, each
/// verbatim. Every other member is dropped. This is the shape the legacy
/// WebSocket VCTM flow delivers.
///
/// The members' order differs from go-wmp's insertion order (JSON objects
/// are unordered; the mirror writes them sorted), which no consumer of the
/// document depends on.
pub fn project_vctm(doc: &[u8], uri: &str) -> Result<Box<RawValue>, VctmError> {
    let all: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice(doc).map_err(|_| VctmError::Invalid)?;
    if all.is_empty() {
        // A document that decoded to an empty object is not one; a null is
        // the other way to get here.
        return Err(VctmError::Invalid);
    }
    let vct = vctm_identifier(&all, uri)?;
    let mut out = serde_json::Map::new();
    out.insert("vct".to_owned(), serde_json::Value::String(vct));
    for (name, string_member) in VCTM_MEMBERS {
        let Some(raw) = all.get(*name) else {
            continue;
        };
        if !carry(*string_member, raw)? {
            continue;
        }
        out.insert(name.to_string(), raw.clone());
    }
    let text =
        serde_json::to_string(&serde_json::Value::Object(out)).map_err(|_| VctmError::Invalid)?;
    RawValue::from_string(text).map_err(|_| VctmError::Invalid)
}

/// The `vct` of the projection: the document's, else the uri.
fn vctm_identifier(
    all: &serde_json::Map<String, serde_json::Value>,
    uri: &str,
) -> Result<String, VctmError> {
    let mut vct = uri.to_owned();
    if let Some(raw) = all.get("vct") {
        if !raw.is_null() {
            let Some(s) = raw.as_str() else {
                return Err(VctmError::Invalid);
            };
            if !s.is_empty() {
                vct = s.to_owned();
            }
        }
    }
    if vct.is_empty() {
        return Err(VctmError::Invalid);
    }
    Ok(vct)
}

/// Whether a member is carried, refusing a name or description that is not
/// a string. A null name or description is absent; display, claims and
/// schema are carried verbatim, null included.
fn carry(string_member: bool, raw: &serde_json::Value) -> Result<bool, VctmError> {
    if !string_member {
        return Ok(true);
    }
    if raw.is_null() {
        return Ok(false);
    }
    if raw.as_str().is_none() {
        return Err(VctmError::Invalid);
    }
    Ok(true)
}

/// Builds the `wmp.resolve` result of a successful vctm lookup from the type
/// metadata document that was found. A document that cannot be carried is an
/// error, and the caller answers [`new_metadata_fetch_error`].
pub fn new_vctm_resolve_result(
    session_id: &str,
    uri: &str,
    doc: &[u8],
) -> Result<ResolveResult, HandlerError> {
    let metadata = project_vctm(doc, uri).map_err(|err| {
        HandlerError::Rpc(RpcError::new(
            ERR_INTERNAL_ERROR,
            Some(serde_json::json!({
                "reason": format!("vctm {uri:?}: {err}"),
            })),
        ))
    })?;
    Ok(ResolveResult {
        wmp: Metadata {
            version: VERSION.to_owned(),
            session_id: session_id.to_owned(),
            ..Metadata::default()
        },
        r#type: crate::methods::RESOLVE_TYPE_VCTM.to_owned(),
        uri: uri.to_owned(),
        metadata,
        trust_info: None,
    })
}

/// The result for a resolver that knows the identifier is unknown: metadata
/// null. A lookup that cannot tell unknown from unreachable (the WebSocket
/// VCTM lookup is one) answers [`new_metadata_fetch_error`].
///
/// go-wmp builds this infallibly (its `RawMessage` is bytes); the mirror's
/// `RawValue` must encode, so the impossible failure of encoding JSON `null`
/// surfaces as an internal error.
pub fn new_unknown_resolve_result(
    session_id: &str,
    resolve_type: &str,
    uri: &str,
) -> Result<ResolveResult, HandlerError> {
    let metadata = RawValue::from_string("null".to_owned())
        .map_err(|_| HandlerError::Rpc(RpcError::code(ERR_INTERNAL_ERROR)))?;
    Ok(ResolveResult {
        wmp: Metadata {
            version: VERSION.to_owned(),
            session_id: session_id.to_owned(),
            ..Metadata::default()
        },
        r#type: resolve_type.to_owned(),
        uri: uri.to_owned(),
        metadata,
        trust_info: None,
    })
}

/// The error of a vctm lookup that found no document, could not reach one,
/// or found one that is not a JSON object: `-32603` with
/// `data.reason = "metadata_fetch_error"` (WMP Core 5.8.1). It carries
/// nothing of the underlying failure.
pub fn new_metadata_fetch_error() -> RpcError {
    RpcError::new(
        ERR_INTERNAL_ERROR,
        Some(serde_json::json!({ "reason": RESOLVE_REASON_METADATA_FETCH_ERROR })),
    )
}

/// Whether the params are a well-formed vctm resolve request: an empty uri
/// is invalid params (`-32602`).
pub fn validate_vctm_resolve_params(params: &ResolveParams) -> Option<RpcError> {
    if params.r#type != crate::methods::RESOLVE_TYPE_VCTM || params.uri.is_empty() {
        return Some(RpcError::code(ERR_INVALID_PARAMS));
    }
    None
}
