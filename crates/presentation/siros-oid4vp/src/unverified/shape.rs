//! The request object of one entry, in the one shape its protocol allows.
//!
//! The protocol label is what a wallet uses to decide whether to verify a signature. A request
//! labelled unsigned that carries a JWS, read here and offered, would be consented to and then
//! handled as though it had never been signed; each label therefore accepts its own shape only.

use serde_json::{Map, Value};
use siros_codec::base64url;
use siros_codec::json::JsonTextError;

use super::{CompactFault, NoQuery, PayloadFault};
use crate::jws_rules::{self, JwsRule};
use crate::protocol::Protocol;

/// The request of an entry, in the shape its protocol names. Its request object has a
/// `dcql_query`.
pub(super) enum Shaped<'a> {
    /// `openid4vp-v1-unsigned`: `data` itself.
    Unsigned(&'a Value),
    /// `openid4vp-v1-signed`: the payload of the compact JWS.
    Signed(Value),
    /// `openid4vp-v1-multisigned`: the payload, and the protected header of each signature that
    /// keeps the key-free rules of a Request Object's JWS ([`signature_headers`]).
    Multisigned {
        object: Value,
        headers: Vec<Map<String, Value>>,
    },
}

impl Shaped<'_> {
    /// The request object.
    pub(super) fn object(&self) -> &Value {
        match self {
            Self::Unsigned(object) => object,
            Self::Signed(object) | Self::Multisigned { object, .. } => object,
        }
    }
}

/// The request an entry carries under `protocol`.
pub(super) fn request_object(protocol: Protocol, data: &Value) -> Result<Shaped<'_>, NoQuery> {
    match protocol {
        Protocol::Unsigned => match data.get("dcql_query") {
            Some(_) => Ok(Shaped::Unsigned(data)),
            // A `request` here is a signed shape under the unsigned label.
            None if data.get("request").is_some() => Err(NoQuery::ShapeDoesNotMatchProtocol),
            None => Err(NoQuery::NoQueryAndNoRequest),
        },
        Protocol::Signed => match data.get("request") {
            Some(Value::String(jws)) => Ok(Shaped::Signed(payload_object(compact_payload(jws)?)?)),
            // An inline query under a signed label.
            None if data.get("dcql_query").is_some() => Err(NoQuery::ShapeDoesNotMatchProtocol),
            _ => Err(NoQuery::NotACompactJws(CompactFault::NotString)),
        },
        Protocol::Multisigned => {
            let (payload, signatures) = json_payload(data)?;
            Ok(Shaped::Multisigned {
                object: payload_object(payload)?,
                headers: signature_headers(signatures),
            })
        }
    }
}

/// The request object inside a decoded, unverified JWS payload.
fn payload_object(payload: Vec<u8>) -> Result<Value, NoQuery> {
    let object: Value = serde_json::from_slice(&payload)
        .map_err(|error| NoQuery::PayloadNotJson(JsonTextError::of(&error)))?;
    if object.get("dcql_query").is_none() {
        return Err(NoQuery::PayloadHasNoDcqlQuery);
    }
    Ok(object)
}

/// The unverified payload of a JWS JSON Serialization object, under `data.request` or as
/// `data` itself, and its `signatures`.
fn json_payload(data: &Value) -> Result<(Vec<u8>, &[Value]), NoQuery> {
    let (jws, missing) = match data.get("request") {
        Some(request @ Value::Object(_)) => (request, NoQuery::JwsObjectHasNoPayload),
        // A string is a compact JWS, the `-signed` shape.
        Some(Value::String(_)) => return Err(NoQuery::ShapeDoesNotMatchProtocol),
        // A number, a bool, null: present, and unable to carry a payload.
        Some(_) => return Err(NoQuery::RequestNotAJwsOrObject),
        // An inline query under a signed label.
        None if data.get("dcql_query").is_some() => return Err(NoQuery::ShapeDoesNotMatchProtocol),
        None => (data, NoQuery::NoQueryAndNoRequest),
    };
    let payload = json_serialization_payload(jws, missing)?;
    let signatures = jws_rules::signatures(jws).map_err(NoQuery::Jws)?;
    Ok((payload, signatures))
}

/// The middle segment of a compact JWS, decoded, whose protected header and signature keep the
/// key-free rules of a Request Object's JWS ([`request_object_header`]).
///
/// The serialization is always `header.payload.signature` (RFC 7515, Section 7.1). Five
/// segments is a JWE, whose second segment is an encrypted key.
///
/// `splitn` bounds the work by the meaningful segments: the input is verifier-controlled and
/// the picker has a time budget.
fn compact_payload(jws: &str) -> Result<Vec<u8>, NoQuery> {
    let fault = NoQuery::NotACompactJws;
    let mut segments = jws.splitn(4, '.');
    let header = segments.next();
    let payload = segments.next();
    let signature = segments.next();
    if segments.next().is_some() || signature.is_none() {
        return Err(fault(CompactFault::Segments));
    }
    if header.is_none_or(str::is_empty) {
        return Err(fault(CompactFault::EmptyHeader));
    }
    let Some(payload) = payload.filter(|p| !p.is_empty()) else {
        return Err(fault(CompactFault::EmptyPayload));
    };
    if let (Some(header), Some(signature)) = (header, signature) {
        request_object_header(header, signature)?;
    }
    decode_payload(payload)
}

/// The protected header `protected` of a Request Object's JWS signed by `signature`, each as
/// written in the serialization, when they keep the rules intake applies without a key: the
/// header is a JSON object naming `alg` `ES256` and `typ` `oauth-authz-req+jwt` without
/// `crit`, and the signature is the 64 bytes of an ES256 `r ‖ s`.
///
/// # Errors
///
/// [`NoQuery::Jws`] or [`NoQuery::TypMismatch`]: the first rule they break.
fn request_object_header(protected: &str, signature: &str) -> Result<Map<String, Value>, NoQuery> {
    let header = decode_payload(protected)
        .map_err(|_| JwsRule::Header)
        .and_then(|decoded| jws_rules::header(&decoded))
        .map_err(NoQuery::Jws)?;
    let signature = decode_payload(signature).map_err(|_| NoQuery::Jws(JwsRule::Signature))?;
    jws_rules::signature_length(&signature).map_err(NoQuery::Jws)?;
    jws_rules::es256(&header).map_err(NoQuery::Jws)?;
    if !jws_rules::is_request_object(&header) {
        return Err(NoQuery::TypMismatch);
    }
    Ok(header)
}

/// The `payload` member of a JWS JSON Serialization object; `missing` when it has none.
fn json_serialization_payload(value: &Value, missing: NoQuery) -> Result<Vec<u8>, NoQuery> {
    let Some(Value::String(payload)) = value.get("payload") else {
        return Err(missing);
    };
    decode_payload(payload)
}

/// The largest JWS payload the picker decodes, in encoded bytes.
///
/// The picker runs in someone else's process, where running out of memory traps and a trap
/// reads as "no matching credential". A request object is a few kilobytes.
const MAX_PAYLOAD: usize = 256 * 1024;

fn decode_payload(payload: &str) -> Result<Vec<u8>, NoQuery> {
    if payload.len() > MAX_PAYLOAD {
        return Err(NoQuery::PayloadNotBase64url(PayloadFault::TooLong));
    }
    base64url::decode(payload).map_err(|e| NoQuery::PayloadNotBase64url(PayloadFault::Encoding(e)))
}

/// The protected header of each of a multisigned request's `signatures` that keeps the key-free
/// rules of a Request Object's JWS ([`request_object_header`]), decoded and unverified, in
/// their order. A signature without a string `protected` and `signature`, or that breaks one
/// of those rules, cannot qualify, and has none.
fn signature_headers(signatures: &[Value]) -> Vec<Map<String, Value>> {
    signatures
        .iter()
        .filter_map(|signature| {
            let protected = signature.get("protected")?.as_str()?;
            let signature = signature.get("signature")?.as_str()?;
            request_object_header(protected, signature).ok()
        })
        .collect()
}
