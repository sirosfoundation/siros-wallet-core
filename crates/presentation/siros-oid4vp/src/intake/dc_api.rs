//! Intake of a DC API request (OpenID4VP 1.0, Appendix A).

use serde_json::{Map, Value};
use siros_codec::date::DateTime;
use siros_codec::json::JsonTextError;

use super::request::{self, Arrival};
use super::signature::{self, Verifier};
use super::trust::{self, KeyMaterial, TrustSubject, Verdict};
use super::{Answers, Halt, IntakeError, JwsFault};
use crate::client_id::ClientId;
use crate::jose::{self, Signed};
use crate::jws_rules;
use crate::protocol::Protocol;
use crate::unverified::{NoQuery, UnverifiedRequest};
use crate::values::Origin;
use crate::verified::VerifiedRequest;

/// Intake of the DC API request `request` from `origin`.
pub(super) fn intake(
    request: &[u8],
    origin: &Origin,
    now: DateTime,
    answers: &mut Answers<'_>,
) -> Result<VerifiedRequest, Halt> {
    let envelope: Value = serde_json::from_slice(request)
        .map_err(|error| IntakeError::EnvelopeNotJson(JsonTextError::of(&error)))?;
    let (protocol, data) = entry(&envelope)?;
    match protocol {
        Protocol::Unsigned => {
            let params = data.as_object().ok_or(IntakeError::EnvelopeUnreadable)?;
            let trusted = trust::verdict(
                answers,
                TrustSubject::Origin(origin.clone()),
                KeyMaterial::None,
            )?;
            Ok(request::verified(
                params,
                Arrival::DcApiUnsigned { origin, trusted },
            )?)
        }
        Protocol::Signed => {
            let jws = data
                .get("request")
                .and_then(Value::as_str)
                .ok_or(IntakeError::EnvelopeUnreadable)?;
            let (signed, payload) = jose::compact(jws).map_err(IntakeError::from)?;
            let params = request_object(&payload)?;
            let client_id = params
                .get("client_id")
                .and_then(Value::as_str)
                .ok_or(IntakeError::ClientIdMissing)?;
            let verifier =
                signature::authenticate(&signed, ClientId::parse(client_id)?, now, answers)?;
            Ok(request::verified(
                &params,
                Arrival::DcApiSigned {
                    origin,
                    protocol,
                    verifier,
                },
            )?)
        }
        Protocol::Multisigned => {
            // The serialization is `data.request`, or `data` itself.
            let jws = match data.get("request") {
                Some(request @ Value::Object(_)) => request,
                _ => data,
            };
            let malformed = || IntakeError::JwsMalformed(JwsFault::Serialization);
            let payload_b64 = jws
                .get("payload")
                .and_then(Value::as_str)
                .ok_or_else(malformed)?;
            let payload = jose::segment(payload_b64).map_err(IntakeError::from)?;
            let mut params = request_object(&payload)?;
            // A.3.2.2: `client_id` and `verifier_info` travel in each signature's protected
            // header only.
            if params.contains_key("client_id") {
                return Err(IntakeError::ClientIdInPayload.into());
            }
            if params.contains_key("verifier_info") {
                return Err(IntakeError::VerifierInfoInPayload.into());
            }
            let signatures = jws_rules::signatures(jws).map_err(IntakeError::from)?;
            let Qualified {
                verifier,
                verifier_info,
            } = first_qualifying(signatures, payload_b64, now, answers)?;
            // The request's `verifier_info` is the qualifying signature's.
            if let Some(verifier_info) = verifier_info {
                drop(params.insert("verifier_info".to_owned(), verifier_info));
            }
            Ok(request::verified(
                &params,
                Arrival::DcApiSigned {
                    origin,
                    protocol,
                    verifier,
                },
            )?)
        }
    }
}

/// The entry the credential picker answers: the first that reads as an
/// [`UnverifiedRequest`].
///
/// # Errors
///
/// The rule the first entry of a known shape breaks of the request parameters or the Client
/// Identifier when no entry reads, else [`IntakeError::EnvelopeUnreadable`].
fn entry(envelope: &Value) -> Result<(Protocol, &Value), IntakeError> {
    let entries = envelope
        .get("requests")
        .and_then(Value::as_array)
        .ok_or(IntakeError::EnvelopeUnreadable)?;
    let mut refused = None;
    for entry in entries {
        let label = entry.get("protocol").and_then(Value::as_str);
        let (Some(label), Some(data)) = (label, entry.get("data")) else {
            continue;
        };
        match UnverifiedRequest::read(label, data) {
            Ok(read) => return Ok((read.protocol(), data)),
            Err(refusal) => {
                if refused.is_none() {
                    refused = rule(&refusal);
                }
            }
        }
    }
    Err(refused.unwrap_or(IntakeError::EnvelopeUnreadable))
}

/// The intake rule the request data of `refusal` breaks: a parameter's, or the Client
/// Identifier's; `None` for an envelope intake does not read.
fn rule(refusal: &NoQuery) -> Option<IntakeError> {
    Some(match refusal {
        NoQuery::Parameter(fault) => IntakeError::Parameter(*fault),
        NoQuery::ClientIdMissing => IntakeError::ClientIdMissing,
        NoQuery::ClientId(error) => IntakeError::ClientId(*error),
        NoQuery::SignedRedirectUri => IntakeError::SignedRedirectUri,
        NoQuery::ClientIdInPayload => IntakeError::ClientIdInPayload,
        NoQuery::VerifierInfoInPayload => IntakeError::VerifierInfoInPayload,
        NoQuery::NoSignatureQualifies => IntakeError::NoVerifiableSignature,
        NoQuery::Jws(rule) => IntakeError::from(*rule),
        NoQuery::TypMismatch => IntakeError::TypMismatch,
        NoQuery::NoData
        | NoQuery::NoQueryAndNoRequest
        | NoQuery::RequestNotAJwsOrObject
        | NoQuery::JwsObjectHasNoPayload
        | NoQuery::ShapeDoesNotMatchProtocol
        | NoQuery::NotACompactJws(_)
        | NoQuery::PayloadNotBase64url(_)
        | NoQuery::PayloadNotJson(_)
        | NoQuery::PayloadHasNoDcqlQuery
        | NoQuery::Malformed(_)
        | NoQuery::TransactionData(_)
        | NoQuery::NoParser => return None,
    })
}

fn request_object(payload: &[u8]) -> Result<Map<String, Value>, IntakeError> {
    match serde_json::from_slice(payload) {
        Ok(Value::Object(object)) => Ok(object),
        _ => Err(IntakeError::RequestObjectNotObject),
    }
}

/// The Verifier of the first signature that verifies and is trusted, or of the first that
/// verifies when none is trusted.
///
/// A signature that breaks a rule does not qualify, and the next is tried. A host result that
/// does not fit its effect stops intake.
fn first_qualifying(
    signatures: &[Value],
    payload_b64: &str,
    now: DateTime,
    answers: &mut Answers<'_>,
) -> Result<Qualified, Halt> {
    let mut first_untrusted = None;
    for entry in signatures {
        match qualify(entry, payload_b64, now, answers) {
            Ok(qualified) if qualified.verifier.trusted == Verdict::Trusted => {
                return Ok(qualified)
            }
            Ok(qualified) => {
                first_untrusted.get_or_insert(qualified);
            }
            Err(Halt::Failed(_)) => {}
            Err(halt) => return Err(halt),
        }
    }
    first_untrusted.ok_or_else(|| IntakeError::NoVerifiableSignature.into())
}

/// A signature of a multisigned request that qualifies: its Verifier, and the `verifier_info`
/// of its protected header.
struct Qualified {
    verifier: Verifier,
    verifier_info: Option<Value>,
}

/// One signature object `{"protected", "signature"}` of the JWS JSON Serialization.
fn qualify(
    entry: &Value,
    payload_b64: &str,
    now: DateTime,
    answers: &mut Answers<'_>,
) -> Result<Qualified, Halt> {
    let text = |name: &str| entry.get(name).and_then(Value::as_str);
    let (Some(protected), Some(signature)) = (text("protected"), text("signature")) else {
        return Err(IntakeError::JwsMalformed(JwsFault::Serialization).into());
    };
    let signed = Signed::parse(protected, payload_b64, signature).map_err(IntakeError::from)?;
    let client_id = signed
        .text("client_id")
        .ok_or(IntakeError::ClientIdMissing)?;
    let verifier = signature::authenticate(&signed, ClientId::parse(client_id)?, now, answers)?;
    Ok(Qualified {
        verifier,
        verifier_info: signed.header().get("verifier_info").cloned(),
    })
}
