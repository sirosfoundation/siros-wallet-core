//! Intake of an authorization request URI: parameters by value, a Request Object by value
//! (`request`), or by reference (`request_uri`, Section 5.10; RFC 9101, Section 5).

use rustc_hash::FxHashMap;
use serde_json::{Map, Value};
use siros_codec::date::DateTime;
use siros_codec::json::JsonTextError;
use siros_codec::url::HttpsUrl;

use super::reference::{RequestUri, RequestUriMethod, WalletParameters};
use super::request::{self, Arrival};
use super::signature::{self, by_request, UriRule};
use super::trust::{self, KeyMaterial, TrustSubject};
use super::{Answers, FormFault, Halt, IntakeError, JsonParameter};
use crate::client_id::{ClientId, ClientIdPrefix};
use crate::form;
use crate::jose;
use crate::values::WalletNonce;
use crate::verified::VerifiedRequest;

/// What the wallet sends for `request_uri_method=post` (Section 5.10).
pub(super) struct Wallet<'a> {
    pub(super) vp_formats_supported: &'a Map<String, Value>,
    pub(super) nonce: &'a WalletNonce,
}

impl Wallet<'_> {
    /// The method `request_uri_method` names, `get` when absent, with this wallet's parameters
    /// for a `post`.
    fn method(&self, name: Option<&str>) -> Result<RequestUriMethod, IntakeError> {
        match name {
            None | Some("get") => Ok(RequestUriMethod::Get),
            Some("post") => Ok(RequestUriMethod::Post(WalletParameters::new(
                self.vp_formats_supported,
                self.nonce.clone(),
            ))),
            Some(_) => Err(IntakeError::RequestUriMethodInvalid),
        }
    }
}

/// Intake of the authorization request URI `uri`.
pub(super) fn intake(
    uri: &str,
    wallet: &Wallet<'_>,
    now: DateTime,
    answers: &mut Answers<'_>,
) -> Result<VerifiedRequest, Halt> {
    let refused = IntakeError::NotAnAuthorizationRequest;
    let query = uri
        .split_once('?')
        .and_then(|(_, rest)| rest.split('#').next())
        .ok_or(refused(FormFault::NoQuery))?;
    let params = form::parse(query).map_err(refused)?;
    let outer = params
        .get("client_id")
        .ok_or(IntakeError::ClientIdMissing)?;
    let method = params.get("request_uri_method").map(String::as_str);
    match (params.get("request"), params.get("request_uri")) {
        (Some(_), Some(_)) => Err(IntakeError::RequestAndRequestUri.into()),
        (_, None) if method.is_some() => Err(IntakeError::RequestUriMethodWithoutRequestUri.into()),
        (Some(jws), None) => signed(jws, outer, None, now, answers),
        (None, Some(request_uri)) => {
            let method = wallet.method(method)?;
            // A `redirect_uri` client cannot sign, so its Request Object is not asked for.
            if ClientId::parse(outer)?.prefix() == ClientIdPrefix::RedirectUri {
                return Err(IntakeError::SignedRedirectUri.into());
            }
            // RFC 9101, Section 5.2: a Request URI the client gives is an `https` URI.
            let uri = HttpsUrl::parse(request_uri).ok_or(IntakeError::RequestUriNotHttps)?;
            let echoed = method.echoed().cloned();
            let text = answers.request_object(RequestUri::new(uri, method))?;
            signed(text.as_str().trim(), outer, echoed.as_ref(), now, answers)
        }
        (None, None) => unsigned(&params, outer, answers),
    }
}

/// A signed Request Object; `wallet_nonce` is the nonce a `request_uri_method=post` request
/// sent.
fn signed(
    jws: &str,
    outer: &str,
    wallet_nonce: Option<&WalletNonce>,
    now: DateTime,
    answers: &mut Answers<'_>,
) -> Result<VerifiedRequest, Halt> {
    let (signed, payload) = jose::compact(jws).map_err(IntakeError::from)?;
    let Ok(Value::Object(object)) = serde_json::from_slice(&payload) else {
        return Err(IntakeError::RequestObjectNotObject.into());
    };
    let inner = object
        .get("client_id")
        .and_then(Value::as_str)
        .ok_or(IntakeError::ClientIdMissing)?;
    if inner != outer {
        return Err(IntakeError::ClientIdMismatch.into());
    }
    if let Some(nonce) = wallet_nonce {
        if object.get("wallet_nonce").and_then(Value::as_str) != Some(nonce.as_str()) {
            return Err(IntakeError::WalletNonceMismatch.into());
        }
    }
    let verifier = signature::authenticate(&signed, ClientId::parse(inner)?, now, answers)?;
    Ok(request::verified(&object, Arrival::Redirect(verifier))?)
}

/// Parameters by value: the request of a `redirect_uri` client.
fn unsigned(
    params: &FxHashMap<String, String>,
    client_id: &str,
    answers: &mut Answers<'_>,
) -> Result<VerifiedRequest, Halt> {
    let client_id = ClientId::parse(client_id)?;
    if client_id.prefix() != ClientIdPrefix::RedirectUri {
        return Err(IntakeError::UnsignedNeedsRedirectUri.into());
    }
    let object = params
        .iter()
        .map(|(name, value)| Ok((name.clone(), parameter(name, value)?)))
        .collect::<Result<Map<String, Value>, IntakeError>>()?;
    let trusted = trust::verdict(
        answers,
        TrustSubject::Client(client_id.clone()),
        KeyMaterial::None,
    )?;
    let verifier = by_request(client_id, trusted, UriRule::IsClientIdValue);
    Ok(request::verified(&object, Arrival::Redirect(verifier))?)
}

/// The request parameter `name` of the form value `value`. Section 5.1: parameters holding
/// objects travel as JSON-serialized strings.
fn parameter(name: &str, value: &str) -> Result<Value, IntakeError> {
    let parameter = match name {
        "dcql_query" => JsonParameter::DcqlQuery,
        "client_metadata" => JsonParameter::ClientMetadata,
        "transaction_data" => JsonParameter::TransactionData,
        _ => return Ok(Value::String(value.to_owned())),
    };
    serde_json::from_str(value)
        .map_err(|error| IntakeError::ParameterNotJson(parameter, JsonTextError::of(&error)))
}
