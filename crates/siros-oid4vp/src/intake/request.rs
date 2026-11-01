//! The request parameters of an authenticated request, read into a [`VerifiedRequest`]
//! (OpenID4VP 1.0, Sections 5.1, 5.2, 8.2, 8.3; A.2).

use serde_json::{Map, Value};
use siros_dcql::DcqlQuery;

use super::signature::{UriRule, Verifier};
use super::trust::Verdict;
use super::{IntakeError, JwkFault};
use crate::client_id::ClientId;
use crate::handover::ec_jwk_thumbprint;
use crate::jose;
use crate::parameters::{self, Carrier, DcApiEncoding, Encoding, Metadata};
use crate::protocol::Protocol;
use crate::request::{TransactionDataInvalid, TransactionDataItem};
use crate::values::{Kid, Origin};
use crate::verified::{Channel, ContentEncryption, Encryption, PostEncoding, VerifiedRequest};
use siros_codec::url::HttpsUrl;

/// The channel a request arrived on, and who sent it.
pub(super) enum Arrival<'a> {
    /// Redirects.
    Redirect(Verifier),
    /// A DC API request from `origin`, signed under `protocol`.
    DcApiSigned {
        origin: &'a Origin,
        protocol: Protocol,
        verifier: Verifier,
    },
    /// An unsigned DC API request from `origin`, with the host's verdict on the origin.
    DcApiUnsigned {
        origin: &'a Origin,
        trusted: Verdict,
    },
}

/// The verified request that arrived as `arrival`, from its request parameters `params`.
pub(super) fn verified(
    params: &Map<String, Value>,
    arrival: Arrival<'_>,
) -> Result<VerifiedRequest, IntakeError> {
    let text = |name: &str| params.get(name).and_then(Value::as_str);
    let (carrier, state) = match &arrival {
        Arrival::Redirect(_) => (Carrier::Redirect, parameters::state(params)?),
        Arrival::DcApiSigned { .. } => (Carrier::SignedObject, None),
        Arrival::DcApiUnsigned { .. } => (Carrier::UnsignedData, None),
    };
    let nonce = parameters::nonce(params, carrier)?;
    let mode = text("response_mode");
    let (target, trusted, certificate, metadata) = match arrival {
        Arrival::Redirect(verifier) => {
            let encoding = Encoding::of(mode)?;
            let target = Target::Redirect {
                response_uri: response_uri(params, &verifier)?,
                client_id: verifier.client_id,
                encoding,
            };
            (
                target,
                verifier.trusted,
                verifier.certificate,
                verifier.metadata,
            )
        }
        Arrival::DcApiSigned {
            origin,
            protocol,
            verifier,
        } => {
            let encoding = DcApiEncoding::of(mode)?;
            let expected = parameters::expected_origins(params)?;
            if !expected.iter().any(|o| o == origin.as_str()) {
                return Err(IntakeError::OriginNotExpected);
            }
            let target = Target::DcApi {
                protocol,
                client_id: Some(verifier.client_id),
                origin,
                encoding,
            };
            (
                target,
                verifier.trusted,
                verifier.certificate,
                verifier.metadata,
            )
        }
        // A.2: the Wallet ignores `client_id` and `expected_origins` of an unsigned request.
        Arrival::DcApiUnsigned { origin, trusted } => {
            let target = Target::DcApi {
                protocol: Protocol::Unsigned,
                client_id: None,
                origin,
                encoding: DcApiEncoding::of(mode)?,
            };
            (target, trusted, None, Metadata::Request)
        }
    };
    let (dcql_query, dcql_query_json) = dcql_query(params)?;
    let verifier_info = parameters::verifier_info(params.get("verifier_info"), &dcql_query)?;
    let client_metadata = parameters::client_metadata(params, metadata)?;
    let transaction_data = match params.get("transaction_data") {
        None => Vec::new(),
        Some(entries) => TransactionDataItem::list(entries)
            .map_err(|TransactionDataInvalid| IntakeError::TransactionDataInvalid)?,
    };
    let metadata = client_metadata.as_ref();
    let channel = match target {
        Target::Redirect {
            client_id,
            response_uri,
            encoding,
        } => Channel::Redirect {
            client_id,
            response_uri,
            encoding: match encoding {
                Encoding::Form => PostEncoding::Form,
                Encoding::Jwe => PostEncoding::Jwe(encryption(metadata, &ContentEncryption::JWE)?),
                Encoding::Cose => {
                    PostEncoding::Cose(encryption(metadata, &ContentEncryption::COSE)?)
                }
            },
        },
        Target::DcApi {
            protocol,
            client_id,
            origin,
            encoding,
        } => Channel::DcApi {
            protocol,
            client_id,
            origin: origin.clone(),
            encryption: match encoding {
                DcApiEncoding::Json => None,
                DcApiEncoding::Jwe => Some(encryption(metadata, &ContentEncryption::JWE)?),
            },
        },
    };
    Ok(VerifiedRequest {
        channel,
        trusted,
        access_certificate: certificate,
        verifier_info,
        nonce,
        state,
        dcql_query,
        dcql_query_json,
        client_metadata,
        transaction_data,
    })
}

/// Where the response goes, before its encryption is chosen.
enum Target<'a> {
    Redirect {
        client_id: ClientId,
        response_uri: HttpsUrl,
        encoding: Encoding,
    },
    DcApi {
        protocol: Protocol,
        client_id: Option<ClientId>,
        origin: &'a Origin,
        encoding: DcApiEncoding,
    },
}

/// The `response_uri` of a redirect request of `verifier` (Section 8.2).
fn response_uri(params: &Map<String, Value>, verifier: &Verifier) -> Result<HttpsUrl, IntakeError> {
    if params.contains_key("redirect_uri") {
        return Err(IntakeError::RedirectUriWithDirectPost);
    }
    let value = verifier.client_id.value();
    let given = params.get("response_uri").and_then(Value::as_str);
    let uri = match (&verifier.response_uri, given) {
        // Section 5.9.3: a `redirect_uri` client may omit the Response URI it is.
        (UriRule::IsClientIdValue, None) => value,
        (_, Some(uri)) => uri,
        (_, None) => return Err(IntakeError::ResponseUriMissing),
    };
    let url = HttpsUrl::parse(uri).ok_or(IntakeError::ResponseUriNotHttps)?;
    let refusal = match &verifier.response_uri {
        UriRule::Any => None,
        UriRule::IsClientIdValue => (uri != value).then_some(IntakeError::ResponseUriNotClientId),
        UriRule::HostIsClientIdValue => (!url.host().eq_ignore_ascii_case(value))
            .then_some(IntakeError::ResponseUriHostMismatch),
        UriRule::OneOf(uris) => {
            (!uris.iter().any(|u| u == uri)).then_some(IntakeError::RedirectUriNotAttested)
        }
    };
    refusal.map_or(Ok(url), Err)
}

/// `dcql_query`, parsed by `siros-dcql`, and as sent (Section 5.1).
fn dcql_query(params: &Map<String, Value>) -> Result<(DcqlQuery, Value), IntakeError> {
    match (params.get("dcql_query"), params.contains_key("scope")) {
        (Some(_), true) => Err(IntakeError::QueryAndScope),
        (None, true) => Err(IntakeError::ScopeUnsupported),
        (None, false) => Err(IntakeError::DcqlQueryMissing),
        (Some(raw), false) => {
            let query = DcqlQuery::parse(raw).map_err(IntakeError::DcqlQueryInvalid)?;
            Ok((query, raw.clone()))
        }
    }
}

/// The key and `enc` of an encrypted response, for a JWE and for a `COSE_Encrypt` alike
/// (Section 8.3; `zkp_req.md`, Section 6.2): the first key of `jwks` that is a P-256 `ECDH-ES`
/// key for encryption, and the first value of `encrypted_response_enc_values_supported` among
/// `supported`, `A128GCM` when the list is absent.
fn encryption(
    metadata: Option<&Value>,
    supported: &[ContentEncryption],
) -> Result<Encryption, IntakeError> {
    let keys = metadata
        .and_then(|m| m.get("jwks"))
        .and_then(|j| j.get("keys"))
        .and_then(Value::as_array)
        .ok_or(IntakeError::EncryptionKeyMissing)?;
    // RFC 7517, Section 5: a key that is no P-256 key is passed over. When none is usable, the
    // first that names P-256 gives the cause.
    let mut unreadable = None;
    let chosen = keys
        .iter()
        .filter(|jwk| {
            let text = |name: &str| jwk.get(name).and_then(Value::as_str);
            text("alg") == Some("ECDH-ES") && text("use").is_none_or(|u| u == "enc")
        })
        .find_map(|jwk| match jose::p256_key(jwk) {
            Ok(key) => Some((jwk, key)),
            Err(JwkFault::OtherKey) => None,
            Err(fault) => {
                if unreadable.is_none() {
                    unreadable = Some(fault);
                }
                None
            }
        });
    let (jwk, key) = chosen.ok_or(unreadable.map_or(
        IntakeError::EncryptionKeyMissing,
        IntakeError::EncryptionKeyInvalid,
    ))?;
    let thumbprint = ec_jwk_thumbprint(jwk).ok_or(IntakeError::EncryptionKeyMissing)?;
    let enc = match metadata.and_then(|m| m.get("encrypted_response_enc_values_supported")) {
        None => ContentEncryption::A128Gcm,
        Some(values) => values
            .as_array()
            .and_then(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .find_map(|v| supported.iter().copied().find(|e| e.as_str() == v))
            })
            .ok_or(IntakeError::EncryptionUnsupported)?,
    };
    Ok(Encryption {
        key,
        kid: jwk.get("kid").and_then(Value::as_str).map(Kid::new),
        enc,
        thumbprint,
    })
}
