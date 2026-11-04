//! A Request Object the host validated, checked against the signed-request and
//! encrypted-response policy of nym_auth (nym_auth catalogue, "Binding" and "Response
//! confidentiality"), and the session it gives.

use serde_json::Value;
use siros_openid4vp::cbor::CborError;
use siros_openid4vp::ids::{ClientId, Nonce, Origin};
use siros_openid4vp::request::thumbprint;
use siros_openid4vp::session::{
    Endpoint as SessionEndpoint, Handover, SessionTranscript, Thumbprint,
};

use crate::policy::{ClientIdFault, PolicyRule};
use crate::verifier_id::prefix;

/// The channel a request arrived on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Channel {
    /// The Digital Credentials API, with the origin of the calling web page.
    DcApi {
        /// The calling origin, as the platform reports it.
        origin: Origin<'static>,
    },
    /// Redirects, including a `request_uri` from a QR code or a link.
    Redirect,
}

/// The channel's own value in the `Handover`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    /// The calling origin, over the Digital Credentials API.
    Origin(Origin<'static>),
    /// `response_uri`, over redirects.
    ResponseUri(String),
}

/// How a Request Object arrived.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Signing {
    /// As a signed Request Object, whose signature and certificate chain the host checked.
    Signed,
    /// As a plain request.
    Unsigned,
}

/// A Request Object that follows the policy, read for the values the session binds.
#[derive(Debug, Clone, PartialEq)]
pub struct CheckedRequest {
    client_id: ClientId<'static>,
    nonce: Nonce<'static>,
    endpoint: Endpoint,
    encryption_keys: Vec<Value>,
}

/// Checks a validated Request Object against the policy.
///
/// # Errors
///
/// [`PolicyRule`]: the first rule the request breaks.
pub fn check_request(
    request_object: &Value,
    signing: Signing,
    channel: Channel,
) -> Result<CheckedRequest, PolicyRule> {
    if signing == Signing::Unsigned {
        return Err(PolicyRule::Unsigned);
    }
    let request = request_object.as_object().ok_or(PolicyRule::NotObject)?;
    let text = |name: &str| request.get(name).and_then(Value::as_str);
    let client_id = text("client_id").ok_or(PolicyRule::ClientIdMissing)?;
    let client_id = ClientId::parse(client_id.to_owned())
        .map_err(|_| PolicyRule::ClientId(ClientIdFault::Syntax))?;
    if prefix(&client_id).is_none() {
        return Err(PolicyRule::ClientId(ClientIdFault::Unprefixed));
    }
    let nonce = text("nonce").ok_or(PolicyRule::NonceMissing)?;
    let nonce = Nonce::parse(nonce.to_owned()).map_err(|_| PolicyRule::NonceMalformed)?;
    let endpoint = match channel {
        Channel::Redirect => {
            if !matches!(
                text("response_mode"),
                Some("direct_post.cwt" | "direct_post.jwt")
            ) {
                return Err(PolicyRule::ResponseMode);
            }
            let uri = text("response_uri").ok_or(PolicyRule::ResponseUriMissing)?;
            Endpoint::ResponseUri(uri.to_owned())
        }
        Channel::DcApi { origin } => {
            if text("response_mode") != Some("dc_api.jwt") {
                return Err(PolicyRule::ResponseMode);
            }
            let expected = request.get("expected_origins").and_then(Value::as_array);
            if !expected
                .is_some_and(|list| list.iter().any(|o| o.as_str() == Some(origin.as_str())))
            {
                return Err(PolicyRule::OriginNotExpected);
            }
            Endpoint::Origin(origin)
        }
    };
    let encryption_keys = request
        .get("client_metadata")
        .and_then(|m| m.get("jwks"))
        .and_then(|j| j.get("keys"))
        .and_then(Value::as_array)
        .filter(|keys| !keys.is_empty())
        .ok_or(PolicyRule::EncryptionKeyMissing)?
        .clone();
    Ok(CheckedRequest {
        client_id,
        nonce,
        endpoint,
        encryption_keys,
    })
}

/// The host chose an encryption key that is not one of the request's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("the JWK thumbprint is of no key in client_metadata.jwks")]
pub struct KeyNotInRequest;

impl CheckedRequest {
    /// `client_id`, with its Client Identifier Prefix.
    #[must_use]
    pub fn client_id(&self) -> &ClientId<'static> {
        &self.client_id
    }

    /// `nonce`.
    #[must_use]
    pub fn nonce(&self) -> &Nonce<'static> {
        &self.nonce
    }

    /// What the `Handover` binds besides `client_id` and `nonce`.
    #[must_use]
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// The keys of `client_metadata.jwks`, at least one.
    #[must_use]
    pub fn encryption_keys(&self) -> &[Value] {
        &self.encryption_keys
    }

    /// The SessionTranscript of this request's `Handover` (OpenID4VP 1.0, B.2.6), for the
    /// response-encryption key whose JWK SHA-256 Thumbprint is `jwk_thumbprint` (Section 8.3
    /// picks the key).
    ///
    /// # Errors
    ///
    /// [`HandoverError::KeyNotInRequest`] when no key of `client_metadata.jwks` has that
    /// thumbprint: the session binds only values of the validated Request Object.
    pub fn transcript(
        &self,
        jwk_thumbprint: Thumbprint,
    ) -> Result<SessionTranscript, HandoverError> {
        let known = self
            .encryption_keys
            .iter()
            .any(|key| ec_jwk_thumbprint(key) == Some(jwk_thumbprint));
        if !known {
            return Err(HandoverError::KeyNotInRequest(KeyNotInRequest));
        }
        let handover = match &self.endpoint {
            Endpoint::Origin(origin) => Handover::DcApi {
                origin,
                nonce: &self.nonce,
                thumbprint: Some(jwk_thumbprint),
            },
            Endpoint::ResponseUri(uri) => Handover::Redirect {
                client_id: &self.client_id,
                nonce: &self.nonce,
                thumbprint: Some(jwk_thumbprint),
                endpoint: SessionEndpoint::ResponseUri(uri),
            },
        };
        SessionTranscript::of(&handover).map_err(HandoverError::Cbor)
    }
}

/// Why a request gives no SessionTranscript.
#[derive(Debug, thiserror::Error)]
pub enum HandoverError {
    /// The key is no key of the request.
    #[error(transparent)]
    KeyNotInRequest(#[from] KeyNotInRequest),
    /// The handover does not encode.
    #[error("the handover does not encode")]
    Cbor(#[source] CborError),
}

/// The JWK SHA-256 Thumbprint (RFC 7638) of an EC public key `jwk`: `None` for another key.
#[must_use]
pub fn ec_jwk_thumbprint(jwk: &Value) -> Option<Thumbprint> {
    let text = |name: &str| jwk.get(name).and_then(Value::as_str);
    if text("kty") != Some("EC") {
        return None;
    }
    Some(Thumbprint(thumbprint(
        "EC",
        text("crv")?,
        text("x")?,
        Some(text("y")?),
    )))
}
