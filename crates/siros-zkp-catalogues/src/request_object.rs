//! A Request Object the host validated, checked against the signed-request and
//! encrypted-response policy of nym_auth (nym_auth catalogue, "Binding" and "Response
//! confidentiality"), and the session it gives.

use serde_json::Value;
use siros_oid4vp::{ec_jwk_thumbprint, ClientId, Handover, JwkThumbprint, Nonce, Origin};

use crate::policy::PolicyRule;

/// The channel a request arrived on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Channel {
    /// The Digital Credentials API, with the origin of the calling web page.
    DcApi {
        /// The calling origin, as the platform reports it.
        origin: Origin,
    },
    /// Redirects, including a `request_uri` from a QR code or a link.
    Redirect,
}

/// The channel's own value in the `Handover`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    /// The calling origin, over the Digital Credentials API.
    Origin(Origin),
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
    client_id: ClientId,
    nonce: Nonce,
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
    let client_id = ClientId::parse(client_id).map_err(PolicyRule::ClientId)?;
    let nonce = text("nonce").ok_or(PolicyRule::NonceMissing)?;
    let nonce = Nonce::parse(nonce).ok_or(PolicyRule::NonceMalformed)?;
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
    pub fn client_id(&self) -> &ClientId {
        &self.client_id
    }

    /// `nonce`.
    #[must_use]
    pub fn nonce(&self) -> &Nonce {
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

    /// The `Handover` of this request, for the response-encryption key whose JWK SHA-256
    /// Thumbprint is `jwk_thumbprint` (OpenID4VP 1.0, Section 8.3 picks the key).
    ///
    /// # Errors
    ///
    /// [`KeyNotInRequest`] when no key of `client_metadata.jwks` has that thumbprint: the
    /// session binds only values of the validated Request Object.
    pub fn handover(&self, jwk_thumbprint: &JwkThumbprint) -> Result<Handover, KeyNotInRequest> {
        let known = self
            .encryption_keys
            .iter()
            .any(|k| ec_jwk_thumbprint(k).as_ref() == Some(jwk_thumbprint));
        if !known {
            return Err(KeyNotInRequest);
        }
        Ok(match &self.endpoint {
            Endpoint::Origin(origin) => {
                Handover::dc_api(origin.as_str(), self.nonce.as_str(), Some(jwk_thumbprint))
            }
            Endpoint::ResponseUri(uri) => Handover::redirect(
                self.client_id.as_str(),
                self.nonce.as_str(),
                Some(jwk_thumbprint),
                uri,
            ),
        })
    }
}
