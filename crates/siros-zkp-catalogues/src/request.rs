//! An authenticated request that meets the nym_auth policy (N2; nym_auth catalogue, "Binding",
//! "Response confidentiality" and "Verifier identity").

use serde_json::Value;
use siros_openid4vp::arrival::ReceivedForm;
use siros_openid4vp::authenticate::{Authenticated, BoundEndpoint};
use siros_openid4vp::ids::Nonce;
use siros_openid4vp::session::{Endpoint, Handover, SessionTranscript, Thumbprint};

use crate::policy::{admitted, PolicyRequest, PolicyRule, RequestRefusal};
use crate::presenter::Session;
use crate::request_object::ec_jwk_thumbprint;
use crate::semantic::SemanticIdentifier;
use crate::verifier_id::{VerifierId, VerifierIdForm, VerifierIdRule};

/// The member of the trust decision's facts that states the access certificate's semantics
/// identifier (ETSI TS 119 475, Clause 5.1.3).
pub const SEMANTICS_IDENTIFIER: &str = "semantics_identifier";

/// A request the core authenticated that meets the nym_auth policy, with the session it binds.
#[derive(Clone)]
pub struct NymAuthRequest<'r> {
    request: &'r Authenticated<'r>,
    session: Session,
}

impl<'r> NymAuthRequest<'r> {
    /// The nym_auth request of `request`, its `verifier_id` in the form `verifier_id`, its
    /// response sealed to the key of `client_metadata.jwks` whose JWK SHA-256 Thumbprint is
    /// `encryption_key`.
    ///
    /// The request meets the policy ([`admitted`]): signed, answered in an encrypted Response
    /// Mode, and without a registration certificate. The core authenticated it: its Verifier is
    /// trusted, and over the Digital Credentials API the calling origin is one it expects. The
    /// session's SessionTranscript binds the encryption key's thumbprint.
    ///
    /// The `verifier_id` derives from the request: the Client Identifier in the `x509_san_dns`
    /// form, `"semantic_id:"` and the semantics identifier the trust service states in the
    /// decision's facts ([`SEMANTICS_IDENTIFIER`]) in the `semantic` form.
    ///
    /// # Errors
    ///
    /// [`RequestRefusal`]: the first rule `request` breaks.
    pub fn new(
        request: &'r Authenticated<'r>,
        verifier_id: VerifierIdForm,
        encryption_key: Thumbprint,
    ) -> Result<Self, RequestRefusal> {
        let verifier_id = match admitted(request, verifier_id)? {
            Some(verifier_id) => verifier_id,
            None => semantic_id(request).map_err(RequestRefusal::VerifierId)?,
        };
        let transcript = transcript(request, encryption_key)?;
        Ok(Self {
            request,
            session: Session {
                transcript,
                verifier_id,
            },
        })
    }

    /// The request.
    pub fn request(&self) -> &'r Authenticated<'r> {
        self.request
    }

    /// The session: the request's SessionTranscript and the Verifier's `verifier_id`.
    pub fn session(&self) -> &Session {
        &self.session
    }
}

/// The SessionTranscript of `request`'s `Handover` (OpenID4VP 1.0, B.2.6), for the
/// response-encryption key whose thumbprint is `encryption_key`, one of `client_metadata.jwks`.
fn transcript(
    request: &Authenticated<'_>,
    encryption_key: Thumbprint,
) -> Result<SessionTranscript, RequestRefusal> {
    let policy = RequestRefusal::Policy;
    let parameters = request.envelope().parameters();
    let keys: Vec<Value> = parameters
        .raw("client_metadata")
        .and_then(|metadata| serde_json::from_str::<Value>(metadata.get()).ok())
        .and_then(|metadata| metadata.get("jwks")?.get("keys")?.as_array().cloned())
        .ok_or(policy(PolicyRule::EncryptionKeyMissing))?;
    if !keys
        .iter()
        .any(|key| ec_jwk_thumbprint(key) == Some(encryption_key))
    {
        return Err(policy(PolicyRule::EncryptionKeyMissing));
    }
    let nonce = parameters
        .text("nonce")
        .flatten()
        .ok_or(policy(PolicyRule::NonceMissing))?;
    let nonce = Nonce::parse(nonce).map_err(|_| policy(PolicyRule::NonceMalformed))?;
    let thumbprint = Some(encryption_key);
    let handover = match (
        request.envelope().received().form(),
        request.verifier().endpoint(),
    ) {
        (ReceivedForm::DcApi { origin, .. }, _) => Handover::DcApi {
            origin,
            nonce: &nonce,
            thumbprint,
        },
        (ReceivedForm::Uri { .. }, BoundEndpoint::ResponseUri { uri, .. }) => Handover::Redirect {
            client_id: request.client().ok_or(policy(PolicyRule::Unsigned))?,
            nonce: &nonce,
            thumbprint,
            endpoint: Endpoint::ResponseUri(uri.as_str()),
        },
        (ReceivedForm::Uri { .. }, BoundEndpoint::DcApi) => {
            return Err(policy(PolicyRule::ResponseUriMissing));
        }
    };
    SessionTranscript::of(&handover).map_err(|_| RequestRefusal::Transcript)
}

/// The `semantic` form of `request`'s `verifier_id`: from the semantics identifier the trust
/// service states.
fn semantic_id(request: &Authenticated<'_>) -> Result<VerifierId, VerifierIdRule> {
    let stated = request
        .verifier()
        .facts()
        .and_then(|facts| facts.get(SEMANTICS_IDENTIFIER))
        .and_then(|value| value.as_str())
        .ok_or(VerifierIdRule::SemanticIdMissing)?;
    let identifier =
        SemanticIdentifier::parse_stated(stated).map_err(VerifierIdRule::SemanticId)?;
    Ok(VerifierId::semantic(&identifier))
}
