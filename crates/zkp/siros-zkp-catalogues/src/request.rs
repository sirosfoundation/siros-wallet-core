//! A verified request that meets the nym_auth policy (N2; nym_auth catalogue, "Binding",
//! "Response confidentiality" and "Verifier identity").

use siros_oid4vp::{AttestationFormat, ClientId, Protocol, ResponseMode, Verdict, VerifiedRequest};

use crate::policy::{admitted, PolicyRequest, PolicyRule, RequestRefusal};
use crate::presenter::Session;
use crate::verifier_id::{VerifierId, VerifierIdForm, VerifierIdRule};

/// A request intake verified that meets the nym_auth policy, with the session it binds.
#[derive(Debug, Clone)]
pub struct NymAuthRequest<'r> {
    request: &'r VerifiedRequest,
    session: Session,
}

impl<'r> NymAuthRequest<'r> {
    /// The nym_auth request of `request`, its `verifier_id` in the form `verifier_id`.
    ///
    /// The request meets the policy ([`admitted`]): signed, trusted, answered in an
    /// encrypted Response Mode, which intake gives an encryption key, and without a
    /// registration certificate. Over the Digital Credentials API the calling origin is in
    /// `expected_origins`. The session's `Handover` binds the encryption key's thumbprint.
    ///
    /// The `verifier_id` derives from the request: the Client Identifier in the `x509_san_dns`
    /// form, `"semantic_id:"` and the access certificate's semantic identifier in the
    /// `semantic` form.
    ///
    /// # Errors
    ///
    /// [`RequestRefusal`]: the first rule `request` breaks.
    pub fn new(
        request: &'r VerifiedRequest,
        verifier_id: VerifierIdForm,
    ) -> Result<Self, RequestRefusal> {
        let verifier_id = match admitted(request, verifier_id)? {
            Some(verifier_id) => verifier_id,
            None => semantic_id(request).map_err(RequestRefusal::VerifierId)?,
        };
        Ok(Self {
            request,
            session: Session {
                handover: request.handover(),
                verifier_id,
            },
        })
    }

    /// The request.
    pub fn request(&self) -> &'r VerifiedRequest {
        self.request
    }

    /// The session: the request's `Handover` and the Verifier's `verifier_id`.
    pub fn session(&self) -> &Session {
        &self.session
    }
}

/// The `semantic` form of `request`'s `verifier_id`: from the semantics identifier of its access
/// certificate.
fn semantic_id(request: &VerifiedRequest) -> Result<VerifierId, VerifierIdRule> {
    let certificate = request
        .access_certificate()
        .ok_or(VerifierIdRule::SemanticIdMissing)?;
    let identifier = certificate
        .semantic_identifier()
        .map_err(VerifierIdRule::SemanticId)?;
    Ok(VerifierId::semantic(identifier))
}

/// The verified request: its Client Identifier, its channel, the host's verdict, its Response
/// Mode and its `verifier_info`, as intake verified them.
impl PolicyRequest for VerifiedRequest {
    type Client<'a> = &'a ClientId;

    fn client(&self) -> Option<&ClientId> {
        self.verifier().client_id()
    }

    fn dc_api_protocol(&self) -> Option<Protocol> {
        VerifiedRequest::dc_api_protocol(self)
    }

    fn trusted(&self) -> Result<(), PolicyRule> {
        match self.verifier().verdict() {
            Verdict::Trusted => Ok(()),
            Verdict::Untrusted => Err(PolicyRule::Untrusted),
        }
    }

    fn response_mode(&self) -> Option<ResponseMode> {
        Some(VerifiedRequest::response_mode(self))
    }

    fn attestation_formats(&self) -> Vec<AttestationFormat> {
        self.verifier_info_formats().to_vec()
    }
}
