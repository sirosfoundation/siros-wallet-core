//! The rules of the signed-request and encrypted-response policy of nym_auth (nym_auth
//! catalogue, "Binding" and "Response confidentiality"), over a verified request and over the
//! request the credential picker reads.

use std::borrow::Borrow;

use siros_oid4vp::{
    AttestationFormat, ClientId, ClientIdError, ClientIdPrefix, Protocol, ResponseMode,
    UnverifiedRequest,
};

use crate::verifier_id::{Intermediary, VerifierId, VerifierIdForm, VerifierIdRule};

/// The `format` of a registration certificate in `verifier_info` (ETSI TS 119 472-2 V1.2.1,
/// OIDFVP-HAIP-COMMON-REQ-RO-15).
const REGISTRATION_CERTIFICATE: &str = "registration_cert";

/// A rule of the policy that a request breaks. Each makes the request invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}", self.code())]
pub enum PolicyRule {
    /// The request is not signed.
    Unsigned,
    /// A Digital Credentials API request arrived as `openid4vp-v1-multisigned`: the catalogue
    /// requires `openid4vp-v1-signed`.
    Multisigned,
    /// The host's trust verdict on the Client Identifier is negative: the Wallet Unit validates
    /// the Request Object's certificate chain for its Client Identifier Prefix.
    Untrusted,
    /// The Request Object is not a JSON object.
    NotObject,
    /// `client_id` is missing or no string.
    ClientIdMissing,
    /// `client_id` is no Client Identifier this wallet supports (OpenID4VP 1.0, Section 5.9).
    ClientId(#[source] ClientIdError),
    /// `nonce` is missing or no string.
    NonceMissing,
    /// `nonce` is empty or holds a character outside the ASCII URL-safe ones (OpenID4VP 1.0,
    /// Section 5.2).
    NonceMalformed,
    /// The Response Mode is not one the channel allows: `direct_post.cwt` or
    /// `direct_post.jwt` over redirects, `dc_api.jwt` over the Digital Credentials API.
    ResponseMode,
    /// A redirect request has no `response_uri`.
    ResponseUriMissing,
    /// Over the Digital Credentials API, the calling origin is not in `expected_origins`.
    OriginNotExpected,
    /// `client_metadata` carries no response-encryption key in `jwks`.
    EncryptionKeyMissing,
}

impl PolicyRule {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Unsigned => "unsigned",
            Self::Multisigned => "multisigned",
            Self::Untrusted => "untrusted",
            Self::NotObject => "request_object_not_object",
            Self::ClientIdMissing => "client_id_missing",
            Self::ClientId(error) => error.code(),
            Self::NonceMissing => "nonce_missing",
            Self::NonceMalformed => "nonce_malformed",
            Self::ResponseMode => "response_mode",
            Self::ResponseUriMissing => "response_uri_missing",
            Self::OriginNotExpected => "origin_not_expected",
            Self::EncryptionKeyMissing => "encryption_key_missing",
        }
    }
}

/// Why a verified request is no nym_auth request: a rule of the policy, or of the Verifier
/// identity. Each makes a nym_auth query invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum RequestRefusal {
    /// A rule of the signed-request and encrypted-response policy.
    Policy(#[source] PolicyRule),
    /// A rule of the `verifier_id` of the trust framework's form.
    VerifierId(#[source] VerifierIdRule),
}

impl RequestRefusal {
    /// The rule's stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Policy(rule) => rule.code(),
            Self::VerifierId(rule) => rule.code(),
        }
    }
}

/// What the policy reads of a request: the wallet's verified request, or the credential
/// picker's unverified one.
pub trait PolicyRequest {
    /// The Client Identifier the request names.
    type Client<'a>: Borrow<ClientId>
    where
        Self: 'a;

    /// The Client Identifier of a signed request; `None` for an unsigned DC API request, whose
    /// `client_id` the wallet ignores (OpenID4VP 1.0, A.2), and for a `client_id` the wallet does
    /// not support.
    fn client(&self) -> Option<Self::Client<'_>>;

    /// The protocol of a DC API request; `None` over redirects.
    fn dc_api_protocol(&self) -> Option<Protocol>;

    /// Checks the host's trust verdict on the Client Identifier.
    ///
    /// # Errors
    ///
    /// [`PolicyRule::Untrusted`] for a negative verdict.
    fn trusted(&self) -> Result<(), PolicyRule>;

    /// The Response Mode the request names.
    fn response_mode(&self) -> Option<ResponseMode>;

    /// The `format` of each `verifier_info` attestation.
    fn attestation_formats(&self) -> Vec<AttestationFormat>;
}

/// The Client Identifier of `request` when it meets the policy: signed under a prefix other
/// than `redirect_uri`, over the Digital Credentials API as `openid4vp-v1-signed`, trusted, and
/// answered in an encrypted Response Mode of its channel (`direct_post.cwt` or
/// `direct_post.jwt` over redirects, `dc_api.jwt` over the Digital Credentials API). A request
/// that carries a registration certificate in `verifier_info` is refused: the catalogue takes
/// the semantic identifier from it, and no intake authenticates it.
///
/// # Errors
///
/// [`RequestRefusal`]: the first rule `request` breaks.
pub fn signed_and_encrypted<R: PolicyRequest>(
    request: &R,
) -> Result<R::Client<'_>, RequestRefusal> {
    let policy = RequestRefusal::Policy;
    let client = request
        .client()
        .filter(|client| client.borrow().prefix() != ClientIdPrefix::RedirectUri)
        .ok_or(policy(PolicyRule::Unsigned))?;
    if request.dc_api_protocol() == Some(Protocol::Multisigned) {
        return Err(policy(PolicyRule::Multisigned));
    }
    request.trusted().map_err(policy)?;
    let encrypted = matches!(
        (request.dc_api_protocol(), request.response_mode()),
        (
            None,
            Some(ResponseMode::DirectPostCwt | ResponseMode::DirectPostJwt)
        ) | (Some(_), Some(ResponseMode::DcApiJwt))
    );
    if !encrypted {
        return Err(policy(PolicyRule::ResponseMode));
    }
    let registered = request
        .attestation_formats()
        .iter()
        .any(|format| format.as_str() == REGISTRATION_CERTIFICATE);
    if registered {
        return Err(RequestRefusal::VerifierId(
            VerifierIdRule::RegistrationCertificate,
        ));
    }
    Ok(client)
}

/// What `request` meets of the policy and of the `verifier_id` rule its Client Identifier decides:
/// the policy ([`signed_and_encrypted`]), and in the `x509_san_dns` form the Client Identifier's
/// prefix. Gives the `verifier_id` of the `x509_san_dns` form; `None` in the `semantic` form,
/// whose identifier comes from the access certificate intake authenticates.
///
/// # Errors
///
/// [`RequestRefusal`]: the first rule `request` breaks.
pub fn admitted<R: PolicyRequest>(
    request: &R,
    form: VerifierIdForm,
) -> Result<Option<VerifierId>, RequestRefusal> {
    let client = signed_and_encrypted(request)?;
    match form {
        VerifierIdForm::X509SanDns => {
            VerifierId::x509_san_dns(client.borrow(), Intermediary::Absent)
                .map(Some)
                .map_err(RequestRefusal::VerifierId)
        }
        VerifierIdForm::Semantic => Ok(None),
    }
}

/// The request as the credential picker reads it. The picker holds no trust verdict: the wallet
/// judges the Client Identifier at intake, and refuses the selection of an untrusted one.
impl PolicyRequest for UnverifiedRequest {
    type Client<'a> = &'a ClientId;

    fn client(&self) -> Option<&ClientId> {
        self.client_id()
    }

    fn dc_api_protocol(&self) -> Option<Protocol> {
        Some(self.protocol())
    }

    fn trusted(&self) -> Result<(), PolicyRule> {
        Ok(())
    }

    fn response_mode(&self) -> Option<ResponseMode> {
        Some(UnverifiedRequest::response_mode(self))
    }

    fn attestation_formats(&self) -> Vec<AttestationFormat> {
        self.verifier_info_formats().to_vec()
    }
}
