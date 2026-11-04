//! The rules of the signed-request and encrypted-response policy of nym_auth (nym_auth
//! catalogue, "Binding" and "Response confidentiality"), over a verified request and over the
//! request the credential picker reads.

use serde_json::value::RawValue;
use serde_json::Value;
use siros_openid4vp::arrival::{DcApiRequest, ReceivedForm};
use siros_openid4vp::authenticate::{Authenticated, VerifierId as AuthenticatedId};
use siros_openid4vp::envelope::Envelope;
use siros_openid4vp::ids::ClientId;
use siros_openid4vp::routing::{DcApiMode, ModeChoice, ResponseMode};

use crate::verifier_id::{prefix, Intermediary, VerifierId, VerifierIdForm, VerifierIdRule};

/// The Client Identifier Prefix of an unsigned redirect request (OpenID4VP 1.0, Section 5.9.3).
const REDIRECT_URI: &str = "redirect_uri";

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
    /// The Request Object is not a JSON object.
    NotObject,
    /// `client_id` is missing or no string.
    ClientIdMissing,
    /// `client_id` is no Client Identifier (OpenID4VP 1.0, Section 5.9.1).
    ClientId(#[source] ClientIdFault),
    /// `nonce` is missing or no string.
    NonceMissing,
    /// `nonce` is empty or holds a character outside the ASCII URL-safe ones (OpenID4VP 1.0,
    /// Section 5.2).
    NonceMalformed,
    /// The Response Mode is not one the channel allows: `direct_post.jwt` over redirects,
    /// `dc_api.jwt` over the Digital Credentials API.
    ResponseMode,
    /// A redirect request has no `response_uri`.
    ResponseUriMissing,
    /// Over the Digital Credentials API, the calling origin is not in `expected_origins`.
    OriginNotExpected,
    /// `client_metadata` carries no response-encryption key in `jwks`.
    EncryptionKeyMissing,
    /// `verifier_info` is no array of objects with a string `format` (OpenID4VP 1.0, Section
    /// 5.1).
    VerifierInfo,
}

impl PolicyRule {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Unsigned => "unsigned",
            Self::Multisigned => "multisigned",
            Self::NotObject => "request_object_not_object",
            Self::ClientIdMissing => "client_id_missing",
            Self::ClientId(error) => error.code(),
            Self::NonceMissing => "nonce_missing",
            Self::NonceMalformed => "nonce_malformed",
            Self::ResponseMode => "response_mode",
            Self::ResponseUriMissing => "response_uri_missing",
            Self::OriginNotExpected => "origin_not_expected",
            Self::EncryptionKeyMissing => "encryption_key_missing",
            Self::VerifierInfo => "verifier_info_malformed",
        }
    }
}

/// Why `client_id` is no Client Identifier the policy reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum ClientIdFault {
    /// The text breaks RFC 6749, Appendix A.1's `*VSCHAR`.
    #[error("not a string of RFC 6749's VSCHAR")]
    Syntax,
    /// The text names no Client Identifier Prefix: no `:` follows a prefix.
    #[error("no Client Identifier Prefix")]
    Unprefixed,
}

impl ClientIdFault {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Syntax => "client_id_invalid",
            Self::Unprefixed => "client_id_unprefixed",
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
    /// The request's `Handover` does not encode as CBOR.
    Transcript,
}

impl RequestRefusal {
    /// The rule's stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Policy(rule) => rule.code(),
            Self::VerifierId(rule) => rule.code(),
            Self::Transcript => "session_transcript_unencodable",
        }
    }
}

/// What the policy reads of a request: the request the core authenticated, or the envelope the
/// credential picker reads.
pub trait PolicyRequest {
    /// The Client Identifier of a signed request; `None` for an unsigned DC API request, whose
    /// `client_id` the wallet ignores (OpenID4VP 1.0, A.2).
    fn client(&self) -> Option<&ClientId<'_>>;

    /// The `data` form of a DC API request; `None` by URI.
    fn dc_api_request(&self) -> Option<DcApiProtocol>;

    /// The Response Mode the core routed the request to.
    fn response_mode(&self) -> ModeChoice;

    /// `verifier_info` as received.
    fn verifier_info(&self) -> Option<&RawValue>;
}

/// The DC API protocol a request arrived under (OpenID4VP 1.0, A.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DcApiProtocol {
    /// `openid4vp-v1-unsigned`.
    Unsigned,
    /// `openid4vp-v1-signed`.
    Signed,
    /// `openid4vp-v1-multisigned`.
    Multisigned,
}

/// The Client Identifier of `request` when it meets the policy: signed under a prefix other
/// than `redirect_uri`, over the Digital Credentials API as `openid4vp-v1-signed`, and answered
/// in an encrypted Response Mode of its channel the core routes (`direct_post.jwt` over
/// redirects, `dc_api.jwt` over the Digital Credentials API). The core authenticated a request
/// before the wallet reads it: its Verifier is trusted. A request that carries a registration
/// certificate in `verifier_info` is refused: the catalogue takes the semantic identifier from
/// it, and no intake authenticates it.
///
/// # Errors
///
/// [`RequestRefusal`]: the first rule `request` breaks.
pub fn signed_and_encrypted<R: PolicyRequest>(
    request: &R,
) -> Result<&ClientId<'_>, RequestRefusal> {
    let policy = RequestRefusal::Policy;
    let client = request
        .client()
        .filter(|client| prefix(client) != Some(REDIRECT_URI))
        .ok_or(policy(PolicyRule::Unsigned))?;
    if request.dc_api_request() == Some(DcApiProtocol::Multisigned) {
        return Err(policy(PolicyRule::Multisigned));
    }
    let encrypted = matches!(
        (request.dc_api_request(), request.response_mode()),
        (None, ModeChoice::Answer(ResponseMode::DirectPostJwt))
            | (
                Some(_),
                ModeChoice::Answer(ResponseMode::DcApi(DcApiMode::DcApiJwt))
            )
    );
    if !encrypted {
        return Err(policy(PolicyRule::ResponseMode));
    }
    let formats = attestation_formats(request.verifier_info()).map_err(policy)?;
    if formats
        .iter()
        .any(|format| format == REGISTRATION_CERTIFICATE)
    {
        return Err(RequestRefusal::VerifierId(
            VerifierIdRule::RegistrationCertificate,
        ));
    }
    Ok(client)
}

/// The `format` of each attestation of `verifier_info` (OpenID4VP 1.0, Section 5.1): an array
/// of objects, each with a string `format`.
fn attestation_formats(verifier_info: Option<&RawValue>) -> Result<Vec<String>, PolicyRule> {
    let Some(raw) = verifier_info else {
        return Ok(Vec::new());
    };
    let entries: Vec<Value> =
        serde_json::from_str(raw.get()).map_err(|_| PolicyRule::VerifierInfo)?;
    entries
        .iter()
        .map(|entry| {
            entry
                .get("format")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or(PolicyRule::VerifierInfo)
        })
        .collect()
}

/// What `request` meets of the policy and of the `verifier_id` rule its Client Identifier decides:
/// the policy ([`signed_and_encrypted`]), and in the `x509_san_dns` form the Client Identifier's
/// prefix. Gives the `verifier_id` of the `x509_san_dns` form; `None` in the `semantic` form,
/// whose identifier the trust service states.
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
        VerifierIdForm::X509SanDns => VerifierId::x509_san_dns(client, Intermediary::Absent)
            .map(Some)
            .map_err(RequestRefusal::VerifierId),
        VerifierIdForm::Semantic => Ok(None),
    }
}

/// The DC API protocol of an envelope's request; `None` by URI.
fn protocol(envelope: &Envelope<'_>) -> Option<DcApiProtocol> {
    match envelope.received().form() {
        ReceivedForm::DcApi { request, .. } => Some(match request {
            DcApiRequest::Unsigned(_) => DcApiProtocol::Unsigned,
            DcApiRequest::Signed(_) => DcApiProtocol::Signed,
            DcApiRequest::Multisigned(_) => DcApiProtocol::Multisigned,
        }),
        ReceivedForm::Uri { .. } => None,
    }
}

/// The request as the credential picker reads it, before the wallet authenticates it.
impl PolicyRequest for Envelope<'_> {
    fn client(&self) -> Option<&ClientId<'_>> {
        self.client_id()
    }

    fn dc_api_request(&self) -> Option<DcApiProtocol> {
        protocol(self)
    }

    fn response_mode(&self) -> ModeChoice {
        self.routing().mode()
    }

    fn verifier_info(&self) -> Option<&RawValue> {
        Envelope::verifier_info(self)
    }
}

/// The request the core authenticated: its Verifier's Client Identifier, its channel, its
/// Response Mode and its `verifier_info`.
impl PolicyRequest for Authenticated<'_> {
    fn client(&self) -> Option<&ClientId<'_>> {
        match self.verifier().id() {
            AuthenticatedId::Client(client) => Some(client),
            AuthenticatedId::Origin(_) => None,
        }
    }

    fn dc_api_request(&self) -> Option<DcApiProtocol> {
        protocol(self.envelope())
    }

    fn response_mode(&self) -> ModeChoice {
        self.envelope().routing().mode()
    }

    fn verifier_info(&self) -> Option<&RawValue> {
        self.envelope().verifier_info()
    }
}
