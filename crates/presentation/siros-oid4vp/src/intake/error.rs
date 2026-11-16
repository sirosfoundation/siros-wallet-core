//! Why intake refused a request.

use std::str::Utf8Error;

use der::asn1::ObjectIdentifier;
use siros_codec::json::JsonTextError;
use siros_codec::member::MemberFault;
use siros_codec::Base64Error;
use siros_dcql::QueryError;

use crate::client_id::ClientIdError;
use crate::error_code::ErrorCode;
use crate::jws_rules::JwsRule;
use crate::parameters::ParameterFault;

/// A rule of OpenID4VP 1.0 (or of RFC 9101, RFC 7515, RFC 5280) that a request breaks.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum IntakeError {
    /// The authorization request URI has no query of form-encoded parameters, each once.
    NotAnAuthorizationRequest(#[source] FormFault),
    /// `client_id` is missing or not a string (Section 5.2; A.2 for signed DC API requests).
    ClientIdMissing,
    /// Both `request` and `request_uri` are present (RFC 9101, Section 5).
    RequestAndRequestUri,
    /// `request_uri_method` is present without `request_uri` (Section 5.1).
    RequestUriMethodWithoutRequestUri,
    /// `request_uri_method` is neither `get` nor `post` (Section 5.1).
    RequestUriMethodInvalid,
    /// `request_uri` is not an `https` URL (RFC 9101, Section 5.2).
    RequestUriNotHttps,
    /// A JWS breaks its serialization.
    JwsMalformed(#[source] JwsFault),
    /// The JWS `alg` is not `ES256`.
    AlgorithmUnsupported,
    /// The JWS header has `crit` (RFC 7515, Section 4.1.11).
    CriticalHeader,
    /// The Request Object's `typ` is not `oauth-authz-req+jwt` (Section 5).
    TypMismatch,
    /// The signature does not verify under the key its Client Identifier Prefix names.
    SignatureInvalid,
    /// The Request Object is not a JSON object.
    RequestObjectNotObject,
    /// The `client_id` parameter and the Request Object's `client_id` differ (Section 5.10.1).
    ClientIdMismatch,
    /// The Request Object does not echo the `wallet_nonce` of the `request_uri_method=post`
    /// request (Section 5.10.1).
    WalletNonceMismatch,
    /// The `client_id` is not one this wallet supports (Section 5.9).
    ClientId(#[from] ClientIdError),
    /// A signed request uses the `redirect_uri` prefix (Section 5.9.3).
    SignedRedirectUri,
    /// An unsigned request uses a prefix other than `redirect_uri` (Section 5.9.3).
    UnsignedNeedsRedirectUri,
    /// `x5c` breaks its rules.
    CertificateChainInvalid(#[source] ChainFault),
    /// No dNSName SAN of the leaf certificate is the `x509_san_dns` value.
    SanMismatch,
    /// The SHA-256 of the leaf certificate is not the `x509_hash` value.
    CertificateHashMismatch,
    /// `kid` does not name a key of the `decentralized_identifier` DID.
    KidNotOfClient,
    /// The host's trust answer carries no JWK for a key it was asked to resolve.
    KeyNotResolved,
    /// The JWK of the host's trust answer is no P-256 key.
    ResolvedKeyInvalid(#[source] JwkFault),
    /// The `jwt` Header Parameter is not a Verifier Attestation JWT (Section 12).
    AttestationInvalid(#[source] AttestationFault),
    /// The attestation's `sub` is not the `verifier_attestation` value.
    AttestationSubjectMismatch,
    /// The attestation's `exp` has passed, or its `nbf` has not come.
    AttestationExpired,
    /// The attestation's signature does not verify under its issuer's key.
    AttestationSignatureInvalid,
    /// The Response URI is not among the attestation's `redirect_uris`.
    RedirectUriNotAttested,
    /// An `openid4vp-v1-multisigned` payload holds `client_id` (A.3.2.2).
    ClientIdInPayload,
    /// An `openid4vp-v1-multisigned` payload holds `verifier_info`, which travels in each
    /// signature's protected header (A.3.2.2).
    VerifierInfoInPayload,
    /// No signature of an `openid4vp-v1-multisigned` request verifies.
    NoVerifiableSignature,
    /// The DC API request has no entry this wallet reads.
    EnvelopeUnreadable,
    /// The DC API request is no JSON text.
    EnvelopeNotJson(#[source] JsonTextError),
    /// The calling origin is not in `expected_origins` (A.2).
    OriginNotExpected,
    /// A `direct_post` request has no `response_uri` (Section 8.2).
    ResponseUriMissing,
    /// `response_uri` is not an `https` URL.
    ResponseUriNotHttps,
    /// A `direct_post` request also has `redirect_uri` (Section 8.2).
    RedirectUriWithDirectPost,
    /// The `response_uri` of a `redirect_uri` client is not its Client Identifier.
    ResponseUriNotClientId,
    /// The host of the `response_uri` of an untrusted `x509_san_dns` client is not its DNS
    /// name (Section 5.9.3).
    ResponseUriHostMismatch,
    /// The request uses `scope` without `dcql_query`; this wallet maps no scope to a query.
    ScopeUnsupported,
    /// The request has both `dcql_query` and `scope` (Section 5.1).
    QueryAndScope,
    /// The request has no `dcql_query` (Section 5.1).
    DcqlQueryMissing,
    /// A parameter of a form-encoded request is no JSON text (Section 5.1).
    ParameterNotJson(JsonParameter, #[source] JsonTextError),
    /// `dcql_query` is no DCQL query `siros-dcql` accepts.
    DcqlQueryInvalid(#[source] QueryError),
    /// `transaction_data` is not a non-empty array of strings (Section 5.1).
    TransactionDataInvalid,
    /// A parameter breaks a rule that needs no key: the rule.
    Parameter(#[from] ParameterFault),
    /// An encrypted Response Mode, and no key of `jwks` is a P-256 `ECDH-ES` encryption key.
    EncryptionKeyMissing,
    /// No key of `jwks` is a usable P-256 `ECDH-ES` encryption key, and the first that names
    /// P-256 is no P-256 key: its fault.
    EncryptionKeyInvalid(#[source] JwkFault),
    /// `encrypted_response_enc_values_supported` names no `enc` of the Response Mode's
    /// envelope: `A128GCM` or `A256GCM` for a JWE, these or `A192GCM` for a `COSE_Encrypt`.
    EncryptionUnsupported,
    /// The host answered an effect with the result of the other kind.
    AnswerMismatch,
    /// The host's trust answer carries a key or metadata the subject takes none of.
    UnexpectedTrustKey,
    /// The state holds more answers than the request asked effects.
    UnusedAnswer,
}

/// Why an authorization request URI has no query of form-encoded parameters (Section 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FormFault {
    /// The URI has no query.
    #[error("the URI has no query")]
    NoQuery,
    /// A parameter name repeats.
    #[error("a parameter name repeats")]
    RepeatedName,
    /// A `%` is not followed by two hexadecimal digits.
    #[error("a `%` is not followed by two hexadecimal digits")]
    Escape,
    /// A decoded name or value is not UTF-8.
    #[error("a decoded name or value is not UTF-8")]
    NotUtf8(#[source] Utf8Error),
}

/// The rule a JWS breaks (RFC 7515, Sections 7.1 and 7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum JwsFault {
    /// A Compact Serialization is not three segments.
    #[error("a Compact Serialization is not three segments")]
    Segments,
    /// A segment is not unpadded base64url.
    #[error("a segment is not unpadded base64url")]
    Encoding(#[source] Base64Error),
    /// The protected header is not a JSON object.
    #[error("the protected header is not a JSON object")]
    Header,
    /// The signature is not the 64 bytes of an ES256 `r ‖ s`.
    #[error("the signature is not the 64 bytes of an ES256 `r ‖ s`")]
    Signature,
    /// A JSON Serialization lacks a string `payload` or an array `signatures`, or a signature
    /// lacks a string `protected` or `signature`.
    #[error("a JSON Serialization lacks a string `payload` or an array `signatures`, or a signature lacks a string `protected` or `signature`")]
    Serialization,
    /// The `trust_chain` Header Parameter is not an array of strings.
    #[error("the `trust_chain` Header Parameter is not an array of strings")]
    TrustChain,
}

/// Why a JWS is refused: its serialization, its algorithm, or a critical extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum JwsError {
    /// The serialization breaks a rule.
    #[error("the serialization breaks a rule")]
    Malformed(#[source] JwsFault),
    /// `alg` is not `ES256`.
    #[error("`alg` is not `ES256`")]
    AlgorithmUnsupported,
    /// The header has `crit` (RFC 7515, Section 4.1.11).
    #[error("the header has `crit` (RFC 7515, Section 4.1.11)")]
    CriticalHeader,
}

/// The rule an `x5c` Header Parameter breaks (RFC 7515, Section 4.1.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ChainFault {
    /// `x5c` is absent, not an array, or empty.
    #[error("`x5c` is absent, not an array, or empty")]
    Absent,
    /// A certificate is not a string.
    #[error("a certificate is not a string")]
    NotString,
    /// A certificate is not base64 with padding.
    #[error("a certificate is not base64 with padding")]
    Encoding(#[source] Base64Error),
    /// The leaf is not a DER X.509 certificate.
    #[error("the leaf is not a DER X.509 certificate")]
    LeafNotCertificate(#[source] der::Error),
    /// The leaf's key is not a P-256 key.
    #[error("the leaf's key is not a P-256 key")]
    LeafKey(#[source] LeafKeyFault),
    /// The leaf's SubjectAltName extension does not decode.
    #[error("the leaf's SubjectAltName extension does not decode")]
    SubjectAltName(#[source] der::Error),
}

/// Why a leaf certificate's key is no P-256 key (RFC 5480).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LeafKeyFault {
    /// The key's algorithm is this one, where the wallet takes `id-ecPublicKey`.
    #[error("the key's algorithm is {0}, where the wallet takes `id-ecPublicKey`")]
    Algorithm(ObjectIdentifier),
    /// The `id-ecPublicKey` parameters are absent.
    #[error("the `id-ecPublicKey` parameters are absent")]
    CurveAbsent,
    /// The parameters are no OBJECT IDENTIFIER.
    #[error("the parameters are no OBJECT IDENTIFIER")]
    Curve(#[source] der::Error),
    /// The named curve is this one, where the wallet takes `prime256v1`.
    #[error("the named curve is {0}, where the wallet takes `prime256v1`")]
    OtherCurve(ObjectIdentifier),
    /// The subjectPublicKey BIT STRING has unused bits.
    #[error("the subjectPublicKey BIT STRING has unused bits")]
    Unaligned,
    /// The point is not on the curve.
    #[error("the point is not on the curve")]
    Point,
}

/// A coordinate of an EC JWK (RFC 7518, Section 6.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Coordinate {
    /// `x`.
    X,
    /// `y`.
    Y,
}

impl Coordinate {
    /// The member's name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::X => "x",
            Self::Y => "y",
        }
    }
}

/// Why a JWK is no public P-256 key (RFC 7518, Section 6.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum JwkFault {
    /// `kty` is not `EC`, or `crv` is not `P-256`.
    #[error("`kty` is not `EC`, or `crv` is not `P-256`")]
    OtherKey,
    /// The coordinate is absent or not a string.
    #[error("the coordinate `{}` is absent or not a string", .0.as_str())]
    CoordinateAbsent(Coordinate),
    /// The coordinate is not unpadded base64url.
    #[error("the coordinate `{}` is not unpadded base64url", .0.as_str())]
    CoordinateEncoding(Coordinate, #[source] Base64Error),
    /// The coordinate has this many bytes, where P-256 takes 32.
    #[error("the coordinate `{name}` has {length} bytes, where P-256 takes 32", name = .0.as_str(), length = .1)]
    CoordinateLength(Coordinate, usize),
    /// The point is not on the curve.
    #[error("the point is not on the curve")]
    Point,
}

/// A claim of a Verifier Attestation JWT the wallet reads (Section 12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttestationClaim {
    /// `iss`: a string.
    Iss,
    /// `sub`: a string.
    Sub,
    /// `exp`: a number.
    Exp,
    /// `nbf`: a number, when present.
    Nbf,
    /// `cnf`: an object with a `jwk`.
    Cnf,
    /// `redirect_uris`: an array of strings, when present.
    RedirectUris,
}

impl AttestationClaim {
    /// The claim's name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Iss => "iss",
            Self::Sub => "sub",
            Self::Exp => "exp",
            Self::Nbf => "nbf",
            Self::Cnf => "cnf",
            Self::RedirectUris => "redirect_uris",
        }
    }
}

/// Why the claims of a Verifier Attestation JWT are refused (Section 12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ClaimsFault {
    /// The payload is no JSON object.
    #[error("the payload is no JSON object")]
    NotObject(#[source] JsonTextError),
    /// The claim breaks its rule.
    #[error("the claim `{}` breaks its rule", .0.as_str())]
    Claim(AttestationClaim, #[source] MemberFault),
    /// `cnf.jwk` is no P-256 key.
    #[error("`cnf.jwk` is no P-256 key")]
    Key(#[source] JwkFault),
}

/// The rule the `jwt` Header Parameter of a `verifier_attestation` request breaks (Section 12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AttestationFault {
    /// The request has no string `jwt` Header Parameter.
    #[error("the request has no string `jwt` Header Parameter")]
    Absent,
    /// `jwt` is not a JWS this wallet reads.
    #[error("`jwt` is not a JWS this wallet reads")]
    Jws(#[source] JwsError),
    /// The attestation's `typ` is not `verifier-attestation+jwt`.
    #[error("the attestation's `typ` is not `verifier-attestation+jwt`")]
    Typ,
    /// The attestation's claims break a rule.
    #[error("the attestation's claims break a rule")]
    Claims(#[source] ClaimsFault),
}

/// A request parameter that holds JSON (Section 5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JsonParameter {
    /// `dcql_query`.
    DcqlQuery,
    /// `client_metadata`.
    ClientMetadata,
    /// `transaction_data`.
    TransactionData,
}

impl JsonParameter {
    /// The code of a refusal of the parameter.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::DcqlQuery => "dcql_query_invalid",
            Self::ClientMetadata => "client_metadata_invalid",
            Self::TransactionData => "transaction_data_invalid",
        }
    }
}

impl IntakeError {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotAnAuthorizationRequest(_) => "not_an_authorization_request",
            Self::ClientIdMissing => "client_id_missing",
            Self::RequestAndRequestUri => "request_and_request_uri",
            Self::RequestUriMethodWithoutRequestUri => "request_uri_method_without_request_uri",
            Self::RequestUriMethodInvalid => "request_uri_method_invalid",
            Self::RequestUriNotHttps => "request_uri_not_https",
            Self::JwsMalformed(_) => "jws_malformed",
            Self::AlgorithmUnsupported => "algorithm_unsupported",
            Self::CriticalHeader => "critical_header",
            Self::TypMismatch => "typ_mismatch",
            Self::SignatureInvalid => "signature_invalid",
            Self::RequestObjectNotObject => "request_object_not_object",
            Self::ClientIdMismatch => "client_id_mismatch",
            Self::WalletNonceMismatch => "wallet_nonce_mismatch",
            Self::ClientId(e) => e.code(),
            Self::SignedRedirectUri => "signed_redirect_uri",
            Self::UnsignedNeedsRedirectUri => "unsigned_needs_redirect_uri",
            Self::CertificateChainInvalid(_) => "certificate_chain_invalid",
            Self::SanMismatch => "san_mismatch",
            Self::CertificateHashMismatch => "certificate_hash_mismatch",
            Self::KidNotOfClient => "kid_not_of_client",
            Self::KeyNotResolved => "key_not_resolved",
            Self::ResolvedKeyInvalid(_) => "resolved_key_invalid",
            Self::AttestationInvalid(_) => "attestation_invalid",
            Self::AttestationSubjectMismatch => "attestation_subject_mismatch",
            Self::AttestationExpired => "attestation_expired",
            Self::AttestationSignatureInvalid => "attestation_signature_invalid",
            Self::RedirectUriNotAttested => "redirect_uri_not_attested",
            Self::ClientIdInPayload => "client_id_in_payload",
            Self::VerifierInfoInPayload => "verifier_info_in_payload",
            Self::NoVerifiableSignature => "no_verifiable_signature",
            Self::EnvelopeUnreadable | Self::EnvelopeNotJson(_) => "envelope_unreadable",
            Self::OriginNotExpected => "origin_not_expected",
            Self::ResponseUriMissing => "response_uri_missing",
            Self::ResponseUriNotHttps => "response_uri_not_https",
            Self::RedirectUriWithDirectPost => "redirect_uri_with_direct_post",
            Self::ResponseUriNotClientId => "response_uri_not_client_id",
            Self::ResponseUriHostMismatch => "response_uri_host_mismatch",
            Self::ScopeUnsupported => "scope_unsupported",
            Self::QueryAndScope => "query_and_scope",
            Self::DcqlQueryMissing => "dcql_query_missing",
            Self::ParameterNotJson(parameter, _) => parameter.code(),
            Self::DcqlQueryInvalid(_) => "dcql_query_invalid",
            Self::TransactionDataInvalid => "transaction_data_invalid",
            Self::Parameter(fault) => fault.code(),
            Self::EncryptionKeyMissing => "encryption_key_missing",
            Self::EncryptionKeyInvalid(_) => "encryption_key_invalid",
            Self::EncryptionUnsupported => "encryption_unsupported",
            Self::AnswerMismatch => "answer_mismatch",
            Self::UnexpectedTrustKey => "unexpected_trust_key",
            Self::UnusedAnswer => "unused_answer",
        }
    }

    /// The error code of OpenID4VP 1.0, Section 8.5, a Verifier receives for this refusal.
    #[must_use]
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::RequestUriMethodInvalid => ErrorCode::InvalidRequestUriMethod,
            Self::ScopeUnsupported => ErrorCode::InvalidScope,
            Self::NotAnAuthorizationRequest(_)
            | Self::ClientIdMissing
            | Self::RequestAndRequestUri
            | Self::RequestUriMethodWithoutRequestUri
            | Self::RequestUriNotHttps
            | Self::JwsMalformed(_)
            | Self::AlgorithmUnsupported
            | Self::CriticalHeader
            | Self::TypMismatch
            | Self::SignatureInvalid
            | Self::RequestObjectNotObject
            | Self::ClientIdMismatch
            | Self::WalletNonceMismatch
            | Self::ClientId(_)
            | Self::SignedRedirectUri
            | Self::UnsignedNeedsRedirectUri
            | Self::CertificateChainInvalid(_)
            | Self::SanMismatch
            | Self::CertificateHashMismatch
            | Self::KidNotOfClient
            | Self::KeyNotResolved
            | Self::ResolvedKeyInvalid(_)
            | Self::AttestationInvalid(_)
            | Self::AttestationSubjectMismatch
            | Self::AttestationExpired
            | Self::AttestationSignatureInvalid
            | Self::RedirectUriNotAttested
            | Self::ClientIdInPayload
            | Self::VerifierInfoInPayload
            | Self::NoVerifiableSignature
            | Self::EnvelopeUnreadable
            | Self::EnvelopeNotJson(_)
            | Self::OriginNotExpected
            | Self::ResponseUriMissing
            | Self::ResponseUriNotHttps
            | Self::RedirectUriWithDirectPost
            | Self::ResponseUriNotClientId
            | Self::ResponseUriHostMismatch
            | Self::QueryAndScope
            | Self::DcqlQueryMissing
            | Self::ParameterNotJson(..)
            | Self::DcqlQueryInvalid(_)
            | Self::TransactionDataInvalid
            | Self::Parameter(_)
            | Self::EncryptionKeyMissing
            | Self::EncryptionKeyInvalid(_)
            | Self::EncryptionUnsupported
            | Self::AnswerMismatch
            | Self::UnexpectedTrustKey
            | Self::UnusedAnswer => ErrorCode::InvalidRequest,
        }
    }
}

impl From<JwsError> for IntakeError {
    fn from(error: JwsError) -> Self {
        match error {
            JwsError::Malformed(fault) => Self::JwsMalformed(fault),
            JwsError::AlgorithmUnsupported => Self::AlgorithmUnsupported,
            JwsError::CriticalHeader => Self::CriticalHeader,
        }
    }
}

impl From<JwsRule> for JwsError {
    fn from(rule: JwsRule) -> Self {
        match rule {
            JwsRule::Serialization => Self::Malformed(JwsFault::Serialization),
            JwsRule::Header => Self::Malformed(JwsFault::Header),
            JwsRule::Signature => Self::Malformed(JwsFault::Signature),
            JwsRule::Algorithm => Self::AlgorithmUnsupported,
            JwsRule::Critical => Self::CriticalHeader,
        }
    }
}

impl From<JwsRule> for IntakeError {
    fn from(rule: JwsRule) -> Self {
        JwsError::from(rule).into()
    }
}
