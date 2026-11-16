//! The response to a verified request (P4 to P6): the `vp_token` (Section 8.1), its submission
//! in the form of the Response Mode, error submissions (Section 8.5), and the Verifier's reply
//! to a direct post (Section 8.2).

mod aead;
mod cose;
mod jwe;
mod reply;
mod submission;
mod vp_token;

use rand_core::CryptoRngCore;
use serde_json::Value;
use siros_codec::json::JsonTextError;

pub use aead::ContentKey;
pub use cose::cose_kdf;
pub use jwe::concat_kdf;
pub use reply::{RedirectUri, Reply};
pub use submission::{
    CoseEncrypt, DcApiData, Jwe, Outcome, Post, PostBody, PostParameters, ResponseParameters,
    Submission,
};
pub use vp_token::{Presentation, VpToken, VpTokenJson};

use crate::bound::TooLarge;
use crate::error_code::ErrorCode;
use crate::verified::{Channel, PostEncoding, VerifiedRequest};
use vp_token::Answer;

/// Why no response could be built or read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}", self.code())]
pub enum ResponseError {
    /// A `vp_token` key is not the `id` of a Credential Query of the request.
    UnknownQueryId,
    /// A `vp_token` key repeats.
    DuplicateQueryId,
    /// A `vp_token` entry has no presentation.
    NoPresentation,
    /// A `vp_token` entry has several presentations, and its query does not set `multiple`.
    MultipleNotAllowed,
    /// A CBOR presentation is not one CBOR map.
    PresentationNotCborMap,
    /// The JWE or the `COSE_Encrypt` could not be produced.
    EncryptionFailed(#[source] EncryptionFault),
    /// The reply is no JSON object the wallet reads.
    ReplyUnreadable(#[source] ReplyFault),
    /// The reply's `redirect_uri` is not an absolute URI (RFC 3986, Section 4.3).
    RedirectUriInvalid,
}

impl ResponseError {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::UnknownQueryId => "unknown_query_id",
            Self::DuplicateQueryId => "duplicate_query_id",
            Self::NoPresentation => "no_presentation",
            Self::MultipleNotAllowed => "multiple_not_allowed",
            Self::PresentationNotCborMap => "presentation_not_cbor_map",
            Self::EncryptionFailed(_) => "encryption_failed",
            Self::ReplyUnreadable(_) => "reply_unreadable",
            Self::RedirectUriInvalid => "redirect_uri_invalid",
        }
    }
}

/// The step of an encryption that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum EncryptionFault {
    /// The ephemeral public key has no affine coordinates.
    #[error("the ephemeral public key has no affine coordinates")]
    EphemeralKey,
    /// A Concat KDF input is longer than a 32-bit length allows.
    #[error("a Concat KDF input is longer than a 32-bit length allows")]
    KdfInput,
    /// The KDF cannot give a key of the length of `enc`.
    #[error("the KDF cannot give a key of the length of `enc`")]
    KdfLength,
    /// The cipher refused the key or the plaintext.
    #[error("the cipher refused the key or the plaintext")]
    Seal,
}

/// Why a reply to a direct post is no JSON object the wallet reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum ReplyFault {
    /// The reply is longer than [`Reply::MAX_BYTES`].
    #[error("the reply is too long")]
    TooLarge(#[source] TooLarge),
    /// The reply is no JSON text.
    #[error("the reply is no JSON text")]
    NotJson(#[source] JsonTextError),
    /// The reply is JSON other than an object.
    #[error("the reply is JSON other than an object")]
    NotObject,
}

impl VerifiedRequest {
    /// The submission refusing this request with `code` (P5: the response target is
    /// verified). Over redirects it carries `state`, encrypted as the Response Mode encrypts,
    /// with a key and IV from `rng`; over the DC API it is `{"error": code}` (A.4).
    ///
    /// # Errors
    ///
    /// [`ResponseError::EncryptionFailed`].
    pub fn error_submission(
        &self,
        code: ErrorCode,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Submission, ResponseError> {
        match &self.channel {
            Channel::Redirect { .. } => self.submit(&Answer::Error(code), rng),
            Channel::DcApi { .. } => Ok(Submission::dc_api_error(code)),
        }
    }

    /// The submission of `answer` in the form of the Response Mode (P4).
    fn submit(
        &self,
        answer: &Answer<'_>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Submission, ResponseError> {
        match &self.channel {
            Channel::Redirect {
                response_uri,
                encoding,
                ..
            } => {
                let state = self.state.as_ref();
                let parameters = match encoding {
                    PostEncoding::Form => PostParameters::Form(answer.parameters(state)),
                    PostEncoding::Jwe(encryption) => {
                        let payload = Value::Object(answer.parameters(state).json()).to_string();
                        PostParameters::Jwt(jwe::encrypt(encryption, payload.as_bytes(), rng)?)
                    }
                    PostEncoding::Cose(encryption) => {
                        let payload = answer.cbor(state).encode();
                        PostParameters::Cwt(cose::encrypt(encryption, &payload, rng)?)
                    }
                };
                Ok(Submission::Post(Post::new(
                    response_uri.clone(),
                    parameters,
                )))
            }
            Channel::DcApi { encryption, .. } => Ok(Submission::DcApi(match encryption {
                None => DcApiData::Json(answer.outcome()),
                Some(encryption) => {
                    let payload = Value::Object(answer.outcome().json()).to_string();
                    DcApiData::Jwt(jwe::encrypt(encryption, payload.as_bytes(), rng)?)
                }
            })),
        }
    }
}

impl VpToken<'_> {
    /// The submission of this `vp_token` in the form of the request's Response Mode (P4):
    ///
    /// | Mode | Form |
    /// |---|---|
    /// | `direct_post` | form parameters `vp_token`, `state` |
    /// | `direct_post.jwt` | form parameter `response`: the JWE of `{vp_token, state}` |
    /// | `direct_post.cwt` | an `application/cwt` body: the `COSE_Encrypt` of the CBOR `{vp_token, state}` |
    /// | `dc_api` | `{vp_token}` |
    /// | `dc_api.jwt` | `{response}`: the JWE of `{vp_token}` |
    ///
    /// `rng` gives the ephemeral key and IV of an encrypted mode.
    ///
    /// # Errors
    ///
    /// [`ResponseError::EncryptionFailed`].
    pub fn submission(&self, rng: &mut impl CryptoRngCore) -> Result<Submission, ResponseError> {
        self.request.submit(&Answer::VpToken(self), rng)
    }
}
