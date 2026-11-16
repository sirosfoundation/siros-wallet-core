//! A submission: the Authorization Response in the form of its Response Mode (P4), as data the
//! host transmits. The host POSTs a [`Post`]'s body to its `response_uri` and follows no
//! redirect: a 307 or 308 resends the body to another URI (Sections 8.2 and 14.3.1; RFC 9700,
//! Section 4.12).

use serde_json::{Map, Value};
use siros_codec::url::HttpsUrl;

use super::vp_token::VpTokenJson;
use crate::error_code::ErrorCode;
use crate::form::{self, FormBody};
use crate::parameters::State;
use crate::request::ResponseMode;

/// What the wallet sends the Verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Submission {
    /// `direct_post`, `direct_post.jwt` or `direct_post.cwt`: the response the wallet sends to
    /// the Response URI (Section 8.2). The Verifier's reply goes to
    /// [`Reply::parse`](super::Reply::parse).
    Post(Post),
    /// `dc_api` or `dc_api.jwt`: the `data` the platform returns to the caller (A.4).
    DcApi(DcApiData),
}

impl Submission {
    /// `{"error": code}`, as the DC API returns a refusal (A.4).
    pub(crate) fn dc_api_error(code: ErrorCode) -> Self {
        Self::DcApi(DcApiData::Json(Outcome::Error(code)))
    }

    /// The Response Mode whose form this is.
    #[must_use]
    pub fn mode(&self) -> ResponseMode {
        match self {
            Self::Post(post) => post.mode(),
            Self::DcApi(data) => data.mode(),
        }
    }
}

/// A response to the Response URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Post {
    response_uri: HttpsUrl,
    parameters: PostParameters,
}

impl Post {
    pub(super) fn new(response_uri: HttpsUrl, parameters: PostParameters) -> Self {
        Self {
            response_uri,
            parameters,
        }
    }

    /// The request's `response_uri`.
    #[must_use]
    pub fn response_uri(&self) -> &HttpsUrl {
        &self.response_uri
    }

    /// The parameters, in the form of the Response Mode.
    #[must_use]
    pub fn parameters(&self) -> &PostParameters {
        &self.parameters
    }

    /// The Response Mode: `direct_post`, `direct_post.jwt` or `direct_post.cwt`.
    #[must_use]
    pub fn mode(&self) -> ResponseMode {
        match self.parameters {
            PostParameters::Form(_) => ResponseMode::DirectPost,
            PostParameters::Jwt(_) => ResponseMode::DirectPostJwt,
            PostParameters::Cwt(_) => ResponseMode::DirectPostCwt,
        }
    }

    /// The body: the response parameters, or `response`, as form parameters (Sections 8.2 and
    /// 8.3.1), or the `COSE_Encrypt` (`zkp_req.md`, Section 6.2).
    #[must_use]
    pub fn body(&self) -> PostBody<'_> {
        match &self.parameters {
            PostParameters::Form(parameters) => PostBody::Form(parameters.form()),
            PostParameters::Jwt(jwe) => PostBody::Form(form::encode(&[("response", jwe.as_str())])),
            PostParameters::Cwt(message) => PostBody::Cwt(message),
        }
    }
}

/// The parameters of a response to the Response URI, as its Response Mode carries them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostParameters {
    /// `direct_post`: the response parameters (Section 8.2).
    Form(ResponseParameters),
    /// `direct_post.jwt`: `response`, the JWE of the response parameters (Section 8.3.1).
    Jwt(Jwe),
    /// `direct_post.cwt`: the `COSE_Encrypt` of the response parameters in CBOR (`zkp_req.md`,
    /// Section 6.2).
    Cwt(CoseEncrypt),
}

/// The body of a [`Post`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostBody<'a> {
    /// Form parameters.
    Form(FormBody),
    /// A `COSE_Encrypt`, the `application/cwt` body of `direct_post.cwt`.
    Cwt(&'a CoseEncrypt),
}

/// The `data` of a DC API response (A.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DcApiData {
    /// `dc_api`: the outcome.
    Json(Outcome),
    /// `dc_api.jwt`: `response`, the JWE of the outcome.
    Jwt(Jwe),
}

impl DcApiData {
    /// The Response Mode: `dc_api` or `dc_api.jwt`.
    #[must_use]
    pub fn mode(&self) -> ResponseMode {
        match self {
            Self::Json(_) => ResponseMode::DcApi,
            Self::Jwt(_) => ResponseMode::DcApiJwt,
        }
    }

    /// The `data` object: `{vp_token}`, `{error}` or `{response}`.
    #[must_use]
    pub fn json(&self) -> Value {
        Value::Object(match self {
            Self::Json(outcome) => outcome.json(),
            Self::Jwt(jwe) => Map::from_iter([("response".to_owned(), jwe.as_str().into())]),
        })
    }
}

/// The response parameters of a redirect response: the outcome, and the request's `state`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseParameters {
    outcome: Outcome,
    state: Option<State>,
}

impl ResponseParameters {
    pub(super) fn new(outcome: Outcome, state: Option<State>) -> Self {
        Self { outcome, state }
    }

    /// `vp_token` or `error`.
    #[must_use]
    pub fn outcome(&self) -> &Outcome {
        &self.outcome
    }

    /// `state`, when the request has one.
    #[must_use]
    pub fn state(&self) -> Option<&State> {
        self.state.as_ref()
    }

    /// The parameters in JSON.
    #[must_use]
    pub fn json(&self) -> Map<String, Value> {
        let mut parameters = self.outcome.json();
        if let Some(state) = &self.state {
            parameters.insert("state".into(), state.as_str().into());
        }
        parameters
    }

    /// The parameters as form parameters, the `vp_token` as JSON text (Section 8.2).
    #[must_use]
    pub fn form(&self) -> FormBody {
        let fields: Vec<(String, String)> = self
            .json()
            .into_iter()
            .map(|(name, value)| match value {
                Value::String(text) => (name, text),
                other => (name, other.to_string()),
            })
            .collect();
        let pairs: Vec<(&str, &str)> = fields
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        form::encode(&pairs)
    }
}

/// What an Authorization Response answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// `vp_token` (Section 8.1).
    VpToken(VpTokenJson),
    /// `error` (Section 8.5).
    Error(ErrorCode),
}

impl Outcome {
    /// The parameter in JSON: `vp_token` or `error`.
    #[must_use]
    pub fn json(&self) -> Map<String, Value> {
        let (name, value) = match self {
            Self::VpToken(token) => ("vp_token", Value::Object(token.as_map().clone())),
            Self::Error(code) => ("error", code.as_str().into()),
        };
        Map::from_iter([(name.to_owned(), value)])
    }
}

/// A JWE Compact Serialization (RFC 7516, Section 7.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Jwe(String);

impl Jwe {
    pub(super) fn new(compact: String) -> Self {
        Self(compact)
    }

    /// The serialization.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A tagged `COSE_Encrypt` message, encoded (RFC 9052, Section 5.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CoseEncrypt(Vec<u8>);

impl CoseEncrypt {
    pub(super) fn new(encoded: Vec<u8>) -> Self {
        Self(encoded)
    }

    /// The encoded message.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
