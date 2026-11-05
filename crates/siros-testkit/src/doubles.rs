//! The doubles of the core's response types and their parameters, response modes and hash
//! algorithms: each states what a test gives it, an output the core must refuse included.

use std::num::NonZeroUsize;

use serde_json::value::RawValue;
use sha2::{Digest, Sha256};
use siros_openid4vp::detail;
use siros_openid4vp::hash::{HashAlgorithm, HashName};
use siros_openid4vp::json::quote;
use siros_openid4vp::plugins::Fault;
use siros_openid4vp::refusal::Refusal;
use siros_openid4vp::request::{Agreements, ClientMetadata, ContentEncryption, Request};
use siros_openid4vp::resolve::{
    AnswerContent, Body, DcApiData, ErrorContent, ModeRoute, PostBody, ResponseMember,
};
use siros_openid4vp::routing::{
    ChannelKind, Encrypting, ErrorModeHost, Mode, ModeHost, ModeName, ResponseParameters,
    ResponseParametersHost, ResponseType, ResponseTypeName, VerifierKey, VerifierMetadata,
};
use siros_openid4vp::session::Session;
use siros_openid4vp::uri::FormBody;
use siros_openid4vp::wallet_metadata::{MetadataMember, ParameterName};

use crate::FAULT;

use crate::rules::TestRule;

/// A response type of the name given (RFC 6749 §3.1.1).
#[derive(Debug, Clone, Copy)]
pub struct TestResponseType(pub ResponseTypeName);

impl ResponseType for TestResponseType {
    fn name(&self) -> ResponseTypeName {
        self.0
    }
}

/// Parameters of the Authorization Response that declare the names given and write the members
/// given, under every response type, which may name what they did not declare.
#[derive(Debug, Clone)]
pub struct TestResponseParameters {
    /// The names declared.
    pub names: &'static [ParameterName],
    /// The members written.
    pub writes: Vec<ResponseMember>,
}

impl ResponseParameters for TestResponseParameters {
    fn names(&self) -> &'static [ParameterName] {
        self.names
    }
}

/// Needs no module.
impl<H> ResponseParametersHost<H> for TestResponseParameters {
    fn members(
        &self,
        _response_type: ResponseTypeName,
        _session: &Session<'_>,
        _host: &H,
    ) -> Result<Vec<ResponseMember>, Fault> {
        Ok(self.writes.clone())
    }
}

/// The encryption a [`TestMode`] chooses, which the core checks: a key the request does not
/// name, a choice the sealing statement does not admit, an `enc` the Verifier does not list, or a
/// key on a route in the clear, is a `Fault`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestChoice {
    /// In the clear.
    Plain,
    /// The Verifier's key at this place among its agreeable keys, and this `enc`, whatever the
    /// statement admits; the mode's rule refuses (C7 under the mode's name) when the Verifier
    /// has no key at the place.
    Key {
        /// The key's place.
        place: usize,
        /// The content encryption.
        enc: ContentEncryption<'static>,
    },
    /// A P-256 `ECDH-ES` key of other metadata than the request's, and this `enc`.
    Foreign {
        /// The content encryption.
        enc: ContentEncryption<'static>,
    },
}

/// The one key of metadata the double reads apart from every request's.
const FOREIGN: &str = r#"{"jwks":{"keys":[{"kty":"EC","crv":"P-256","kid":"foreign","x":"DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0","y":"XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc","use":"enc","alg":"ECDH-ES"}]}}"#;

/// The key of [`FOREIGN`]; the metadata it lives in is leaked, so it outlives every request.
fn foreign() -> Result<VerifierKey<'static>, Fault> {
    let raw: &'static RawValue = serde_json::from_str(FOREIGN)
        .map_err(|e| Fault::caused(FAULT, detail!("the foreign metadata's JSON"), e))?;
    let metadata: &'static ClientMetadata<'static> =
        Box::leak(Box::new(ClientMetadata::parse(Some(raw)).map_err(|e| {
            Fault::caused(FAULT, detail!("the foreign metadata"), e)
        })?));
    let metadata: &'static VerifierMetadata<'static> =
        Box::leak(Box::new(VerifierMetadata::new(metadata)));
    metadata
        .keys()
        .iter()
        .next()
        .ok_or_else(|| Fault::new(FAULT, detail!("the foreign metadata's key")))
}

/// The channel whose body a [`TestMode`] writes: its own, or the other, which the core refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestBody {
    /// The mode's channel.
    Own,
    /// The other channel.
    Other,
}

/// A response mode a test configures, for answers and for errors: its name and channel, its request rule, the
/// `wallet_metadata` names it declares and the members it writes, which may name what it did not
/// declare, its encryption choice, and the channel whose body it writes. A DC API body is the
/// clear response's JSON or `{"response": JWE}`; a POST body the form of `vp_token` and `state`
/// or `response=<JWE>`.
#[derive(Debug, Clone)]
pub struct TestMode {
    /// The `response_mode` value.
    pub name: ModeName,
    /// The channel it answers on.
    pub channel: ChannelKind,
    /// The rule it refuses every request with, when given.
    pub refuses: Option<TestRule>,
    /// The `wallet_metadata` names it declares.
    pub declares: &'static [ParameterName],
    /// The members it writes.
    pub writes: Vec<MetadataMember>,
    /// Its encryption.
    pub choice: TestChoice,
    /// The channel whose body it writes.
    pub body: TestBody,
}

impl TestMode {
    /// A mode in the clear of the name and channel, without a rule, declaring and writing nothing.
    #[must_use]
    pub const fn new(name: ModeName, channel: ChannelKind) -> Self {
        Self {
            name,
            channel,
            refuses: None,
            declares: &[],
            writes: Vec::new(),
            choice: TestChoice::Plain,
            body: TestBody::Own,
        }
    }
}

impl Mode for TestMode {
    fn name(&self) -> ModeName {
        self.name
    }

    fn channel(&self) -> ChannelKind {
        self.channel
    }

    fn rules(&self, _request: &Request<'_>, _metadata: &VerifierMetadata<'_>) -> Vec<Refusal> {
        self.refuses.iter().cloned().map(Refusal::new).collect()
    }

    fn metadata_names(&self) -> &'static [ParameterName] {
        self.declares
    }
}

/// Needs no module.
impl<H> ModeHost<H> for TestMode {
    fn encryption<'k>(
        &self,
        metadata: &'k VerifierMetadata<'k>,
        _sealer: &Agreements,
        _host: &H,
    ) -> Result<Encrypting<'k>, Refusal> {
        match self.choice {
            TestChoice::Plain => Ok(Encrypting::Plain),
            TestChoice::Key { place, enc } => metadata
                .keys()
                .iter()
                .nth(place)
                .map(|key| Encrypting::Jwe { key, enc })
                .ok_or_else(|| {
                    Refusal::new(TestRule::invalid_request(format!(
                        "C7 {}: no key at place {place}",
                        self.name
                    )))
                }),
            TestChoice::Foreign { enc } => foreign()
                .map(|key| Encrypting::Jwe { key, enc })
                .map_err(|fault| {
                    Refusal::new(TestRule::invalid_request(format!(
                        "C7 {}: {fault}",
                        self.name
                    )))
                }),
        }
    }

    fn wallet_metadata(
        &self,
        _sealer: &Agreements,
        _host: &H,
    ) -> Result<Vec<MetadataMember>, Fault> {
        Ok(self.writes.clone())
    }

    fn answer(
        &self,
        _route: &ModeRoute<'_>,
        content: &AnswerContent<'_>,
        _host: &H,
    ) -> Result<Body, Fault> {
        let channel = match (self.body, self.channel) {
            (TestBody::Own, channel) => channel,
            (TestBody::Other, ChannelKind::DcApi) => ChannelKind::Uri,
            (TestBody::Other, ChannelKind::Uri) => ChannelKind::DcApi,
        };
        let fault = |e| Fault::caused(FAULT, detail!("a test mode's body"), e);
        Ok(match (channel, content) {
            (ChannelKind::DcApi, AnswerContent::Clear(response)) => {
                Body::DcApi(DcApiData::of(response.json()).map_err(fault)?)
            }
            (ChannelKind::DcApi, AnswerContent::Sealed(jwe)) => Body::DcApi(
                DcApiData::of(format!(r#"{{"response":{}}}"#, quote(jwe.as_str())))
                    .map_err(fault)?,
            ),
            (ChannelKind::Uri, AnswerContent::Clear(response)) => {
                let vp_token = response.vp_token().json();
                let mut members = vec![("vp_token", vp_token.as_str())];
                if let Some(state) = response.state() {
                    members.push(("state", state.as_str()));
                }
                Body::Post(PostBody::form(FormBody::of(&members).map_err(|e| {
                    Fault::caused(FAULT, detail!("a test mode's form"), e)
                })?))
            }
            (ChannelKind::Uri, AnswerContent::Sealed(jwe)) => Body::Post(PostBody::form(
                FormBody::of(&[("response", jwe.as_str())])
                    .map_err(|e| Fault::caused(FAULT, detail!("a test mode's form"), e))?,
            )),
        })
    }
}

/// Needs no module: the plain error form of `error`, `error_description` and `state`, or
/// `response=<JWE>`.
impl<H> ErrorModeHost<H> for TestMode {
    fn error(
        &self,
        _route: &ModeRoute<'_>,
        content: &ErrorContent<'_>,
        _host: &H,
    ) -> Result<PostBody, Fault> {
        let members = match content {
            ErrorContent::Clear(error) => {
                let mut members = vec![("error", error.code().as_str())];
                if let Some(description) = error.description() {
                    members.push(("error_description", description.as_str()));
                }
                if let Some(echo) = error.echo() {
                    members.push(("state", echo.as_str()));
                }
                members
            }
            ErrorContent::Sealed(jwe) => vec![("response", jwe.as_str())],
        };
        FormBody::of(&members)
            .map(PostBody::form)
            .map_err(|e| Fault::caused(FAULT, detail!("a test mode's form"), e))
    }
}

/// A hash algorithm of the name and digest length given, whose digest is SHA-256's octets, cycled
/// or cut to `writes`: a `writes` other than `octets` breaks the contract the core checks.
#[derive(Debug, Clone, Copy)]
pub struct TestHash {
    /// The Hash Name String.
    pub name: HashName,
    /// The digest length it states.
    pub octets: NonZeroUsize,
    /// The digest length it writes.
    pub writes: usize,
}

impl HashAlgorithm for TestHash {
    fn name(&self) -> HashName {
        self.name
    }

    fn octets(&self) -> NonZeroUsize {
        self.octets
    }

    fn digest(&self, data: &[u8]) -> Vec<u8> {
        Sha256::digest(data)
            .iter()
            .copied()
            .cycle()
            .take(self.writes)
            .collect()
    }
}
