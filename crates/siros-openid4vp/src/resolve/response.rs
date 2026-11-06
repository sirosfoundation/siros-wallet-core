//! The answer: `vp_token`, the bodies a mode writes, and the delivery the caller performs.

use siros_explain::Explain;

use crate::host::{Presentation, SealedJwe};
use crate::ids::{CredentialId, QueryId};
use crate::json::{Node, quote};
use crate::media::MediaType;
use crate::refusal::{ErrorCode, ErrorDescription};
use crate::request::{AgreeableKey, ContentEncryption};
use crate::routing::{Echo, State, VerifierKey};
use crate::uri::{FormBody, ResponseUri};
use crate::wallet_metadata::ParameterName;

/// The key and `enc` a route bound: what the core seals to through `Haip::encrypt_jwe` and what
/// the session holds. Only `Route::new` makes one, from the mode's [`Encrypting::Jwe`] once it
/// has checked it: the key is one of the request's (`VerifierKey`), its curve and `alg` and the
/// `enc` are ones the sealing module states (`Haip::agreements`), and the `enc` is one the
/// Verifier lists (A128GCM when it lists none, §5.1):
///
/// ```compile_fail,E0451
/// use siros_openid4vp::request::ContentEncryption;
/// use siros_openid4vp::resolve::RouteKey;
/// use siros_openid4vp::routing::VerifierKey;
///
/// fn forged<'k>(key: VerifierKey<'k>, enc: ContentEncryption<'static>) -> RouteKey<'k> {
///     RouteKey { key, enc }
/// }
/// ```
///
/// [`Encrypting::Jwe`]: crate::routing::Encrypting::Jwe
#[derive(Debug, Clone, Copy)]
pub struct RouteKey<'k> {
    key: VerifierKey<'k>,
    enc: ContentEncryption<'static>,
}

impl<'k> RouteKey<'k> {
    pub(crate) const fn of(key: VerifierKey<'k>, enc: ContentEncryption<'static>) -> Self {
        Self { key, enc }
    }

    /// The key.
    #[must_use]
    pub const fn key(&self) -> &'k AgreeableKey<'k> {
        self.key.key()
    }

    /// The content encryption.
    #[must_use]
    pub const fn enc(&self) -> ContentEncryption<'static> {
        self.enc
    }
}

#[cfg(feature = "test-util")]
impl<'k> RouteKey<'k> {
    /// The key and `enc` a plug-in's tests seal to, as phase 2 binds them once it has checked
    /// them.
    #[must_use]
    pub const fn new(key: VerifierKey<'k>, enc: ContentEncryption<'static>) -> Self {
        Self::of(key, enc)
    }
}

/// `vp_token`: per Credential Query presented, its presentations in selection order; the queries
/// in the order of their first record.
#[derive(Debug, Clone, Default)]
pub struct VpToken(Vec<(String, Vec<Presentation>)>);

impl VpToken {
    pub(crate) fn push(&mut self, query: &QueryId<'_>, presentation: Presentation) {
        match self.0.iter_mut().find(|(id, _)| id == query.as_str()) {
            Some((_, presentations)) => presentations.push(presentation),
            None => self.0.push((query.to_string(), vec![presentation])),
        }
    }

    /// The JSON text, without whitespace.
    #[must_use]
    pub fn json(&self) -> String {
        let members: Vec<String> = self
            .0
            .iter()
            .map(|(query, presentations)| {
                let items: Vec<&str> = presentations.iter().map(Presentation::as_str).collect();
                format!("{}:[{}]", quote(query), items.join(","))
            })
            .collect();
        format!("{{{}}}", members.join(","))
    }
}

/// One parameter of the Authorization Response beside `vp_token` and `state` (§8.1: "Additional
/// response parameters MAY be defined"): its name and JSON value.
#[derive(Debug, Clone)]
pub struct ResponseMember {
    name: ParameterName,
    value: Node<'static>,
}

impl ResponseMember {
    /// The member.
    #[must_use]
    pub const fn new(name: ParameterName, value: Node<'static>) -> Self {
        Self { name, value }
    }

    /// Its name.
    #[must_use]
    pub const fn name(&self) -> ParameterName {
        self.name
    }

    /// Its value.
    #[must_use]
    pub const fn value(&self) -> &Node<'static> {
        &self.value
    }
}

/// An Authorization Response (§8.1): the VP Token, the request's `state`, and the registered
/// response parameters' members. Only `Prepared::respond` makes one, from the routing:
///
/// ```compile_fail,E0451
/// use siros_openid4vp::resolve::{AuthorizationResponse, VpToken};
///
/// fn forged(vp_token: VpToken) -> AuthorizationResponse<'static> {
///     AuthorizationResponse { vp_token, state: None, members: Vec::new() }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct AuthorizationResponse<'a> {
    vp_token: VpToken,
    state: Option<State<'a>>,
    members: Vec<ResponseMember>,
}

impl<'a> AuthorizationResponse<'a> {
    pub(crate) const fn of(
        vp_token: VpToken,
        state: Option<State<'a>>,
        members: Vec<ResponseMember>,
    ) -> Self {
        Self {
            vp_token,
            state,
            members,
        }
    }

    /// The VP Token.
    #[must_use]
    pub const fn vp_token(&self) -> &VpToken {
        &self.vp_token
    }

    /// `state`, as received.
    #[must_use]
    pub const fn state(&self) -> Option<&State<'a>> {
        self.state.as_ref()
    }

    /// The registered response parameters' members.
    #[must_use]
    pub fn members(&self) -> &[ResponseMember] {
        &self.members
    }

    /// §8.1's JSON object, without whitespace: `vp_token`, `state` when the request has one, then
    /// each member.
    #[must_use]
    pub fn json(&self) -> String {
        let mut text = format!("{{\"vp_token\":{}", self.vp_token.json());
        if let Some(state) = &self.state {
            text.push_str(&format!(",\"state\":{}", quote(state.as_str())));
        }
        for member in &self.members {
            text.push_str(&format!(
                ",{}:{}",
                quote(member.name.as_str()),
                member.value.python_compact()
            ));
        }
        text.push('}');
        text
    }
}

/// An error response (§8.5, RFC 6749 §4.1.2.1): its code, its description, and `state` as
/// received. Only the core's route and rejection make one:
///
/// ```compile_fail,E0451
/// use siros_openid4vp::refusal::ErrorCode;
/// use siros_openid4vp::resolve::ErrorResponse;
///
/// fn forged() -> ErrorResponse<'static> {
///     ErrorResponse { code: ErrorCode::ACCESS_DENIED, description: None, echo: None }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct ErrorResponse<'a> {
    code: ErrorCode,
    description: Option<ErrorDescription>,
    echo: Option<Echo<'a>>,
}

impl<'a> ErrorResponse<'a> {
    pub(crate) const fn of(
        code: ErrorCode,
        description: Option<ErrorDescription>,
        echo: Option<Echo<'a>>,
    ) -> Self {
        Self {
            code,
            description,
            echo,
        }
    }

    /// The code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        self.code
    }

    /// The description.
    #[must_use]
    pub const fn description(&self) -> Option<&ErrorDescription> {
        self.description.as_ref()
    }

    /// `state` as received.
    #[must_use]
    pub const fn echo(&self) -> Option<&Echo<'a>> {
        self.echo.as_ref()
    }

    /// The JSON object the core seals on an encrypted route, without whitespace: `error`,
    /// `error_description` when there is one, `state` when the request has one.
    #[must_use]
    pub fn json(&self) -> String {
        let mut text = format!("{{\"error\":{}", quote(self.code.as_str()));
        if let Some(description) = &self.description {
            text.push_str(&format!(
                ",\"error_description\":{}",
                quote(description.as_str())
            ));
        }
        if let Some(echo) = &self.echo {
            text.push_str(&format!(",\"state\":{}", quote(echo.as_str())));
        }
        text.push('}');
        text
    }
}

/// What a mode wraps for an answer: the clear response on a route in the clear, the JWE the core
/// sealed it in on a sealed one.
#[derive(Debug, Clone, Copy)]
pub enum AnswerContent<'a> {
    /// The Authorization Response, in the clear.
    Clear(&'a AuthorizationResponse<'a>),
    /// The Authorization Response sealed to the route's key.
    Sealed(&'a SealedJwe),
}

/// What an error mode wraps: the clear error on a route the core seals nothing on, the JWE the
/// core sealed it in on a sealed one.
#[derive(Debug, Clone, Copy)]
pub enum ErrorContent<'a> {
    /// The error response, in the clear.
    Clear(&'a ErrorResponse<'a>),
    /// The error response sealed to the route's key.
    Sealed(&'a SealedJwe),
}

/// What a mode reads of its route: the key and `enc` the route bound, and `state` as received.
/// Only the core's route makes one:
///
/// ```compile_fail,E0451
/// use siros_openid4vp::resolve::ModeRoute;
///
/// fn forged() -> ModeRoute<'static> {
///     ModeRoute { encryption: None, echo: None }
/// }
/// ```
#[derive(Debug, Clone, Copy)]
pub struct ModeRoute<'r> {
    encryption: Option<&'r RouteKey<'r>>,
    echo: Option<&'r Echo<'r>>,
}

impl<'r> ModeRoute<'r> {
    pub(crate) const fn of(
        encryption: Option<&'r RouteKey<'r>>,
        echo: Option<&'r Echo<'r>>,
    ) -> Self {
        Self { encryption, echo }
    }

    /// The bound key and `enc`; `None` on a route in the clear.
    #[must_use]
    pub const fn encryption(&self) -> Option<&'r RouteKey<'r>> {
        self.encryption
    }

    /// `state` as received.
    #[must_use]
    pub const fn echo(&self) -> Option<&'r Echo<'r>> {
        self.echo
    }
}

/// What a mode writes: the content its channel carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    /// The DigitalCredential's `data` (A.4).
    DcApi(DcApiData),
    /// A POST body.
    Post(PostBody),
}

/// A POST body with its media type. A form comes from [`FormBody::of`] alone: [`PostBody::of`]
/// refuses `application/x-www-form-urlencoded`, and only the two make one:
///
/// ```compile_fail,E0451
/// use siros_openid4vp::media::MediaType;
/// use siros_openid4vp::resolve::PostBody;
///
/// fn forged(media: MediaType) -> PostBody {
///     PostBody { media, bytes: b"a[b]=1".to_vec() }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostBody {
    media: MediaType,
    bytes: Vec<u8>,
}

/// A POST body of the form media type that no [`FormBody`] wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.post_body")]
#[error("a body of application/x-www-form-urlencoded comes from FormBody::of alone")]
pub struct FormMedia;

impl PostBody {
    /// A form: `application/x-www-form-urlencoded`.
    #[must_use]
    pub fn form(body: FormBody) -> Self {
        Self {
            media: MediaType::form(),
            bytes: body.into_string().into_bytes(),
        }
    }

    /// Bytes of another media type.
    ///
    /// # Errors
    ///
    /// The media type is `application/x-www-form-urlencoded`.
    pub fn of(media: MediaType, bytes: Vec<u8>) -> Result<Self, FormMedia> {
        if media.is_form() {
            Err(FormMedia)
        } else {
            Ok(Self { media, bytes })
        }
    }

    /// The `Content-Type` the caller sends.
    #[must_use]
    pub const fn media_type(&self) -> &MediaType {
        &self.media
    }

    /// The bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// The DigitalCredential's `data` (A.4): a JSON object whose objects name each member once.
/// Only [`DcApiData::of`] makes one:
///
/// ```compile_fail,E0423
/// use siros_openid4vp::resolve::DcApiData;
///
/// fn forged() -> DcApiData {
///     DcApiData(String::from("{\"a\":1,\"a\":2}"))
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DcApiData(String);

/// A DC API body that is no JSON object whose objects name each member once.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.dc_api_data")]
#[error("the DC API data is no JSON object with unique member names")]
pub struct NotObject;

impl DcApiData {
    /// A.4's error: `{"error": code}`, which the core writes in the clear on every DC API route.
    #[must_use]
    pub fn error(error: &ErrorResponse<'_>) -> Self {
        Self(format!("{{\"error\":{}}}", quote(error.code().as_str())))
    }

    /// A JSON text the core reads back through its `json` module.
    ///
    /// # Errors
    ///
    /// The text is no JSON object, or an object in it repeats a member name.
    pub fn of(text: String) -> Result<Self, NotObject> {
        match Node::parse(&text) {
            Ok(Node::Object(_)) => Ok(Self(text)),
            _ => Err(NotObject),
        }
    }

    /// The JSON text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What the caller does with an answer: the core writes it from the route's endpoint and the
/// mode's body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivery {
    /// POST the body to the `response_uri`, then read the answer with `ResponseUriAnswer`.
    Post {
        /// The `response_uri`.
        endpoint: ResponseUri,
        /// The body.
        body: PostBody,
    },
    /// Return the JSON object as the DigitalCredential's `data` (A.4).
    DcApi(DcApiData),
}

/// Phase 2's answer: the Authorization Response and its delivery. Only `Prepared::respond`
/// makes one, so a delivery goes where the route sends it:
///
/// ```compile_fail,E0451
/// use siros_openid4vp::resolve::{AuthorizationResponse, Built, Delivery};
///
/// fn forged(response: AuthorizationResponse<'_>, delivery: Delivery) -> Built<'_> {
///     Built { response, delivery, used: Vec::new(), audience: String::new() }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct Built<'p> {
    response: AuthorizationResponse<'p>,
    delivery: Delivery,
    used: Vec<CredentialId<'static>>,
    audience: String,
}

impl<'p> Built<'p> {
    pub(crate) fn of(
        response: AuthorizationResponse<'p>,
        delivery: Delivery,
        used: Vec<CredentialId<'static>>,
        audience: String,
    ) -> Self {
        Self {
            response,
            delivery,
            used,
            audience,
        }
    }

    /// The Authorization Response.
    #[must_use]
    pub const fn response(&self) -> &AuthorizationResponse<'p> {
        &self.response
    }

    /// What the caller does with it.
    #[must_use]
    pub const fn delivery(&self) -> &Delivery {
        &self.delivery
    }

    /// The credentials the presentations used, each once, in the order the response presents
    /// them.
    #[must_use]
    pub fn used(&self) -> &[CredentialId<'static>] {
        &self.used
    }

    /// The audience the presentations bind to (Annex A, B.3.6).
    #[must_use]
    pub fn audience(&self) -> &str {
        &self.audience
    }
}
