//! What a request asks of its answer: the response type (§5.6), the response mode (§5.2, §8.2,
//! §8.3.1, A.2), the `response_uri` (§8.2) and `state` (§5.2, §5.3). One read serves the rules,
//! the formats' readings of each query and the answer.

use std::borrow::Cow;

use siros_explain::Explain;

use crate::envelope::{Channel, Parameters};
use crate::json::Node;
use crate::refusal::{ErrorCode, Refusal, RequestRule};
use crate::request::Request;

/// A response mode the wallet answers in: the closed set of the core.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResponseMode {
    /// `direct_post.jwt` (§8.3.1), by URI.
    DirectPostJwt,
    /// Over the DC API.
    DcApi(DcApiMode),
}

impl ResponseMode {
    /// How the mode protects the response it carries.
    #[must_use]
    pub const fn protection(self) -> Protection {
        match self {
            Self::DcApi(DcApiMode::DcApi) => Protection::Plain,
            Self::DcApi(DcApiMode::DcApiJwt) | Self::DirectPostJwt => Protection::Encrypted,
        }
    }

    /// The mode's name as `response_mode` writes it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DirectPostJwt => "direct_post.jwt",
            Self::DcApi(DcApiMode::DcApiJwt) => "dc_api.jwt",
            Self::DcApi(DcApiMode::DcApi) => "dc_api",
        }
    }
}

/// A response mode over the DC API (A.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DcApiMode {
    /// `dc_api.jwt`.
    DcApiJwt,
    /// `dc_api`.
    DcApi,
}

/// How a mode protects the response it carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protection {
    /// In the clear: `dc_api`.
    Plain,
    /// Encrypted to the Verifier (§8.3): `dc_api.jwt`, `direct_post.jwt`.
    Encrypted,
}

/// The mode a request names, as the wallet routes its answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModeChoice {
    /// A mode the wallet answers in, on the request's channel.
    Answer(ResponseMode),
    /// `direct_post` by URI, which C5 refuses, its errors plain to the `response_uri` (reading
    /// 24).
    DirectPost,
    /// Absent, or no mode the wallet answers in on the channel (C5): over the DC API its error
    /// goes in `dc_api`; by URI no endpoint receives it.
    Unsupported,
}

/// A `state` value (§5.2): non-empty, of ASCII letters, digits, `-`, `.`, `_` and `~` (P6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State<'r>(Cow<'r, str>);

impl<'r> State<'r> {
    /// The value; `None` when P6 refuses it.
    #[must_use]
    pub fn parse(text: Cow<'r, str>) -> Option<Self> {
        url_safe(&text).then_some(Self(text))
    }

    /// Its text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Whether a text is non-empty URL-safe ASCII: letters, digits, `-`, `.`, `_` and `~` (§5.2's
/// rule on `nonce` and `state`).
fn url_safe(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

/// `state` as received, which every answer echoes (RFC 6749 §4.1.2, §4.1.2.1).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(transparent)]
pub struct Echo<'r>(Cow<'r, str>);

impl<'r> Echo<'r> {
    /// `state` as received.
    pub(crate) const fn of(text: Cow<'r, str>) -> Self {
        Self(text)
    }

    /// Its text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A routing rule a request breaks, each with its code.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.routing")]
pub enum RoutingRule {
    /// P1: `response_type` absent (RFC 6749 §3.1.1).
    #[error("P1 response_type is absent")]
    #[explain(id = "p1_absent")]
    ResponseTypeAbsent,
    /// P1: `response_type` other than `vp_token` (HAIP §5).
    #[error("P1 response_type {0} is not vp_token")]
    #[explain(id = "p1_other")]
    ResponseType(#[explain(name = "response_type")] String),
    /// C5 over the DC API: no DC API response mode (A.2).
    #[error("C5 response_mode {mode} is no DC API response mode")]
    #[explain(id = "c5")]
    DcApiMode {
        /// The mode, as Python's `repr` writes the value.
        mode: String,
    },
    /// C5 by URI: no mode the wallet answers in by URI (§5.2, HAIP §5.1; reading 2, 24).
    #[error("C5 response_mode {mode} is no mode the wallet answers in by URI")]
    #[explain(id = "c5_uri")]
    UriMode {
        /// The mode, as Python's `repr` writes the value.
        mode: String,
    },
    /// P5: `redirect_uri` beside a `response_uri` mode (§8.2).
    #[error("P5 redirect_uri is present with response_mode {mode}")]
    #[explain(id = "p5")]
    RedirectUri {
        /// The mode.
        mode: String,
    },
    /// P6: `state` not URL-safe ASCII (§5.2).
    #[error("P6 state is not a non-empty string of URL-safe ASCII")]
    #[explain(id = "p6")]
    State,
}

impl RequestRule for RoutingRule {
    fn code(&self) -> ErrorCode {
        match self {
            Self::ResponseType(_) => ErrorCode::UnsupportedResponseType,
            Self::ResponseTypeAbsent
            | Self::DcApiMode { .. }
            | Self::UriMode { .. }
            | Self::RedirectUri { .. }
            | Self::State => ErrorCode::InvalidRequest,
        }
    }
}

/// The mode a request names: one the wallet answers in, or C5's refusal with the mode's choice.
#[derive(Debug, Clone)]
#[cfg_attr(
    not(feature = "match"),
    expect(dead_code, reason = "the request rules read the rule")
)]
enum Routed {
    Answer(ResponseMode),
    Refused {
        choice: ModeChoice,
        rule: RoutingRule,
    },
}

/// The routing a request asks for, with the rules it breaks.
#[derive(Debug, Clone)]
pub struct Routing<'r> {
    mode: Routed,
    response_uri: Option<Cow<'r, str>>,
    state: Option<Echo<'r>>,
    refusals: Vec<RoutingRule>,
}

impl<'r> Routing<'r> {
    /// The routing of the parameters on the channel; only `Envelope::parse` makes
    /// one, and the envelope holds it. Its refusals, in order: P1, C5, P5, P6. Over the DC API
    /// `state` and `redirect_uri` are unrecognized parameters (A.2), which P5 and P6 leave alone.
    pub(crate) fn read(parameters: &Parameters<'r>, channel: &Channel<'_>) -> Self {
        let mut refusals = Vec::new();
        match parameters.json("response_type") {
            None => refusals.push(RoutingRule::ResponseTypeAbsent),
            Some(Node::String(kind)) if kind == "vp_token" => {}
            Some(other) => refusals.push(RoutingRule::ResponseType(repr(Some(other)))),
        }
        let named = parameters.json("response_mode");
        let name = named.and_then(Node::as_str);
        let mode = match channel {
            Channel::DcApi(_) => match name {
                Some("dc_api") => ModeChoice::Answer(ResponseMode::DcApi(DcApiMode::DcApi)),
                Some("dc_api.jwt") => ModeChoice::Answer(ResponseMode::DcApi(DcApiMode::DcApiJwt)),
                _ => ModeChoice::Unsupported,
            },
            Channel::Uri => match name {
                Some("direct_post.jwt") => ModeChoice::Answer(ResponseMode::DirectPostJwt),
                Some("direct_post") => ModeChoice::DirectPost,
                _ => ModeChoice::Unsupported,
            },
        };
        let routed = match mode {
            ModeChoice::Answer(answer) => Routed::Answer(answer),
            choice @ (ModeChoice::DirectPost | ModeChoice::Unsupported) => {
                let mode = repr(named);
                let rule = match channel {
                    Channel::DcApi(_) => RoutingRule::DcApiMode { mode },
                    Channel::Uri => RoutingRule::UriMode { mode },
                };
                refusals.push(rule.clone());
                Routed::Refused { choice, rule }
            }
        };
        let (response_uri, state) = match channel {
            Channel::DcApi(_) => (None, None),
            Channel::Uri => {
                if let Some(name) = name.filter(|_| mode != ModeChoice::Unsupported)
                    && parameters.holds("redirect_uri")
                {
                    refusals.push(RoutingRule::RedirectUri {
                        mode: name.to_owned(),
                    });
                }
                let state = parameters.text("state");
                if state
                    .as_ref()
                    .is_some_and(|state| !state.as_deref().is_some_and(url_safe))
                {
                    refusals.push(RoutingRule::State);
                }
                (
                    parameters.text("response_uri").flatten(),
                    state.flatten().map(Echo::of),
                )
            }
        };
        Self {
            mode: routed,
            response_uri,
            state,
            refusals,
        }
    }

    /// The mode.
    #[must_use]
    pub const fn mode(&self) -> ModeChoice {
        match &self.mode {
            Routed::Answer(mode) => ModeChoice::Answer(*mode),
            Routed::Refused { choice, .. } => *choice,
        }
    }

    /// The mode the wallet answers in, or C5's refusal.
    #[cfg(feature = "match")]
    pub(crate) fn answer(&self) -> Result<ResponseMode, Refusal> {
        match &self.mode {
            Routed::Answer(mode) => Ok(*mode),
            Routed::Refused { rule, .. } => Err(Refusal::new(rule.clone())),
        }
    }

    /// The `response_uri` as the request names it, which authentication parses (A13).
    #[must_use]
    pub fn response_uri(&self) -> Option<&str> {
        self.response_uri.as_deref()
    }

    /// `state` as received.
    #[must_use]
    pub const fn echo(&self) -> Option<&Echo<'r>> {
        self.state.as_ref()
    }

    /// `state` when P6 holds.
    #[must_use]
    pub fn state(&self) -> Option<State<'_>> {
        self.state
            .as_ref()
            .and_then(|echo| State::parse(Cow::Borrowed(echo.as_str())))
    }

    /// The rules it breaks, in order.
    #[must_use]
    pub fn refusals(&self) -> Vec<Refusal> {
        self.refusals.iter().cloned().map(Refusal::new).collect()
    }
}

/// A value as Python's `repr` writes it, `None` when absent: the model's way of quoting it.
fn repr(value: Option<&Node<'_>>) -> String {
    value.map_or_else(
        || "None".to_owned(),
        |value| value.python_repr().to_string(),
    )
}

/// What a format's request rules read beyond the query (the zkp_req proposal's M4): the request,
/// its mode, whether transaction data names the query, and the Verifier's `vp_formats_supported`
/// value for the format. Only `Accepted::new` makes one, from the request's routing, and phase 2
/// inside an [`AnsweredContext`]; how the mode protects the response is
/// [`ResponseMode::protection`].
#[derive(Debug, Clone)]
pub struct QueryContext<'q> {
    request: &'q Request<'q>,
    mode: Option<ResponseMode>,
    named: bool,
    supported: Option<Node<'q>>,
}

impl<'q> QueryContext<'q> {
    #[cfg(feature = "match")]
    pub(crate) const fn of(
        request: &'q Request<'q>,
        mode: Option<ResponseMode>,
        named: bool,
        supported: Option<Node<'q>>,
    ) -> Self {
        Self {
            request,
            mode,
            named,
            supported,
        }
    }

    /// The request.
    #[must_use]
    pub const fn request(&self) -> &'q Request<'q> {
        self.request
    }

    /// The response mode; `None` when rule C5 refuses the request's.
    #[must_use]
    pub const fn mode(&self) -> Option<ResponseMode> {
        self.mode
    }

    /// Whether a `transaction_data` entry names the query.
    #[must_use]
    pub const fn named(&self) -> bool {
        self.named
    }

    /// The Verifier's `vp_formats_supported` value for the format, from its `client_metadata`.
    #[must_use]
    pub const fn supported(&self) -> Option<&Node<'q>> {
        self.supported.as_ref()
    }
}

#[cfg(feature = "test-util")]
impl<'q> QueryContext<'q> {
    /// The context a plug-in's tests read a query with, as `Accepted::new` makes it.
    #[must_use]
    pub const fn new(
        request: &'q Request<'q>,
        mode: Option<ResponseMode>,
        named: bool,
        supported: Option<Node<'q>>,
    ) -> Self {
        Self::of(request, mode, named, supported)
    }
}

/// What a format's phase 2 reads of a query: its phase-1 context, under the mode rule C5
/// accepted. Only `Prepared::prepare` makes one, from a request whose mode C5 accepts, so no
/// phase-2 reading under a refused mode exists:
///
/// ```compile_fail,E0451
/// use siros_openid4vp::routing::{AnsweredContext, QueryContext, ResponseMode};
///
/// fn forged(context: QueryContext<'_>, mode: ResponseMode) -> AnsweredContext<'_> {
///     AnsweredContext { context, mode }
/// }
/// ```
#[cfg(feature = "resolve")]
#[derive(Debug, Clone)]
pub struct AnsweredContext<'q> {
    context: QueryContext<'q>,
    mode: ResponseMode,
}

#[cfg(feature = "resolve")]
impl<'q> AnsweredContext<'q> {
    pub(crate) const fn of(context: QueryContext<'q>, mode: ResponseMode) -> Self {
        Self { context, mode }
    }

    /// The accepted mode.
    #[must_use]
    pub const fn mode(&self) -> ResponseMode {
        self.mode
    }

    /// The context phase 1 read the query with: a format reads the query in phase 2 with the
    /// rules it read it with in phase 1.
    #[must_use]
    pub const fn context(&self) -> &QueryContext<'q> {
        &self.context
    }
}

#[cfg(feature = "test-util")]
impl<'q> AnsweredContext<'q> {
    /// The context a plug-in's tests read a query with, as phase 2 makes it from a request whose
    /// mode the rules accept.
    #[must_use]
    pub const fn new(
        request: &'q Request<'q>,
        mode: ResponseMode,
        named: bool,
        supported: Option<Node<'q>>,
    ) -> Self {
        Self::of(
            QueryContext::of(request, Some(mode), named, supported),
            mode,
        )
    }
}
