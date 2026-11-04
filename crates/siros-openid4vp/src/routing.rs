//! What a request asks of its answer: the response type (RFC 6749 §3.1.1, §5.6), the response
//! mode (OAuth 2.0 Multiple Response Type Encoding Practices §2.1; §8.2, §8.3.1, A.2), the
//! `response_uri` (§8.2) and `state` (§5.2, §5.3). One read serves the rules, the formats'
//! readings of each query and the answer. A response type and a response mode are extension
//! points: the registry holds those the build registers, the core's own among them as peers.

use std::borrow::Cow;
use std::fmt;

use dyn_clone::DynClone;
use siros_explain::{Explain, IntoArg, kind};

use crate::envelope::{Channel, Parameters};
use crate::json::Node;
use crate::plugins::registry::Routes;
use crate::refusal::{ErrorCode, Refusal, RequestRule};
use crate::request::{AgreeableKey, ClientMetadata, Request};
#[cfg(feature = "resolve")]
use crate::request::{Agreements, ContentEncryption};

/// A `response_mode` value (OAuth 2.0 Multiple Response Type Encoding Practices §2.1): one or
/// more of ASCII letters, digits, `_`, `.` and `-`, the characters of the registered names. A
/// mode makes its own with `checked!(ModeName, "...")`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ModeName(&'static str);

impl ModeName {
    /// The name; `None` for an empty text or another character.
    #[must_use]
    pub const fn new(name: &'static str) -> Option<Self> {
        let mut rest = name.as_bytes();
        if rest.is_empty() {
            return None;
        }
        while let [byte, tail @ ..] = rest {
            if !(byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')) {
                return None;
            }
            rest = tail;
        }
        Some(Self(name))
    }

    /// The name as `response_mode` writes it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for ModeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// A mode is named by its text in a message.
impl IntoArg for ModeName {
    type Kind = kind::Name;

    fn arg(&self) -> &'static str {
        self.0
    }
}

/// The channel a request arrives on, which its answer leaves by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChannelKind {
    /// The DC API (Appendix A).
    DcApi,
    /// A URI (§5, §8.2).
    Uri,
}

/// What a registered mode carries, by its registration: `mode` and `jwe_mode` register answers,
/// `error_mode` alone a URI mode's errors alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carries {
    /// Authorization Responses and error responses.
    Answers,
    /// Error responses alone: C5 refuses a request naming the mode, and its error goes in the
    /// mode's form (reading 24's plain `direct_post`).
    Errors,
}

/// A response mode (OAuth 2.0 Multiple Response Type Encoding Practices §2.1: "additional
/// Response Modes may be defined by other specifications"), as phase 1 reads it. The core's
/// `dc_api`, `dc_api.jwt`, `direct_post.jwt` and `direct_post` ([`crate::modes`]) implement it
/// as peers of any extension's.
///
/// # Implementing
///
/// `name` and `channel` are constants: the registry keys the mode by them and refuses a name
/// registered twice on one channel (`RegistryError::ModeTwice`). `rules` reads the request the
/// core parsed and the Verifier's metadata, and returns the refusals of the mode's own rules (a
/// JWE mode: a key and an `enc` its key rule accepts, C7); the core lists them after C6, each
/// with its rule's code.
pub trait Mode: DynClone + Send + Sync {
    /// The `response_mode` value it answers.
    fn name(&self) -> ModeName;
    /// The channel it answers on.
    fn channel(&self) -> ChannelKind;
    /// The mode's request rules over the request and the Verifier's metadata: the refusals of
    /// the rules they break, in order.
    fn rules(&self, request: &Request<'_>, metadata: &VerifierMetadata<'_>) -> Vec<Refusal>;
}

dyn_clone::clone_trait_object!(Mode);

/// A `response_type` value (RFC 6749 §3.1.1): one or more response names of ASCII letters,
/// digits and `_`, separated by single spaces. A plug-in makes its own with
/// `checked!(ResponseTypeName, "...")`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResponseTypeName(&'static str);

impl ResponseTypeName {
    /// The name; `None` for an empty text, an empty response name, or another character.
    #[must_use]
    pub const fn new(name: &'static str) -> Option<Self> {
        let mut rest = name.as_bytes();
        let mut after_space = true;
        while let [byte, tail @ ..] = rest {
            if *byte == b' ' {
                if after_space {
                    return None;
                }
                after_space = true;
            } else if byte.is_ascii_alphanumeric() || *byte == b'_' {
                after_space = false;
            } else {
                return None;
            }
            rest = tail;
        }
        if after_space { None } else { Some(Self(name)) }
    }

    /// The name as `response_type` writes it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for ResponseTypeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// A response type is named by its text in a message.
impl IntoArg for ResponseTypeName {
    type Kind = kind::Name;

    fn arg(&self) -> &'static str {
        self.0
    }
}

/// A response type whose Authorization Response carries the VP Token (§8: `vp_token`, `vp_token
/// id_token`; RFC 6749 §8.4: "New response types ... are defined and registered").
///
/// # Implementing
///
/// `name` is a constant; the registry refuses a name registered twice
/// (`RegistryError::ResponseTypeTwice`), and P1 refuses a request whose `response_type` names no
/// registered type (`unsupported_response_type`). The core's [`VpToken`] is the peer that adds
/// no parameter.
pub trait ResponseType: DynClone + Send + Sync {
    /// The `response_type` value it answers.
    fn name(&self) -> ResponseTypeName;
}

dyn_clone::clone_trait_object!(ResponseType);

/// `vp_token` (§5.6, HAIP §5).
#[derive(Debug, Clone, Copy, Default)]
pub struct VpToken;

impl ResponseType for VpToken {
    fn name(&self) -> ResponseTypeName {
        siros_explain::checked!(ResponseTypeName, "vp_token")
    }
}

/// The Verifier's metadata as a mode reads it: `client_metadata` (§5.1, §5.9.3), and its `jwks`
/// keys the wallet can agree a key with. Only the core makes one, from the request it parsed:
///
/// ```compile_fail,E0451
/// use siros_openid4vp::request::ClientMetadata;
/// use siros_openid4vp::routing::{VerifierKeys, VerifierMetadata};
///
/// fn forged<'k>(
///     metadata: &'k ClientMetadata<'k>,
///     keys: VerifierKeys<'k>,
/// ) -> VerifierMetadata<'k> {
///     VerifierMetadata { metadata, keys }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct VerifierMetadata<'k> {
    metadata: &'k ClientMetadata<'k>,
    keys: VerifierKeys<'k>,
}

impl<'k> VerifierMetadata<'k> {
    /// The metadata of the request's `client_metadata`, which C6 accepted.
    #[cfg_attr(
        not(feature = "match"),
        expect(dead_code, reason = "the request rules read it")
    )]
    pub(crate) fn of(metadata: &'k ClientMetadata<'k>) -> Self {
        Self {
            metadata,
            keys: VerifierKeys {
                keys: metadata.agreeable_keys(),
            },
        }
    }

    /// A member of `client_metadata`.
    #[must_use]
    pub fn member(&self, name: &str) -> Option<&Node<'k>> {
        self.metadata.member(name)
    }

    /// The `jwks` keys the wallet can agree a key with, in the Verifier's order.
    #[must_use]
    pub const fn keys(&self) -> &VerifierKeys<'k> {
        &self.keys
    }
}

/// The keys of the Verifier's `client_metadata.jwks` that [`AgreeableKey`] reads, in the
/// Verifier's order. Only the core makes them, so every [`VerifierKey`] is one of the request's:
///
/// ```compile_fail,E0451
/// use siros_openid4vp::request::AgreeableKey;
/// use siros_openid4vp::routing::VerifierKeys;
///
/// fn forged(keys: Vec<AgreeableKey<'static>>) -> VerifierKeys<'static> {
///     VerifierKeys { keys }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct VerifierKeys<'k> {
    keys: Vec<AgreeableKey<'k>>,
}

impl VerifierKeys<'_> {
    /// Each key, in the Verifier's order.
    pub fn iter(&self) -> impl Iterator<Item = VerifierKey<'_>> {
        self.keys
            .iter()
            .enumerate()
            .map(|(place, key)| VerifierKey { place, key })
    }
}

/// One of the Verifier's keys, by its place among them. Only [`VerifierKeys::iter`] yields one,
/// so a mode chooses among the request's keys alone:
///
/// ```compile_fail,E0451
/// use siros_openid4vp::request::AgreeableKey;
/// use siros_openid4vp::routing::VerifierKey;
///
/// fn forged<'k>(key: &'k AgreeableKey<'k>) -> VerifierKey<'k> {
///     VerifierKey { place: 0, key }
/// }
/// ```
#[derive(Debug, Clone, Copy)]
pub struct VerifierKey<'k> {
    place: usize,
    key: &'k AgreeableKey<'k>,
}

impl<'k> VerifierKey<'k> {
    /// The key.
    #[must_use]
    pub const fn key(&self) -> &'k AgreeableKey<'k> {
        self.key
    }

    /// Its place in `jwks`.
    #[must_use]
    pub const fn place(&self) -> usize {
        self.place
    }
}

/// A registered mode, by its place in the registry; only the registry makes one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ModeHandle(usize);

impl ModeHandle {
    /// The handle of the registry's mode at `place`.
    pub(crate) const fn at(place: usize) -> Self {
        Self(place)
    }

    /// Its place in the registry.
    #[cfg_attr(
        not(feature = "resolve"),
        expect(dead_code, reason = "phase 2 reads the registration")
    )]
    pub(crate) const fn place(self) -> usize {
        self.0
    }
}

/// The registered mode a request names on its channel, as the registry holds it. Only
/// `Envelope::parse` makes one, from the registry the envelope then holds, so no answer goes in
/// a mode the request did not name:
///
/// ```compile_fail,E0451
/// use siros_openid4vp::routing::{Carries, ModeHandle, ModeName, RoutedMode};
///
/// fn forged(handle: ModeHandle, name: ModeName) -> RoutedMode {
///     RoutedMode { handle, name, carries: Carries::Answers }
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoutedMode {
    handle: ModeHandle,
    name: ModeName,
    carries: Carries,
}

impl RoutedMode {
    /// The registry's mode at `handle`, which carries `carries`.
    pub(crate) const fn of(handle: ModeHandle, name: ModeName, carries: Carries) -> Self {
        Self {
            handle,
            name,
            carries,
        }
    }

    /// The mode's name.
    #[must_use]
    pub const fn name(&self) -> ModeName {
        self.name
    }

    /// What it carries.
    #[must_use]
    pub const fn carries(&self) -> Carries {
        self.carries
    }

    /// The registration.
    #[must_use]
    pub const fn handle(&self) -> ModeHandle {
        self.handle
    }
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
    /// P1: `response_type` naming no registered response type (RFC 6749 §4.1.2.1).
    #[error("P1 response_type {0} names no response type the wallet answers")]
    #[explain(id = "p1_other")]
    ResponseType(#[explain(name = "response_type")] String),
    /// C5 over the DC API: absent, or no registered DC API response mode (A.2).
    #[error("C5 response_mode {mode} is no DC API response mode")]
    #[explain(id = "c5")]
    DcApi {
        /// The mode, as Python's `repr` writes the value.
        mode: String,
    },
    /// C5 by URI: absent, no registered URI mode, or one that carries errors alone (§5.2, HAIP
    /// §5.1; reading 2, 24).
    #[error("C5 response_mode {mode} is no mode the wallet answers in by URI")]
    #[explain(id = "c5_uri")]
    Uri {
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
            Self::ResponseType(_) => ErrorCode::UNSUPPORTED_RESPONSE_TYPE,
            Self::ResponseTypeAbsent
            | Self::DcApi { .. }
            | Self::Uri { .. }
            | Self::RedirectUri { .. }
            | Self::State => ErrorCode::INVALID_REQUEST,
        }
    }
}

/// A registered mode as the routing holds it, written by its name.
#[derive(Clone, Copy)]
struct Registered<'r>(&'r dyn Mode);

impl fmt::Debug for Registered<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0.name().as_str())
    }
}

/// The mode a request names: a registered mode that carries answers, or C5's refusal with the
/// registered mode that carries errors alone when the request names one.
#[derive(Debug, Clone)]
#[cfg_attr(
    not(feature = "match"),
    expect(dead_code, reason = "the request rules read the mode and the rule")
)]
enum Routed<'r> {
    Answers(RoutedMode, Registered<'r>),
    Refused {
        mode: Option<RoutedMode>,
        rule: RoutingRule,
    },
}

/// The routing a request asks for, with the rules it breaks.
#[derive(Debug, Clone)]
pub struct Routing<'r> {
    response_type: Option<ResponseTypeName>,
    mode: Routed<'r>,
    response_uri: Option<Cow<'r, str>>,
    state: Option<Echo<'r>>,
    refusals: Vec<RoutingRule>,
}

impl<'r> Routing<'r> {
    /// The routing of the parameters on the channel, over the registry's response types and
    /// modes; only `Envelope::parse` makes one, and the envelope holds it. Its refusals, in
    /// order: P1, C5, P5, P6. Over the DC API `state` and `redirect_uri` are unrecognized
    /// parameters (A.2), which P5 and P6 leave alone.
    pub(crate) fn read(
        parameters: &Parameters<'r>,
        channel: &Channel<'_>,
        routes: &'r dyn Routes,
    ) -> Self {
        let mut refusals = Vec::new();
        let response_type = match parameters.json("response_type") {
            None => {
                refusals.push(RoutingRule::ResponseTypeAbsent);
                None
            }
            Some(named) => {
                let registered = named.as_str().and_then(|name| routes.response_type(name));
                if registered.is_none() {
                    refusals.push(RoutingRule::ResponseType(repr(Some(named))));
                }
                registered
            }
        };
        let named = parameters.json("response_mode");
        let name = named.and_then(Node::as_str);
        let kind = channel.kind();
        let mode = match name.and_then(|name| routes.routed(kind, name)) {
            Some((mode, registered)) if mode.carries() == Carries::Answers => {
                Routed::Answers(mode, Registered(registered))
            }
            mode => {
                let mode = mode.map(|(mode, _)| mode);
                let named = repr(named);
                let rule = match kind {
                    ChannelKind::DcApi => RoutingRule::DcApi { mode: named },
                    ChannelKind::Uri => RoutingRule::Uri { mode: named },
                };
                refusals.push(rule.clone());
                Routed::Refused { mode, rule }
            }
        };
        let (response_uri, state) = match kind {
            ChannelKind::DcApi => (None, None),
            ChannelKind::Uri => {
                if let Routed::Answers(mode, _)
                | Routed::Refused {
                    mode: Some(mode), ..
                } = &mode
                    && parameters.holds("redirect_uri")
                {
                    refusals.push(RoutingRule::RedirectUri {
                        mode: mode.name().as_str().to_owned(),
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
            response_type,
            mode,
            response_uri,
            state,
            refusals,
        }
    }

    /// The registered response type the request names; `None` when P1 refuses it.
    #[must_use]
    pub const fn response_type(&self) -> Option<ResponseTypeName> {
        self.response_type
    }

    /// The registered mode the request names on its channel; `None` when it names none.
    #[must_use]
    pub const fn mode(&self) -> Option<&RoutedMode> {
        match &self.mode {
            Routed::Answers(mode, _)
            | Routed::Refused {
                mode: Some(mode), ..
            } => Some(mode),
            Routed::Refused { mode: None, .. } => None,
        }
    }

    /// The mode the wallet answers in, with its registration, or C5's refusal.
    #[cfg(feature = "match")]
    pub(crate) fn answer(&self) -> Result<(RoutedMode, &'r dyn Mode), Refusal> {
        match &self.mode {
            Routed::Answers(mode, registered) => Ok((*mode, registered.0)),
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
/// inside an [`AnsweredContext`].
#[derive(Debug, Clone)]
pub struct QueryContext<'q> {
    request: &'q Request<'q>,
    mode: Option<ModeName>,
    named: bool,
    supported: Option<Node<'q>>,
}

impl<'q> QueryContext<'q> {
    #[cfg(feature = "match")]
    pub(crate) const fn of(
        request: &'q Request<'q>,
        mode: Option<ModeName>,
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

    /// The response mode's name; `None` when rule C5 refuses the request's.
    #[must_use]
    pub const fn mode(&self) -> Option<ModeName> {
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
        mode: Option<ModeName>,
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
/// use siros_openid4vp::routing::{AnsweredContext, QueryContext, ModeName};
///
/// fn forged(context: QueryContext<'_>, mode: ModeName) -> AnsweredContext<'_> {
///     AnsweredContext { context, mode }
/// }
/// ```
#[cfg(feature = "resolve")]
#[derive(Debug, Clone)]
pub struct AnsweredContext<'q> {
    context: QueryContext<'q>,
    mode: ModeName,
}

#[cfg(feature = "resolve")]
impl<'q> AnsweredContext<'q> {
    pub(crate) const fn of(context: QueryContext<'q>, mode: ModeName) -> Self {
        Self { context, mode }
    }

    /// The accepted mode.
    #[must_use]
    pub const fn mode(&self) -> ModeName {
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
        mode: ModeName,
        named: bool,
        supported: Option<Node<'q>>,
    ) -> Self {
        Self::of(
            QueryContext::of(request, Some(mode), named, supported),
            mode,
        )
    }
}

/// How a mode's route seals its answer: in the clear, or as a JWE the core seals to one of the
/// Verifier's keys under a content encryption the sealing module states.
#[cfg(feature = "resolve")]
#[derive(Debug, Clone, Copy)]
pub enum Encrypting<'k> {
    /// In the clear.
    Plain,
    /// Sealed to the key with `enc`.
    Jwe {
        /// One of the request's keys.
        key: VerifierKey<'k>,
        /// The content encryption.
        enc: ContentEncryption<'static>,
    },
}

/// A response mode's phase 2 over the build's host: the encryption of its route.
///
/// # Implementing
///
/// `encryption` chooses among the request's keys alone ([`VerifierMetadata::keys`]) under
/// `sealer`, the sealing module's statement (`Haip::agreements`), and refuses with the mode's
/// rule when it finds none. A mode registered with `mode` returns [`Encrypting::Plain`]; the
/// core refuses a key the statement does not admit, and a key on a route in the clear, with a
/// `Fault`.
#[cfg(feature = "resolve")]
pub trait ModeHost<H>: Mode {
    /// The route's encryption.
    ///
    /// # Errors
    ///
    /// The mode's rule the request breaks under the statement.
    fn encryption<'k>(
        &self,
        metadata: &'k VerifierMetadata<'k>,
        sealer: &Agreements,
        host: &H,
    ) -> Result<Encrypting<'k>, Refusal>;
}
