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
use crate::ids::{KeyId, NamedResponseUri};
use crate::json::Node;
#[cfg(feature = "resolve")]
use crate::plugins::Fault;
use crate::plugins::registry::Routes;
use crate::refusal::{ErrorCode, Refusal, ReprItem, ReprOption, RequestRule};
#[cfg(feature = "resolve")]
use crate::request::Agreements;
use crate::request::{AgreeableKey, ClientMetadata, ContentEncryption, Request};
#[cfg(feature = "resolve")]
use crate::resolve::{AnswerContent, Body, ErrorContent, ModeRoute, PostBody, ResponseMember};
#[cfg(feature = "resolve")]
use crate::session::Session;
#[cfg(feature = "resolve")]
use crate::wallet_metadata::MetadataMember;
use crate::wallet_metadata::ParameterName;

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
/// with its rule's code. `metadata_names` are the `wallet_metadata` members (§10.1) the mode
/// writes, a constant: the registry refuses a name another registered part declares or the core
/// writes (`NameTwice`, `NameReserved`).
pub trait Mode: DynClone + Send + Sync {
    /// The `response_mode` value it answers.
    fn name(&self) -> ModeName;
    /// The channel it answers on.
    fn channel(&self) -> ChannelKind;
    /// The mode's request rules over the request and the Verifier's metadata: the refusals of
    /// the rules they break, in order.
    fn rules(&self, request: &Request<'_>, metadata: &VerifierMetadata<'_>) -> Vec<Refusal>;
    /// The `wallet_metadata` members it writes (§5.10, §10.1).
    fn metadata_names(&self) -> &'static [ParameterName];
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

/// Parameters an extension adds to the Authorization Response beside `vp_token` and `state`
/// (§8.1: "Additional response parameters MAY be defined"; RFC 9207's `iss`, `id_token` for a
/// `vp_token id_token` response type).
///
/// # Implementing
///
/// `names` is a constant: the registry refuses a name another registered part declares
/// (`RegistryError::NameTwice`) and the names the core writes, `vp_token`, `state`, `error`,
/// `error_description` and `error_uri` (`RegistryError::NameReserved`). The phase-2 half
/// [`ResponseParametersHost`] writes members of declared names alone, each name once, for the
/// response type the request names, each value JSON; the core refuses another name and a name
/// written twice with a `Fault` caused by `resolve::ParameterBreach`, and writes the members
/// after `vp_token` and `state`. `siros-testkit`'s `TestResponseParameters` is the double.
pub trait ResponseParameters: DynClone + Send + Sync {
    /// The parameter names it writes.
    fn names(&self) -> &'static [ParameterName];
}

dyn_clone::clone_trait_object!(ResponseParameters);

/// The phase-2 half of [`ResponseParameters`] over the build's host: its bounds name the modules
/// it calls.
#[cfg(feature = "resolve")]
pub trait ResponseParametersHost<H>: ResponseParameters {
    /// The members of the Authorization Response the request's response type takes: none, some
    /// or all of [`ResponseParameters::names`], from the session the presentations bind.
    ///
    /// # Errors
    ///
    /// The part cannot write them: its bug, or a module it calls failed.
    fn members(
        &self,
        response_type: ResponseTypeName,
        session: &Session<'_>,
        host: &H,
    ) -> Result<Vec<ResponseMember>, Fault>;
}

#[cfg(feature = "resolve")]
dyn_clone::clone_trait_object!(<H> ResponseParametersHost<H>);

/// `vp_token` (§5.6, HAIP §5).
#[derive(Debug, Clone, Copy, Default)]
pub struct VpToken;

impl ResponseType for VpToken {
    fn name(&self) -> ResponseTypeName {
        siros_explain::checked!(ResponseTypeName, "vp_token")
    }
}

/// The Verifier's metadata as a mode reads it: `client_metadata` (§5.1, §5.9.3), and its `jwks`
/// keys the wallet can agree a key with. Only the core makes one, from the request it parsed.
#[derive(Debug, Clone)]
pub struct VerifierMetadata<'k> {
    metadata: &'k ClientMetadata<'k>,
    keys: VerifierKeys<'k>,
}

impl<'k> VerifierMetadata<'k> {
    /// The metadata of the request's `client_metadata`, which C6 accepted.
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

    /// Whether the Verifier takes answers under the content encryption:
    /// `encrypted_response_enc_values_supported` lists it, or, absent, it is A128GCM (§5.1's
    /// default).
    #[must_use]
    pub fn lists(&self, enc: ContentEncryption<'_>) -> bool {
        match self.member("encrypted_response_enc_values_supported") {
            Some(listed) => listed.as_array().is_some_and(|values| {
                values
                    .iter()
                    .any(|value| value.as_str() == Some(enc.as_str()))
            }),
            None => enc == ContentEncryption::A128GCM,
        }
    }
}

/// What HAIP §5's key rule chooses under its own statement, as phase 1 reads it: the key's
/// place among the request's agreeable keys and its `kid`, and the content encryption. Phase 2
/// chooses under the sealing module's statement, which can narrow it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyChoice {
    place: KeyPlace,
    kid: KeyId<'static>,
    enc: ContentEncryption<'static>,
}

impl KeyChoice {
    /// The key rule's choice among the request's `client_metadata.jwks`, for a reader that binds
    /// the key before phase 2 (a session transcript).
    ///
    /// # Errors
    ///
    /// C7 under `mode`.
    pub fn of(
        mode: ModeName,
        metadata: &ClientMetadata<'_>,
    ) -> Result<Self, crate::modes::KeyRule> {
        let metadata = VerifierMetadata::of(metadata);
        crate::modes::key_rule(mode, &metadata, &crate::modes::KEY_RULE).map(|(key, enc)| Self {
            place: key.place(),
            kid: key.key().kid().clone().into_owned(),
            enc,
        })
    }

    /// The key's place among `ClientMetadata::agreeable_keys`.
    #[must_use]
    pub const fn place(&self) -> KeyPlace {
        self.place
    }

    /// The key's `kid`.
    #[must_use]
    pub const fn kid(&self) -> &KeyId<'static> {
        &self.kid
    }

    /// The content encryption.
    #[must_use]
    pub const fn enc(&self) -> ContentEncryption<'static> {
        self.enc
    }
}

/// The keys of the Verifier's `client_metadata.jwks` that [`AgreeableKey`] reads, in the
/// Verifier's order. Only the core makes them, so every [`VerifierKey`] is one of the request's.
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
            .map(|(place, key)| VerifierKey {
                place: KeyPlace(place),
                key,
            })
    }

    /// Whether the key is the one these keys hold at its place.
    #[cfg(feature = "resolve")]
    pub(crate) fn holds(&self, key: &VerifierKey<'_>) -> bool {
        self.keys
            .get(key.place.0)
            .is_some_and(|held| std::ptr::addr_eq(held, key.key))
    }
}

/// A key's place among the Verifier's agreeable keys. Only [`VerifierKeys::iter`] makes one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyPlace(usize);

impl KeyPlace {
    /// The position among the keys.
    #[must_use]
    pub const fn position(self) -> usize {
        self.0
    }
}

/// One of the Verifier's keys, by its place among them. Only [`VerifierKeys::iter`] yields one,
/// so a mode chooses among the request's keys alone.
#[derive(Debug, Clone, Copy)]
pub struct VerifierKey<'k> {
    place: KeyPlace,
    key: &'k AgreeableKey<'k>,
}

impl<'k> VerifierKey<'k> {
    /// The key.
    #[must_use]
    pub const fn key(&self) -> &'k AgreeableKey<'k> {
        self.key
    }

    /// Its place among the keys.
    #[must_use]
    pub const fn place(&self) -> KeyPlace {
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
/// a mode the request did not name.
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
    ResponseType(#[explain(name = "response_type")] ReprItem),
    /// C5 over the DC API: absent, or no registered DC API response mode (A.2).
    #[error("C5 response_mode {mode} is no DC API response mode")]
    #[explain(id = "c5")]
    DcApi {
        /// The mode.
        mode: ReprOption,
    },
    /// C5 by URI: absent, no registered URI mode, or one that carries errors alone (§5.2, HAIP
    /// §5.1; reading 2, 24).
    #[error("C5 response_mode {mode} is no mode the wallet answers in by URI")]
    #[explain(id = "c5_uri")]
    Uri {
        /// The mode.
        mode: ReprOption,
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
    response_uri: Option<NamedResponseUri<'r>>,
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
                    refusals.push(RoutingRule::ResponseType(ReprItem::repr(named)));
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
                let named = ReprOption::of(named);
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
                    parameters
                        .text("response_uri")
                        .flatten()
                        .and_then(|uri| NamedResponseUri::parse(uri).ok()),
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
    pub const fn response_uri(&self) -> Option<&NamedResponseUri<'r>> {
        self.response_uri.as_ref()
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

/// Whether a `transaction_data` entry names a query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntryNaming {
    /// An entry names it.
    Named,
    /// No entry names it.
    Unnamed,
}

impl EntryNaming {
    /// Whether the query is in the set of queries entries name.
    #[cfg(feature = "match")]
    pub(crate) fn of(named: crate::request::QuerySet, query: crate::request::QueryIndex) -> Self {
        if named.contains(query) {
            Self::Named
        } else {
            Self::Unnamed
        }
    }
}

/// What a format's request rules read beyond the query (the zkp_req proposal's M4): the request,
/// its mode, whether transaction data names the query, and the Verifier's `vp_formats_supported`
/// value for the format. Only `Accepted::new` makes one, from the request's routing, and phase 2
/// inside an [`AnsweredContext`].
#[derive(Debug, Clone)]
pub struct QueryContext<'q> {
    request: &'q Request<'q>,
    mode: Option<ModeName>,
    naming: EntryNaming,
    supported: Option<Node<'q>>,
}

impl<'q> QueryContext<'q> {
    #[cfg(feature = "match")]
    pub(crate) const fn of(
        request: &'q Request<'q>,
        mode: Option<ModeName>,
        naming: EntryNaming,
        supported: Option<Node<'q>>,
    ) -> Self {
        Self {
            request,
            mode,
            naming,
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
    pub const fn naming(&self) -> EntryNaming {
        self.naming
    }

    /// The Verifier's `vp_formats_supported` value for the format, from its `client_metadata`.
    #[must_use]
    pub const fn supported(&self) -> Option<&Node<'q>> {
        self.supported.as_ref()
    }
}

/// What a format's phase 2 reads of a query: its phase-1 context, under the mode rule C5
/// accepted. Only `Prepared::prepare` makes one, from a request whose mode C5 accepts, so no
/// phase-2 reading under a refused mode exists.
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

/// A response mode's phase 2 over the build's host: the encryption of its route, its
/// `wallet_metadata` members, and the body around an answer.
///
/// # Implementing
///
/// `encryption` chooses among the request's keys alone ([`VerifierMetadata::keys`]) under
/// `sealer`, the sealing module's statement (`Haip::agreements`), and refuses with the mode's
/// rule when it finds none. A mode registered with `mode` returns [`Encrypting::Plain`]; the
/// core refuses a key the statement does not admit or whose `enc` the Verifier does not list, a
/// key on a route in the clear, and no key on a sealed route, with a `Fault`. `wallet_metadata`
/// writes the members [`Mode::metadata_names`] declares, from the same statement
/// ([`Agreements::NONE`] for a mode registered with `mode`); the core refuses another name
/// (`MetadataRefused::Undeclared`). `answer` writes the [`Body`] of the mode's channel around
/// the [`AnswerContent`]: the clear response on a route in the clear, the JWE the core sealed to
/// the route's key on a sealed one, so no plaintext of a sealed route reaches the mode. The core
/// refuses a body of the other channel with a `Fault` and sends a body to the route's endpoint
/// alone.
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

    /// The `wallet_metadata` members it declares, from what the build seals with (§5.10).
    ///
    /// # Errors
    ///
    /// The mode cannot write them: its bug, or a module it calls failed.
    fn wallet_metadata(&self, sealer: &Agreements, host: &H) -> Result<Vec<MetadataMember>, Fault>;

    /// The body around an answer.
    ///
    /// # Errors
    ///
    /// The mode cannot write it: its bug, or a module it calls failed.
    fn answer(
        &self,
        route: &ModeRoute<'_>,
        content: &AnswerContent<'_>,
        host: &H,
    ) -> Result<Body, Fault>;
}

/// A URI response mode's error responses over the build's host (§8.2, §8.3.1): the form body
/// around the error.
///
/// # Implementing
///
/// `error` writes the [`PostBody`] around the [`ErrorContent`]: the clear error on a route the
/// core seals nothing on, the JWE the core sealed the error in to the route's key on a sealed
/// one. The core sends the body to the route's `response_uri`; over the DC API it writes A.4's
/// error itself, and the registry refuses a DC API mode registered for errors
/// (`RegistryError::ErrorModeChannel`). A mode registered with `error_mode` alone carries
/// errors alone: C5 refuses a request naming it.
#[cfg(feature = "resolve")]
pub trait ErrorModeHost<H>: Mode {
    /// The body around an error.
    ///
    /// # Errors
    ///
    /// The mode cannot write it: its bug, or a module it calls failed.
    fn error(
        &self,
        route: &ModeRoute<'_>,
        content: &ErrorContent<'_>,
        host: &H,
    ) -> Result<PostBody, Fault>;
}
