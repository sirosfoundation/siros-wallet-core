//! The route an answer and an error take: the endpoint the wallet authenticated, the registered
//! modes the request names, and the encryption the answering mode chose once, checked by the core.

use siros_explain::Explain;

use super::{
    AnswerContent, AuthorizationResponse, Body, DcApiData, Delivery, ErrorContent, ErrorResponse,
    ModeRoute, Outcome, RouteBreach,
};
use super::{RouteKey, Session, SessionBinding};
use crate::authenticate::{Authenticated, BoundEndpoint, VerifierId};
use crate::envelope::Channel;
use crate::host::{CoreHost, Haip};
use crate::ids::{ClientId, Nonce, Origin};
use crate::matching::{CoreRule, UnmetCode};
use crate::plugins::registry::RegisteredMode;
use crate::plugins::{Build, Fault, Registry};
use crate::recourse::{DcApiErrors, Reply};
use crate::refusal::{ErrorCode, ErrorDescription, Refusal, Refused};
use crate::request::Agreements;
use crate::routing::{
    Carries, Echo, Encrypting, ModeHost, RoutedMode, VerifierKeys, VerifierMetadata,
};
use crate::uri::ResponseUri;
use crate::{FAULT, detail};

/// A URI request whose `response_mode` names no registered error mode (C5): no error can go
/// anywhere, and the wallet tells the End-User. A DC API request is always routable: its errors
/// are A.4's, which the core writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.route")]
#[error("the request names no response mode the wallet can carry an error in")]
pub struct Unroutable;

/// Where and how an answer and an error go, from an [`Authenticated`] request and the registry
/// its envelope was read with. Only [`Route::new`] makes one, so every answer it carries goes to
/// the endpoint the wallet authenticated, in the mode the request named:
///
/// ```compile_fail,E0451
/// use siros_openid4vp::authenticate::Authenticated;
/// use siros_openid4vp::plugins::{NoHost, Registry};
/// use siros_openid4vp::resolve::Route;
///
/// fn forged<'a>(
///     authenticated: &'a Authenticated<'a>,
///     registry: &'a Registry,
///     other: Route<'a, NoHost>,
/// ) -> Route<'a, NoHost> {
///     Route { authenticated, registry, ..other }
/// }
/// ```
pub struct Route<'a, H: Build> {
    authenticated: &'a Authenticated<'a>,
    registry: &'a Registry<H>,
    channel: ChannelRoute<'a>,
    nonce: Option<&'a Nonce<'a>>,
}

/// The route of each channel. Over the DC API errors are A.4's, which the core writes, and the
/// answering mode is present when the request names a registered one. By URI the bound
/// `response_uri`, the Client Identifier the wallet authenticated and the registered error mode
/// of the request's name are present.
enum ChannelRoute<'a> {
    DcApi {
        origin: &'a Origin<'a>,
        answers: Option<Chosen<'a>>,
    },
    Uri {
        endpoint: &'a ResponseUri,
        client_id: &'a ClientId<'a>,
        errors: RoutedMode,
        answers: Option<Chosen<'a>>,
    },
}

/// An answering mode and the encryption it chose once.
struct Chosen<'a> {
    mode: RoutedMode,
    encryption: RouteEncryption<'a>,
}

/// What the answering mode chose: the clear, a key the core checked and bound, or C7 (C6 when
/// the request's `client_metadata` breaks its rule), whose error goes plain.
enum RouteEncryption<'a> {
    Plain,
    Jwe(RouteKey<'a>),
    Refused,
}

impl<'a> ChannelRoute<'a> {
    const fn answers(&self) -> Option<&Chosen<'a>> {
        match self {
            Self::DcApi { answers, .. } | Self::Uri { answers, .. } => answers.as_ref(),
        }
    }
}

impl<'a, H: CoreHost> Route<'a, H> {
    /// The route of an authenticated request: the bound endpoint, the registered modes of the
    /// routing its envelope holds, each read from `registry` by its handle, the name checked, and
    /// the encryption the answering mode chose (`ModeHost::encryption`, once), checked. A C7
    /// refusal stays on the route, and the request's error then goes plain.
    ///
    /// # Errors
    ///
    /// [`Outcome::Unroutable`] for a URI request whose mode names no registered error mode; a
    /// `Fault` for a handle `registry` holds under another name, a URI request without a bound
    /// `response_uri` and Client Identifier, or a choice that breaks the mode's registration (its
    /// cause a [`RouteBreach`]).
    pub fn new(
        authenticated: &'a Authenticated<'a>,
        registry: &'a Registry<H>,
        host: &H,
    ) -> Result<Self, Outcome> {
        Self::read(authenticated, registry, host).map(|(route, _)| route)
    }

    /// [`Route::new`]'s route, with the refusal of the answering mode's choice when it refused
    /// (C7, or C6 for the request's `client_metadata`), which phase 2 answers with.
    pub(crate) fn read(
        authenticated: &'a Authenticated<'a>,
        registry: &'a Registry<H>,
        host: &H,
    ) -> Result<(Self, Option<Refusal>), Outcome> {
        let envelope = authenticated.envelope();
        let routing = envelope.routing();
        let answering = routing
            .mode()
            .filter(|mode| mode.carries() == Carries::Answers)
            .copied();
        let mut refusal = None;
        let mut chosen = |mode: Option<RoutedMode>| -> Result<Option<Chosen<'a>>, Outcome> {
            let Some(mode) = mode else {
                return Ok(None);
            };
            let (chosen, refused) = choose(authenticated, registry, mode, host)?;
            refusal = refused;
            Ok(Some(chosen))
        };
        let channel = match envelope.channel() {
            Channel::DcApi(origin) => ChannelRoute::DcApi {
                origin,
                answers: chosen(answering)?,
            },
            Channel::Uri => {
                let errors = routing
                    .mode()
                    .and_then(|mode| registry.error_mode(mode.name()))
                    .ok_or(Outcome::Unroutable(Unroutable))?;
                let verifier = authenticated.verifier();
                let (BoundEndpoint::ResponseUri { uri, .. }, VerifierId::Client(client_id)) =
                    (verifier.endpoint(), verifier.id())
                else {
                    return Err(Fault::new(
                        FAULT,
                        detail!(
                            "a URI request authenticated without a response_uri and a client_id"
                        ),
                    )
                    .into());
                };
                ChannelRoute::Uri {
                    endpoint: uri,
                    client_id,
                    errors,
                    answers: chosen(answering)?,
                }
            }
        };
        // A route carries the error of a request N1 refuses, which binds no session.
        let nonce = envelope.nonce().ok();
        Ok((
            Self {
                authenticated,
                registry,
                channel,
                nonce,
            },
            refusal,
        ))
    }

    /// The route an Authorization Response takes; `None` when the request names no registered
    /// answering mode on its channel (C5), its mode refused every key (C7), its `client_metadata`
    /// breaks C6, or it names no `nonce` N1 accepts.
    #[must_use]
    pub fn answering(&'a self) -> Option<AnswerRoute<'a, H>> {
        let chosen = self.channel.answers()?;
        let key = match &chosen.encryption {
            RouteEncryption::Plain => None,
            RouteEncryption::Jwe(key) => Some(key),
            RouteEncryption::Refused => return None,
        };
        Some(AnswerRoute {
            route: self,
            chosen,
            key,
            keys: self.authenticated.metadata().ok()?.keys(),
            nonce: self.nonce?,
        })
    }

    /// The error of the first refusal: its code, its text sanitized to RFC 6749 Appendix A.8's
    /// characters as the description (§4.1.2.1), `state` as received. Over the DC API A.4's
    /// `{"error": code}`, or [`Reply::Cancel`] under [`DcApiErrors::Cancel`] (§15.9.2); by URI
    /// the error mode's body to the bound `response_uri`, sealed by the core to the route's key
    /// when the answering mode bound one, else in the clear (§8.3.1).
    ///
    /// # Errors
    ///
    /// The sealing module or the error mode broke its contract.
    pub fn refusal(
        &self,
        refused: &Refused,
        policy: DcApiErrors,
        host: &H,
    ) -> Result<Reply, Fault> {
        let first = refused
            .refusals()
            .first()
            .ok_or_else(|| Fault::new(FAULT, detail!("a refusal without a rule")))?;
        let error = ErrorResponse::of(
            first.code(),
            ErrorDescription::sanitized(&first.text()),
            self.echo().cloned(),
        );
        self.reply(&error, policy, host)
    }

    /// The error of a request the wallet does not meet, under its code, without a description
    /// (§8.5, §15.4.1); its delivery as [`Route::refusal`]'s.
    ///
    /// # Errors
    ///
    /// The sealing module or the error mode broke its contract.
    pub fn unmet(&self, code: UnmetCode, policy: DcApiErrors, host: &H) -> Result<Reply, Fault> {
        let error = ErrorResponse::of(code.code(), None, self.echo().cloned());
        self.reply(&error, policy, host)
    }

    /// `wallet_unavailable` (§8.5), for the component an https link reaches in place of the
    /// wallet; its delivery as [`Route::refusal`]'s under [`DcApiErrors::Respond`].
    ///
    /// # Errors
    ///
    /// The sealing module or the error mode broke its contract.
    pub fn unavailable(&self, host: &H) -> Result<Delivery, Fault> {
        let error = ErrorResponse::of(ErrorCode::WALLET_UNAVAILABLE, None, self.echo().cloned());
        self.error(&error, host)
    }

    /// The error as the policy has it over the DC API, delivered otherwise.
    fn reply(
        &self,
        error: &ErrorResponse<'_>,
        policy: DcApiErrors,
        host: &H,
    ) -> Result<Reply, Fault> {
        match (&self.channel, policy) {
            (ChannelRoute::DcApi { .. }, DcApiErrors::Cancel) => Ok(Reply::Cancel),
            (_, _) => self.error(error, host).map(Reply::Deliver),
        }
    }

    /// The error's delivery: A.4's over the DC API, which the core writes; by URI the error
    /// mode's body around the error the core sealed to the route's key, or the clear error on a
    /// route the core seals nothing on.
    fn error(&self, error: &ErrorResponse<'_>, host: &H) -> Result<Delivery, Fault> {
        let ChannelRoute::Uri {
            endpoint,
            errors,
            answers,
            ..
        } = &self.channel
        else {
            return Ok(Delivery::DcApi(DcApiData::error(error)));
        };
        let RegisteredMode::Errors(mode) = self.registered(*errors)? else {
            return Err(Fault::new(
                FAULT,
                detail!("the route's error mode is registered for answers"),
            ));
        };
        let key = self.key();
        let sealed;
        let content = match (key, answers) {
            (None, _) => ErrorContent::Clear(error),
            (Some(key), Some(chosen)) => {
                let RegisteredMode::Jwe(_, access) = self.registered(chosen.mode)? else {
                    return Err(breach(RouteBreach::KeyInTheClear));
                };
                sealed = access(host).encrypt_jwe(key.key(), key.enc(), error.json().as_bytes())?;
                ErrorContent::Sealed(&sealed)
            }
            (Some(_), None) => {
                return Err(Fault::new(
                    FAULT,
                    detail!("a key without an answering mode"),
                ));
            }
        };
        let body = mode.error(&ModeRoute::of(key, self.echo()), &content, host)?;
        Ok(Delivery::Post {
            endpoint: (*endpoint).clone(),
            body,
        })
    }

    /// `state` as received.
    fn echo(&self) -> Option<&'a Echo<'a>> {
        self.authenticated.envelope().routing().echo()
    }

    /// The key the answering mode bound; `None` on a route the core seals nothing on.
    fn key(&self) -> Option<&RouteKey<'a>> {
        match self.channel.answers().map(|chosen| &chosen.encryption) {
            Some(RouteEncryption::Jwe(key)) => Some(key),
            _ => None,
        }
    }

    /// A mode's registration, by the handle the route holds, the name checked.
    fn registered(&self, mode: RoutedMode) -> Result<&'a RegisteredMode<H>, Fault> {
        registered(self.registry, mode)
    }

    /// The body as a delivery to the route's bound endpoint: a body of another channel than the
    /// request's breaks the mode's contract.
    fn deliver(&self, body: Body) -> Result<Delivery, Fault> {
        match (&self.channel, body) {
            (ChannelRoute::DcApi { .. }, Body::DcApi(data)) => Ok(Delivery::DcApi(data)),
            (ChannelRoute::Uri { endpoint, .. }, Body::Post(body)) => Ok(Delivery::Post {
                endpoint: (*endpoint).clone(),
                body,
            }),
            (_, _) => Err(breach(RouteBreach::BodyChannel)),
        }
    }
}

/// The route an Authorization Response takes: a route whose request names a registered answering
/// mode that chose its encryption, and a `nonce`. Only [`Route::answering`] makes one:
///
/// ```compile_fail,E0451
/// use siros_openid4vp::plugins::NoHost;
/// use siros_openid4vp::resolve::AnswerRoute;
///
/// fn forged<'a>(sealed: AnswerRoute<'a, NoHost>) -> AnswerRoute<'a, NoHost> {
///     AnswerRoute { key: None, ..sealed }
/// }
/// ```
pub struct AnswerRoute<'a, H: Build> {
    route: &'a Route<'a, H>,
    chosen: &'a Chosen<'a>,
    key: Option<&'a RouteKey<'a>>,
    keys: &'a VerifierKeys<'a>,
    nonce: &'a Nonce<'a>,
}

impl<'a, H: CoreHost> AnswerRoute<'a, H> {
    /// The session the presentations bind (decision 20): over the DC API the Origin, by URI the
    /// full Client Identifier and the `response_uri` as the request names it; the `nonce`; the
    /// key the core seals the answer to; the Verifier's keys.
    #[must_use]
    pub fn session(&self) -> Session<'a> {
        let binding = match &self.route.channel {
            ChannelRoute::DcApi { origin, .. } => SessionBinding::DcApi { origin },
            ChannelRoute::Uri {
                endpoint,
                client_id,
                ..
            } => SessionBinding::Redirect {
                client_id,
                response_uri: endpoint,
            },
        };
        Session::of(binding, self.nonce, self.key.copied(), self.keys)
    }

    /// The delivery of the response: sealed by the core to the route's key on a sealed route,
    /// wrapped by the mode, sent to the bound endpoint.
    ///
    /// # Errors
    ///
    /// The sealing module or the mode broke its contract: a body of another channel than the
    /// request's is a `Fault` caused by [`RouteBreach::BodyChannel`].
    pub fn answer(
        &self,
        response: &AuthorizationResponse<'_>,
        host: &H,
    ) -> Result<Delivery, Fault> {
        let (mode, haip): (&dyn ModeHost<H>, Option<&dyn Haip>) =
            match self.route.registered(self.chosen.mode)? {
                RegisteredMode::Clear(mode) => (mode.as_ref(), None),
                RegisteredMode::Jwe(mode, access) => (mode.as_ref(), Some(access(host))),
                RegisteredMode::Errors(_) => return Err(breach(RouteBreach::ErrorsAnswered)),
            };
        let sealed;
        let content = match (self.key, haip) {
            (None, _) => AnswerContent::Clear(response),
            (Some(key), Some(haip)) => {
                sealed = haip.encrypt_jwe(key.key(), key.enc(), response.json().as_bytes())?;
                AnswerContent::Sealed(&sealed)
            }
            (Some(_), None) => return Err(breach(RouteBreach::KeyInTheClear)),
        };
        let body = mode.answer(&ModeRoute::of(self.key, self.route.echo()), &content, host)?;
        self.route.deliver(body)
    }
}

/// A mode's registration in `registry`, by its handle, the name checked.
fn registered<H: Build>(
    registry: &Registry<H>,
    mode: RoutedMode,
) -> Result<&RegisteredMode<H>, Fault> {
    registry
        .mode_host(mode.handle())
        .filter(|registered| registered.mode().name() == mode.name())
        .ok_or_else(|| {
            Fault::new(
                FAULT,
                detail!(
                    "the registry holds no mode {name} at the request's handle",
                    name = mode.name()
                ),
            )
        })
}

/// The answering mode's encryption, chosen once and checked: a key of the request's
/// `client_metadata.jwks` at its place whose curve and `alg` and an `enc` the sealing module
/// states, an `enc` the Verifier lists; the clear from a mode registered with `mode`.
fn choose<'a, H: CoreHost>(
    authenticated: &'a Authenticated<'a>,
    registry: &Registry<H>,
    mode: RoutedMode,
    host: &H,
) -> Result<(Chosen<'a>, Option<Refusal>), Outcome> {
    let (answering, sealer, sealing): (&dyn ModeHost<H>, _, _) = match registered(registry, mode)? {
        RegisteredMode::Clear(answering) => (answering.as_ref(), Agreements::NONE, false),
        RegisteredMode::Jwe(answering, access) => {
            (answering.as_ref(), access(host).agreements(), true)
        }
        RegisteredMode::Errors(_) => return Err(breach(RouteBreach::ErrorsAnswered).into()),
    };
    let refused = |refusal| {
        let chosen = Chosen {
            mode,
            encryption: RouteEncryption::Refused,
        };
        Ok((chosen, Some(refusal)))
    };
    let metadata = match authenticated.metadata() {
        Ok(metadata) => metadata,
        Err(e) => return refused(Refusal::new(CoreRule::ClientMetadata(e.clone()))),
    };
    let encryption = match (answering.encryption(metadata, &sealer, host), sealing) {
        (Err(refusal), _) => return refused(refusal),
        (Ok(Encrypting::Plain), false) => RouteEncryption::Plain,
        (Ok(Encrypting::Jwe { key, enc }), true) => {
            checked(metadata, &sealer, key, enc).map_err(breach)?
        }
        (Ok(Encrypting::Jwe { .. }), false) => {
            return Err(breach(RouteBreach::KeyInTheClear).into());
        }
        (Ok(Encrypting::Plain), true) => return Err(breach(RouteBreach::NoKey).into()),
    };
    Ok((Chosen { mode, encryption }, None))
}

/// A JWE mode's choice as the route binds it, or the breach it commits.
fn checked<'a>(
    metadata: &'a VerifierMetadata<'a>,
    sealer: &Agreements,
    key: crate::routing::VerifierKey<'a>,
    enc: crate::request::ContentEncryption<'static>,
) -> Result<RouteEncryption<'a>, RouteBreach> {
    if !metadata.keys().holds(&key) {
        return Err(RouteBreach::Foreign);
    }
    let stated = key
        .key()
        .alg()
        .is_some_and(|alg| sealer.admits(key.key().curve(), alg, enc));
    if !stated {
        return Err(RouteBreach::Unstated);
    }
    if !metadata.lists(enc) {
        return Err(RouteBreach::Unlisted);
    }
    Ok(RouteEncryption::Jwe(RouteKey::of(key, enc)))
}

/// The fault of a mode that broke its contract.
fn breach(cause: RouteBreach) -> Fault {
    Fault::caused(FAULT, detail!("the routed mode broke its contract"), cause)
}
