//! Where the error of a request refused before its Verifier is authenticated goes (RFC 6749
//! §4.1.2.1, RFC 9101 §6, RFC 9700 §4.11.2, OpenID4VP §5.10.1, §5.10.2, §8.2, A.4): the platform
//! over the DC API; by URI, the `response_uri` a trust decision listed, else the `response_uri`
//! the request names, unverified, when the End-User chooses to return to the site.

use siros_explain::Explain;

use crate::arrival::{Received, ReceivedForm, Unreadable};
use crate::authenticate::Unauthenticated;
use crate::envelope::Parameters;
use crate::jose::JwsError;
use crate::refusal::ErrorCode;
use crate::routing::Echo;
use crate::uri::ResponseUri;

/// Why a request is refused before its Verifier is authenticated.
#[derive(Debug, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.recourse")]
pub enum Failure {
    /// A U rule.
    #[error(transparent)]
    Unreadable(#[from] Unreadable),
    /// An A rule.
    #[error(transparent)]
    Unauthenticated(#[from] Unauthenticated),
}

impl Failure {
    /// The code its error response carries (§8.5, RFC 9101 §7); `None` when the specification
    /// terminates the request (U9, U14: §5.10.1, §5.10.2).
    #[must_use]
    pub const fn code(&self) -> Option<ErrorCode> {
        match self {
            Self::Unreadable(rule) => rule.code(),
            Self::Unauthenticated(rule) => Some(rule.code()),
        }
    }
}

impl Unreadable {
    /// The rule's code; `None` for the terminating U9 and U14.
    #[must_use]
    pub const fn code(&self) -> Option<ErrorCode> {
        Some(match self {
            Self::Fetch(_) | Self::ClientIdMismatch { .. } => return None,
            Self::Protocol(_)
            | Self::Unregistered(_)
            | Self::Shape { .. }
            | Self::Json(_)
            | Self::Uri(_)
            | Self::ClientId(_)
            | Self::Repeated(_)
            | Self::ClientIdAbsent
            | Self::RequestAndRequestUri
            | Self::Placement(_)
            | Self::ParametersInUri => ErrorCode::InvalidRequest,
            Self::RequestUri(_) => ErrorCode::InvalidRequestUri,
            Self::RequestUriMethod(_) => ErrorCode::InvalidRequestUriMethod,
            Self::Jws(_)
            | Self::Encrypted
            | Self::Jwe(_)
            | Self::Undecryptable
            | Self::Typ(_)
            | Self::Nested(_) => ErrorCode::InvalidRequestObject,
            Self::RequestByValue => ErrorCode::RequestNotSupported,
        })
    }
}

/// Where the error of a refused request goes, plain (§8.3.1), with `state` as received. After a
/// POST the caller reads the Response URI's answer and sends the user agent to its
/// `redirect_uri` (§8.2: "for Error Responses" too). Only a [`Rejected`] holds one, beside the
/// failure it routes.
#[derive(Debug, Clone)]
pub struct ErrorRoute<'a> {
    target: ErrorTarget,
    echo: Option<Echo<'a>>,
}

impl<'a> ErrorRoute<'a> {
    /// The target.
    #[must_use]
    pub const fn target(&self) -> &ErrorTarget {
        &self.target
    }

    /// `state` as received.
    #[must_use]
    pub const fn echo(&self) -> Option<&Echo<'a>> {
        self.echo.as_ref()
    }
}

/// Where an [`ErrorRoute`] delivers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorTarget {
    /// The DC API return, in `dc_api` (A.4).
    DcApi,
    /// A `response_uri` the trust decision vouches for (`EndpointBasis::Framework`). The caller
    /// sends after the End-User has interacted.
    Listed(ResponseUri),
    /// The `response_uri` an unauthenticated request names. The caller tells the End-User that
    /// the wallet could not verify the site, shows the URI's host, and sends only when the
    /// End-User chooses to return to it (RFC 9700 §4.11.2).
    Unverified(ResponseUri),
}

/// A request refused before its Verifier is authenticated, and its error's route. Over the DC
/// API the route is the DC API's. By URI it is the `response_uri` of a `Framework` binding when
/// A8 to A10 fail, else the `response_uri` the payload names, unverified, when it is an absolute
/// `https` URI with a host. A request without a readable payload, A13, and the terminating U9 and
/// U14 have none: the End-User alone hears of them. The step that refuses makes one, so the route
/// is its failure's.
#[must_use]
#[derive(Debug)]
pub struct Rejected<'e> {
    failure: Failure,
    route: Option<ErrorRoute<'e>>,
}

impl<'r> Rejected<'r> {
    /// The rejection of a DC API request `Received::dc_api` refuses (U1, U2, U3, U10, U16), on
    /// the DC API's route.
    pub fn dc_api(cause: Unreadable) -> Self {
        Self {
            failure: Failure::Unreadable(cause),
            route: Some(ErrorRoute {
                target: ErrorTarget::DcApi,
                echo: None,
            }),
        }
    }

    /// The rejection of a request whose envelope is refused in phase 2 (`Envelope::parse`
    /// returns the bare [`Unreadable`]): over the DC API on its route; by URI unverified for U12,
    /// U13 and U16 when the payload names an absolute `https` `response_uri` with a host, and
    /// without a route for the others.
    pub fn unreadable(received: &'r Received<'r>, cause: Unreadable) -> Self {
        match received.form() {
            ReceivedForm::DcApi { .. } => Self::dc_api(cause),
            ReceivedForm::Uri { object, .. } => {
                let route = match cause {
                    Unreadable::Typ(_) | Unreadable::Nested(_) => {
                        Parameters::parse(object.payload())
                            .ok()
                            .and_then(|parameters| unverified(&parameters))
                    }
                    _ => None,
                };
                Self::of(cause, route)
            }
        }
    }

    /// A rejection with its route, which the step that refuses chose.
    pub(crate) fn of(failure: impl Into<Failure>, route: Option<ErrorRoute<'r>>) -> Self {
        Self {
            failure: failure.into(),
            route,
        }
    }

    /// Why.
    #[must_use]
    pub const fn failure(&self) -> &Failure {
        &self.failure
    }

    /// The route its error takes; `None`: the End-User alone.
    #[must_use]
    pub const fn route(&self) -> Option<&ErrorRoute<'r>> {
        self.route.as_ref()
    }
}

/// The route over the DC API.
pub(crate) const fn dc_api_route<'a>() -> ErrorRoute<'a> {
    ErrorRoute {
        target: ErrorTarget::DcApi,
        echo: None,
    }
}

/// The route to the `response_uri` a trust decision listed, with `state` as received.
pub(crate) const fn listed<'a>(uri: ResponseUri, echo: Option<Echo<'a>>) -> ErrorRoute<'a> {
    ErrorRoute {
        target: ErrorTarget::Listed(uri),
        echo,
    }
}

/// The unverified route a payload names: its `response_uri` when that is an absolute `https` URI
/// with a host, with its `state` as received.
pub(crate) fn unverified<'a>(parameters: &Parameters<'a>) -> Option<ErrorRoute<'a>> {
    let uri = parameters.text("response_uri").flatten()?;
    let uri = ResponseUri::parse(uri.into_owned()).ok()?;
    Some(ErrorRoute {
        target: ErrorTarget::Unverified(uri),
        echo: parameters.text("state").flatten().map(Echo::of),
    })
}

/// The unverified route of a U10 body whose payload still decodes to a JSON object (reading 3).
pub(crate) fn unverified_body<'a>(body: &str, cause: &JwsError) -> Option<ErrorRoute<'a>> {
    if matches!(
        cause,
        JwsError::Structure | JwsError::Base64 | JwsError::Json(_)
    ) {
        return None;
    }
    let payload = crate::jose::payload_text(body)?;
    let parameters = Parameters::parse(&payload).ok()?;
    let route = unverified(&parameters)?;
    Some(ErrorRoute {
        target: route.target,
        echo: route
            .echo
            .map(|echo| Echo::of(std::borrow::Cow::Owned(echo.as_str().to_owned()))),
    })
}
