//! The request as it reached the wallet: over the DC API with its Origin (Annex A), or by a URI
//! with the Request Object fetched from its `request_uri` (§5, RFC 9101; feature `resolve`).
//! Records commit to its digest.

use std::borrow::Cow;
use std::fmt;

use siros_explain::{Explain, IntoArg, kind};

use crate::envelope::{ClientIdPlacement, NestedParameter, Parameters};
use crate::ids::Origin;
use crate::jose::{CompactJws, JsonJws, JweError, JwsError};
use crate::json::{self, JsonError, RawObject};
use crate::request::RequestDigest;
#[cfg(feature = "resolve")]
use crate::uri::AuthorizationUri;

/// A DC API exchange protocol (A.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DcApiProtocol {
    /// `openid4vp-v1-unsigned` (A.3.1).
    Unsigned,
    /// `openid4vp-v1-signed` (A.3.2.1).
    Signed,
    /// `openid4vp-v1-multisigned` (A.3.2.2).
    Multisigned,
}

impl DcApiProtocol {
    const ALL: [Self; 3] = [Self::Unsigned, Self::Signed, Self::Multisigned];

    /// The protocol a DC API request names (U1).
    ///
    /// # Errors
    ///
    /// The text names none of A.1's protocols.
    pub fn parse(text: &str) -> Result<Self, Unreadable> {
        Self::ALL
            .into_iter()
            .find(|protocol| protocol.as_str() == text)
            .ok_or_else(|| Unreadable::Protocol(text.to_owned()))
    }

    /// The protocol's identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unsigned => "openid4vp-v1-unsigned",
            Self::Signed => "openid4vp-v1-signed",
            Self::Multisigned => "openid4vp-v1-multisigned",
        }
    }
}

impl fmt::Display for DcApiProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A protocol is named by its identifier in a message.
impl IntoArg for DcApiProtocol {
    type Kind = kind::Name;

    fn arg(&self) -> &'static str {
        self.as_str()
    }
}

/// The DC API protocols the wallet registers with the platform: [`DcApiProtocols::ALL`] under
/// HAIP's width, [`DcApiProtocols::SIGNED`] for a deployment that admits signed requests alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DcApiProtocols(&'static [DcApiProtocol]);

impl DcApiProtocols {
    /// The three protocols of A.1.
    pub const ALL: Self = Self(&DcApiProtocol::ALL);
    /// The signed and the multisigned protocol.
    pub const SIGNED: Self = Self(&[DcApiProtocol::Signed, DcApiProtocol::Multisigned]);

    /// Whether the wallet registers the protocol.
    #[must_use]
    pub fn holds(&self, protocol: DcApiProtocol) -> bool {
        self.0.contains(&protocol)
    }
}

/// Why a URI is unreadable (U3).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.uri")]
pub enum UriError {
    /// No URI (RFC 3986 §3): fluent-uri's error.
    #[error("no URI: {0}")]
    Syntax(#[explain(name = "cause")] String),
    /// A URI without a query.
    #[error("the URI holds no query")]
    Query,
    /// A query serde_urlencoded does not read: its error, which holds a message alone.
    #[error("the query: {0}")]
    Form(#[explain(name = "cause")] String),
}

/// An HTTP status code other than 200, from 100 to 599 (RFC 9110 §15).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailedStatus(u16);

impl FailedStatus {
    /// The code; `None` for 200 and for a code outside 100 to 599.
    #[must_use]
    pub const fn new(code: u16) -> Option<Self> {
        if code == 200 || code < 100 || code > 599 {
            None
        } else {
            Some(Self(code))
        }
    }

    /// The code.
    #[must_use]
    pub const fn code(self) -> u16 {
        self.0
    }
}

impl fmt::Display for FailedStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A status is a count in a message.
impl IntoArg for FailedStatus {
    type Kind = kind::Count;

    fn arg(&self) -> siros_explain::Count {
        siros_explain::Count::of(u64::from(self.0))
    }
}

/// Why the caller's fetch of a Request Object failed (§5.10.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.fetch")]
pub enum FetchFailure {
    /// An HTTP status other than 200.
    #[error("the request_uri answered HTTP {0}")]
    Status(#[explain(name = "status")] FailedStatus),
    /// A media type other than `application/oauth-authz-req+jwt`.
    #[error("the request_uri answered another media type than application/oauth-authz-req+jwt")]
    MediaType,
    /// No response: TLS, DNS, a timeout, the size limit.
    #[error("the request_uri gave no response")]
    Transport,
}

/// A request the wallet cannot read or must not process (the U rules). Its error goes where
/// section 4.5 of the flows design says.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.arrival")]
pub enum Unreadable {
    /// U1: a DC API protocol other than A.1's.
    #[error("DC API protocol {0:?} is none of OpenID4VP A.1")]
    Protocol(#[explain(name = "protocol")] String),
    /// U1: a protocol of A.1 the wallet does not register.
    #[error("the wallet does not register the DC API protocol {0}")]
    Unregistered(#[explain(name = "protocol")] DcApiProtocol),
    /// U2: DC API `data` without its protocol's shape.
    #[error("the DC API data does not have the {protocol} shape: {cause}")]
    Shape {
        /// The protocol.
        protocol: DcApiProtocol,
        /// What the shape lacks.
        cause: DataShape,
    },
    /// U3: parameters that are no JSON object with unique member names at every level.
    #[error("the parameters: {0}")]
    Json(#[explain(name = "cause")] JsonError),
    /// U3: an Authorization Request URI that cannot be read.
    #[error("the Authorization Request URI: {0}")]
    Uri(#[explain(name = "cause")] UriError),
    /// U3: a `client_id`, in the URI or the parameters, outside RFC 6749 Appendix A.1's
    /// `*VSCHAR` (%x20-7E), U+FFFD included: what serde_urlencoded reads an octet that is no
    /// UTF-8 as.
    #[error("client_id {0:?} holds a character outside RFC 6749 Appendix A.1")]
    ClientId(#[explain(name = "client_id")] String),
    /// U4: a parameter given twice, known or unknown; one without a value counts as omitted
    /// (RFC 6749 §3.1).
    #[error("the parameter {0} is given twice")]
    Repeated(#[explain(name = "parameter")] String),
    /// U5: a URI request without `client_id` (§5.2, RFC 9101 §5).
    #[error("client_id is absent")]
    ClientIdAbsent,
    /// U6: `request` and `request_uri` together (RFC 9101 §5).
    #[error("request and request_uri are both present")]
    RequestAndRequestUri,
    /// U7: `request_uri` no absolute https URI with a host (RFC 9101 §5.2).
    #[error("request_uri {0:?} is no absolute https URI with a host")]
    RequestUri(#[explain(name = "request_uri")] String),
    /// U8: `request_uri_method` neither `get` nor `post` (§5.1).
    #[error("request_uri_method {0:?} is neither get nor post")]
    RequestUriMethod(#[explain(name = "method")] String),
    /// U9: the fetch failed (§5.10.2).
    #[error("the request_uri fetch failed: {0}")]
    Fetch(#[explain(name = "failure")] FetchFailure),
    /// U10, U16: a Request Object that is no ES256 JWS.
    #[error("the Request Object: {0}")]
    Jws(#[explain(name = "cause")] JwsError),
    /// U11: a JWE Request Object after a GET, which posted no key (reading 21).
    #[error("the Request Object is a JWE; a GET posts no key to encrypt one to")]
    Encrypted,
    /// U11: a JWE Request Object after a POST that [`JweError`] refuses.
    #[error("the encrypted Request Object: {0}")]
    Jwe(#[explain(name = "cause")] JweError),
    /// U11: a JWE the host's module cannot decrypt with the posted key.
    #[error("the encrypted Request Object does not decrypt under the posted key")]
    Undecryptable,
    /// U12: `typ` absent or other than `oauth-authz-req+jwt` (§5).
    #[error("typ {0:?}: the wallet processes oauth-authz-req+jwt alone")]
    Typ(#[explain(name = "typ")] Option<String>),
    /// U13: a Request Object holding `request` or `request_uri` (RFC 9101 §4).
    #[error("the Request Object holds {0}")]
    Nested(#[explain(name = "parameter")] NestedParameter),
    /// U14: the `client_id` parameter and the Request Object's differ (§5.10.1).
    #[error("client_id {outer:?} and the Request Object's {inner:?} differ")]
    ClientIdMismatch {
        /// The parameter.
        outer: String,
        /// The Request Object's.
        inner: Option<String>,
    },
    /// U17: a multisigned request with `client_id` in its payload or an unprotected header
    /// (A.3.2.2).
    #[error("multisigned: client_id in the {0}, outside the protected headers")]
    Placement(#[explain(name = "member")] ClientIdPlacement),
    /// U18: a URI without `request_uri` (HAIP §5.1: signed requests by `request_uri`).
    #[error("the URI holds no request_uri; the wallet reads signed Request Objects by reference")]
    ParametersInUri,
    /// U19: `request` (RFC 9101 §7 `request_not_supported`).
    #[error("the request parameter is unsupported; the wallet reads request_uri")]
    RequestByValue,
}

/// Why `data` lacks the shape A.3.2.1 gives a signed request: a JSON object whose `request` is
/// the JWS.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.arrival.data")]
pub enum DataShape {
    /// `data` is no JSON object with unique member names.
    #[error("{0}")]
    Json(#[explain(name = "cause")] JsonError),
    /// `request` is absent or no string.
    #[error("data.request is no string")]
    Request,
}

/// The request as received. The caller keeps it: phase 2 and a replay parse it again.
#[derive(Debug, Clone)]
pub struct Received<'a> {
    form: ReceivedForm<'a>,
    digest: RequestDigest,
}

/// How the request arrived.
#[derive(Debug, Clone)]
pub enum ReceivedForm<'a> {
    /// Over the DC API, with the Origin the platform reports.
    DcApi {
        /// The Origin.
        origin: Origin<'a>,
        /// The request as `data` holds it.
        request: DcApiRequest<'a>,
    },
    /// By a URI (feature `resolve`): the URI, and the Request Object fetched from its
    /// `request_uri`.
    #[cfg(feature = "resolve")]
    Uri {
        /// The URI as the link or the QR code holds it, its parameters read.
        uri: AuthorizationUri<'a>,
        /// The Request Object: the body, or a JWE body's plaintext.
        object: CompactJws<'a>,
    },
}

/// A DC API request in its protocol's form (A.3).
#[derive(Debug, Clone)]
pub enum DcApiRequest<'a> {
    /// `data`, the parameters: a JSON object with unique member names at every level (U3).
    Unsigned(Parameters<'a>),
    /// `data.request`, a compact JWS.
    Signed(CompactJws<'a>),
    /// `data.request`, or `data` itself, a JWS JSON Serialization (A.3.2.2; reading 5).
    Multisigned(JsonJws<'a>),
}

impl<'a> Received<'a> {
    /// A DC API request: its protocol, its `data` and the Origin the platform reports. Refused
    /// per U1 (a protocol outside A.1's or outside `protocols`), U2, U3 for unsigned `data`, U10
    /// and U16.
    ///
    /// # Errors
    ///
    /// The U rule `data` or the protocol breaks.
    pub fn dc_api(
        protocol: &str,
        data: &'a str,
        origin: Origin<'a>,
        protocols: &DcApiProtocols,
    ) -> Result<Self, Unreadable> {
        let protocol = DcApiProtocol::parse(protocol)?;
        if !protocols.holds(protocol) {
            return Err(Unreadable::Unregistered(protocol));
        }
        let request = match protocol {
            DcApiProtocol::Unsigned => {
                DcApiRequest::Unsigned(Parameters::parse(data).map_err(Unreadable::Json)?)
            }
            DcApiProtocol::Signed => {
                let jws = wrapped(data).map_err(|cause| Unreadable::Shape { protocol, cause })?;
                DcApiRequest::Signed(CompactJws::parse(jws).map_err(Unreadable::Jws)?)
            }
            // A.3.2.2's example puts the serialization in `data` itself (reading 5).
            DcApiProtocol::Multisigned => {
                let jws = match wrapped(data) {
                    Ok(jws) => jws,
                    Err(DataShape::Json(_) | DataShape::Request) => Cow::Borrowed(data),
                };
                DcApiRequest::Multisigned(JsonJws::parse(jws).map_err(Unreadable::Jws)?)
            }
        };
        let digest = match &request {
            DcApiRequest::Unsigned(_) => {
                RequestDigest::of(&[origin.as_str().as_bytes(), &[0], data.as_bytes()])
            }
            DcApiRequest::Signed(jws) => RequestDigest::of(&[
                origin.as_str().as_bytes(),
                &[1],
                jws.text().as_bytes(),
                jws.payload().as_bytes(),
            ]),
            DcApiRequest::Multisigned(jws) => RequestDigest::of(&[
                origin.as_str().as_bytes(),
                &[2],
                jws.text().as_bytes(),
                jws.payload().as_bytes(),
            ]),
        };
        Ok(Self {
            form: ReceivedForm::DcApi { origin, request },
            digest,
        })
    }

    /// A request by URI with its Request Object, its digest over the URI and the Request Object.
    #[cfg(feature = "resolve")]
    pub(crate) fn uri(uri: AuthorizationUri<'a>, object: CompactJws<'a>) -> Self {
        let digest =
            RequestDigest::of(&[uri.as_str().as_bytes(), &[0x10], object.text().as_bytes()]);
        Self {
            form: ReceivedForm::Uri { uri, object },
            digest,
        }
    }

    /// How the request arrived.
    #[must_use]
    pub const fn form(&self) -> &ReceivedForm<'a> {
        &self.form
    }

    /// The digest records commit to.
    #[must_use]
    pub const fn digest(&self) -> &RequestDigest {
        &self.digest
    }
}

/// `data.request` as A.3.2.1 places a JWS: `data` a JSON object with unique member names whose
/// `request` is a string.
fn wrapped(data: &str) -> Result<Cow<'_, str>, DataShape> {
    let request = RawObject::parse(data)
        .map_err(DataShape::Json)?
        .get("request")
        .ok_or(DataShape::Request)?;
    json::string(request).map_err(|_| DataShape::Request)
}
