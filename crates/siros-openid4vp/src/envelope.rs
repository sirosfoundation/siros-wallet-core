//! The request's parameters and signatures, read from what was received and verified by nothing
//! yet: what the matcher parses, and what authentication verifies.

use std::borrow::Cow;
use std::fmt;

use siros_explain::{IntoArg, kind};

use serde_json::value::RawValue;

use crate::arrival::{DcApiRequest, Received, ReceivedForm, Unreadable};
use crate::ids::{ClientId, Origin};
use crate::jose::{CompactJws, JsonJws, ProtectedHeader, Signed};
use crate::json::{JsonError, Member, Node, Object, RawObject};
use crate::plugins::Registry;
use crate::plugins::registry::Routes;
use crate::routing::{ChannelKind, Routing};

/// The request's parameters: DC API `data` or the Request Object's payload, a JSON object with
/// unique member names at every level. `client_metadata` is kept as received: its own levels are
/// C6's.
#[derive(Debug, Clone)]
pub struct Parameters<'r> {
    raw: RawObject<'r>,
    read: Object<'r>,
}

impl<'r> Parameters<'r> {
    /// The parameters of a JSON text.
    ///
    /// # Errors
    ///
    /// The text is no JSON object with unique member names at every level outside
    /// `client_metadata` (U3).
    pub fn parse(text: &'r str) -> Result<Self, JsonError> {
        let raw = RawObject::parse(text)?;
        let read = raw
            .members()
            .filter(|(name, _)| *name != "client_metadata")
            .map(|(name, value)| {
                Node::from_raw(value).map(|value| Member {
                    name: Cow::Owned(name.to_owned()),
                    value,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            raw,
            read: Object::new(read)?,
        })
    }

    /// A parameter's JSON value as received.
    #[must_use]
    pub fn raw(&self, name: &str) -> Option<&'r RawValue> {
        self.raw.get(name)
    }

    /// A parameter's JSON value; `None` for an absent one and for `client_metadata`.
    #[must_use]
    pub fn json(&self, name: &str) -> Option<&Node<'r>> {
        self.read.get(name)
    }

    /// A parameter that is a JSON string; `Some(None)` for another value.
    #[must_use]
    pub fn text(&self, name: &str) -> Option<Option<Cow<'r, str>>> {
        self.json(name).map(|value| match value {
            Node::String(text) => Some(text.clone()),
            _ => None,
        })
    }

    /// Whether the parameters name the member.
    #[must_use]
    pub fn holds(&self, name: &str) -> bool {
        self.raw.get(name).is_some()
    }
}

/// Where the request came from.
#[derive(Debug, Clone, Copy)]
pub enum Channel<'r> {
    /// The DC API, from this Origin.
    DcApi(&'r Origin<'r>),
    /// A URI, its Request Object fetched.
    Uri,
}

impl Channel<'_> {
    /// The channel's kind.
    #[must_use]
    pub const fn kind(&self) -> ChannelKind {
        match self {
            Self::DcApi(_) => ChannelKind::DcApi,
            Self::Uri => ChannelKind::Uri,
        }
    }
}

/// The request's signatures, each the JWS the request arrived in, whose parse holds its
/// signatures.
#[derive(Debug, Clone)]
pub enum Signatures<'r> {
    /// An unsigned DC API request.
    Unsigned,
    /// A Request Object: one signature, and the `client_id` of its payload; `None` when the
    /// payload names none, which A3 refuses over the DC API and U14 by URI.
    One {
        /// The JWS.
        jws: &'r CompactJws<'r>,
        /// The payload's `client_id`.
        client_id: Option<ClientId<'r>>,
    },
    /// A multisigned DC API request: one or more signatures, each with the `client_id` of its
    /// protected header (A.3.2.2).
    Many(Multisigned<'r>),
}

/// A JWS JSON Serialization and its signers in the order received: one or more.
#[derive(Debug, Clone)]
pub struct Multisigned<'r> {
    jws: &'r JsonJws<'r>,
    first: Signer<'r>,
    rest: Vec<Signer<'r>>,
}

impl<'r> Multisigned<'r> {
    /// Each signature's `client_id`, read from its protected header (U3).
    fn read(jws: &'r JsonJws<'r>) -> Result<Self, Unreadable> {
        Ok(Self {
            jws,
            first: Signer::read(jws.first())?,
            rest: jws.rest().map(Signer::read).collect::<Result<_, _>>()?,
        })
    }

    /// The JWS.
    #[must_use]
    pub const fn jws(&self) -> &'r JsonJws<'r> {
        self.jws
    }

    /// The first signer.
    #[must_use]
    pub const fn first(&self) -> &Signer<'r> {
        &self.first
    }

    /// The signers after the first, in the order received.
    pub fn rest(&self) -> impl Iterator<Item = &Signer<'r>> {
        self.rest.iter()
    }
}

/// One signature of a multisigned request and the `client_id` of its protected header; `None`
/// when the header names none, which A3 refuses.
#[derive(Debug, Clone)]
pub struct Signer<'r> {
    signed: Signed<'r>,
    client_id: Option<ClientId<'r>>,
}

impl<'r> Signer<'r> {
    /// The signature and its header's `client_id`, within RFC 6749 Appendix A.1 (U3).
    fn read(signed: Signed<'r>) -> Result<Self, Unreadable> {
        let client_id = match signed.header().member("client_id") {
            None => None,
            Some(Node::String(text)) => {
                Some(ClientId::parse(text.clone()).map_err(|e| Unreadable::ClientId(e.value))?)
            }
            Some(other) => return Err(Unreadable::ClientId(other.python_compact().to_string())),
        };
        Ok(Self { signed, client_id })
    }

    /// The signature.
    #[must_use]
    pub const fn signed(&self) -> Signed<'r> {
        self.signed
    }

    /// The protected header's `client_id`.
    #[must_use]
    pub const fn client_id(&self) -> Option<&ClientId<'r>> {
        self.client_id.as_ref()
    }
}

/// The request's parameters, signatures and routing, its mode the registry's it was read with,
/// which every later step reads. The channel is the received form's.
#[derive(Debug, Clone)]
pub struct Envelope<'r> {
    received: &'r Received<'r>,
    parameters: Parameters<'r>,
    signatures: Signatures<'r>,
    routing: Routing<'r>,
}

/// The media type a Request Object's `typ` names (§5; RFC 9101 §10.8).
const REQUEST_OBJECT: &str = "oauth-authz-req+jwt";

impl<'r> Envelope<'r> {
    /// The envelope of a received request, its routing read over the registry's response types
    /// and modes: the type and the mode the request names on its channel. The envelope keeps the
    /// registry's. Refused per U3, U10, U12, U13, U14, U16 and U17; the routing's rules are
    /// refusals it holds.
    ///
    /// # Errors
    ///
    /// The U rule the request breaks.
    pub fn parse<H>(
        received: &'r Received<'r>,
        registry: &'r Registry<H>,
    ) -> Result<Self, Unreadable> {
        let routes: &'r dyn Routes = registry;
        let (parameters, signatures) = match received.form() {
            ReceivedForm::DcApi { request, .. } => match request {
                DcApiRequest::Unsigned(parameters) => (parameters.clone(), Signatures::Unsigned),
                DcApiRequest::Signed(jws) => {
                    let parameters = object(jws)?;
                    let client_id = client_id(&parameters)?;
                    (parameters, Signatures::One { jws, client_id })
                }
                DcApiRequest::Multisigned(jws) => {
                    jws.signatures()
                        .try_for_each(|signed| typ(signed.header()))?;
                    let parameters =
                        nested(Parameters::parse(jws.payload()).map_err(Unreadable::Json)?)?;
                    if parameters.holds("client_id") {
                        return Err(Unreadable::Placement(ClientIdPlacement::Payload));
                    }
                    if jws.signatures().any(|signed| {
                        signed
                            .unprotected()
                            .is_some_and(|header| header.get("client_id").is_some())
                    }) {
                        return Err(Unreadable::Placement(ClientIdPlacement::UnprotectedHeader));
                    }
                    (parameters, Signatures::Many(Multisigned::read(jws)?))
                }
            },
            #[cfg(feature = "resolve")]
            ReceivedForm::Uri { uri, object: jws } => {
                let parameters = object(jws)?;
                let client_id = client_id(&parameters)?;
                if client_id.as_ref() != Some(uri.client_id()) {
                    return Err(Unreadable::ClientIdMismatch {
                        outer: uri.client_id().to_string(),
                        inner: client_id.map(|inner| inner.to_string()),
                    });
                }
                (parameters, Signatures::One { jws, client_id })
            }
        };
        let routing = Routing::read(&parameters, &channel(received), routes);
        Ok(Self {
            received,
            parameters,
            signatures,
            routing,
        })
    }

    /// What the request asks of its answer: every later step reads it here.
    #[must_use]
    pub const fn routing(&self) -> &Routing<'r> {
        &self.routing
    }

    /// The request as received.
    #[must_use]
    pub const fn received(&self) -> &'r Received<'r> {
        self.received
    }

    /// The channel the received form names.
    #[must_use]
    pub fn channel(&self) -> Channel<'r> {
        channel(self.received)
    }

    /// The parameters: the Request Object's alone when there is one (§5.10.1, RFC 9101 §6.3).
    #[must_use]
    pub const fn parameters(&self) -> &Parameters<'r> {
        &self.parameters
    }

    /// The signatures.
    #[must_use]
    pub const fn signatures(&self) -> &Signatures<'r> {
        &self.signatures
    }

    /// The `client_id` of a Request Object ([`Signatures::One`]); `None` for an unsigned DC API
    /// request, whose `client_id` the wallet ignores (A.2), and for a multisigned one, whose
    /// signatures each name theirs.
    #[must_use]
    pub const fn client_id(&self) -> Option<&ClientId<'r>> {
        match &self.signatures {
            Signatures::One { client_id, .. } => client_id.as_ref(),
            Signatures::Unsigned | Signatures::Many(_) => None,
        }
    }

    /// `verifier_info` as received, for the trust service (reading 22).
    #[must_use]
    pub fn verifier_info(&self) -> Option<&'r RawValue> {
        self.parameters.raw("verifier_info")
    }
}

fn channel<'r>(received: &'r Received<'r>) -> Channel<'r> {
    match received.form() {
        ReceivedForm::DcApi { origin, .. } => Channel::DcApi(origin),
        #[cfg(feature = "resolve")]
        ReceivedForm::Uri { .. } => Channel::Uri,
    }
}

/// U12: `typ` names the Request Object's media type.
fn typ(header: &ProtectedHeader) -> Result<(), Unreadable> {
    if header.typ_is(REQUEST_OBJECT) {
        Ok(())
    } else {
        Err(Unreadable::Typ(header.typ().map(str::to_owned)))
    }
}

/// A compact JWS's parameters: its `typ` (U12), its payload's JSON (U3), no nesting (U13).
fn object<'r>(jws: &'r CompactJws<'r>) -> Result<Parameters<'r>, Unreadable> {
    typ(jws.header())?;
    nested(Parameters::parse(jws.payload()).map_err(Unreadable::Json)?)
}

/// U13: a Request Object holds neither `request` nor `request_uri` (RFC 9101 §4).
fn nested(parameters: Parameters<'_>) -> Result<Parameters<'_>, Unreadable> {
    match NestedParameter::ALL
        .into_iter()
        .find(|name| parameters.holds(name.as_str()))
    {
        Some(name) => Err(Unreadable::Nested(name)),
        None => Ok(parameters),
    }
}

/// The payload's `client_id`, within RFC 6749 Appendix A.1 (U3).
fn client_id<'r>(parameters: &Parameters<'r>) -> Result<Option<ClientId<'r>>, Unreadable> {
    match parameters.json("client_id") {
        None => Ok(None),
        Some(Node::String(text)) => ClientId::parse(text.clone())
            .map(Some)
            .map_err(|e| Unreadable::ClientId(e.value)),
        Some(other) => Err(Unreadable::ClientId(other.python_compact().to_string())),
    }
}

/// A parameter that nests a request in a Request Object (U13).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NestedParameter {
    /// `request`.
    Request,
    /// `request_uri`.
    RequestUri,
}

impl NestedParameter {
    const ALL: [Self; 2] = [Self::Request, Self::RequestUri];

    /// The parameter's name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::RequestUri => "request_uri",
        }
    }
}

impl fmt::Display for NestedParameter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A parameter is named by its name in a message.
impl IntoArg for NestedParameter {
    type Kind = kind::Name;

    fn arg(&self) -> &'static str {
        self.as_str()
    }
}

/// Where a multisigned request names a `client_id` outside its protected headers (U17).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientIdPlacement {
    /// The payload.
    Payload,
    /// An unprotected header.
    UnprotectedHeader,
}

impl ClientIdPlacement {
    /// The place as a message names it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Payload => "payload",
            Self::UnprotectedHeader => "unprotected header",
        }
    }
}

impl fmt::Display for ClientIdPlacement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A place is named by its words in a message.
impl IntoArg for ClientIdPlacement {
    type Kind = kind::Name;

    fn arg(&self) -> &'static str {
        self.as_str()
    }
}
