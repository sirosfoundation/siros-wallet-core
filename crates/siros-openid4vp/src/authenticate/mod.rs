//! Verifier authentication (§5.9, A.2, A.3): the Client Identifier read by its prefix (§5.9.1),
//! the prefix a plug-in that binds a key to the Verifier and vouches for its endpoint from the
//! caller's decisions; the core verifies the signature under the bound key. The matcher never
//! authenticates.

mod pending;

use std::borrow::Cow;
use std::fmt;

use dyn_clone::DynClone;
use serde_json::value::RawValue;
use siros_explain::{AllOf, Explain, Explained, IntoArg, kind};

use crate::effects::{Decided, Evaluation};
use crate::envelope::Parameters;
use crate::host::Timestamp;
use crate::ids::{ClientId, Origin};
use crate::jose::{Signed, Skew, VerificationKey};
use crate::json::{Member, Node, Object};
use crate::refusal::{ErrorCode, Refusal};
use crate::uri::{RequestUri, ResponseUri};

pub use pending::{Authenticated, Pending};

/// A Client Identifier Prefix (§5.9.1): the text before the first `:`, one or more characters of
/// RFC 6749 Appendix A.1's `VSCHAR` other than `:`, and other than the reserved `origin`
/// (§5.9.3). A plug-in makes its own with `siros_explain::checked!`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PrefixName(&'static str);

impl PrefixName {
    /// The prefix; `None` for an empty text, a character outside `VSCHAR`, a `:`, or `origin`.
    #[must_use]
    pub const fn new(name: &'static str) -> Option<Self> {
        let mut rest = name.as_bytes();
        let mut origin = ORIGIN;
        let mut reserved = rest.len() == ORIGIN.len();
        while let [byte, tail @ ..] = rest {
            if *byte < 0x20 || *byte > 0x7e || *byte == b':' {
                return None;
            }
            if let [letter, others @ ..] = origin {
                reserved = reserved && *byte == *letter;
                origin = others;
            }
            rest = tail;
        }
        if name.is_empty() || reserved {
            None
        } else {
            Some(Self(name))
        }
    }

    /// The prefix as written before the `:`.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        self.0
    }
}

/// The reserved prefix of an unsigned DC API request's Verifier (§5.9.3).
const ORIGIN: &[u8] = b"origin";

impl fmt::Display for PrefixName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// A prefix is named by its text in a message.
impl IntoArg for PrefixName {
    type Kind = kind::Name;

    fn arg(&self) -> &'static str {
        self.0
    }
}

/// What a prefix reads of a signed request. Only `Envelope::questions` makes one, from the
/// envelope and the signature the Client Identifier belongs to.
#[derive(Debug, Clone)]
pub struct ClientClaim<'c> {
    client_id: ClientId<'c>,
    signed: Signed<'c>,
    parameters: &'c Parameters<'c>,
    channel: ClaimChannel<'c>,
    verifier_info: Option<&'c RawValue>,
    query: Option<&'c RawValue>,
}

impl<'c> ClientClaim<'c> {
    /// The full Client Identifier (§14.8).
    #[must_use]
    pub const fn client_id(&self) -> &ClientId<'c> {
        &self.client_id
    }

    /// The part after the prefix and its `:`.
    #[must_use]
    pub fn original(&self) -> &str {
        self.client_id
            .as_str()
            .split_once(':')
            .map_or("", |(_, original)| original)
    }

    /// The signature the Client Identifier belongs to.
    #[must_use]
    pub const fn signed(&self) -> Signed<'c> {
        self.signed
    }

    /// The request parameters.
    #[must_use]
    pub const fn parameters(&self) -> &'c Parameters<'c> {
        self.parameters
    }

    /// The channel, with what the prefix reads of it.
    #[must_use]
    pub const fn channel(&self) -> &ClaimChannel<'c> {
        &self.channel
    }

    /// `verifier_info` as received: the prefix puts it in its evaluation's context, and the trust
    /// service owns every rule on it (reading 22).
    #[must_use]
    pub const fn verifier_info(&self) -> Option<&'c RawValue> {
        self.verifier_info
    }

    /// `dcql_query` as received, in the same context, for the over-asking check (CS-13
    /// WU-INT-01).
    #[must_use]
    pub const fn query(&self) -> Option<&'c RawValue> {
        self.query
    }

    /// The context a prefix's evaluation carries: `channel` (`dc_api` or `uri`), the `origin`
    /// over the DC API, the `response_uri` and the `request_uri` by URI (§15.8.2), and
    /// `verifier_info` and `dcql_query` as received (reading 22).
    #[must_use]
    pub fn context(&self) -> Object<'static> {
        let text = |value: &str| Node::String(Cow::Owned(value.to_owned()));
        let mut members = Vec::new();
        match &self.channel {
            ClaimChannel::DcApi(origin) => {
                members.push(("channel", text("dc_api")));
                members.push(("origin", text(origin.as_str())));
            }
            ClaimChannel::Uri {
                request_uri,
                response_uri,
            } => {
                members.push(("channel", text("uri")));
                if let Some(uri) = response_uri {
                    members.push(("response_uri", text(uri.as_str())));
                }
                members.push(("request_uri", text(request_uri.as_str())));
            }
        }
        for name in ["verifier_info", "dcql_query"] {
            if let Some(value) = self.parameters.json(name) {
                members.push((name, value.clone().into_owned()));
            }
        }
        Object::distinct(
            members
                .into_iter()
                .map(|(name, value)| Member {
                    name: Cow::Borrowed(name),
                    value,
                })
                .collect(),
        )
    }
}

/// The channel of a claim, with what the prefix reads of it.
#[derive(Debug, Clone)]
pub enum ClaimChannel<'c> {
    /// The DC API, from this Origin.
    DcApi(&'c Origin<'c>),
    /// A URI: the `request_uri` the Request Object came from (§15.8.2), and the request's
    /// `response_uri`, parsed (A13); `None` when the request names none, which A12 refuses.
    Uri {
        /// The `request_uri`.
        request_uri: &'c RequestUri,
        /// The `response_uri`.
        response_uri: Option<ResponseUri>,
    },
}

/// A prefix rule a claim breaks: the prefix the core called, and the plug-in's rule (A5). The
/// core makes one from [`ClientPrefix::claim`]'s refusal.
#[derive(Debug, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.authenticate", id = "prefix")]
#[error("{prefix}: {rule}")]
pub struct PrefixRefusal {
    prefix: PrefixName,
    rule: Box<dyn Explained>,
}

impl PrefixRefusal {
    /// The prefix.
    #[must_use]
    pub const fn prefix(&self) -> PrefixName {
        self.prefix
    }

    /// The plug-in's rule.
    #[must_use]
    pub fn rule(&self) -> &dyn Explained {
        &*self.rule
    }
}

/// A prefix plug-in (§5.9.3: "Other specifications can define further Client Identifier
/// Prefixes"): its name. Its claim is [`PrefixHost`].
///
/// # Implementing
///
/// `name` is a constant; the registry refuses a name registered twice (`PrefixTwice`), and
/// [`PrefixName`] refuses `origin`. `PrefixHost::claim` reads the core-made [`ClientClaim`] and
/// returns its rule's refusal (A5) or a [`PrefixClaim`]: the evaluations the caller answers, the
/// binding read from their decisions, and by URI what vouches for the `response_uri`. The prefix
/// binds a key; the core checks the `alg` against `Haip::verifies` before it asks the caller
/// (A7), verifies the signature under the bound key through the `Haip` the registration reached
/// (A8), and binds the endpoint itself, so a prefix reaches no endpoint and no key the request
/// and the decisions do not give.
pub trait ClientPrefix: DynClone + Send + Sync {
    /// The prefix as written before the `:`.
    fn name(&self) -> PrefixName;
}

/// A prefix's claim over the build's host: its bounds name the modules it calls.
pub trait PrefixHost<H>: ClientPrefix {
    /// Reads a claim: the prefix's syntax and header rules, refused with the rule the claim
    /// breaks (A5), and the questions its trust framework answers.
    ///
    /// # Errors
    ///
    /// The prefix's rule the claim breaks.
    fn claim<'c>(
        &'c self,
        claim: ClientClaim<'c>,
        host: &H,
    ) -> Result<Box<dyn PrefixClaim + 'c>, Box<dyn Explained>>;
}

/// A prefix the registry takes, as [`HostedFormat`](crate::plugins::HostedFormat) takes a format.
pub trait HostedPrefix<H>: PrefixHost<H> {}

impl<H, P: PrefixHost<H>> HostedPrefix<H> for P {}

dyn_clone::clone_trait_object!(<H> HostedPrefix<H>);

/// A claim a prefix read: its evaluations, then its binding from their decisions, then, by URI,
/// what vouches for the endpoint. The core hands each method the decisions on the claim's own
/// evaluations, one per evaluation, in the order `questions` gave them.
pub trait PrefixClaim {
    /// The evaluations for the caller, in order.
    fn questions(&self) -> Vec<Evaluation>;

    /// The key and what the framework states, from the decisions at `now` (A6).
    ///
    /// # Errors
    ///
    /// The decisions bind nothing.
    fn bind(
        &self,
        decided: Decided<'_>,
        now: Timestamp,
        skew: Skew,
    ) -> Result<ClientBinding, Unbound>;

    /// What vouches for the request's `response_uri` (A12). The core asks it of a URI request
    /// alone, once `bind` holds, with the `response_uri` the request names; over the DC API the
    /// endpoint is the platform's.
    ///
    /// # Errors
    ///
    /// Nothing vouches for the `response_uri`.
    fn endpoint(
        &self,
        decided: Decided<'_>,
        response_uri: &ResponseUri,
    ) -> Result<EndpointBasis, Unbound>;
}

/// Why a claim binds nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.authenticate.unbound")]
pub enum Unbound {
    /// A6: a `Deny`, or a decision that binds nothing.
    #[error("the trust framework does not bind the Verifier")]
    Denied,
    /// A12: the decision's `endpoints` omit the `response_uri`, or the prefix's own endpoint
    /// rule refuses it (§5.9.3).
    #[error("the response_uri is none the framework allows")]
    Endpoint,
}

/// Where answers go, as the core bound it: the platform over the DC API; by URI the request's
/// `response_uri` and what vouches for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoundEndpoint {
    /// The DC API return to the Origin.
    DcApi,
    /// The request's `response_uri`.
    ResponseUri {
        /// The endpoint.
        uri: ResponseUri,
        /// What vouches for it.
        basis: EndpointBasis,
    },
}

/// What vouches for a bound `response_uri` (RFC 6749 §4.1.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointBasis {
    /// The framework, apart from the request: the trust decision lists the endpoint, or the
    /// identifier the prefix authenticated names its host (§5.9.3). The error of a request that
    /// fails a later check goes there.
    Framework,
    /// The request, which names it: it stands once the request is authenticated.
    Request,
}

/// What a prefix binds to the Verifier.
#[derive(Debug, Clone)]
pub struct ClientBinding {
    /// The key the signature verifies under.
    pub key: VerificationKey,
    /// How the trust framework names the Verifier, for the consent.
    pub name: Option<String>,
    /// What the trust framework states about the Verifier (its decision's context `facts`), for
    /// the plug-ins that read it.
    pub facts: Option<Object<'static>>,
}

/// Whether the wallet asks the caller about the Origin of an unsigned DC API request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginPolicy {
    /// The platform's Origin stands.
    Accept,
    /// An evaluation of the Origin as the subject.
    Evaluate,
}

/// A Request Object's `exp` and `aud`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestClaims {
    /// Checked when present (RFC 7519 §4.1.3, §4.1.4).
    Checked,
    /// Present, then checked (CS-02 §8.2: "The Presentation Request Object MUST include"): A9
    /// for `exp` absent, A10 for `aud` absent.
    Required,
}

/// A rule a profile or a deployment sets on an authenticated Request Object's claims, beside RFC
/// 7519's checks when present (A9, A10): a claim it requires, a value it restricts.
///
/// # Implementing
///
/// `check` reads the Request Object's payload claims as the signature covers them, after A10,
/// and returns its rule's refusal; the core refuses the request with A14 and the rule's code. The
/// rule reads claims alone and reaches no key or endpoint.
pub trait ObjectRule: DynClone + Send + Sync {
    /// The rule's refusal of the claims; `None` when they hold.
    fn check(&self, claims: &Object<'_>) -> Option<Refusal>;
}

dyn_clone::clone_trait_object!(ObjectRule);

/// The wallet's authentication configuration.
#[derive(Debug, Clone, Copy)]
pub struct TrustConfig {
    /// The clock skew allowed.
    pub skew: Skew,
    /// Unsigned DC API requests.
    pub origins: OriginPolicy,
    /// A Request Object's `exp` and `aud`.
    pub claims: RequestClaims,
}

/// Why the wallet does not authenticate the Verifier (the A rules).
#[derive(Debug, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.authenticate")]
pub enum Unauthenticated {
    /// A1: the reserved `origin` prefix (§5.9.3).
    #[error("A1 the origin Client Identifier Prefix is reserved")]
    #[explain(id = "a1")]
    Origin,
    /// A2: a prefix the wallet does not support, or none (a pre-registered client; §5.9.2).
    #[error("A2 the Client Identifier {0} names no prefix the wallet supports")]
    #[explain(id = "a2")]
    UnknownPrefix(#[explain(name = "client_id")] String),
    /// A3: a signed DC API request without `client_id` (A.2).
    #[error("A3 a signed request without client_id")]
    #[explain(id = "a3")]
    ClientIdAbsent,
    /// A5: a prefix rule.
    #[error("A5 {0}")]
    #[explain(id = "a5")]
    Prefix(#[explain(name = "rule")] PrefixRefusal),
    /// A7: the JWS `alg` is none the verifying module states (`Haip::verifies`; RFC 8725 §3.1).
    #[error("A7 alg {0} is none the wallet verifies")]
    #[explain(id = "a7")]
    Algorithm(#[explain(name = "alg")] String),
    /// A6: the trust framework denies the Verifier.
    #[error("A6 {0}: the trust framework does not bind the Verifier")]
    #[explain(id = "a6")]
    Untrusted(#[explain(name = "client_id")] String),
    /// A8: the signature does not verify under the bound key.
    #[error("A8 the signature does not verify")]
    #[explain(id = "a8")]
    Signature,
    /// A9: the Request Object is expired or not yet valid (RFC 7519 §4.1.4, §4.1.5), or under
    /// `RequestClaims::Required` states no `exp`.
    #[error("A9 the Request Object is outside its validity: {0}")]
    #[explain(id = "a9")]
    Validity(#[explain(name = "cause")] OutsideValidity),
    /// A10: `aud` names another recipient than `https://self-issued.me/v2` (§5.8, RFC 7519
    /// §4.1.3), or under `RequestClaims::Required` is absent.
    #[error("A10 aud {0:?} names another recipient")]
    #[explain(id = "a10")]
    Audience(#[explain(name = "aud")] Option<String>),
    /// A11: no signature of a multisigned request authenticates; each one's reason.
    #[error("A11 no signature authenticates the Verifier")]
    #[explain(id = "a11")]
    NoSignature(#[explain(name = "reasons")] AllOf<Unauthenticated>),
    /// A12: by URI, no `response_uri`, or one the prefix's binding does not allow: outside the
    /// trust decision's list, or outside the prefix's own endpoint rule (§8.2, §5.9.3).
    #[error("A12 response_uri {0:?} is none the framework allows")]
    #[explain(id = "a12")]
    Endpoint(#[explain(name = "response_uri")] Option<String>),
    /// A13: a `response_uri` that is no absolute https URI with a host (RFC 9700 §2.6).
    #[error("A13 {0}")]
    #[explain(id = "a13")]
    EndpointScheme(#[explain(name = "cause")] crate::uri::NotHttps),
    /// A14: a registered [`ObjectRule`] refuses the Request Object's claims; the code is the
    /// rule's.
    #[error("A14 {0}")]
    #[explain(id = "a14")]
    Object(#[explain(name = "rule")] Refusal),
}

impl Unauthenticated {
    /// The rule's code (§8.5, RFC 9101 §6.2).
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Object(refusal) => refusal.code(),
            Self::Algorithm(_)
            | Self::Signature
            | Self::Validity(_)
            | Self::Audience(_)
            | Self::NoSignature(_) => ErrorCode::INVALID_REQUEST_OBJECT,
            Self::Origin
            | Self::UnknownPrefix(_)
            | Self::ClientIdAbsent
            | Self::Prefix(_)
            | Self::Untrusted(_)
            | Self::Endpoint(_)
            | Self::EndpointScheme(_) => ErrorCode::INVALID_REQUEST,
        }
    }
}

/// Why a Request Object is outside its validity (A9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.authenticate.validity")]
pub enum OutsideValidity {
    /// `exp` or `nbf` is no NumericDate, `exp` has passed or `nbf` is still ahead.
    #[error(transparent)]
    Time(crate::jose::TimeError),
    /// `exp` absent under `RequestClaims::Required`.
    #[error("exp is absent")]
    ExpAbsent,
}

/// The Verifier as authenticated.
#[derive(Debug, Clone)]
pub enum VerifierId<'r> {
    /// An unsigned DC API request: its Origin.
    Origin(&'r Origin<'r>),
    /// A Client Identifier, prefix included.
    Client(ClientId<'r>),
}

/// The authenticated Verifier: who, how the framework names it, its metadata, its endpoint. Only
/// [`Pending::authenticate`] makes one, inside the [`Authenticated`] it returns.
#[derive(Debug, Clone)]
pub struct Verifier<'r> {
    id: VerifierId<'r>,
    name: Option<String>,
    facts: Option<Object<'static>>,
    metadata: Option<&'r RawValue>,
    endpoint: BoundEndpoint,
}

impl<'r> Verifier<'r> {
    /// Who.
    #[must_use]
    pub const fn id(&self) -> &VerifierId<'r> {
        &self.id
    }

    /// The framework's name for it.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// What the framework states about it ([`ClientBinding::facts`]).
    #[must_use]
    pub const fn facts(&self) -> Option<&Object<'static>> {
        self.facts.as_ref()
    }

    /// The request's `client_metadata` (§5.9.3: all metadata but the key).
    #[must_use]
    pub const fn metadata(&self) -> Option<&'r RawValue> {
        self.metadata
    }

    /// The endpoint answers go to.
    #[must_use]
    pub const fn endpoint(&self) -> &BoundEndpoint {
        &self.endpoint
    }
}
