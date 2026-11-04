//! The authentication steps: the envelope's trust questions ([`Envelope::questions`]), then the
//! caller's decisions on them and the checks under the bound key ([`Pending::authenticate`]).

use std::borrow::Cow;

use siros_explain::AllOf;

use super::{
    BoundEndpoint, ClaimChannel, ClientBinding, ClientClaim, EndpointBasis, ObjectRule,
    OriginPolicy, PrefixClaim, PrefixRefusal, TrustConfig, Unauthenticated, Unbound, Verifier,
    VerifierId,
};
use crate::arrival::ReceivedForm;
use crate::effects::{
    Action, ActionName, Decided, Decision, Entity, EntityId, EntityType, Evaluation, Slots, Verdict,
};
use crate::envelope::{Channel, Envelope, Signatures, Signer};
use crate::host::{CoreHost, Host, Platform};
use crate::ids::{ClientId, Origin};
use crate::jose::{Signed, TimeError, Validity};
use crate::json::{Node, Object};
use crate::plugins::Registry;
use crate::plugins::registry::HaipAccess;
use crate::recourse::{self, ErrorRoute, Rejected};
use crate::uri::ResponseUri;

/// The audience a Request Object may name: the wallet, discovered statically (§5.8; reading 13).
const SELF_ISSUED: &str = "https://self-issued.me/v2";

/// The Origin's evaluation: its subject and resource types, and the action.
const ORIGIN: EntityType = siros_explain::checked!(EntityType, "origin");
const VERIFIER: ActionName = siros_explain::checked!(ActionName, "credential-verifier");

/// A request whose evaluations wait for the caller's decisions: one slot per evaluation, held
/// with what asked it.
#[must_use]
pub struct Pending<'e, H> {
    envelope: &'e Envelope<'e>,
    rules: &'e [Box<dyn ObjectRule>],
    response_uri: Option<ResponseUri>,
    asked: Asked<'e, H>,
}

/// What a pending request asked: the Origin's evaluation of an unsigned DC API request under
/// `OriginPolicy::Evaluate`, nothing under `Accept`, or each signature's claim, the first apart.
enum Asked<'e, H> {
    Origin(&'e Origin<'e>, Slots<Evaluation>),
    Nothing(&'e Origin<'e>),
    Claims(Claimed<'e, H>, Vec<Claimed<'e, H>>),
}

/// A signature's claim: read by its prefix, with the slots of its own evaluations and the
/// accessor of the `Haip` the prefix's registration bounded, or refused by A1 to A5 or A7.
enum Claimed<'e, H> {
    Read {
        client_id: ClientId<'e>,
        signed: Signed<'e>,
        claim: Box<dyn PrefixClaim + 'e>,
        slots: Slots<Evaluation>,
        haip: HaipAccess<H>,
    },
    Refused(Unauthenticated),
}

impl<'e, H> Claimed<'e, H> {
    fn of(read: Result<Pieces<'e, H>, Unauthenticated>) -> Self {
        match read {
            Ok(Pieces {
                client_id,
                signed,
                claim,
                haip,
            }) => {
                let slots = Slots::of(claim.questions());
                Self::Read {
                    client_id,
                    signed,
                    claim,
                    slots,
                    haip,
                }
            }
            Err(cause) => Self::Refused(cause),
        }
    }

    fn questions(&self) -> &[Evaluation] {
        match self {
            Self::Read { slots, .. } => slots.questions(),
            Self::Refused(_) => &[],
        }
    }
}

/// A request whose Verifier the wallet authenticated. Only [`Pending::authenticate`] makes one.
pub struct Authenticated<'e> {
    envelope: &'e Envelope<'e>,
    verifier: Verifier<'e>,
}

impl<'e> Authenticated<'e> {
    /// The envelope.
    #[must_use]
    pub const fn envelope(&self) -> &'e Envelope<'e> {
        self.envelope
    }

    /// The Verifier.
    #[must_use]
    pub const fn verifier(&self) -> &Verifier<'e> {
        &self.verifier
    }
}

impl<'e> Envelope<'e> {
    /// The questions that authenticate the Verifier: the Origin's evaluation for an unsigned DC
    /// API request (as configured), else each signature's prefix claim. Refused per A1 to A3, A5
    /// and A13, with the route [`Rejected`] describes.
    ///
    /// # Errors
    ///
    /// The A rule the request breaks.
    pub fn questions<H: CoreHost>(
        &'e self,
        registry: &'e Registry<H>,
        config: &TrustConfig,
        host: &H,
    ) -> Result<Pending<'e, H>, Box<Rejected<'e>>> {
        let reject = |cause: Unauthenticated, route| Box::new(Rejected::of(cause, route));
        let response_uri = match (self.channel(), self.routing().response_uri()) {
            (Channel::Uri, Some(text)) => Some(
                ResponseUri::parse(text.to_owned())
                    .map_err(|e| reject(Unauthenticated::EndpointScheme(e), None))?,
            ),
            _ => None,
        };
        let asked = match (self.signatures(), self.channel()) {
            (Signatures::Unsigned, Channel::DcApi(origin)) => match config.origins {
                OriginPolicy::Accept => Asked::Nothing(origin),
                OriginPolicy::Evaluate => {
                    Asked::Origin(origin, Slots::of(vec![origin_evaluation(origin)]))
                }
            },
            (Signatures::Unsigned, Channel::Uri)
            | (
                Signatures::One {
                    client_id: None, ..
                },
                _,
            ) => {
                return Err(reject(Unauthenticated::ClientIdAbsent, self.route()));
            }
            (
                Signatures::One {
                    jws,
                    client_id: Some(client_id),
                },
                _,
            ) => {
                let claimed = self
                    .claim(
                        registry,
                        host,
                        client_id.clone(),
                        jws.signed(),
                        response_uri.as_ref(),
                    )
                    .map_err(|cause| reject(cause, self.route()))?;
                Asked::Claims(Claimed::of(Ok(claimed)), Vec::new())
            }
            (Signatures::Many(signers), _) => {
                let read = |signer: &Signer<'e>| -> Result<Pieces<'e, H>, Unauthenticated> {
                    let client_id = signer.client_id().ok_or(Unauthenticated::ClientIdAbsent)?;
                    self.claim(
                        registry,
                        host,
                        client_id.clone(),
                        signer.signed(),
                        response_uri.as_ref(),
                    )
                };
                let first = read(signers.first());
                let rest: Vec<_> = signers.rest().map(read).collect();
                match first {
                    Err(first) if rest.iter().all(Result::is_err) => {
                        let reasons = rest
                            .into_iter()
                            .filter_map(Result::err)
                            .fold(AllOf::one(first), |all, cause| all.and(AllOf::one(cause)));
                        let cause = Unauthenticated::NoSignature(reasons);
                        return Err(reject(cause, self.route()));
                    }
                    first => Asked::Claims(
                        Claimed::of(first),
                        rest.into_iter().map(Claimed::of).collect(),
                    ),
                }
            }
        };
        Ok(Pending {
            envelope: self,
            rules: registry.object_rules(),
            response_uri,
            asked,
        })
    }

    /// A signature's claim, read by the prefix its Client Identifier names (§5.9.1): A1 for
    /// `origin`, A2 for an unregistered prefix or none (a pre-registered client, §5.9.2), A5 for
    /// the prefix's rule, A7 for an `alg` the `Haip` the prefix's registration bounded does not
    /// state.
    fn claim<H>(
        &'e self,
        registry: &'e Registry<H>,
        host: &H,
        client_id: ClientId<'e>,
        signed: Signed<'e>,
        response_uri: Option<&ResponseUri>,
    ) -> Result<Pieces<'e, H>, Unauthenticated> {
        let (prefix, haip) = match client_id.prefixed() {
            Some(("origin", _)) => return Err(Unauthenticated::Origin),
            Some((name, _)) => registry.client_prefix(name),
            None => None,
        }
        .ok_or_else(|| Unauthenticated::UnknownPrefix(client_id.to_string()))?;
        let channel = match self.received().form() {
            ReceivedForm::DcApi { origin, .. } => ClaimChannel::DcApi(origin),
            ReceivedForm::Uri { uri, .. } => ClaimChannel::Uri {
                request_uri: uri.request_uri(),
                response_uri: response_uri.cloned(),
            },
        };
        let read = ClientClaim {
            client_id: client_id.clone(),
            signed,
            parameters: self.parameters(),
            channel,
            verifier_info: self.verifier_info(),
            query: self.parameters().raw("dcql_query"),
        };
        let claim = prefix.claim(read, host).map_err(|rule| {
            Unauthenticated::Prefix(PrefixRefusal {
                prefix: prefix.name(),
                rule,
            })
        })?;
        let alg = signed.header().alg();
        if !haip(host).verifies().accepts(alg) {
            return Err(Unauthenticated::Algorithm(alg.to_owned()));
        }
        Ok(Pieces {
            client_id,
            signed,
            claim,
            haip,
        })
    }

    /// The route of an error before authentication: the DC API's, or by URI the `response_uri`
    /// the payload names, unverified.
    fn route(&self) -> Option<ErrorRoute<'e>> {
        match self.channel() {
            Channel::DcApi(_) => Some(recourse::dc_api_route()),
            Channel::Uri => recourse::unverified(self.parameters()),
        }
    }
}

/// A signature's claim before its slots are counted.
struct Pieces<'e, H> {
    client_id: ClientId<'e>,
    signed: Signed<'e>,
    claim: Box<dyn PrefixClaim + 'e>,
    haip: HaipAccess<H>,
}

/// The Origin's evaluation: may the Origin act as a credential Verifier over the DC API?
fn origin_evaluation(origin: &Origin<'_>) -> Evaluation {
    let entity = || Entity {
        kind: ORIGIN,
        id: EntityId::from(origin),
        properties: None,
    };
    Evaluation {
        subject: entity(),
        action: Action {
            name: VERIFIER,
            properties: None,
        },
        resource: entity(),
        context: Some(Object::single(
            Cow::Borrowed("channel"),
            Node::String(Cow::Borrowed("dc_api")),
        )),
    }
}

impl<'e, H: CoreHost> Pending<'e, H> {
    /// The evaluations for the caller, in order: the Origin's, or each claim's in the
    /// signatures' order.
    pub fn questions(&self) -> impl Iterator<Item = &Evaluation> {
        let (origin, first, rest): (&[Evaluation], &[Evaluation], &[Claimed<'e, H>]) =
            match &self.asked {
                Asked::Origin(_, slots) => (slots.questions(), &[], &[]),
                Asked::Nothing(_) => (&[], &[], &[]),
                Asked::Claims(first, rest) => (&[], first.questions(), rest),
            };
        origin
            .iter()
            .chain(first)
            .chain(rest.iter().flat_map(Claimed::questions))
    }

    /// The authenticated request. `decide` answers every evaluation of `questions`, once, in
    /// order, and each claim reads the decisions on its own evaluations. Then the first claim, in
    /// the signatures' order, whose binding holds (A6), whose endpoint holds by URI (A12: no
    /// `response_uri`, or [`PrefixClaim::endpoint`] refusing it), whose signature verifies under
    /// the bound key (A8), with the Request Object inside its validity (A9) and its `aud` absent
    /// or `https://self-issued.me/v2` (A10). A11 lists each signature's reason when none does. A
    /// refusal carries the route [`Rejected`] describes.
    ///
    /// # Errors
    ///
    /// The A rule the request breaks.
    pub fn authenticate(
        self,
        decide: impl FnMut(&Evaluation) -> Decision,
        config: &TrustConfig,
        host: &H,
    ) -> Result<Authenticated<'e>, Box<Rejected<'e>>> {
        let Self {
            envelope,
            rules,
            response_uri,
            asked,
        } = self;
        let authenticated = |id, binding: Option<ClientBinding>, endpoint| {
            let (name, facts) = binding.map_or((None, None), |b| (b.name, b.facts));
            Authenticated {
                envelope,
                verifier: Verifier {
                    id,
                    name,
                    facts,
                    metadata: envelope.parameters().raw("client_metadata"),
                    endpoint,
                },
            }
        };
        match asked {
            Asked::Nothing(origin) => Ok(authenticated(
                VerifierId::Origin(origin),
                None,
                BoundEndpoint::DcApi,
            )),
            Asked::Origin(origin, slots) => {
                let filled = slots.fill(decide);
                if filled
                    .replies()
                    .iter()
                    .all(|reply| reply.answer().verdict == Verdict::Permit)
                {
                    Ok(authenticated(
                        VerifierId::Origin(origin),
                        None,
                        BoundEndpoint::DcApi,
                    ))
                } else {
                    let cause = Unauthenticated::Untrusted(origin.to_string());
                    Err(Box::new(Rejected::of(cause, envelope.route())))
                }
            }
            Asked::Claims(first, rest) => {
                let check = Check {
                    envelope,
                    rules,
                    response_uri: response_uri.as_ref(),
                    config,
                    now: host.get::<dyn Platform>().now(),
                };
                let mut decide = decide;
                let mut checked = |claimed: Claimed<'e, H>| match claimed {
                    Claimed::Refused(cause) => Err(Failed::of(cause, envelope.route())),
                    Claimed::Read {
                        client_id,
                        signed,
                        claim,
                        slots,
                        haip,
                    } => {
                        let filled = slots.fill(&mut decide);
                        check
                            .claim(
                                &client_id,
                                claim.as_ref(),
                                &signed,
                                Decided::of(filled.replies()),
                                haip(host),
                            )
                            .map(|(binding, endpoint)| {
                                authenticated(
                                    VerifierId::Client(client_id),
                                    Some(binding),
                                    endpoint,
                                )
                            })
                    }
                };
                let Failed { cause, route } = match checked(first) {
                    Ok(authenticated) => return Ok(authenticated),
                    Err(failed) => *failed,
                };
                let Signatures::Many(_) = envelope.signatures() else {
                    return Err(Box::new(Rejected::of(cause, route)));
                };
                let mut reasons = AllOf::one(cause);
                for claimed in rest {
                    match checked(claimed) {
                        Ok(authenticated) => return Ok(authenticated),
                        Err(failed) => reasons = reasons.and(AllOf::one(failed.cause)),
                    }
                }
                let cause = Unauthenticated::NoSignature(reasons);
                Err(Box::new(Rejected::of(cause, envelope.route())))
            }
        }
    }
}

/// A claim refused, with the route its error takes.
struct Failed<'e> {
    cause: Unauthenticated,
    route: Option<ErrorRoute<'e>>,
}

impl<'e> Failed<'e> {
    fn of(cause: Unauthenticated, route: Option<ErrorRoute<'e>>) -> Box<Self> {
        Box::new(Self { cause, route })
    }
}

/// What checking a claim reads: the envelope, the decisions, the `response_uri` as parsed, the
/// configuration and the platform's clock.
struct Check<'c, 'e> {
    envelope: &'e Envelope<'e>,
    rules: &'e [Box<dyn ObjectRule>],
    response_uri: Option<&'c ResponseUri>,
    config: &'c TrustConfig,
    now: crate::host::Timestamp,
}

impl<'e> Check<'_, 'e> {
    /// A claim's binding (A6), endpoint (A12), signature (A8), validity (A9) and audience
    /// (A10), each refusal with its route.
    fn claim(
        &self,
        client_id: &ClientId<'_>,
        claim: &dyn PrefixClaim,
        signed: &Signed<'_>,
        decided: Decided<'_>,
        haip: &dyn crate::host::Haip,
    ) -> Result<(ClientBinding, BoundEndpoint), Box<Failed<'e>>> {
        let unverified = || self.envelope.route();
        let binding = claim
            .bind(decided, self.now, self.config.skew)
            .map_err(|unbound| Failed::of(self.unbound(client_id, unbound), unverified()))?;
        let endpoint = match self.envelope.channel() {
            Channel::DcApi(_) => BoundEndpoint::DcApi,
            Channel::Uri => {
                let uri = self
                    .response_uri
                    .ok_or_else(|| Failed::of(Unauthenticated::Endpoint(None), unverified()))?;
                let basis = claim.endpoint(decided, uri).map_err(|unbound| {
                    Failed::of(self.unbound(client_id, unbound), unverified())
                })?;
                BoundEndpoint::ResponseUri {
                    uri: uri.clone(),
                    basis,
                }
            }
        };
        let route = match &endpoint {
            BoundEndpoint::ResponseUri {
                uri,
                basis: EndpointBasis::Framework,
            } => Some(recourse::listed(
                uri.clone(),
                self.envelope.routing().echo().cloned(),
            )),
            BoundEndpoint::ResponseUri {
                basis: EndpointBasis::Request,
                ..
            }
            | BoundEndpoint::DcApi => unverified(),
        };
        let failed = |cause| Failed::of(cause, route.clone());
        haip.verify(&binding.key, signed)
            .map_err(|_| failed(Unauthenticated::Signature))?;
        self.validity()
            .map_err(|cause| failed(Unauthenticated::Validity(cause)))?;
        self.audience()
            .map_err(|aud| failed(Unauthenticated::Audience(aud)))?;
        if let Some(refusal) = self
            .rules
            .iter()
            .find_map(|rule| rule.check(self.envelope.parameters().object()))
        {
            return Err(failed(Unauthenticated::Object(refusal)));
        }
        Ok((binding, endpoint))
    }

    /// A6 for a decision that binds nothing; A12 for an endpoint the decision omits.
    fn unbound(&self, client_id: &ClientId<'_>, unbound: Unbound) -> Unauthenticated {
        match unbound {
            Unbound::Denied => Unauthenticated::Untrusted(client_id.to_string()),
            Unbound::Endpoint => {
                Unauthenticated::Endpoint(self.response_uri.map(|uri| uri.as_str().to_owned()))
            }
        }
    }

    /// A9: the Request Object is processed before `exp` and at or after `nbf`, each within the
    /// skew, when present (RFC 7519 §4.1.4, §4.1.5).
    fn validity(&self) -> Result<(), TimeError> {
        let parameters = self.envelope.parameters();
        Validity::read(parameters.json("exp"), parameters.json("nbf"))?
            .check(self.now, self.config.skew)
    }

    /// A10: `aud` absent or `https://self-issued.me/v2` (§5.8).
    fn audience(&self) -> Result<(), String> {
        match self.envelope.parameters().json("aud") {
            None => Ok(()),
            Some(Node::String(aud)) if aud == SELF_ISSUED => Ok(()),
            Some(other) => Err(other
                .as_str()
                .map_or_else(|| other.python_compact().to_string(), str::to_owned)),
        }
    }
}
