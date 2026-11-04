//! A claim an X.509 prefix read: its evaluation in AuthZEN's shape, the binding of the leaf's key
//! from the decision, and the endpoint rule (§5.9.3, §15.8.2).

use std::borrow::Cow;

use siros_openid4vp::authenticate::{
    ClientBinding, ClientClaim, EndpointBasis, PrefixClaim, Unbound,
};
use siros_openid4vp::effects::{
    Action, ActionName, Decided, Entity, EntityId, EntityType, Evaluation, Verdict,
};
use siros_openid4vp::host::Timestamp;
use siros_openid4vp::jose::{Skew, VerificationKey};
use siros_openid4vp::json::{Node, Object};
use siros_openid4vp::uri::ResponseUri;

use crate::chain::X5c;
use crate::names::SanDnsName;

const CLIENT_ID: EntityType = siros_explain::checked!(EntityType, "client_id");
const X5C: EntityType = siros_explain::checked!(EntityType, "x5c");
const VERIFIER: ActionName = siros_explain::checked!(ActionName, "credential-verifier");

/// What vouches for the `response_uri` without `endpoints` in the decision.
pub(crate) enum Rule {
    /// `x509_hash`: the request names it.
    Hash,
    /// `x509_san_dns`: the certificate names its host.
    San(SanDnsName),
}

/// A claim read by an X.509 prefix: the claim, its chain, the leaf's key, the endpoint rule.
pub(crate) struct X509Claim<'c> {
    claim: ClientClaim<'c>,
    chain: X5c,
    key: VerificationKey,
    rule: Rule,
}

impl<'c> X509Claim<'c> {
    pub(crate) const fn new(
        claim: ClientClaim<'c>,
        chain: X5c,
        key: VerificationKey,
        rule: Rule,
    ) -> Self {
        Self {
            claim,
            chain,
            key,
            rule,
        }
    }
}

/// The decision's context member of that name.
fn member<'d>(decided: &Decided<'d>, name: &str) -> Option<&'d Node<'static>> {
    decided
        .replies()
        .first()
        .and_then(|reply| reply.answer().context.as_ref())
        .and_then(|context| context.get(name))
}

/// A decision's context as §4.4's vocabulary reads it: `name` a string, `facts` an object,
/// `endpoints` an array of URIs. A member outside it binds nothing (A6).
struct Vocabulary<'d> {
    name: Option<&'d str>,
    facts: Option<&'d Object<'static>>,
    endpoints: Option<Vec<&'d str>>,
}

impl<'d> Vocabulary<'d> {
    fn read(decided: &Decided<'d>) -> Result<Self, Unbound> {
        let name = member(decided, "name")
            .map(|name| name.as_str().ok_or(Unbound::Denied))
            .transpose()?;
        let facts = member(decided, "facts")
            .map(|facts| facts.as_object().ok_or(Unbound::Denied))
            .transpose()?;
        let endpoints = member(decided, "endpoints")
            .map(|endpoints| {
                endpoints
                    .as_array()
                    .ok_or(Unbound::Denied)?
                    .iter()
                    .map(|uri| uri.as_str().ok_or(Unbound::Denied))
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;
        Ok(Self {
            name,
            facts,
            endpoints,
        })
    }
}

impl PrefixClaim for X509Claim<'_> {
    /// One evaluation: the full Client Identifier as the subject, the action
    /// `credential-verifier`, the leaf hash as the resource with each `x5c` item as received.
    fn questions(&self) -> Vec<Evaluation> {
        let items = Node::Array(
            self.chain
                .certificates()
                .map(|certificate| Node::String(Cow::Owned(certificate.text().to_owned())))
                .collect(),
        );
        vec![Evaluation {
            subject: Entity {
                kind: CLIENT_ID,
                id: EntityId::from(self.claim.client_id()),
                properties: None,
            },
            action: Action {
                name: VERIFIER,
                properties: None,
            },
            resource: Entity {
                kind: X5C,
                id: EntityId::digest(self.chain.leaf().hash().octets()),
                properties: Some(Object::single(Cow::Borrowed("x5c"), items)),
            },
            context: Some(self.claim.context()),
        }]
    }

    /// `Permit` binds the leaf's key, the decision's `name` and `facts`; `Deny`, and a context
    /// outside the vocabulary, bind nothing (A6).
    fn bind(
        &self,
        decided: Decided<'_>,
        _now: Timestamp,
        _skew: Skew,
    ) -> Result<ClientBinding, Unbound> {
        let permitted = !decided.replies().is_empty()
            && decided
                .replies()
                .iter()
                .all(|reply| reply.answer().verdict == Verdict::Permit);
        if !permitted {
            return Err(Unbound::Denied);
        }
        let vocabulary = Vocabulary::read(&decided)?;
        Ok(ClientBinding {
            key: self.key.clone(),
            name: vocabulary.name.map(str::to_owned),
            facts: vocabulary.facts.cloned(),
        })
    }

    /// The decision's `endpoints` vouch for a `response_uri` they list exactly (`Framework`).
    /// Without them, `x509_hash` vouches by the request; `x509_san_dns` for a `response_uri` on
    /// the DNS name (`Framework`).
    fn endpoint(
        &self,
        decided: Decided<'_>,
        response_uri: &ResponseUri,
    ) -> Result<EndpointBasis, Unbound> {
        if let Some(endpoints) = Vocabulary::read(&decided)?.endpoints {
            return endpoints
                .contains(&response_uri.as_str())
                .then_some(EndpointBasis::Framework)
                .ok_or(Unbound::Endpoint);
        }
        match &self.rule {
            Rule::Hash => Ok(EndpointBasis::Request),
            Rule::San(name) if name.hosts(response_uri) => Ok(EndpointBasis::Framework),
            Rule::San(_) => Err(Unbound::Endpoint),
        }
    }
}
