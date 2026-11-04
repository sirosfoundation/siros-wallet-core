//! The test Verifier's Client Identifier Prefix (`test:`) and a trust service double, for the
//! tests of Verifier authentication: the prefix binds the test Verifier's key ([`verifier_key`])
//! when the decision permits, and vouches for the `response_uri` as the decision's `endpoints`
//! list it, else on the basis it was made with; the trust service answers as configured, and
//! under a WE BUILD build refuses a request without a registration certificate in its
//! `verifier_info` (CS-02 §7.1).
//!
//! [`verifier_key`]: crate::jose::verifier_key

use std::borrow::Cow;

use siros_explain::Explained;
use siros_openid4vp::authenticate::{
    ClientBinding, ClientClaim, ClientPrefix, EndpointBasis, PrefixClaim, PrefixHost, PrefixName,
    Unbound,
};
use siros_openid4vp::effects::{
    Action, ActionName, Decided, Decision, Entity, EntityId, EntityType, Evaluation, Verdict,
};
use siros_openid4vp::host::Timestamp;
use siros_openid4vp::jose::Skew;
use siros_openid4vp::json::{Member, Node, Object};
use siros_openid4vp::uri::ResponseUri;

use crate::jose::verifier_key;

const TEST: PrefixName = siros_explain::checked!(PrefixName, "test");
const CLIENT_ID: EntityType = siros_explain::checked!(EntityType, "client_id");
const KEY: EntityType = siros_explain::checked!(EntityType, "test_key");
const VERIFIER: ActionName = siros_explain::checked!(ActionName, "credential-verifier");

/// The `test` prefix. Without `endpoints` in the decision, `Request` vouches for any
/// `response_uri` the request names, as `x509_hash` does; `Framework(host)` for one on the host,
/// as `x509_san_dns` does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TestPrefix {
    /// The request names the endpoint.
    Request,
    /// The identifier names the endpoint's host.
    Framework(String),
}

impl ClientPrefix for TestPrefix {
    fn name(&self) -> PrefixName {
        TEST
    }
}

impl<H> PrefixHost<H> for TestPrefix {
    fn claim<'c>(
        &'c self,
        claim: ClientClaim<'c>,
        _host: &H,
    ) -> Result<Box<dyn PrefixClaim + 'c>, Box<dyn Explained>> {
        Ok(Box::new(TestClaim {
            prefix: self,
            claim,
        }))
    }
}

/// A claim the test prefix read.
struct TestClaim<'c> {
    prefix: &'c TestPrefix,
    claim: ClientClaim<'c>,
}

fn text(value: &str) -> Node<'static> {
    Node::String(Cow::Owned(value.to_owned()))
}

/// The decision's context member.
fn context<'d>(decided: &Decided<'d>, name: &str) -> Option<&'d Node<'static>> {
    decided
        .replies()
        .first()
        .and_then(|reply| reply.answer().context.as_ref())
        .and_then(|context| context.get(name))
}

impl PrefixClaim for TestClaim<'_> {
    /// One evaluation: the Client Identifier as the subject, the test key as the resource; the
    /// claim's context.
    fn questions(&self) -> Vec<Evaluation> {
        let context = Some(self.claim.context());
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
                kind: KEY,
                id: EntityId::from(self.claim.client_id()),
                properties: None,
            },
            context,
        }]
    }

    fn bind(
        &self,
        decided: Decided<'_>,
        _now: Timestamp,
        _skew: Skew,
    ) -> Result<ClientBinding, Unbound> {
        let permitted = decided
            .replies()
            .iter()
            .all(|reply| reply.answer().verdict == Verdict::Permit);
        if !permitted || decided.replies().is_empty() {
            return Err(Unbound::Denied);
        }
        let key = verifier_key().map_err(|_| Unbound::Denied)?;
        Ok(ClientBinding {
            key,
            name: context(&decided, "name")
                .and_then(Node::as_str)
                .map(str::to_owned),
            facts: context(&decided, "facts")
                .and_then(Node::as_object)
                .cloned(),
        })
    }

    fn endpoint(
        &self,
        decided: Decided<'_>,
        response_uri: &ResponseUri,
    ) -> Result<EndpointBasis, Unbound> {
        if let Some(endpoints) = context(&decided, "endpoints") {
            let listed = endpoints.as_array().is_some_and(|uris| {
                uris.iter()
                    .any(|uri| uri.as_str() == Some(response_uri.as_str()))
            });
            return listed
                .then_some(EndpointBasis::Framework)
                .ok_or(Unbound::Endpoint);
        }
        match self.prefix {
            TestPrefix::Request => Ok(EndpointBasis::Request),
            TestPrefix::Framework(host) if response_uri.host().eq_ignore_ascii_case(host) => {
                Ok(EndpointBasis::Framework)
            }
            TestPrefix::Framework(_) => Err(Unbound::Endpoint),
        }
    }
}

/// Whether the trust service requires a registration certificate (CS-02 §7.1; reading 22).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Registration {
    /// HAIP's width: `verifier_info` is ignored.
    Ignored,
    /// The WE BUILD build: a request whose `verifier_info` holds no `registration_cert` is
    /// denied.
    Required,
}

/// The trust service double: its verdict, the name and facts it states, the endpoints it lists,
/// and its registration rule.
#[derive(Debug, Clone)]
pub struct TestTrust {
    /// Permit or deny.
    pub verdict: Verdict,
    /// The name the consent shows.
    pub name: Option<String>,
    /// What the framework states about the Verifier.
    pub facts: Option<Object<'static>>,
    /// The endpoints the framework lists; `None` lists none.
    pub endpoints: Option<Vec<String>>,
    /// The registration rule.
    pub registration: Registration,
}

impl Default for TestTrust {
    /// Permits, names nothing, lists no endpoint, ignores `verifier_info`.
    fn default() -> Self {
        Self {
            verdict: Verdict::Permit,
            name: None,
            facts: None,
            endpoints: None,
            registration: Registration::Ignored,
        }
    }
}

impl TestTrust {
    /// The decision on an evaluation.
    #[must_use]
    pub fn decide(&self, evaluation: &Evaluation) -> Decision {
        let registered = evaluation
            .context
            .as_ref()
            .and_then(|context| context.get("verifier_info"))
            .is_some_and(|info| {
                info.python_compact()
                    .to_string()
                    .contains("registration_cert")
            });
        let verdict = match self.registration {
            Registration::Required if !registered => Verdict::Deny,
            Registration::Ignored | Registration::Required => self.verdict,
        };
        let mut members = Vec::new();
        if let Some(name) = &self.name {
            members.push(("name", text(name)));
        }
        if let Some(facts) = &self.facts {
            members.push(("facts", Node::Object(facts.clone())));
        }
        if let Some(endpoints) = &self.endpoints {
            members.push((
                "endpoints",
                Node::Array(endpoints.iter().map(|uri| text(uri)).collect()),
            ));
        }
        let context = Object::new(
            members
                .into_iter()
                .map(|(name, value)| Member {
                    name: Cow::Borrowed(name),
                    value,
                })
                .collect(),
        )
        .ok()
        .filter(|context| !context.members().is_empty());
        Decision { verdict, context }
    }
}
