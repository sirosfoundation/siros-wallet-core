//! The test Verifier's Client Identifier Prefix (`test:`) and a trust service double, for the
//! tests of Verifier authentication: the prefix binds the test Verifier's key ([`verifier_key`])
//! when the decision permits, and vouches for the `response_uri` as the decision's `endpoints`
//! list it, else on the basis it was made with; the trust service answers as configured, and
//! under a WE BUILD build refuses a request without a registration certificate in its
//! `verifier_info` (CS-02 §7.1).
//!
//! [`verifier_key`]: crate::jose::verifier_key

use std::borrow::Cow;

use siros_explain::Explain;
use siros_i18n::Context;
use siros_openid4vp::authenticate::{
    ClientBinding, ClientClaim, ClientPrefix, EndpointBasis, PrefixClaim, PrefixHost, PrefixName,
    Unbound,
};
use siros_openid4vp::effects::{
    Action, ActionName, Decided, Decision, Entity, EntityId, EntityType, Evaluation, Verdict,
};
use siros_openid4vp::host::Timestamp;
use siros_openid4vp::jose::{Skew, VerificationKey};
use siros_openid4vp::json::{Node, Object};
use siros_openid4vp::uri::ResponseUri;

use crate::format::DoubleText;
use crate::jose::verifier_key;

const TEST: PrefixName = siros_syntax::checked!(PrefixName, "test");
const CLIENT_ID: EntityType = siros_syntax::checked!(EntityType, "client_id");
const KEY: EntityType = siros_syntax::checked!(EntityType, "test_key");
const VERIFIER: ActionName = siros_syntax::checked!(ActionName, "credential-verifier");

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
    /// The claim, with the test Verifier's key; the test doubles' fault when the key does not
    /// derive.
    fn claim<'c>(
        &'c self,
        claim: ClientClaim<'c>,
        _host: &H,
    ) -> Result<Box<dyn PrefixClaim + 'c>, Box<dyn Explain>> {
        let key = verifier_key().map_err(|fault| Box::new(fault) as Box<dyn Explain>)?;
        Ok(Box::new(TestClaim {
            prefix: self,
            claim,
            key,
        }))
    }
}

/// The test prefix under another name: a Client Identifier of a registered prefix's name, its key
/// and endpoint the test prefix's.
#[derive(Debug, Clone)]
pub struct NamedPrefix {
    /// The name.
    pub name: PrefixName,
    /// What it binds and vouches for.
    pub prefix: TestPrefix,
}

impl ClientPrefix for NamedPrefix {
    fn name(&self) -> PrefixName {
        self.name
    }
}

impl<H> PrefixHost<H> for NamedPrefix {
    fn claim<'c>(
        &'c self,
        claim: ClientClaim<'c>,
        host: &H,
    ) -> Result<Box<dyn PrefixClaim + 'c>, Box<dyn Explain>> {
        self.prefix.claim(claim, host)
    }
}

/// A claim the test prefix read, with the key it binds.
struct TestClaim<'c> {
    prefix: &'c TestPrefix,
    claim: ClientClaim<'c>,
    key: VerificationKey,
}

fn text(value: &str) -> Node<'static> {
    Node::String(Cow::Owned(value.to_owned()))
}

/// The decision's context member.
fn stated<'d>(decided: &Decided<'d>, name: &str) -> Option<&'d Node<'static>> {
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

    /// The test Verifier's key when every decision permits; the decision's `name` as written,
    /// worded by `context`, and its `facts`.
    fn bind(
        &self,
        decided: Decided<'_>,
        _now: Timestamp,
        _skew: Skew,
        context: &Context,
    ) -> Result<ClientBinding, Unbound> {
        let permitted = decided
            .replies()
            .iter()
            .all(|reply| reply.answer().verdict == Verdict::Permit);
        if !permitted || decided.replies().is_empty() {
            return Err(Unbound::Denied);
        }
        Ok(ClientBinding {
            key: self.key.clone(),
            name: stated(&decided, "name")
                .and_then(Node::as_str)
                .map(|name| context.resolve(&DoubleText::written(name)))
                .transpose()?,
            facts: stated(&decided, "facts").and_then(Node::as_object).cloned(),
        })
    }

    fn endpoint(
        &self,
        decided: Decided<'_>,
        response_uri: &ResponseUri,
    ) -> Result<EndpointBasis, Unbound> {
        if let Some(endpoints) = stated(&decided, "endpoints") {
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
                info.json_compact()
                    .to_string()
                    .contains("registration_cert")
            });
        let verdict = match self.registration {
            Registration::Required if !registered => Verdict::Deny,
            Registration::Ignored | Registration::Required => self.verdict,
        };
        let mut context = Object::default();
        if let Some(name) = &self.name {
            context.set(Cow::Borrowed("name"), text(name));
        }
        if let Some(facts) = &self.facts {
            context.set(Cow::Borrowed("facts"), Node::Object(facts.clone()));
        }
        if let Some(endpoints) = &self.endpoints {
            context.set(
                Cow::Borrowed("endpoints"),
                Node::Array(endpoints.iter().map(|uri| text(uri)).collect()),
            );
        }
        Decision {
            verdict,
            context: (!context.members().is_empty()).then_some(context),
        }
    }
}
