//! What the tests share: requests over the DC API, the test plug-ins' registry, credentials of
//! the test format, the wallet's configuration.

#![allow(dead_code)]

use siros_explain::Explained;
use siros_openid4vp::claims::kit::ClaimsFormat;
use siros_openid4vp::claims::{Claim, ClaimPath, Step};
use siros_openid4vp::ids::{
    AuthorityType, AuthorityValue, CredentialId, CredentialType, DocumentKey, FormatId, LocaleTag,
    TransactionType,
};
use siros_openid4vp::json::Node;
use siros_openid4vp::plugins::Registry;
use siros_openid4vp::plugins::{Fault, Member};
use siros_openid4vp::rows::{Choice, Env};
use siros_openid4vp::wallet::{Credential, Document, Facts, HeldAuthority, Holder};
use siros_testkit::TestHost;
use siros_testkit::fixtures::OPTIONS;
use siros_testkit::rules::TestRule;
use siros_testkit::{Binds, TestFormat, TestProfile};

/// The Origin the model's requests carry.
pub const ORIGIN: &str = "https://verifier.example";

#[allow(
    unused_imports,
    reason = "a test binary that reads no request includes the module too"
)]
pub use siros_testkit::fixtures::{request_of, unsigned};

/// Request parameters: `dc_api`, the model's nonce, the DCQL query, then `extra` members.
pub fn parameters(dcql: &str, extra: &str) -> String {
    let extra = if extra.is_empty() {
        String::new()
    } else {
        format!(",{extra}")
    };
    format!(
        r#"{{"response_type":"vp_token","response_mode":"dc_api","nonce":"n-0S6_WzA2Mj","dcql_query":{dcql}{extra}}}"#
    )
}

/// One `test` query per id, without options.
pub fn test_queries(ids: &[&str]) -> String {
    let queries: Vec<String> = ids
        .iter()
        .map(|id| format!(r#"{{"id":"{id}","format":"test"}}"#))
        .collect();
    format!(r#"{{"credentials":[{}]}}"#, queries.join(","))
}

/// The test format, and a test profile binding as told under the type `t1`.
pub fn registry(binds: Binds) -> Registry<TestHost> {
    let mut builder = Registry::<TestHost>::builder();
    siros_testkit::fixtures::openid4vp(&mut builder);
    builder.format(TestFormat::new().expect("test format"));
    let profile = builder.profile(TestProfile::new(binds));
    builder.exact(TransactionType::parse("t1").expect("type"), profile);
    builder.build().expect("registry")
}

/// The wallet's configuration with one locale.
pub fn env(locale: &'static str) -> Env {
    Env::new(
        vec![LocaleTag::parse(locale).expect("tag")],
        Vec::new(),
        OPTIONS,
        Vec::new(),
        Choice::First,
    )
    .expect("env")
}

/// A test credential: its view and `test` document as JSON texts, bound to a key.
pub struct Held {
    /// The id.
    pub id: &'static str,
    /// The view.
    pub view: String,
    /// The `test` document.
    pub document: String,
    /// The Trusted Authorities values, by type.
    pub authorities: Vec<(&'static str, Vec<&'static str>)>,
    /// Whether it is bound to a key.
    pub holder: Holder,
}

impl Held {
    /// A credential answering the queries, supporting the types, with algorithm A.
    pub fn answering(id: &'static str, queries: &[&str], supports: &[&str]) -> Self {
        let quoted = |items: &[&str]| {
            items
                .iter()
                .map(|q| format!("\"{q}\""))
                .collect::<Vec<_>>()
                .join(",")
        };
        Self {
            id,
            view: format!(r#"{{"answers":[{}],"alg":"A"}}"#, quoted(queries)),
            document: format!(
                r#"{{"supports":[{}],"nonconforming":[]}}"#,
                quoted(supports)
            ),
            authorities: Vec::new(),
            holder: Holder::Bound,
        }
    }

    /// The credential as the registration holds it.
    pub fn credential(&self) -> Credential<'_> {
        let authorities = self
            .authorities
            .iter()
            .map(|(kind, values)| HeldAuthority {
                kind: AuthorityType::parse(*kind).expect("type"),
                values: values
                    .iter()
                    .map(|v| AuthorityValue::parse(*v).expect("value"))
                    .collect(),
            })
            .collect();
        Credential::new(
            CredentialId::parse(self.id).expect("id"),
            FormatId::parse("test").expect("format"),
            self.view.as_bytes(),
            vec![Document {
                key: DocumentKey::parse("test").expect("key"),
                content: self.document.as_bytes(),
            }],
            Facts::new(self.holder, authorities).expect("facts"),
        )
        .expect("credential")
    }
}

/// base64url without padding over a JSON text, as a Verifier writes an entry.
pub fn entry(json: &str) -> String {
    siros_testkit::verifier::encode(json).expect("entry")
}

/// A DCQL example of `data/spec_vectors`.
pub fn vector(name: &str) -> String {
    let path = format!(
        "{}/tests/data/spec_vectors/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(path).expect("vector")
}

/// PaSO Core Annex A.5's DCQL query.
pub const PASO_A5: &str = r#"{"credentials": [
    {"id": "sca_card", "format": "dc+sd-jwt", "meta": {"vct_values": ["https://bank.example/sca/card"]}},
    {"id": "sca_account", "format": "dc+sd-jwt", "meta": {"vct_values": ["https://bank.example/sca/account"]}},
    {"id": "pid", "format": "dc+sd-jwt", "meta": {"vct_values": ["https://credentials.example/pid"]},
     "claims": [{"path": ["given_name"]}, {"path": ["family_name"]}]}],
  "credential_sets": [{"options": [["sca_card", "pid"], ["sca_card"], ["sca_account", "pid"], ["sca_account"]]}]}"#;

/// A claims format matching `meta.<member>` against the view's `type` (SD-JWT VC's
/// `vct_values`, mdoc's `doctype_value`), labels under `label`, logos under `logo.uri`; a
/// claim `[namespace, element]` without values names a device-signed element the transaction
/// writes.
pub struct ClaimsTest {
    /// The `meta` member.
    pub member: &'static str,
    /// The claim display member holding the label.
    pub label: &'static str,
}

impl ClaimsFormat for ClaimsTest {
    fn id(&self) -> &'static str {
        "x"
    }
    fn label_key(&self) -> &'static str {
        self.label
    }
    fn appendix(&self) -> &'static str {
        "B.3"
    }
    fn is_algorithm(&self, value: &Node<'_>) -> bool {
        value.as_str().is_some()
    }
    fn logo<'n>(&self, entry: &'n Node<'n>) -> Option<&'n str> {
        entry
            .get("logo")
            .and_then(|logo| logo.get("uri"))
            .and_then(Node::as_str)
    }
    fn read_meta<'n, 'm>(
        &self,
        meta: Option<&'n Node<'m>>,
    ) -> Result<&'n Node<'m>, Box<dyn Explained>> {
        meta.filter(|meta| meta.get(self.member).is_some())
            .ok_or_else(|| {
                Box::new(TestRule::invalid_request(format!(
                    "meta.{} is absent",
                    self.member
                ))) as Box<dyn Explained>
            })
    }
    fn types<'n>(&self, view: &'n Node<'n>) -> Result<Vec<CredentialType<'n>>, Fault> {
        view.get("type")
            .and_then(Node::as_str)
            .and_then(|kind| CredentialType::parse(kind).ok())
            .map(|kind| vec![kind])
            .ok_or_else(|| Fault::new(siros_testkit::FAULT, siros_openid4vp::detail!("no type")))
    }
    fn meta_matches(&self, meta: &Node<'_>, types: &[CredentialType<'_>]) -> bool {
        let names = |value: &Node<'_>| {
            value
                .as_str()
                .is_some_and(|value| types.iter().any(|kind| *kind == *value))
        };
        match meta.get(self.member) {
            Some(Node::Array(values)) => values.iter().any(names),
            Some(value) => names(value),
            None => false,
        }
    }
    fn written(&self, claim: &Claim<'_>, provided: &[Member]) -> bool {
        match claim.path().steps() {
            [Step::Key(namespace), Step::Key(element)] if claim.values().is_none() => provided.iter().any(|member| {
                matches!(member, Member::Element { namespace: n, element: e } if n == namespace && e == element)
            }),
            _ => false,
        }
    }
    fn pointer_refusal(&self, _path: &ClaimPath<'_>) -> Option<Box<dyn Explained>> {
        None
    }
}
