//! What the tests share: the CSC examples, entries and requests as a Verifier sends them, a
//! stand-in for the formats QES binds to, credentials, the registry, the wallet's configuration,
//! and the core's phase 1 summed up.

#![allow(dead_code)]

pub mod fixtures;

use serde_json::Value as Json;
use siros_explain::AllOf;
use siros_explain::Text;
use siros_openid4vp::consent::{Card, ConsentEntry, Header};
use siros_openid4vp::detail;
use siros_openid4vp::effects::{Fetch, MediaType, Resource};
use siros_openid4vp::envelope::Envelope;
use siros_openid4vp::host::{
    AnsweredContext, AnsweredOption, AnsweredQuery, FormatHost, PresentError, Presentation, Usable,
};
use siros_openid4vp::ids::{CredentialId, DocumentKey, FormatId, LocaleTag};
use siros_openid4vp::json::{Node, quote};
use siros_openid4vp::matching::{Accepted, Match, Views};
use siros_openid4vp::plugins::{
    Carriage, Fault, FindingData, Format, FormatQuery, Member, MemberValue, Members, NoCandidate,
    OptionIndex, OptionItems, Options, Registry, Shown,
};
use siros_openid4vp::refusal::{Refusal, Refused};
use siros_openid4vp::request::{AgreeableKey, Query, Request};
use siros_openid4vp::resolve::{Outcome, Prepared};
use siros_openid4vp::rows::{Choice, Env, HttpsUrl, Row, Value};
use siros_openid4vp::session::Session;
use siros_openid4vp::wallet::{Credential, Document, Facts, Holder, Wallet};
use siros_qes::QesProfile;
use siros_testkit::FAULT;
use siros_testkit::fixtures::OPTIONS;
use siros_testkit::render::{App, CrateSource, ENGLISH_QES, GERMAN_QES};
use siros_testkit::{Published, PublishedResource, TestHost};

/// The Origin of the requests.
pub const ORIGIN: &str = "https://verifier.example";

/// §7.1.2's DCQL query as check_qes.py writes it: one mdoc query `xyz123`.
pub const QUERY_7_1_2: &str = r#"{"credentials": [{"id": "xyz123", "format": "mso_mdoc", "meta": {"doctype_value": "com.example.service.1.attestation"}, "claims": [{"path": ["com.example.service.1", "userName"]}]}]}"#;

/// The SD-JWT VC query of check_qes.py: one query `xyz123`.
pub const QUERY_SD_JWT: &str = r#"{"credentials": [{"id": "xyz123", "format": "dc+sd-jwt", "meta": {"vct_values": ["https://example.com/service"]}}]}"#;

/// A CSC example of `tests/data`: the JSON text the model's reader takes from the specification.
pub fn csc(name: &str) -> String {
    let path = format!("{}/tests/data/{name}.json", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(path).expect("CSC example")
}

/// base64url without padding over the JSON as Python's `json.dumps` writes it, as a Verifier
/// writes an entry.
pub fn entry(json: &str) -> String {
    siros_testkit::verifier::encode(json).expect("entry")
}

/// An object's members in order, as (name, JSON text) pairs, for editing a fixture.
#[derive(Debug, Clone)]
pub struct Fields(Vec<(String, String)>);

impl Fields {
    /// The members of a JSON object text.
    pub fn of(json: &str) -> Self {
        let node = Node::parse(json).expect("JSON");
        let object = node.as_object().expect("an object");
        Self(
            object
                .members()
                .iter()
                .map(|member| {
                    (
                        member.name.to_string(),
                        member.value.python_text().to_string(),
                    )
                })
                .collect(),
        )
    }

    /// The member set to a JSON text, in its place or last.
    #[must_use]
    pub fn set(mut self, name: &str, value: &str) -> Self {
        match self.0.iter_mut().find(|(n, _)| n == name) {
            Some((_, old)) => *old = value.to_owned(),
            None => self.0.push((name.to_owned(), value.to_owned())),
        }
        self
    }

    /// A member's JSON text.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, value)| value.as_str())
    }

    /// The object without the member.
    #[must_use]
    pub fn without(mut self, name: &str) -> Self {
        self.0.retain(|(n, _)| n != name);
        self
    }

    /// The JSON text.
    pub fn json(&self) -> String {
        let members: Vec<String> = self
            .0
            .iter()
            .map(|(name, value)| format!("{}: {value}", quote(name)))
            .collect();
        format!("{{{}}}", members.join(", "))
    }
}

/// The items of a JSON array text, each as JSON text, in order.
pub fn items(json: &str) -> Vec<String> {
    Node::parse(json)
        .expect("JSON")
        .as_array()
        .expect("an array")
        .iter()
        .map(|item| item.python_text().to_string())
        .collect()
}

/// A string member of a JSON object text.
pub fn string(json: &str, name: &str) -> String {
    Node::parse(json)
        .expect("JSON")
        .get(name)
        .and_then(Node::as_str)
        .expect("a string member")
        .to_owned()
}

/// Request parameters over the DC API: `dc_api`, a nonce, the DCQL query and the entries.
pub fn parameters(dcql: &str, entries: &[String]) -> String {
    let data = if entries.is_empty() {
        String::new()
    } else {
        let quoted: Vec<String> = entries.iter().map(|e| quote(e)).collect();
        format!(r#","transaction_data":[{}]"#, quoted.join(","))
    };
    format!(
        r#"{{"response_type":"vp_token","response_mode":"dc_api","nonce":"n-0S6_WzA2Mj","dcql_query":{dcql}{data}}}"#
    )
}

#[allow(
    unused_imports,
    reason = "a test binary that reads no request includes the module too"
)]
pub use siros_testkit::fixtures::{request_of, unsigned};

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

/// The stand-ins for `mso_mdoc` and `dc+sd-jwt`, and the profile when given.
pub fn registry(profile: Option<QesProfile>) -> Registry<TestHost> {
    let mut builder = Registry::<TestHost>::builder();
    siros_testkit::fixtures::openid4vp(&mut builder);
    builder.format(StandIn::new("mso_mdoc"));
    builder.format(StandIn::new("dc+sd-jwt"));
    if let Some(profile) = profile {
        siros_qes::register(&mut builder, profile).expect("the QES type");
    }
    builder.build().expect("registry")
}

/// A stand-in for a format QES binds to. A query has one option of no item. A credential's view
/// is `{"carries"?: bool, "rows"?: [[label, value], ...]}`: whether its presentation can carry
/// the transaction's members (true when absent), and its card's rows. Its presentation is
/// `{"credential": id, "members": [[member, value], ...]}`, a member `["claim", name]` or
/// `["element", namespace, element]`, a value `{"text": text}` or `{"bytes": hex}`.
#[derive(Clone)]
pub struct StandIn {
    id: FormatId<'static>,
}

impl StandIn {
    /// The stand-in for a format.
    pub fn new(id: &'static str) -> Self {
        Self {
            id: FormatId::parse(id).expect("format"),
        }
    }
}

impl Format for StandIn {
    fn id(&self) -> FormatId<'_> {
        self.id.borrowed()
    }

    fn reserved(&self) -> &[Member] {
        &[]
    }

    fn wallet_formats(
        &self,
    ) -> Result<siros_openid4vp::json::Node<'static>, siros_openid4vp::plugins::Fault> {
        Ok(siros_openid4vp::json::Node::Object(
            siros_openid4vp::json::Object::default(),
        ))
    }

    /// The placement of the format it stands in for.
    fn placement(&self) -> Option<siros_openid4vp::wallet_metadata::Placement> {
        crate::common::placement(&self.id)
    }

    /// None: a stand-in credential states no type.
    fn additions<'c>(
        &self,
        _credential: &'c siros_openid4vp::wallet::Credential<'c>,
    ) -> Result<Box<dyn siros_openid4vp::plugins::ViewAdditions + 'c>, Fault> {
        Ok(Box::new(siros_openid4vp::plugins::ViewTypes::new(
            Vec::new(),
        )))
    }

    fn query<'q>(
        &'q self,
        _query: &'q Query<'q>,
        _context: siros_openid4vp::routing::QueryContext<'q>,
    ) -> Result<Box<dyn FormatQuery + 'q>, AllOf<Refusal>> {
        Ok(Box::new(StandInQuery::one()))
    }
}

impl<H> FormatHost<H> for StandIn {
    fn answer<'q>(
        &'q self,
        _query: &'q Query<'q>,
        _context: AnsweredContext<'q>,
    ) -> Result<Box<dyn AnsweredQuery<H> + 'q>, AllOf<Refusal>> {
        Ok(Box::new(StandInQuery::one()))
    }
}

struct StandInQuery {
    options: Options,
}

impl StandInQuery {
    /// One option of no item.
    fn one() -> Self {
        Self {
            options: Options::new(vec![OptionItems::new(Vec::new())]),
        }
    }
}

/// The stand-in's one option for a credential.
struct StandInOption<'a> {
    option: OptionIndex,
    credential: Usable<'a>,
}

fn view<'c>(credential: &'c Credential<'_>) -> Result<Node<'c>, Fault> {
    let text = std::str::from_utf8(credential.view)
        .map_err(|e| Fault::caused(FAULT, detail!("view"), e))?;
    Node::parse(text).map_err(|e| Fault::caused(FAULT, detail!("view"), e))
}

impl FormatQuery for StandInQuery {
    fn options(&self) -> &Options {
        &self.options
    }

    fn admits(
        &self,
        _credential: &Credential<'_>,
        _keys: &[AgreeableKey<'_>],
    ) -> Result<(), NoCandidate> {
        Ok(())
    }

    fn answerable(
        &self,
        _credential: &Credential<'_>,
        _env: &Env,
        _provided: &[Member],
    ) -> Result<Vec<OptionIndex>, Fault> {
        Ok(self.options.indexed().map(|(option, _)| option).collect())
    }

    fn carries(&self, credential: &Credential<'_>, _members: &[Member]) -> Result<Carriage, Fault> {
        Ok(match view(credential)?.get("carries") {
            Some(Node::Bool(false)) => Carriage::Uncarried,
            _ => Carriage::Carried,
        })
    }

    fn draw(
        &self,
        credential: &Credential<'_>,
        _shown: Shown<'_>,
        env: &Env,
    ) -> Result<Card, Fault> {
        let view = view(credential)?;
        let rows = view
            .get("rows")
            .and_then(Node::as_array)
            .unwrap_or(&[])
            .iter()
            .map(|row| {
                let cell = |k: usize| {
                    row.as_array()
                        .and_then(|cells| cells.get(k))
                        .and_then(Node::as_str)
                        .unwrap_or("")
                        .to_owned()
                };
                Row::new(Text::Raw(cell(0)), Value::Text(Text::Raw(cell(1))))
            })
            .collect();
        Ok(Card {
            icon: env.icon(None).clone(),
            title: Text::Raw(credential.id.to_string()),
            subtitle: None,
            rows,
        })
    }
}

impl<H> AnsweredQuery<H> for StandInQuery {
    fn choose<'a>(
        &'a self,
        credential: Usable<'a>,
        _env: &Env,
        _provided: &[Member],
    ) -> Result<Vec<Box<dyn AnsweredOption<H> + 'a>>, Fault> {
        Ok(self
            .options
            .indexed()
            .map(|(option, _)| {
                Box::new(StandInOption { option, credential }) as Box<dyn AnsweredOption<H> + 'a>
            })
            .collect())
    }
}

impl<H> AnsweredOption<H> for StandInOption<'_> {
    fn option(&self) -> OptionIndex {
        self.option
    }

    fn revalidate(
        &self,
        _session: &Session<'_>,
        _host: &H,
    ) -> Result<Option<Box<dyn FindingData>>, Fault> {
        Ok(None)
    }

    fn present(
        &self,
        members: &Members,
        _session: &Session<'_>,
        _host: &H,
    ) -> Result<Presentation, PresentError> {
        let written: Vec<String> = members
            .iter()
            .map(|(member, value)| {
                let name = match member {
                    Member::Claim(name) => format!(r#"["claim",{}]"#, quote(name)),
                    Member::Element { namespace, element } => {
                        format!(r#"["element",{},{}]"#, quote(namespace), quote(element))
                    }
                };
                let value = match value {
                    MemberValue::Text(text) => format!(r#"{{"text":{}}}"#, quote(text)),
                    MemberValue::Bytes(bytes) => format!(r#"{{"bytes":"{}"}}"#, hex(bytes)),
                    MemberValue::Json(json) => format!(r#"{{"json":{}}}"#, json.as_str()),
                    MemberValue::Cbor(item) => format!(r#"{{"cbor":"{}"}}"#, hex(item.as_bytes())),
                };
                format!("[{name},{value}]")
            })
            .collect();
        let text = format!(
            r#"{{"credential":{},"members":[{}]}}"#,
            quote(self.credential.credential().id.as_str()),
            written.join(",")
        );
        Ok(Presentation::object(&text)
            .map_err(|e| Fault::caused(FAULT, detail!("presentation"), e))?)
    }
}

/// Lowercase hexadecimal.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A credential of a stand-in format: its view, its QES document, whether it is bound to a key.
#[derive(Debug, Clone)]
pub struct Holding {
    /// The id.
    pub id: &'static str,
    /// The format.
    pub format: &'static str,
    /// The view.
    pub view: String,
    /// The QES document.
    pub qes: Option<String>,
    /// Whether it is bound to a key.
    pub holder: Holder,
}

impl Holding {
    /// §7.3's service user attestation as check_qes.py has it: its card shows `userName`, its
    /// rulebook lets it approve the qualifiers, its presentation carries `qesApproval`.
    pub fn approving(id: &'static str, format: &'static str, qualifiers: &[&str]) -> Self {
        let listed: Vec<String> = qualifiers.iter().map(|q| quote(q)).collect();
        Self {
            id,
            format,
            view: r#"{"rows": [["userName", "willeke"]]}"#.to_owned(),
            qes: Some(format!(
                r#"{{"signature_qualifiers": [{}]}}"#,
                listed.join(", ")
            )),
            holder: Holder::Bound,
        }
    }

    /// The credential with its presentation unable to carry the transaction's members.
    #[must_use]
    pub fn uncarried(self) -> Self {
        Self {
            view: r#"{"carries": false, "rows": [["userName", "willeke"]]}"#.to_owned(),
            ..self
        }
    }

    /// Whether its presentation can carry the transaction's members.
    pub fn carries(&self) -> bool {
        Node::parse(&self.view).expect("view").get("carries") != Some(&Node::Bool(false))
    }

    /// The credential as the registration holds it.
    pub fn credential(&self) -> Credential<'_> {
        let documents = self
            .qes
            .iter()
            .map(|qes| Document {
                key: DocumentKey::parse(siros_qes::DOCUMENT).expect("key"),
                content: qes.as_bytes(),
            })
            .collect();
        Credential::new(
            CredentialId::parse(self.id).expect("id"),
            FormatId::parse(self.format).expect("format"),
            self.view.as_bytes(),
            documents,
            Facts::new(self.holder, Vec::new()).expect("facts"),
        )
        .expect("credential")
    }
}

/// The wallet of the credentials.
pub fn wallet(held: &[Holding]) -> Wallet<'_> {
    Wallet::new(held.iter().map(Holding::credential).collect()).expect("wallet")
}

/// The test app: the core's and the profile's modules in its English and German.
fn app() -> App {
    let qes = CrateSource::of::<siros_qes::CrateModule>(ENGLISH_QES, GERMAN_QES);
    App::of(&[CrateSource::openid4vp(), qes]).expect("the test app")
}

thread_local! {
    /// The test app, built once per test thread.
    static APP: App = app();
}

/// A text as the test app renders it in a locale.
pub fn plain(text: &Text, locale: &'static str) -> String {
    APP.with(|app| app.plain(&env(locale), text).expect("the text renders"))
}

/// A row as (section, label, value kind: an image or a text, value text).
pub type ShownRow = (Option<String>, String, Option<&'static str>, Option<String>);

/// The rows of an entry, rendered in English.
pub fn shown<'r>(rows: impl IntoIterator<Item = &'r Row>) -> Vec<ShownRow> {
    let plain = |text: &Text| plain(text, "en");
    rows.into_iter()
        .map(|row| {
            (
                row.section.as_ref().map(plain),
                plain(&row.label),
                row.value.as_ref().map(|value| match value {
                    Value::Image(_) => "image",
                    Value::Text(_) => "text",
                }),
                row.value.as_ref().and_then(|value| value.text()).map(plain),
            )
        })
        .collect()
}

/// A query's matching: per candidate its credential and bound entries, per exclusion its
/// credential, reason and clause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Matched {
    /// (credential, bound entries).
    pub candidates: Vec<(String, Vec<usize>)>,
    /// (credential, clause).
    pub excluded: Vec<(String, String)>,
}

/// One entry of the consent: what it shows, its header and record id.
#[derive(Debug, Clone)]
pub struct Viewed {
    /// What it shows.
    pub entry: ConsentEntry,
    /// The transaction's header.
    pub header: Option<Header>,
    /// The record's id.
    pub record: String,
}

/// Phase 1 for the request: the first query's matching and every consent entry; the request's
/// refusal when the rules refuse it.
pub fn phase_one(
    parameters: &str,
    held: &[Holding],
    registry: &Registry<TestHost>,
    env: &Env,
) -> Result<(Matched, Vec<Viewed>), Refused> {
    let received = unsigned(parameters).expect("received");
    let envelope = Envelope::parse(&received, registry).expect("the envelope");
    let request = Request::parse(&envelope)?;
    let wallet = wallet(held);
    let accepted = Accepted::new(&request, registry)?;
    let app = siros_testkit::render::App::of(&[siros_testkit::render::CrateSource::openid4vp()])
        .expect("the test app");
    let rendering = app.rendering().expect("the rendering");
    let matched = Match::run(&accepted, &wallet, env, &rendering).expect("match");
    let (first, _) = request.indexed_queries().next().expect("a query");
    let summary = Matched {
        candidates: matched
            .candidates(first)
            .iter()
            .map(|candidate| {
                (
                    candidate.credential.id.to_string(),
                    candidate
                        .bound
                        .as_ref()
                        .map(|binding| {
                            binding
                                .bound
                                .entries
                                .entries()
                                .iter()
                                .map(|e| e.get())
                                .collect()
                        })
                        .unwrap_or_default(),
                )
            })
            .collect(),
        excluded: matched
            .excluded()
            .iter()
            .map(|excluded| {
                (
                    excluded.credential.id.to_string(),
                    excluded.exclude.clause().to_string(),
                )
            })
            .collect(),
    };
    let views = Views::of(&matched, env).expect("views");
    let viewed = views
        .iter()
        .map(|view| Viewed {
            entry: view.entry.clone(),
            header: view.header.cloned(),
            record: view.record.id().as_str().to_owned(),
        })
        .collect();
    Ok((summary, viewed))
}

/// The documents served as PDFs at their hrefs.
pub fn serving(documents: fixtures::Published) -> Published {
    Published::new(
        documents
            .into_iter()
            .map(|(href, content)| PublishedResource {
                url: HttpsUrl::parse(&href).expect("an https URL"),
                content,
                media: MediaType::parse("application/pdf").expect("a media type"),
            })
            .collect(),
    )
}

/// The response's members for the one record of the request, phase 2's fetches answered by
/// `fetch`, or phase 2's outcome.
pub fn approve(
    text: &str,
    held: &Holding,
    profile: &Registry<TestHost>,
    fetch: impl FnMut(&Resource) -> Fetch,
) -> Result<Json, Outcome> {
    let held = std::slice::from_ref(held);
    let (_, views) = phase_one(text, held, profile, &env("en")).expect("accepted");
    let ids: Vec<&str> = views.iter().map(|view| view.record.as_str()).collect();
    let received = unsigned(text).expect("received");
    let request = request_of(&received).expect("request");
    let wallet = wallet(held);
    let env = env("en");
    let host = TestHost::default();
    let authenticated = siros_testkit::fixtures::authenticate(request.envelope(), profile, &host)
        .expect("authentic");
    let app = siros_testkit::render::App::of(&[siros_testkit::render::CrateSource::openid4vp()])
        .expect("the test app");
    let rendering = app.rendering().expect("the rendering");
    let response = Prepared::prepare(
        &authenticated,
        &ids,
        &wallet,
        profile,
        &env,
        &rendering,
        &host,
    )?
    .respond(fetch, &host)?;
    let vp_token: Json =
        serde_json::from_str(&response.response().vp_token().json()).expect("vp_token");
    Ok(vp_token["xyz123"][0]["members"].clone())
}

/// The placement the plug-in of `format` states: siros-mdoc's, siros-sdjwt's or the test
/// format's; `None` for another format.
pub fn placement(
    format: &siros_openid4vp::ids::FormatId<'_>,
) -> Option<siros_openid4vp::wallet_metadata::Placement> {
    let mdoc = siros_mdoc::Mdoc::new().expect("the mdoc plug-in");
    let sd_jwt = siros_sdjwt::SdJwtVc::new().expect("the SD-JWT VC plug-in");
    let test = siros_testkit::TestFormat::new().expect("the test format");
    siros_testkit::fixtures::placement(&[&mdoc, &sd_jwt, &test], format)
}
