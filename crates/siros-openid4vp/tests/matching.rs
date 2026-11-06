//! Matching: the candidates OpenID4VP §6.1 holder binding, the Verifier's algorithms and a
//! transaction's carriage admit, the members a bound transaction provides to its format, and a
//! plug-in failing or breaking its contract.

mod common;

use siros_explain::AllOf;
use siros_openid4vp::detail;
use siros_openid4vp::host::{
    AnsweredContext, AnsweredQuery, Authentication, AuthenticationNeed, FormatHost, ProfileHost,
};
use siros_openid4vp::ids::TransactionType;
use siros_openid4vp::matching::{Accepted, Consent, Match, UnmetCode, Views};
use siros_openid4vp::plugins::{
    Answered, Binding, Bound, BoundEntries, Fault, FetchedRecord, Member, Members, NoCandidate,
    OptionIndex, Profile, Registry,
};
use siros_openid4vp::refusal::Refusal;
use siros_openid4vp::request::{EntryIndex, Request};
use siros_openid4vp::rows::{Env, HttpsUrl};
use siros_openid4vp::wallet::Wallet;
use siros_testkit::FAULT;
use siros_testkit::{Binds, Stale, TestFormat, TestHost, TestProfile};

use common::{Held, env, parameters, registry, request_of, unsigned};

#[test]
fn holder_binding_and_carriage_decide_candidates() {
    use siros_openid4vp::wallet::Holder;
    let env = env("en");
    let candidates = |query: &str, entries: &str, held: &[Held]| -> Vec<String> {
        let text = parameters(&format!(r#"{{"credentials": [{query}]}}"#), entries);
        let received = unsigned(&text).expect("received");
        let request = request_of(&received).expect("request");
        let registry = registry(Binds::First);
        let wallet = Wallet::new(held.iter().map(Held::credential).collect()).expect("wallet");
        let accepted = Accepted::new(&request, &registry).expect("accepted");
        let app =
            siros_testkit::render::App::of(&[siros_testkit::render::CrateSource::openid4vp()])
                .expect("the test app");
        let rendering = app.rendering().expect("the rendering");
        let matched = Match::run(&accepted, &wallet, &env, &rendering).expect("match");
        let q = request.indexed_queries().next().expect("query").0;
        matched
            .candidates(q)
            .iter()
            .map(|c| c.credential.id.to_string())
            .collect()
    };
    let mut unbound = Held::answering("unbound", &["q"], &["t1"]);
    unbound.holder = Holder::Unbound;
    let bound = Held::answering("bound", &["q"], &["t1"]);
    // OpenID4VP §6.1: holder binding, required unless the query waives it, needs a credential
    // bound to a key.
    let required = r#"{"id": "q", "format": "test"}"#;
    let waived = r#"{"id": "q", "format": "test", "require_cryptographic_holder_binding": false}"#;
    assert_eq!(candidates(required, "", &[unbound, bound]), ["bound"]);
    let mut unbound = Held::answering("unbound", &["q"], &["t1"]);
    unbound.holder = Holder::Unbound;
    assert_eq!(candidates(waived, "", &[unbound]), ["unbound"]);
    // A transaction binds only when the presentation can carry the profile's members.
    let named = format!(
        r#""transaction_data":["{}"]"#,
        common::entry(r#"{"type": "t1", "credential_ids": ["q"]}"#)
    );
    let mut uncarried = Held::answering("uncarried", &["q"], &["t1"]);
    uncarried.view = r#"{"answers": ["q"], "carries": false, "alg": "A"}"#.to_owned();
    assert_eq!(
        candidates(
            required,
            &named,
            &[uncarried, Held::answering("carried", &["q"], &["t1"])]
        ),
        ["carried"]
    );
    // The Verifier's vp_formats_supported admits the credentials of an algorithm it lists.
    let algs = r#""client_metadata": {"vp_formats_supported": {"test": {"algs": ["B"]}}}"#;
    let mut b = Held::answering("b", &["q"], &[]);
    b.view = r#"{"answers": ["q"], "alg": "B"}"#.to_owned();
    assert_eq!(
        candidates(required, algs, &[Held::answering("a", &["q"], &[]), b]),
        ["b"]
    );
    // A request whose query no credential answers has no consent.
    let text = parameters(&common::test_queries(&["q"]), "");
    let received = unsigned(&text).expect("received");
    let request = request_of(&received).expect("request");
    let registry = registry(Binds::First);
    let other = Held::answering("other", &["r"], &[]);
    let wallet = Wallet::new(vec![other.credential()]).expect("wallet");
    let accepted = Accepted::new(&request, &registry).expect("accepted");
    let app = siros_testkit::render::App::of(&[siros_testkit::render::CrateSource::openid4vp()])
        .expect("the test app");
    let rendering = app.rendering().expect("the rendering");
    assert!(
        Consent::of(&Match::run(&accepted, &wallet, &env, &rendering).expect("match")).is_none()
    );
}

/// How a scripted format answers.
#[derive(Clone, Copy)]
enum Script {
    /// The test format's options, when the transaction provides response members.
    WhenProvided,
    /// An option the query does not have.
    OutOfRange,
    /// The test format's options, and no card.
    DrawFails,
}

/// The test format with a scripted `answerable`.
#[derive(Clone)]
struct Scripted(siros_testkit::TestFormat, Script);

struct ScriptedQuery<'q>(Box<dyn siros_openid4vp::plugins::FormatQuery + 'q>, Script);

impl siros_openid4vp::plugins::Format for Scripted {
    fn id(&self) -> siros_openid4vp::ids::FormatId<'_> {
        self.0.id()
    }
    fn reserved(&self) -> &[siros_openid4vp::plugins::Member] {
        self.0.reserved()
    }

    fn wallet_formats(
        &self,
    ) -> Result<siros_openid4vp::json::Node<'static>, siros_openid4vp::plugins::Fault> {
        Ok(siros_openid4vp::json::Node::Object(
            siros_openid4vp::json::Object::default(),
        ))
    }

    fn placement(&self) -> Option<siros_openid4vp::wallet_metadata::Placement> {
        self.0.placement()
    }

    fn additions<'c>(
        &self,
        credential: &'c siros_openid4vp::wallet::Credential<'c>,
    ) -> Result<Box<dyn siros_openid4vp::plugins::ViewAdditions + 'c>, Fault> {
        self.0.additions(credential)
    }
    fn query<'q>(
        &'q self,
        query: &'q siros_openid4vp::request::Query<'q>,
        context: siros_openid4vp::routing::QueryContext<'q>,
    ) -> Result<
        Box<dyn siros_openid4vp::plugins::FormatQuery + 'q>,
        AllOf<siros_openid4vp::refusal::Refusal>,
    > {
        Ok(Box::new(ScriptedQuery(
            self.0.query(query, context)?,
            self.1,
        )))
    }
}

impl siros_openid4vp::plugins::FormatQuery for ScriptedQuery<'_> {
    fn options(&self) -> &[siros_openid4vp::plugins::OptionItems] {
        self.0.options()
    }
    fn admits(
        &self,
        credential: &siros_openid4vp::wallet::Credential<'_>,
        keys: &[siros_openid4vp::request::AgreeableKey<'_>],
    ) -> Result<(), siros_openid4vp::plugins::NoCandidate> {
        self.0.admits(credential, keys)
    }
    fn answerable(
        &self,
        credential: &siros_openid4vp::wallet::Credential<'_>,
        env: &siros_openid4vp::rows::Env,
        provided: &[siros_openid4vp::plugins::Member],
    ) -> Result<Vec<OptionIndex>, siros_openid4vp::plugins::Fault> {
        match self.1 {
            Script::WhenProvided if provided.is_empty() => Ok(Vec::new()),
            Script::WhenProvided | Script::DrawFails => {
                self.0.answerable(credential, env, provided)
            }
            Script::OutOfRange => Ok(vec![OptionIndex(5)]),
        }
    }
    fn carries(
        &self,
        credential: &siros_openid4vp::wallet::Credential<'_>,
        members: &[siros_openid4vp::plugins::Member],
    ) -> Result<bool, siros_openid4vp::plugins::Fault> {
        self.0.carries(credential, members)
    }
    fn displayable(
        &self,
        credential: &siros_openid4vp::wallet::Credential<'_>,
        options: &[OptionIndex],
        env: &siros_openid4vp::rows::Env,
    ) -> Result<(), NoCandidate> {
        self.0.displayable(credential, options, env)
    }
    fn draw(
        &self,
        credential: &siros_openid4vp::wallet::Credential<'_>,
        shown: siros_openid4vp::plugins::Shown<'_>,
        env: &siros_openid4vp::rows::Env,
    ) -> Result<siros_openid4vp::consent::Card, siros_openid4vp::plugins::Fault> {
        match self.1 {
            Script::DrawFails => Err(Fault::new(FAULT, detail!("the format draws no card"))),
            Script::WhenProvided | Script::OutOfRange => self.0.draw(credential, shown, env),
        }
    }
}

/// Phase 2 reads the query as the test format does: the scripts concern phase 1.
impl<H> FormatHost<H> for Scripted {
    fn answer<'q>(
        &'q self,
        query: &'q siros_openid4vp::request::Query<'q>,
        context: AnsweredContext<'q>,
    ) -> Result<Box<dyn AnsweredQuery<H> + 'q>, AllOf<Refusal>> {
        FormatHost::<H>::answer(&self.0, query, context)
    }
}

/// The scripted format, and the test profile under the type `t1`.
fn scripted(script: Script) -> Registry<TestHost> {
    let mut builder = Registry::<TestHost>::builder();
    siros_testkit::fixtures::openid4vp(&mut builder);
    builder.format(Scripted(TestFormat::new().expect("format"), script));
    let profile = builder.profile(TestProfile::new(Binds::First));
    builder.exact(TransactionType::parse("t1").expect("type"), profile);
    builder.build().expect("registry")
}

#[test]
fn a_format_answers_with_the_members_the_transaction_provides() {
    // A claim may name a member the bound transaction writes (CSC §7.3): the format sees the
    // profile's members for a bound credential, none for a query without transaction data.
    let text = parameters(
        &common::test_queries(&["q", "r"]),
        &format!(
            r#""transaction_data":["{}"]"#,
            common::entry(r#"{"type": "t1", "credential_ids": ["q"]}"#)
        ),
    );
    let received = unsigned(&text).expect("received");
    let request = request_of(&received).expect("request");
    let held = [
        Held::answering("c", &["q"], &["t1"]),
        Held::answering("d", &["r"], &[]),
    ];
    let wallet = Wallet::new(held.iter().map(Held::credential).collect()).expect("wallet");
    let env = env("en");
    let registry = scripted(Script::WhenProvided);
    let accepted = Accepted::new(&request, &registry).expect("accepted");
    let app = siros_testkit::render::App::of(&[siros_testkit::render::CrateSource::openid4vp()])
        .expect("the test app");
    let rendering = app.rendering().expect("the rendering");
    let matched = Match::run(&accepted, &wallet, &env, &rendering).expect("match");
    let ids = |k: usize| -> Vec<String> {
        let q = request.indexed_queries().nth(k).expect("query").0;
        matched
            .candidates(q)
            .iter()
            .map(|c| c.credential.id.to_string())
            .collect()
    };
    assert_eq!(
        (ids(0), ids(1)),
        (vec!["c".to_owned()], Vec::<String>::new())
    );
}

/// The test profile binding, in place of the entries offered for the query, the others.
#[derive(Clone)]
struct Foreign(TestProfile);

impl Profile for Foreign {
    type Finding = Stale;

    fn refusals(&self, request: &Request<'_>, entries: &[EntryIndex]) -> Vec<Refusal> {
        self.0.refusals(request, entries)
    }
    fn members(&self, placement: siros_openid4vp::wallet_metadata::Placement) -> Option<&[Member]> {
        self.0.members(placement)
    }
    fn bind(&self, binding: Binding<'_>, env: &Env) -> Result<Bound, NoCandidate> {
        let bound = self.0.bind(binding, env)?;
        let every: Vec<EntryIndex> = binding
            .request
            .indexed_entries()
            .map(|(index, _)| index)
            .collect();
        let others = every
            .iter()
            .copied()
            .filter(|entry| !binding.entries.contains(entry))
            .collect();
        let entries = BoundEntries::select(&every, others)
            .map_err(|e| Fault::caused(FAULT, detail!("other entries"), e))?;
        Ok(Bound { entries, ..bound })
    }
}

impl<H> ProfileHost<H> for Foreign {
    fn wanted(&self, answered: Answered<'_>, host: &H) -> Result<Vec<HttpsUrl>, Fault> {
        ProfileHost::<H>::wanted(&self.0, answered, host)
    }

    fn informed(&self, findings: &[&Stale]) -> Self {
        Self(ProfileHost::<H>::informed(&self.0, findings))
    }

    fn authentication(&self, _: Answered<'_>) -> Result<AuthenticationNeed, Fault> {
        Ok(AuthenticationNeed::Presence)
    }

    fn revalidate(&self, fetched: FetchedRecord<'_>, host: &H) -> Result<Option<Stale>, Fault> {
        self.0.revalidate(fetched, host)
    }

    fn respond(
        &self,
        answered: Answered<'_>,
        host: &H,
        authentication: &Authentication,
    ) -> Result<Members, Fault> {
        self.0.respond(answered, host, authentication)
    }
}

#[test]
fn a_plug_in_failing_or_breaking_its_contract_fails_phase_1() {
    // q or r, each named by an entry; c answers q and supports the entries' type.
    let named = |query: &str| {
        common::entry(&format!(
            r#"{{"type": "t1", "credential_ids": ["{query}"]}}"#
        ))
    };
    let text = parameters(
        r#"{"credentials": [{"id": "q", "format": "test"}, {"id": "r", "format": "test"}],
            "credential_sets": [{"options": [["q"], ["r"]]}]}"#,
        &format!(r#""transaction_data":["{}","{}"]"#, named("q"), named("r")),
    );
    let received = unsigned(&text).expect("received");
    let request = request_of(&received).expect("request");
    let env = env("en");
    let honest = Held::answering("c", &["q"], &["t1"]);
    let mut unreadable = Held::answering("c", &["q"], &["t1"]);
    unreadable.document = "not JSON".to_owned();
    let mut foreign = Registry::<TestHost>::builder();
    siros_testkit::fixtures::openid4vp(&mut foreign);
    foreign.format(TestFormat::new().expect("format"));
    let profile = foreign.profile(Foreign(TestProfile::new(Binds::First)));
    foreign.exact(TransactionType::parse("t1").expect("type"), profile);
    let foreign = foreign.build().expect("registry");
    // Each case differs from the first, which matches and draws, by one plug-in: a format
    // answering an option the query lacks, a profile binding an entry no entry naming the query
    // offered, a profile failing to read the wallet's data, a format failing to draw. `None`: the
    // match fails; else whether the views draw.
    let cases: [(Registry<TestHost>, &Held, Option<bool>); 5] = [
        (registry(Binds::First), &honest, Some(true)),
        (scripted(Script::OutOfRange), &honest, None),
        (foreign, &honest, None),
        (registry(Binds::First), &unreadable, None),
        (scripted(Script::DrawFails), &honest, Some(false)),
    ];
    for (k, (registry, held, want)) in cases.iter().enumerate() {
        let wallet = Wallet::new(vec![held.credential()]).expect("wallet");
        let accepted = Accepted::new(&request, registry).expect("accepted");
        let app =
            siros_testkit::render::App::of(&[siros_testkit::render::CrateSource::openid4vp()])
                .expect("the test app");
        let rendering = app.rendering().expect("the rendering");
        let drawn = Match::run(&accepted, &wallet, &env, &rendering)
            .ok()
            .map(|matched| Views::of(&matched, &env).is_ok());
        assert_eq!(drawn, *want, "case {k}");
    }
}

/// The code of an unmet request (§8.5): `vp_formats_not_supported` when every alternative holds
/// a query whose format excluded the wallet's credential under the Verifier's
/// `vp_formats_supported`, `access_denied` when a credential answers no query or an alternative
/// holds queries no format excluded a credential for.
#[test]
fn an_unmet_requests_code_tells_unsupported_formats_from_the_rest() {
    let registry = registry(Binds::First);
    let env = env("en");
    let algs = r#""client_metadata":{"vp_formats_supported":{"test":{"algs":["B"]}}}"#;
    let one = r#"{"credentials":[{"id":"q","format":"test"}]}"#;
    let either = r#"{"credentials":[{"id":"q","format":"test"},{"id":"r","format":"test"}],"credential_sets":[{"options":[["q"],["r"]]}]}"#;
    let other = r#"{"credentials":[{"id":"q","format":"test"},{"id":"r","format":"other"}],"credential_sets":[{"options":[["q"],["r"]]}]}"#;
    let cases = [
        (one, algs, vec!["q"], UnmetCode::VpFormatsNotSupported),
        (one, "", vec![], UnmetCode::AccessDenied),
        (
            either,
            algs,
            vec!["q", "r"],
            UnmetCode::VpFormatsNotSupported,
        ),
        (other, algs, vec!["q"], UnmetCode::AccessDenied),
    ];
    for (dcql, extra, answers, code) in cases {
        let parameters = parameters(dcql, extra);
        let received = unsigned(&parameters).expect("received");
        let request = request_of(&received).expect("request");
        let accepted = Accepted::new(&request, &registry).expect("accepted");
        let held = Held::answering("c", &answers, &[]);
        let wallet = Wallet::new(vec![held.credential()]).expect("wallet");
        let app =
            siros_testkit::render::App::of(&[siros_testkit::render::CrateSource::openid4vp()])
                .expect("the test app");
        let rendering = app.rendering().expect("the rendering");
        let matched = Match::run(&accepted, &wallet, &env, &rendering).expect("matched");
        assert!(Consent::of(&matched).is_none(), "{dcql} {answers:?}");
        assert_eq!(matched.unmet(), code, "{dcql} {extra} {answers:?}");
    }
}
