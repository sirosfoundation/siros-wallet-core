//! Phase 2 trusts the user's choice alone: it rejects ids that are no records or no selection
//! the request allows, falls back on records it does not derive or on what no longer holds,
//! answers nothing when the wallet fails to authenticate the End-User (OpenID4VP §8.5
//! `access_denied`) or authenticates them more weakly than a profile needs, and faults on a
//! profile writing a member it does not declare, on a host that cannot seal the response as
//! `dc_api.jwt` asks, and on a mode's choice or body that breaks its registration.

mod common;

use siros_explain::AllOf;
use siros_openid4vp::detail;
use siros_openid4vp::envelope::Envelope;
use siros_openid4vp::host::{
    Authentication, AuthenticationNeed, CoreHost, Factor, Haip, Knowledge, Platform, ProfileHost,
    RequestDecryption, SealedJwe, SignFailed, Signature, SignatureInvalid,
};
use siros_openid4vp::ids::{CredentialId, TransactionType};
use siros_openid4vp::jose::JwsAlgorithms;
use siros_openid4vp::jose::{Signed, VerificationKey};
use siros_openid4vp::matching::{Accepted, Consent, Match, Views, display, offer};
use siros_openid4vp::plugins::{
    Answered, Binding, Bound, Fault, FetchedRecord, InformError, Member, MemberValue, Members,
    NoCandidate, Profile, Registry,
};
use siros_openid4vp::refusal::Refusal;
use siros_openid4vp::request::{AgreeableKey, Agreements, ContentEncryption, EntryIndex, Request};
use siros_openid4vp::resolve::{Delivery, Finding, Outcome, ParameterBreach, Prepared, Rejection};
use siros_openid4vp::rows::{Choice, Env, HttpsUrl};
use siros_openid4vp::wallet::Wallet;
use siros_testkit::FAULT;
use siros_testkit::{
    Binds, Published, Stale, TestFormat, TestHaip, TestHost, TestPlatform, TestProfile,
    TestRequestDecryption,
};

use common::{Held, entry, env, parameters, registry, request_of, test_queries, unsigned};
use siros_testkit::fixtures::authenticate;

/// q (multiple) or r, each named by an entry; c1 and c2 answer q, c3 and c4 answer r.
fn fixture() -> (String, Vec<Held>) {
    let named = |query: &str| {
        entry(&format!(
            r#"{{"type": "t1", "credential_ids": ["{query}"]}}"#
        ))
    };
    let text = parameters(
        r#"{"credentials": [{"id": "q", "format": "test", "multiple": true}, {"id": "r", "format": "test"}],
            "credential_sets": [{"options": [["q"], ["r"]]}]}"#,
        &format!(r#""transaction_data":["{}","{}"]"#, named("q"), named("r")),
    );
    let mut stale = Held::answering("c2", &["q"], &["t1"]);
    stale.document = r#"{"supports": ["t1"], "nonconforming": [], "stale": [0]}"#.to_owned();
    (
        text,
        vec![
            Held::answering("c1", &["q"], &["t1"]),
            stale,
            Held::answering("c3", &["r"], &["t1"]),
            Held::answering("c4", &["r"], &["t1"]),
        ],
    )
}

/// The test app of the core's module.
fn test_app() -> siros_testkit::render::App {
    siros_testkit::render::App::of(&[siros_testkit::render::CrateSource::openid4vp()])
        .expect("the test app")
}

/// The id of each entry the display offers, in display order.
fn offered(text: &str, held: &[Held]) -> Vec<String> {
    offered_in(text, held, &registry(Binds::First))
}

/// The ids the consent offers over a registry, which reads the request.
fn offered_in<H: siros_openid4vp::plugins::Build>(
    text: &str,
    held: &[Held],
    registry: &Registry<H>,
) -> Vec<String> {
    let received = unsigned(text).expect("received");
    let envelope = Envelope::parse(&received, registry).expect("envelope");
    let request = Request::parse(&envelope).expect("request");
    let wallet = Wallet::new(held.iter().map(Held::credential).collect()).expect("wallet");
    let env = env("en");
    let accepted = Accepted::new(&request, registry).expect("accepted");
    let app = test_app();
    let rendering = app.rendering().expect("the rendering");
    let matched = Match::run(&accepted, &wallet, &env, &rendering).expect("match");
    let consent = Consent::of(&matched).expect("consent");
    let views = Views::of(&matched, &env).expect("views");
    let sets = offer(&matched, &consent, Choice::LetChoose);
    let shown = display(&sets, &views, &[]).expect("display");
    let mut ids: Vec<String> = Vec::new();
    for choice in shown.sets().iter().flatten().flatten() {
        if !ids.iter().any(|id| id == choice.id()) && choice.id() != "none" {
            ids.push(choice.id().to_owned());
        }
    }
    ids
}

fn outcome(text: &str, held: &[Held], ids: &[&str], host: &TestHost) -> Result<String, Outcome> {
    let received = unsigned(text).expect("received");
    let request = request_of(&received).expect("request");
    let registry = registry(Binds::First);
    let authenticated = authenticate(request.envelope(), &registry, host).expect("authentic");
    let wallet = Wallet::new(held.iter().map(Held::credential).collect()).expect("wallet");
    let app = test_app();
    let rendering = app.rendering().expect("the rendering");
    Prepared::prepare(
        &authenticated,
        ids,
        &wallet,
        &registry,
        &env("en"),
        &rendering,
        host,
    )
    .and_then(|prepared| prepared.respond(|resource| Published::default().answer(resource), host))
    .map(|built| built.response().vp_token().json())
}

#[test]
fn phase_2_rejects_what_no_selection_allows() {
    let (text, held) = fixture();
    let ids = offered(&text, &held);
    let [c1, c2, c3, c4] = ids.as_slice() else {
        panic!("four records: {ids:?}")
    };
    let honest = outcome(&text, &held, &[c1], &TestHost::default());
    assert!(honest.is_ok(), "{honest:?}");
    // §6.4's selection rules: a record per query without `multiple`, one transaction per
    // confirmation (C3), and the alternatives the request allows.
    let query_records = |query: &str, records: usize, credentials: usize| Rejection::QueryRecords {
        query: query.to_owned(),
        records,
        credentials,
    };
    let cases: [(Vec<&str>, Option<Rejection>); 5] = [
        (vec![c1, "none"], None),
        (vec![c3, c4], Some(query_records("r", 2, 2))),
        (vec![c1, c1], Some(query_records("q", 2, 1))),
        (vec![c1, c2], Some(Rejection::TwoTransactions)),
        (vec![], Some(Rejection::NoAlternative(Vec::new()))),
    ];
    for (ids, want) in cases {
        match (outcome(&text, &held, &ids, &TestHost::default()), want) {
            (Err(Outcome::Rejected(Rejection::NotARecord(_))), None) => {}
            (Err(Outcome::Rejected(rejection)), Some(want)) => assert_eq!(rejection, want),
            (other, _) => panic!("{ids:?}: {other:?}"),
        }
    }
    // §6.4.2: no record meets a request whose every credential set is optional, and §8.1's
    // `vp_token` then holds no query.
    let optional = parameters(
        r#"{"credentials": [{"id": "q", "format": "test"}],
            "credential_sets": [{"options": [["q"]], "required": false}]}"#,
        "",
    );
    match outcome(&optional, &held, &[], &TestHost::default()) {
        Ok(vp_token) => assert_eq!(vp_token, "{}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn phase_2_falls_back_on_a_record_it_does_not_derive() {
    let (text, held) = fixture();
    let ids = offered(&text, &held);
    let c1 = ids[0].as_str();
    // Whatever part changed: the option, the credential, an attested fact, an entry the query is
    // not named by; or the request the record commits to.
    let another = text.replace("n-0S6_WzA2Mj", "n-another");
    let cases = [
        (text.as_str(), c1.replace(",0,[0],", ",99,[0],")),
        (text.as_str(), c1.replace("\"c1\"", "\"nobody\"")),
        (
            text.as_str(),
            c1.replace(r#"{"entries":"0"}"#, r#"{"entries":"0x"}"#),
        ),
        (text.as_str(), c1.replace(",[0],", ",[0,1],")),
        (another.as_str(), c1.to_owned()),
    ];
    for (request, id) in &cases {
        match outcome(request, &held, &[id], &TestHost::default()) {
            Err(Outcome::Fallback(findings)) => assert!(
                matches!(findings.items(), [Finding::Diverged { record: 0 }]),
                "{findings:?}"
            ),
            other => panic!("{id}: {other:?}"),
        }
    }
}

/// I31: phase 2 refuses a pick whose rendering inputs differ from its own, naming the input, and
/// renders nothing to compare: one fixture per input.
#[test]
fn phase_2_refuses_a_pick_rendered_with_other_inputs() {
    use siros_openid4vp::matching::RenderingInput;
    let (text, held) = fixture();
    let ids = offered(&text, &held);
    let c1 = ids[0].as_str();
    let digest_at = c1.find(r#""openid4vp":""#).expect("the core's module") + 13;
    let mut altered_digest = c1.to_owned();
    let flipped = if &c1[digest_at..=digest_at] == "0" {
        "1"
    } else {
        "0"
    };
    altered_digest.replace_range(digest_at..=digest_at, flipped);
    let cases = [
        (
            c1.replace(r#""selected":null"#, r#""selected":["paso","en"]"#),
            RenderingInput::Selected,
        ),
        (
            c1.replace(r#""language":"en""#, r#""language":"de""#),
            RenderingInput::Language,
        ),
        (
            c1.replace(r#""fallback":false"#, r#""fallback":true"#),
            RenderingInput::Fallback,
        ),
        (
            altered_digest,
            RenderingInput::Module("openid4vp".to_owned()),
        ),
        (
            c1.replace(r#""modules":{"#, r#""modules":{"extra":"00","#),
            RenderingInput::Module("extra".to_owned()),
        ),
        (
            c1.replace(r#""amounts":"formatted""#, r#""amounts":"written""#),
            RenderingInput::Amounts,
        ),
        (
            c1.replace(r#""bidi":"none""#, r#""bidi":"default""#),
            RenderingInput::Bidi,
        ),
        (
            c1.replace(r#""renderer":1}"#, r#""renderer":2}"#),
            RenderingInput::Renderer,
        ),
    ];
    for (id, want) in &cases {
        assert_ne!(id, c1, "{want:?} alters the pick");
        match outcome(&text, &held, &[id], &TestHost::default()) {
            Err(Outcome::Fallback(findings)) => assert!(
                matches!(findings.items(), [Finding::Rendered { record: 0, input }] if input == want),
                "{want:?}: {findings:?}"
            ),
            other => panic!("{want:?}: {other:?}"),
        }
    }
}

#[test]
fn phase_2_falls_back_on_what_no_longer_holds() {
    let (text, held) = fixture();
    let ids = offered(&text, &held);
    let (c1, c2) = (ids[0].as_str(), ids[1].as_str());
    // A credential that can no longer be presented.
    let mut host = TestHost::default();
    host.platform.unusable = vec!["c1".to_owned()];
    match outcome(&text, &held, &[c1], &host) {
        Err(Outcome::Fallback(findings)) => assert!(matches!(
            findings.items(),
            [Finding::Unusable { record: 0 }]
        )),
        other => panic!("{other:?}"),
    }
    // An entry the profile finds stale, which the informed profile binds no longer.
    match outcome(&text, &held, &[c2], &TestHost::default()) {
        Err(Outcome::Fallback(findings)) => {
            let [Finding::Revalidation { record: 0, finding }] = findings.items() else {
                panic!("{findings:?}")
            };
            assert_eq!(
                finding.data::<Stale>(),
                Some(&Stale(vec![("c2".to_owned(), 0)]))
            );
            let received = unsigned(&text).expect("received");
            let request = request_of(&received).expect("request");
            let informed = registry(Binds::First)
                .informed(&[finding])
                .expect("informed");
            // A finding informs only a registry holding the profile that made it.
            let mut bare = Registry::<TestHost>::builder();
            bare.format(TestFormat::new().expect("format"));
            let bare = bare.build().expect("registry");
            assert_eq!(bare.informed(&[finding]).map(drop), Err(InformError));
            let wallet = Wallet::new(held.iter().map(Held::credential).collect()).expect("wallet");
            let accepted = Accepted::new(&request, &informed).expect("accepted");
            let app = test_app();
            let rendering = app.rendering().expect("the rendering");
            let matched = Match::run(&accepted, &wallet, &env("en"), &rendering).expect("match");
            let q = request.indexed_queries().next().expect("q").0;
            let ids: Vec<&str> = matched
                .candidates(q)
                .iter()
                .map(|c| c.credential.id.as_str())
                .collect();
            assert_eq!(ids, ["c1"]);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn phase_2_answers_nothing_without_the_users_authentication() {
    let (text, held) = fixture();
    let ids = offered(&text, &held);
    let mut host = TestHost::default();
    host.platform.authentication = None;
    assert!(matches!(
        outcome(&text, &held, &[&ids[0]], &host),
        Err(Outcome::UserUnauthenticated)
    ));
}

/// The test profile needing strong authentication.
#[derive(Clone)]
struct Strong(TestProfile);

impl Profile for Strong {
    type Finding = Stale;

    fn refusals(&self, request: &Request<'_>, entries: &[EntryIndex]) -> Vec<Refusal> {
        self.0.refusals(request, entries)
    }
    fn members(&self, placement: siros_openid4vp::wallet_metadata::Placement) -> Option<&[Member]> {
        self.0.members(placement)
    }
    fn bind(&self, binding: Binding<'_>, env: &Env) -> Result<Bound, NoCandidate> {
        self.0.bind(binding, env)
    }
}

impl<H> ProfileHost<H> for Strong {
    fn wanted(&self, answered: Answered<'_>, host: &H) -> Result<Vec<HttpsUrl>, Fault> {
        ProfileHost::<H>::wanted(&self.0, answered, host)
    }

    fn informed(&self, findings: &[&Stale]) -> Self {
        Self(ProfileHost::<H>::informed(&self.0, findings))
    }

    fn authentication(&self, _: Answered<'_>) -> Result<AuthenticationNeed, Fault> {
        Ok(AuthenticationNeed::Strong)
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
fn phase_2_refuses_an_authentication_weaker_than_a_profile_needs() {
    let (text, held) = fixture();
    let ids = offered(&text, &held);
    let mut builder = Registry::<TestHost>::builder();
    siros_testkit::fixtures::openid4vp(&mut builder);
    builder.format(TestFormat::new().expect("format"));
    let profile = builder.profile(Strong(TestProfile::new(Binds::First)));
    builder.exact(TransactionType::parse("t1").expect("type"), profile);
    let registry = builder.build().expect("registry");
    let received = unsigned(&text).expect("received");
    let request = request_of(&received).expect("request");
    let wallet = Wallet::new(held.iter().map(Held::credential).collect()).expect("wallet");
    // A PIN alone is one PSD2 category; strong authentication needs two (Art. 4(30)).
    let mut host = TestHost::default();
    host.platform.authentication = Some(Authentication::new(
        host.platform.now,
        AllOf::one(Factor::Knowledge(Knowledge::Pin(None))),
    ));
    let authenticated = authenticate(request.envelope(), &registry, &host).expect("authentic");
    let ids: &[&str] = &[&ids[0]];
    let app = test_app();
    let rendering = app.rendering().expect("the rendering");
    match Prepared::prepare(
        &authenticated,
        ids,
        &wallet,
        &registry,
        &env("en"),
        &rendering,
        &host,
    )
    .and_then(|prepared| prepared.respond(|resource| Published::default().answer(resource), &host))
    {
        Err(Outcome::AuthenticationTooWeak { need, covered }) => {
            assert_eq!(need, AuthenticationNeed::Strong);
            assert_eq!(covered.count(), 1);
        }
        other => panic!("{other:?}"),
    }
}

/// The test profile writing `extra` too, which it does not declare.
#[derive(Clone)]
struct Undeclared(TestProfile);

impl Profile for Undeclared {
    type Finding = Stale;

    fn refusals(&self, request: &Request<'_>, entries: &[EntryIndex]) -> Vec<Refusal> {
        self.0.refusals(request, entries)
    }
    fn members(&self, placement: siros_openid4vp::wallet_metadata::Placement) -> Option<&[Member]> {
        self.0.members(placement)
    }
    fn bind(&self, binding: Binding<'_>, env: &Env) -> Result<Bound, NoCandidate> {
        self.0.bind(binding, env)
    }
}

impl<H> ProfileHost<H> for Undeclared {
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
        let written = self.0.respond(answered, host, authentication)?;
        let mut members: Vec<(Member, MemberValue)> = written.iter().cloned().collect();
        members.push((
            Member::claim("extra"),
            MemberValue::Text("forged".to_owned()),
        ));
        Members::new(members).map_err(|twice| Fault::new(FAULT, detail!("{twice}")))
    }
}

#[test]
fn phase_2_faults_on_a_member_the_profile_does_not_declare() {
    let (text, held) = fixture();
    let ids = offered(&text, &held);
    let mut builder = Registry::<TestHost>::builder();
    siros_testkit::fixtures::openid4vp(&mut builder);
    builder.format(TestFormat::new().expect("format"));
    let profile = builder.profile(Undeclared(TestProfile::new(Binds::First)));
    builder.exact(TransactionType::parse("t1").expect("type"), profile);
    let registry = builder.build().expect("registry");
    let received = unsigned(&text).expect("received");
    let request = request_of(&received).expect("request");
    let wallet = Wallet::new(held.iter().map(Held::credential).collect()).expect("wallet");
    let host = TestHost::default();
    let authenticated = authenticate(request.envelope(), &registry, &host).expect("authentic");
    let ids: &[&str] = &[&ids[0]];
    let app = test_app();
    let rendering = app.rendering().expect("the rendering");
    match Prepared::prepare(
        &authenticated,
        ids,
        &wallet,
        &registry,
        &env("en"),
        &rendering,
        &host,
    )
    .and_then(|prepared| prepared.respond(|resource| Published::default().answer(resource), &host))
    {
        Err(Outcome::Fault(fault)) => assert_eq!(
            std::error::Error::source(&fault)
                .and_then(|source| source.downcast_ref::<ParameterBreach>()),
            Some(&ParameterBreach::Undeclared),
            "{fault}"
        ),
        other => panic!("{other:?}"),
    }
}

/// HAIP's keystore stand-in, whose encryption fails.
struct FailingHaip;

impl Haip for FailingHaip {
    fn verifies(&self) -> JwsAlgorithms {
        TestHaip.verifies()
    }

    fn agreements(&self) -> Agreements {
        TestHaip.agreements()
    }

    fn verify(&self, key: &VerificationKey, signed: &Signed<'_>) -> Result<(), SignatureInvalid> {
        TestHaip.verify(key, signed)
    }

    fn sign(&self, credential: &CredentialId<'_>, data: &[u8]) -> Result<Signature, SignFailed> {
        TestHaip.sign(credential, data)
    }
    fn encrypt_jwe(
        &self,
        _: &AgreeableKey<'_>,
        _: ContentEncryption<'_>,
        _: &[u8],
    ) -> Result<SealedJwe, Fault> {
        Err(Fault::new(FAULT, detail!("no key agreement")))
    }
}

/// HAIP's keystore stand-in, stating no key agreement.
struct SealerlessHaip;

impl Haip for SealerlessHaip {
    fn verifies(&self) -> JwsAlgorithms {
        TestHaip.verifies()
    }

    fn agreements(&self) -> Agreements {
        Agreements::NONE
    }

    fn verify(&self, key: &VerificationKey, signed: &Signed<'_>) -> Result<(), SignatureInvalid> {
        TestHaip.verify(key, signed)
    }

    fn sign(&self, credential: &CredentialId<'_>, data: &[u8]) -> Result<Signature, SignFailed> {
        TestHaip.sign(credential, data)
    }

    fn encrypt_jwe(
        &self,
        key: &AgreeableKey<'_>,
        enc: ContentEncryption<'_>,
        plaintext: &[u8],
    ) -> Result<SealedJwe, Fault> {
        TestHaip.encrypt_jwe(key, enc, plaintext)
    }
}

siros_testkit::test_host! {
    /// The test host, its encryption failing.
    #[derive(Default)]
    struct Failing {
        handles { platform: TestPlatform => Platform }
        zero_sized { FailingHaip => Haip, TestRequestDecryption => RequestDecryption }
        optional {}
        lacks {}
    }
}

siros_testkit::test_host! {
    /// The test host, its HAIP module stating no key agreement.
    #[derive(Default)]
    struct Sealerless {
        handles { platform: TestPlatform => Platform }
        zero_sized { SealerlessHaip => Haip, TestRequestDecryption => RequestDecryption }
        optional {}
        lacks {}
    }
}

/// The delivery of the response to the record over a host.
fn sealed<H: CoreHost>(
    request: &Request<'_>,
    id: &str,
    wallet: &Wallet<'_>,
    registry: &Registry<H>,
    host: &H,
) -> Result<Delivery, Outcome> {
    let authenticated = authenticate(request.envelope(), registry, host)
        .map_err(|e| Fault::new(FAULT, detail!("{e}", e = e.to_string())))?;
    let ids: &[&str] = &[id];
    let app = test_app();
    let rendering = app.rendering().expect("the rendering");
    Prepared::prepare(
        &authenticated,
        ids,
        wallet,
        registry,
        &env("en"),
        &rendering,
        host,
    )
    .and_then(|prepared| prepared.respond(|resource| Published::default().answer(resource), host))
    .map(|built| built.delivery().clone())
}

/// Whether the DC API data wraps a JWE: `{"response": JWE}` (A.2, §8.3).
fn wraps_a_jwe(delivery: &Delivery) -> bool {
    let Delivery::DcApi(data) = delivery else {
        return false;
    };
    let data: serde_json::Value = serde_json::from_str(data.as_str()).expect("JSON");
    data.get("response")
        .is_some_and(serde_json::Value::is_string)
}

#[test]
fn phase_2_answers_nothing_it_cannot_encrypt_as_dc_api_jwt_asks() {
    let jwk = r#"{"kty": "EC", "crv": "P-256", "kid": "k", "x": "DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0", "y": "XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc", "use": "enc", "alg": "ECDH-ES"}"#;
    let text = format!(
        r#"{{"response_type":"vp_token","response_mode":"dc_api.jwt","nonce":"n-0S6_WzA2Mj","client_metadata":{{"jwks":{{"keys":[{jwk}]}}}},"dcql_query":{}}}"#,
        test_queries(&["q"])
    );
    let held = [Held::answering("c", &["q"], &[])];
    let ids = offered(&text, &held);
    let received = unsigned(&text).expect("received");
    let request = request_of(&received).expect("request");
    let registry = registry(Binds::First);
    let wallet = Wallet::new(held.iter().map(Held::credential).collect()).expect("wallet");
    // The response is a JWE, else nothing: a failing encryption faults.
    assert!(
        sealed(&request, &ids[0], &wallet, &registry, &TestHost::default())
            .is_ok_and(|response| wraps_a_jwe(&response))
    );
    let mut failing = Registry::<Failing>::builder();
    siros_testkit::fixtures::openid4vp(&mut failing);
    failing.format(TestFormat::new().expect("format"));
    let failing = failing.build().expect("registry");
    assert!(matches!(
        sealed(&request, &ids[0], &wallet, &failing, &Failing::default()),
        Err(Outcome::Fault(_))
    ));
    // A module that states no agreement admits no key under the key rule: C7, refused before
    // the End-User authenticates, and no plaintext reaches the module.
    let mut sealerless = Registry::<Sealerless>::builder();
    siros_testkit::fixtures::openid4vp(&mut sealerless);
    sealerless.format(TestFormat::new().expect("format"));
    let sealerless = sealerless.build().expect("registry");
    let host = Sealerless::default();
    let Err(Outcome::Refused(refused)) = sealed(&request, &ids[0], &wallet, &sealerless, &host)
    else {
        panic!("C7 under the module's statement");
    };
    let refusals = refused.into_refusals();
    assert_eq!(
        refusals
            .iter()
            .map(|refusal| refusal.rule().id())
            .collect::<Vec<_>>(),
        [siros_explain::checked!(
            siros_explain::MessageId,
            "openid4vp.modes.c7_key"
        )]
    );
    assert_eq!(host.platform.authentications(), 0);
}

#[test]
fn the_core_checks_what_a_mode_chooses_and_writes() {
    use siros_openid4vp::resolve::RouteBreach;
    use siros_openid4vp::routing::{ChannelKind, ModeName};
    use siros_testkit::{TestBody, TestChoice, TestMode};

    const NAME: ModeName = siros_explain::checked!(ModeName, "dc_api.test");
    let jwk = r#"{"kty": "EC", "crv": "P-256", "kid": "k", "x": "DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0", "y": "XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc", "use": "enc", "alg": "ECDH-ES"}"#;
    // The Verifier lists A192GCM and A128GCM; the test HAIP module states A256GCM and A128GCM.
    let text = format!(
        r#"{{"response_type":"vp_token","response_mode":"dc_api.test","nonce":"n-0S6_WzA2Mj","client_metadata":{{"jwks":{{"keys":[{jwk}]}},"encrypted_response_enc_values_supported":["A192GCM","A128GCM"]}},"dcql_query":{}}}"#,
        test_queries(&["q"])
    );
    let held = [Held::answering("c", &["q"], &[])];
    let received = unsigned(&text).expect("received");
    let wallet = Wallet::new(held.iter().map(Held::credential).collect()).expect("wallet");
    let key = |enc| TestChoice::Key { place: 0, enc };
    // Each case: the mode's choice, whether its registration seals, the channel of the body it
    // writes, and the breach the core finds, none when it answers. A choice is checked before
    // the End-User authenticates, a body once the presentations are made.
    let cases = [
        (key(ContentEncryption::A128GCM), true, TestBody::Own, None),
        (TestChoice::Plain, false, TestBody::Own, None),
        (
            TestChoice::Foreign {
                enc: ContentEncryption::A128GCM,
            },
            true,
            TestBody::Own,
            Some(RouteBreach::Foreign),
        ),
        (
            key(siros_explain::checked!(
                ContentEncryption<'static>,
                "A192GCM"
            )),
            true,
            TestBody::Own,
            Some(RouteBreach::Unstated),
        ),
        (
            key(ContentEncryption::A256GCM),
            true,
            TestBody::Own,
            Some(RouteBreach::Unlisted),
        ),
        (
            key(ContentEncryption::A128GCM),
            false,
            TestBody::Own,
            Some(RouteBreach::KeyInTheClear),
        ),
        (
            TestChoice::Plain,
            true,
            TestBody::Own,
            Some(RouteBreach::NoKey),
        ),
        (
            TestChoice::Plain,
            false,
            TestBody::Other,
            Some(RouteBreach::BodyChannel),
        ),
    ];
    for (choice, sealed_route, body, breach) in cases {
        let mode = TestMode {
            choice,
            body,
            ..TestMode::new(NAME, ChannelKind::DcApi)
        };
        let mut builder = Registry::<TestHost>::builder();
        siros_testkit::fixtures::openid4vp(&mut builder);
        builder.format(TestFormat::new().expect("format"));
        if sealed_route {
            builder.jwe_mode(mode);
        } else {
            builder.mode(mode);
        }
        let registry = builder.build().expect("registry");
        let envelope = Envelope::parse(&received, &registry).expect("envelope");
        let request = Request::parse(&envelope).expect("request");
        let ids = offered_in(&text, &held, &registry);
        let host = TestHost::default();
        let outcome = sealed(&request, &ids[0], &wallet, &registry, &host);
        match (breach, outcome) {
            (None, Ok(delivery)) if wraps_a_jwe(&delivery) == sealed_route => {
                assert_eq!(host.platform.authentications(), 1, "{choice:?}");
            }
            (Some(breach), Err(Outcome::Fault(fault))) => {
                let cause = std::error::Error::source(&fault)
                    .and_then(|cause| cause.downcast_ref::<RouteBreach>());
                assert_eq!(cause, Some(&breach), "{choice:?}");
                let authenticated = u64::from(breach == RouteBreach::BodyChannel);
                assert_eq!(host.platform.authentications(), authenticated, "{choice:?}");
            }
            (_, other) => panic!("{choice:?}, sealed route {sealed_route}: {other:?}"),
        }
    }
}

/// A registered part's response parameters follow `vp_token` in the Authorization Response
/// (§8.1). A member of a name the registry did not check for the part, `vp_token` from a part
/// whose names changed after `build`, and a name written twice are `Fault`s.
#[test]
fn phase_2_writes_the_registered_response_parameters_after_vp_token() {
    use std::sync::atomic::{AtomicBool, Ordering};

    use siros_openid4vp::json::Node;
    use siros_openid4vp::plugins::RegistryBuilder;
    use siros_openid4vp::resolve::{ParameterBreach, ResponseMember};
    use siros_openid4vp::routing::{ResponseParameters, ResponseParametersHost, ResponseTypeName};
    use siros_openid4vp::session::Session;
    use siros_openid4vp::wallet_metadata::ParameterName;
    use siros_testkit::TestResponseParameters;

    const ISS: ParameterName = siros_explain::checked!(ParameterName, "iss");
    const VP_TOKEN: ParameterName = siros_explain::checked!(ParameterName, "vp_token");

    /// Declares `iss` at `build`, `vp_token` afterwards, and writes `vp_token`.
    #[derive(Debug)]
    struct Shifting(AtomicBool);

    impl Clone for Shifting {
        fn clone(&self) -> Self {
            Self(AtomicBool::new(self.0.load(Ordering::SeqCst)))
        }
    }

    impl ResponseParameters for Shifting {
        fn names(&self) -> &'static [ParameterName] {
            if self.0.swap(true, Ordering::SeqCst) {
                &[VP_TOKEN]
            } else {
                &[ISS]
            }
        }
    }

    impl<H> ResponseParametersHost<H> for Shifting {
        fn members(
            &self,
            _response_type: ResponseTypeName,
            _session: &Session<'_>,
            _host: &H,
        ) -> Result<Vec<ResponseMember>, Fault> {
            Ok(vec![ResponseMember::new(
                VP_TOKEN,
                Node::String("forged".into()),
            )])
        }
    }

    let text = parameters(&test_queries(&["q"]), "");
    let held = [Held::answering("c", &["q"], &[])];
    let ids = offered(&text, &held);
    type Register<'a> = &'a dyn Fn(&mut RegistryBuilder<TestHost>);
    let respond = |register: Register<'_>| {
        let mut builder = Registry::<TestHost>::builder();
        siros_testkit::fixtures::openid4vp(&mut builder);
        builder.format(TestFormat::new().expect("format"));
        register(&mut builder);
        let registry = builder.build().expect("registry");
        let received = unsigned(&text).expect("received");
        let request = request_of(&received).expect("request");
        let host = TestHost::default();
        let authenticated = authenticate(request.envelope(), &registry, &host).expect("authentic");
        let wallet = Wallet::new(held.iter().map(Held::credential).collect()).expect("wallet");
        let ids: &[&str] = &[&ids[0]];
        let app = test_app();
        let rendering = app.rendering().expect("the rendering");
        Prepared::prepare(
            &authenticated,
            ids,
            &wallet,
            &registry,
            &env("en"),
            &rendering,
            &host,
        )
        .and_then(|prepared| {
            prepared.respond(|resource| Published::default().answer(resource), &host)
        })
        .map(|built| built.response().json())
    };
    let issuer = ResponseMember::new(ISS, Node::String("https://wallet.example".into()));
    let writes = |writes: Vec<ResponseMember>| {
        move |builder: &mut RegistryBuilder<TestHost>| {
            builder.response_parameters(TestResponseParameters {
                names: &[ISS],
                writes: writes.clone(),
            });
        }
    };
    let json = respond(&writes(vec![issuer.clone()])).expect("a response");
    assert!(
        json.starts_with(r#"{"vp_token":"#)
            && json.ends_with(r#","iss":"https://wallet.example"}"#),
        "{json}"
    );
    let shifting = |builder: &mut RegistryBuilder<TestHost>| {
        builder.response_parameters(Shifting(AtomicBool::new(false)));
    };
    let cases: [(Register<'_>, ParameterBreach); 2] = [
        (&shifting, ParameterBreach::Undeclared),
        (
            &writes(vec![issuer.clone(), issuer]),
            ParameterBreach::Twice,
        ),
    ];
    for (register, breach) in cases {
        match respond(register) {
            Err(Outcome::Fault(fault)) => {
                let cause = std::error::Error::source(&fault)
                    .and_then(|cause| cause.downcast_ref::<ParameterBreach>());
                assert_eq!(cause, Some(&breach), "{fault}");
            }
            other => panic!("{breach:?}: {other:?}"),
        }
    }
}
