//! Phase 2 trusts the user's choice alone: it rejects ids that are no records or no selection
//! the request allows, falls back on records it does not derive or on what no longer holds,
//! answers nothing when the wallet fails to authenticate the End-User (OpenID4VP §8.5
//! `access_denied`) or authenticates them more weakly than a profile needs, and faults on a
//! profile writing a member it does not declare and on a host that cannot seal the response as
//! `dc_api.jwt` asks.

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
use siros_openid4vp::resolve::Response;
use siros_openid4vp::resolve::{Finding, Outcome, Prepared, Rejection, ResponseData};
use siros_openid4vp::rows::{Choice, Env, HttpsUrl};
use siros_openid4vp::wallet::Wallet;
use siros_testkit::FAULT;
use siros_testkit::{
    Binds, Published, Stale, TestFormat, TestHaip, TestHost, TestPlatform, TestProfile,
    TestRequestDecryption,
};

use common::{Held, entry, env, parameters, registry, request_of, test_queries, unsigned};

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

/// The id of each entry the display offers, in display order.
fn offered(text: &str, held: &[Held]) -> Vec<String> {
    offered_in(text, held, &registry(Binds::First))
}

/// The ids the consent offers over a registry, which reads the request.
fn offered_in<H>(text: &str, held: &[Held], registry: &Registry<H>) -> Vec<String> {
    let received = unsigned(text).expect("received");
    let envelope = Envelope::parse(&received, registry).expect("envelope");
    let request = Request::parse(&envelope).expect("request");
    let wallet = Wallet::new(held.iter().map(Held::credential).collect()).expect("wallet");
    let env = env("en");
    let accepted = Accepted::new(&request, registry).expect("accepted");
    let matched = Match::run(&accepted, &wallet, &env).expect("match");
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
    let wallet = Wallet::new(held.iter().map(Held::credential).collect()).expect("wallet");
    Prepared::prepare(&request, ids, &wallet, &registry, &env("en"))
        .and_then(|prepared| {
            prepared.respond(|resource| Published::default().answer(resource), host)
        })
        .map(|response| response.vp_token.json())
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
            let matched = Match::run(&accepted, &wallet, &env("en")).expect("match");
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
    fn wanted(&self, answered: Answered<'_>) -> Result<Vec<HttpsUrl>, Fault> {
        ProfileHost::<H>::wanted(&self.0, answered)
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
    match Prepared::prepare(&request, &[&ids[0]], &wallet, &registry, &env("en")).and_then(
        |prepared| prepared.respond(|resource| Published::default().answer(resource), &host),
    ) {
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
    fn wanted(&self, answered: Answered<'_>) -> Result<Vec<HttpsUrl>, Fault> {
        ProfileHost::<H>::wanted(&self.0, answered)
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
    match Prepared::prepare(&request, &[&ids[0]], &wallet, &registry, &env("en")).and_then(
        |prepared| {
            prepared.respond(
                |resource| Published::default().answer(resource),
                &TestHost::default(),
            )
        },
    ) {
        Err(Outcome::Fault(fault)) => assert!(fault.to_string().contains("extra"), "{fault}"),
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

/// The response to the record over a host.
fn sealed<H: CoreHost>(
    request: &Request<'_>,
    id: &str,
    wallet: &Wallet<'_>,
    registry: &Registry<H>,
    host: &H,
) -> Result<Response, Outcome> {
    Prepared::prepare(request, &[id], wallet, registry, &env("en")).and_then(|prepared| {
        prepared.respond(|resource| Published::default().answer(resource), host)
    })
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
    assert!(matches!(
        sealed(&request, &ids[0], &wallet, &registry, &TestHost::default()),
        Ok(Response {
            data: ResponseData::Encrypted(_),
            ..
        })
    ));
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
fn the_core_checks_the_key_and_enc_a_mode_chooses() {
    use siros_openid4vp::routing::{ChannelKind, ModeName};
    use siros_testkit::{TestChoice, TestMode};

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
    // Each case: the mode's choice, whether its registration seals, and whether the core seals.
    let cases = [
        (key(ContentEncryption::A128GCM), true, true),
        (TestChoice::Plain, false, true),
        // An enc the module does not state; an enc the Verifier does not list.
        (
            key(siros_explain::checked!(
                ContentEncryption<'static>,
                "A192GCM"
            )),
            true,
            false,
        ),
        (key(ContentEncryption::A256GCM), true, false),
        // A key on a route in the clear; no key on a sealed route.
        (key(ContentEncryption::A128GCM), false, false),
        (TestChoice::Plain, true, false),
    ];
    for (choice, sealed_route, seals) in cases {
        let mode = TestMode {
            choice,
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
        match (seals, sealed_route, outcome) {
            (
                true,
                true,
                Ok(Response {
                    data: ResponseData::Encrypted(_),
                    ..
                }),
            )
            | (
                true,
                false,
                Ok(Response {
                    data: ResponseData::Plain(_),
                    ..
                }),
            ) => assert_eq!(host.platform.authentications(), 1, "{choice:?}"),
            (false, _, Err(Outcome::Fault(_))) => {
                assert_eq!(host.platform.authentications(), 0, "{choice:?}");
            }
            (_, _, other) => panic!("{choice:?}, sealed route {sealed_route}: {other:?}"),
        }
    }
}
