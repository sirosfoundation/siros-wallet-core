//! The response members against PaSO Core A.3 and Risk Signals A.4-A.7 and Default.md, the values
//! computed here from the bytes the specifications name; ad-hoc metadata and the images phase 2
//! revalidates, through the core's matching and response with the test format standing in for
//! `dc+sd-jwt`. Core A.2's Key Binding JWT is siros-integration's end-to-end path.

#[path = "../common/mod.rs"]
mod common;
#[path = "../host.rs"]
mod paso_host;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::{Card, PAY, annex, en, member, parameters, request_app, section, tables};
use serde_json::Value as Json;
use sha2::{Digest, Sha256};
use siros_explain::AllOf;
use siros_openid4vp::host::{
    AnsweredContext, AnsweredQuery, CoreHost, FormatHost, ProfileHost, Timestamp,
};
use siros_openid4vp::ids::{FormatId, TransactionType};
use siros_openid4vp::json::Node;
use siros_openid4vp::matching::{Accepted, Consent, Match, Views, display, offer};
use siros_openid4vp::plugins::{
    Answered, Attested, BoundEntries, Format, FormatQuery, HostedProfile, Member, MemberValue,
    Registry,
};
use siros_openid4vp::refusal::Refusal;
use siros_openid4vp::request::{Query, Request};
use siros_openid4vp::resolve::{Outcome as Phase2, Prepared};
use siros_openid4vp::rows::Choice;
use siros_openid4vp::wallet::Wallet;
use siros_paso::risk::{
    Catalogue, DEFAULT_PROFILE, Effective, MaxAge, Need, ProfileId, RiskProfile, RiskSignal,
    Sealing, SignalSpec, SignalType,
};
use siros_paso::{Measured, PasoProfile, Reading, Signal};
use siros_testkit::verifier::ISSUER;
use siros_testkit::{Published, TestFormat, pin_and_device};

use paso_host::PasoHost;

mod adhoc_and_phase2;
mod signals;

const AMR: &str = "urn:paso:risk:global:amr:1";
const MODE: &str = "urn:paso:risk:global:response_mode:1";
const NOW: u64 = 1_785_000_000;

/// The test format under another identifier: its presentation's proof holds the members.
#[derive(Clone)]
struct Standing {
    id: FormatId<'static>,
    inner: TestFormat,
}

impl Format for Standing {
    fn id(&self) -> FormatId<'_> {
        self.id.borrowed()
    }

    fn reserved(&self) -> &[Member] {
        self.inner.reserved()
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
    ) -> Result<
        Box<dyn siros_openid4vp::plugins::ViewAdditions + 'c>,
        siros_openid4vp::plugins::Fault,
    > {
        Ok(Box::new(siros_openid4vp::plugins::ViewTypes::new(
            Vec::new(),
        )))
    }

    fn query<'q>(
        &'q self,
        query: &'q Query<'q>,
        context: siros_openid4vp::routing::QueryContext<'q>,
    ) -> Result<Box<dyn FormatQuery + 'q>, AllOf<Refusal>> {
        self.inner.query(query, context)
    }
}

impl<H> FormatHost<H> for Standing {
    fn answer<'q>(
        &'q self,
        query: &'q Query<'q>,
        context: AnsweredContext<'q>,
    ) -> Result<Box<dyn AnsweredQuery<H> + 'q>, AllOf<Refusal>> {
        FormatHost::<H>::answer(&self.inner, query, context)
    }
}

fn registry(profile: PasoProfile) -> Registry<PasoHost> {
    registry_of("dc+sd-jwt", profile)
}

/// The registry over host `H` with the test format standing in for `format`.
fn registry_of<H>(format: &str, profile: PasoProfile) -> Registry<H>
where
    PasoProfile: HostedProfile<H>,
    H: siros_openid4vp::host::CoreHost
        + siros_openid4vp::host::Has<dyn siros_openid4vp::host::Haip>
        + siros_openid4vp::host::Has<dyn siros_openid4vp::host::RequestDecryption>,
{
    let mut builder = Registry::<H>::builder();
    siros_testkit::fixtures::openid4vp(&mut builder);
    builder.client_prefix(siros_testkit::TestPrefix::Request);
    builder.format(Standing {
        id: FormatId::parse(format.to_owned()).expect("format"),
        inner: TestFormat::new().expect("test format"),
    });
    let handle = profile.register(&mut builder).expect("registers");
    let registry = builder.build().expect("registry");
    let kind = TransactionType::parse(PAY).expect("type");
    assert_eq!(
        registry.profile(&kind),
        Some(handle),
        "PaSO holds urn:paso:sca:"
    );
    registry
}

/// The card answering the query `sca_card`.
fn card(types: &str, keys: Option<&str>, issuer: &str) -> Card {
    let mut card = Card::new("dc+sd-jwt", types, keys, issuer);
    card.view = r#"{"answers":["sca_card"],"alg":"A"}"#.to_owned();
    card
}

fn payment(extra: &str) -> String {
    format!(
        r#"{{"type": "{PAY}", "credential_ids": ["sca_card"], "payload": {{"transaction_id": "ab9c4d5e-6f78-9012-3456-789abcdef012", "amount": "49.99 EUR", "payee": {{"name": "Shop Inc.", "id": "DE98ZZZ09999999999"}}}}{extra}}}"#
    )
}

fn payment_meta() -> String {
    member(&annex("Payment.md", "A.1")[1], PAY)
}

/// The VP Token answering the first selection the consent offers, phase 2's fetches answered
/// from `published`.
fn answer<H: CoreHost>(
    request: &Request<'_>,
    card: &Card,
    registry: &Registry<H>,
    published: &Published,
    host: &H,
) -> Result<String, Phase2> {
    let credential = card.credential();
    let wallet = Wallet::new(vec![credential]).expect("wallet");
    let env = en();
    let app = request_app(request, &[card], &env);
    let rendering = app.rendering().expect("the rendering");
    let accepted = Accepted::new(request, registry).expect("accepted");
    let matched = Match::run(&accepted, &wallet, &env, &rendering).expect("match");
    let consent = Consent::of(&matched).expect("the wallet meets the request");
    let sets = offer(&matched, &consent, Choice::First);
    let views = Views::of(&matched, &env).expect("views");
    let shown = display(&sets, &views, &[]).expect("display");
    let ids: Vec<&str> = shown.sets()[0].iter().map(|slot| slot[0].id()).collect();
    let authenticated = siros_testkit::fixtures::authenticate(request.envelope(), registry, host)
        .expect("authentic");
    Prepared::prepare(
        &authenticated,
        &ids,
        &wallet,
        registry,
        &env,
        &rendering,
        host,
    )
    .and_then(|prepared| prepared.respond(|resource| published.answer(resource), host))
    .map(|built| built.response().vp_token().json())
}

/// The proof of the first presentation of `sca_card` in a VP Token.
fn proof(token: &str) -> Json {
    let token: Json = serde_json::from_str(token).expect("vp_token");
    token["sca_card"][0]["proof"].clone()
}

fn digest_b64(text: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(text.as_bytes()))
}

fn host_with(signals: Vec<(&str, u64, Reading, bool)>) -> PasoHost {
    let mut host = PasoHost::at(Timestamp(NOW));
    host.paso.signals = signals
        .into_iter()
        .map(|(kind, ago, reading, retakes)| Measured {
            signal: SignalType::parse(kind.to_owned()).expect("signal"),
            last: Signal {
                collected_at: Timestamp(NOW - ago),
                reading,
                retakes,
            },
        })
        .collect();
    host
}

fn ok(json: &str) -> Reading {
    Reading::Ok(serde_json::value::RawValue::from_string(json.to_owned()).expect("json"))
}

#[test]
fn core_a3_the_device_signed_elements_are_the_examples_and_the_hash_a_byte_string() {
    let a3: Vec<String> = section("paso-core.md", "### A.3 mdoc DeviceSigned Namespace")
        .lines()
        .filter_map(|line| {
            line.strip_prefix("  \"")
                .and_then(|rest| rest.split_once("\" :"))
                .map(|(name, _)| name.to_owned())
        })
        .collect();
    let entry_json = payment("");
    let parameters = parameters(
        r#"{"credentials": [{"id": "sca_card", "format": "mso_mdoc"}]}"#,
        &[&entry_json],
        "",
    );
    siros_testkit::signed_request!(let request = &parameters);
    let meta = payment_meta();
    let required = format!(
        r#"{}, "risk_signals": [{{"type": "{MODE}", "required": true}}]}}"#,
        meta.strip_suffix('}').expect("an object")
    );
    let card = Card::new(
        "mso_mdoc",
        &format!(r#"{{"{PAY}": {required}}}"#),
        None,
        ISSUER,
    );
    let credential = card.credential();
    let offered: Vec<_> = request.indexed_entries().map(|(index, _)| index).collect();
    let entries = BoundEntries::select(&offered, offered.clone()).expect("entries");
    let attested = Attested::new(vec![
        ("display_locale".to_owned(), "de".to_owned()),
        ("metadata_integrity".to_owned(), card.integrity()),
    ])
    .expect("attested");
    let format = FormatId::parse("mso_mdoc").expect("format");
    let record = Answered::new(
        &request,
        &credential,
        &entries,
        &attested,
        crate::common::placement(&format),
        siros_testkit::fixtures::mode_of(&request).expect("a mode"),
    );
    let host = PasoHost::at(Timestamp(NOW));
    let authentication = pin_and_device(Timestamp(NOW));
    let members = PasoProfile::default()
        .respond(record, &host, &authentication)
        .expect("members");
    let mut names: Vec<String> = members
        .names()
        .map(|member| match member {
            Member::Element { namespace, element } => {
                assert_eq!(namespace, "urn:paso:sca:1");
                element.to_string()
            }
            Member::Claim(name) => panic!("a claim {name} in an mdoc"),
        })
        .collect();
    let mut want = a3.clone();
    names.sort();
    want.sort();
    assert_eq!(names, want);
    let hash = members
        .iter()
        .find(|(member, _)| *member == Member::element("urn:paso:sca:1", "transaction_data_hash"))
        .map(|(_, value)| value.clone());
    assert_eq!(
        hash,
        Some(MemberValue::Bytes(
            Sha256::digest(request.entries()[0].raw().as_bytes()).to_vec()
        ))
    );
}

fn spec_profile(rows: &[Vec<String>]) -> RiskProfile {
    RiskProfile {
        sealing: Sealing::Plain,
        signals: rows[1..]
            .iter()
            .map(|row| SignalSpec {
                signal: RiskSignal::parse(&row[0]).expect("a signal"),
                need: if row[1] == "true" {
                    Need::Required
                } else {
                    Need::Optional
                },
                max_age: row[2].parse().ok().map(MaxAge),
            })
            .collect(),
    }
}

#[test]
fn risk_signals_a7_resolves_two_profiles_and_a4s_enumeration_to_its_table() {
    let a7 = section(
        "paso-proof-risk-signals.md",
        "### A.7 Profile Reference and Resolution",
    );
    let names: Vec<String> = a7
        .split("profile `")
        .skip(1)
        .filter_map(|rest| {
            rest.split_once("` declares")
                .map(|(name, _)| name.to_owned())
        })
        .collect();
    let [baseline, high, resolved] =
        <[Vec<Vec<String>>; 3]>::try_from(tables(&a7)).expect("three tables");
    let catalogue = Catalogue::new(vec![
        (
            ProfileId::parse(&names[0]).expect("id"),
            spec_profile(&baseline),
        ),
        (
            ProfileId::parse(&names[1]).expect("id"),
            spec_profile(&high),
        ),
    ]);
    let a4 = member(&annex("paso-proof-risk-signals.md", "A.4")[0], PAY);
    let with_profiles = |enumeration: &str| {
        let profiles = names
            .iter()
            .map(|n| format!("\"{n}\""))
            .collect::<Vec<_>>()
            .join(", ");
        format!(r#"{{"risk_signal_profiles": [{profiles}], "risk_signals": {enumeration}}}"#)
    };
    let enumeration = member(&a4, "risk_signals");
    let meta = with_profiles(&enumeration);
    let effective =
        Effective::resolve(&Node::parse(&meta).expect("meta"), &catalogue).expect("resolves");
    let table: Vec<(String, bool, Option<u64>)> = resolved[1..]
        .iter()
        .map(|row| (row[0].clone(), row[1] == "true", row[2].parse().ok()))
        .collect();
    let got = |effective: &Effective| -> Vec<(String, bool, Option<u64>)> {
        effective
            .signals
            .iter()
            .map(|spec| {
                (
                    spec.signal.as_str().to_owned(),
                    spec.need == Need::Required,
                    spec.max_age.map(|a| a.0),
                )
            })
            .collect()
    };
    assert_eq!(
        (got(&effective), effective.sealing),
        (table.clone(), Sealing::Plain)
    );
    // §4.1 step 3: demoting amr or raising geolocation's bound has no effect beyond the profiles.
    let reversed = r#"[{"type": "urn:paso:risk:global:geolocation:1", "max_age": 600}, {"type": "urn:paso:risk:global:amr:1", "required": false}]"#;
    let effective = Effective::resolve(
        &Node::parse(&with_profiles(reversed)).expect("meta"),
        &catalogue,
    )
    .expect("resolves");
    let profiles_only: Vec<(String, bool, Option<u64>)> = table
        .iter()
        .map(|(kind, required, age)| {
            let age = if kind == "urn:paso:risk:global:geolocation:1" {
                Some(120)
            } else {
                *age
            };
            (kind.clone(), *required, age)
        })
        .collect();
    assert_eq!(got(&effective), profiles_only);
    // §4.1: a signal optional in every source stays optional.
    let screen = "urn:paso:risk:global:screen_capture:1";
    let optional = Catalogue::new(vec![(
        ProfileId::parse(&names[0]).expect("id"),
        spec_profile(&[
            vec![
                "type".to_owned(),
                "required".to_owned(),
                "max_age".to_owned(),
            ],
            vec![screen.to_owned(), "false".to_owned(), "—".to_owned()],
        ]),
    )]);
    let meta = format!(
        r#"{{"risk_signal_profiles": ["{}"], "risk_signals": [{{"type": "{screen}", "required": false, "max_age": 30}}]}}"#,
        names[0]
    );
    let effective =
        Effective::resolve(&Node::parse(&meta).expect("meta"), &optional).expect("resolves");
    assert_eq!(got(&effective), [(screen.to_owned(), false, Some(30))]);
    assert_eq!(effective.required().count(), 0);
    // The wallet renders a type whose metadata references the profiles it holds, and no other.
    let card = card(
        &format!(
            r#"{{"{PAY}": {}, "risk_signal_profiles": [{}]}}}}"#,
            payment_meta().strip_suffix('}').expect("an object"),
            names
                .iter()
                .map(|n| format!("\"{n}\""))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        None,
        ISSUER,
    );
    let entry = common::entry(&payment(""));
    let holding = PasoProfile::default().with_catalogue(catalogue);
    let rendered = |profile: &PasoProfile| {
        profile
            .render(
                &entry,
                siros_openid4vp::routing::ChannelKind::DcApi,
                &card.credential(),
                crate::common::placement(&card.credential().format),
                &en(),
            )
            .expect("no fault")
            .map(|_| ())
            .map_err(|outcome| outcome.clause())
    };
    assert_eq!(rendered(&holding), Ok(()));
    assert_eq!(rendered(&PasoProfile::default()), Err("Risk Signals §4.1"));
}

#[test]
fn the_wallets_default_profile_is_default_md_transcribed() {
    let text = std::fs::read_to_string(format!(
        "{}/tests/data/paso-d2/Default.md",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("Default.md");
    let all = tables(&text);
    let head = &all[0];
    let encrypted = head
        .iter()
        .find(|row| row[0] == "encrypted")
        .map(|row| row[1] == "true");
    let signals: Vec<SignalSpec> = all[1][1..]
        .iter()
        .map(|row| SignalSpec {
            signal: RiskSignal::parse(&row[0]).expect("a signal"),
            need: if row[1] == "true" {
                Need::Required
            } else {
                Need::Optional
            },
            max_age: Some(MaxAge(row[2].parse().expect("an age"))),
        })
        .collect();
    let id = ProfileId::parse(DEFAULT_PROFILE).expect("id");
    assert_eq!(encrypted, Some(true));
    assert_eq!(
        Catalogue::paso().get(&id),
        Some(&RiskProfile {
            sealing: Sealing::Encrypted,
            signals
        })
    );
}
