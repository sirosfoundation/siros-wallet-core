//! The matcher's emission over its registration: the context it loads from the registration's
//! sources resolves what the wallet's resolves, so it emits the entries of the wallet's display;
//! a choice that does not emit fails the emission; an icon Credential Manager does not draw gives
//! way to the wallet's.

use std::io::Cursor;

use siros_credman::register::write;
use siros_credman::{
    Base, CredmanEntry, Emission, Emitted, NotEmitted, Registration, Unshown, emit,
};
use siros_i18n::{Bidi, Context, LocaleTag, ResolveError, Text};
use siros_openid4vp::consent::Card;
use siros_openid4vp::ids::{StaticEntryId, TransactionType};
use siros_openid4vp::matching::{Accepted, Consent, Match, StaticEntry, Views, display, offer};
use siros_openid4vp::plugins::Registry;
use siros_openid4vp::request::Request;
use siros_openid4vp::rows::{ClaimText, Env, Icon, IconReference, ImageMedia, Row, Value};
use siros_openid4vp::wallet::Wallet;
use siros_syntax::{AllOf, Keyed};
use siros_testkit::fixtures::{Held, parameters, request_of, unsigned};
use siros_testkit::render::{self, ENGLISH_OPENID4VP, Language};
use siros_testkit::{Binds, TestFormat, TestHost, TestProfile};

const QUERY: &str = r#"{"credentials":[{"id":"q","format":"test"}]}"#;
const OPTIONAL: &str = r#"{"credentials":[{"id":"q","format":"test"},{"id":"r","format":"test"}],
    "credential_sets":[{"options":[["q"]]},{"options":[["r"]],"required":false}]}"#;

fn registry() -> Registry<TestHost> {
    let mut builder = Registry::<TestHost>::builder();
    siros_testkit::fixtures::openid4vp(&mut builder);
    builder.format(TestFormat::new().expect("test format"));
    let profile = builder.profile(TestProfile::new(Binds::First));
    builder.exact(TransactionType::parse("t1").expect("type"), profile);
    builder.build().expect("registry")
}

/// A credential answering `queries` whose transactions bind type `t1`.
fn holding(id: &str, queries: &[&str]) -> Held {
    let answers: Vec<String> = queries.iter().map(|q| format!("\"{q}\"")).collect();
    let mut holding = Held::new(
        id,
        "test",
        format!(r#"{{"answers":[{}],"alg":"A"}}"#, answers.join(",")),
    );
    holding.documents.push((
        "test".to_owned(),
        br#"{"supports":["t1"],"nonconforming":[]}"#.to_vec(),
    ));
    holding
}

/// A request and the wallet it is matched over.
struct Case {
    parameters: String,
    wallet: Vec<Held>,
}

/// The cases: a request without a transaction, one with a transaction, and one whose optional
/// set offers the empty choice.
fn cases() -> [Case; 3] {
    let entry =
        siros_testkit::verifier::encode(r#"{"type":"t1","credential_ids":["q"]}"#).expect("entry");
    [
        Case {
            parameters: parameters(QUERY, ""),
            wallet: vec![holding("c", &["q"])],
        },
        Case {
            parameters: parameters(QUERY, &format!(r#""transaction_data":["{entry}"]"#)),
            wallet: vec![holding("c", &["q"])],
        },
        Case {
            parameters: parameters(OPTIONAL, ""),
            wallet: vec![holding("c", &["q"]), holding("d", &["r"])],
        },
    ]
}

/// A display's choice ids, per set and slot, and the emission of the display.
struct Emitting {
    ids: Vec<Vec<Vec<String>>>,
    emission: Result<Emission, NotEmitted>,
}

impl Case {
    /// The display of the request matched over the wallet under the context `context_of` gives
    /// for the request, the static entries `statics` resolves opening every set, and its
    /// emission.
    fn emitted(
        &self,
        context_of: impl FnOnce(&Request<'_>) -> Context,
        statics: impl Fn(&Context) -> Vec<StaticEntry>,
        env: &Env,
    ) -> Emitting {
        let registry = registry();
        let received = unsigned(&self.parameters).expect("received");
        let request = request_of(&received).expect("request");
        let context = context_of(&request);
        let credentials = self
            .wallet
            .iter()
            .map(|holding| holding.credential().expect("credential"))
            .collect();
        let wallet = Wallet::new(credentials).expect("wallet");
        let accepted = Accepted::new(&request, &registry).expect("accepted");
        let matched = Match::run(&accepted, &wallet, env, &context).expect("match");
        let consent = Consent::of(&matched).expect("consent");
        let views = Views::of(&matched, env, &context).expect("views");
        let sets = offer(&matched, &consent, env.choice());
        let statics = statics(&context);
        let shown = display(&sets, &views, &statics).expect("display");
        let ids = shown
            .sets()
            .iter()
            .map(|set| {
                set.iter()
                    .map(|slot| slot.iter().map(|c| c.id().as_str().to_owned()).collect())
                    .collect()
            })
            .collect();
        Emitting {
            ids,
            emission: emit(&shown, &context),
        }
    }
}

/// The ids of what an emission adds, per set and slot.
fn emitted_ids(emission: &Emission) -> Vec<Vec<Vec<String>>> {
    emission
        .sets()
        .iter()
        .map(|set| {
            set.iter()
                .map(|slot| {
                    slot.iter()
                        .map(|emitted| match emitted {
                            Emitted::Entry { id, .. } | Emitted::Nothing { id, .. } => {
                                id.as_str().to_owned()
                            }
                        })
                        .collect()
                })
                .collect()
        })
        .collect()
}

fn tag(text: &str) -> LocaleTag {
    LocaleTag::parse(text).expect("a tag")
}

/// A text as the context resolves the value written.
fn written(context: &Context, value: &str) -> Text {
    context
        .resolve(&ClaimText::Text {
            value: value.to_owned(),
        })
        .expect("the test app words a written text")
}

/// The wallet's static entry `notice`.
fn notice(context: &Context) -> Vec<StaticEntry> {
    vec![StaticEntry {
        id: StaticEntryId::parse("notice").expect("an id"),
        card: Card {
            icon: Icon::DEFAULT,
            title: written(context, "Notice"),
            subtitle: None,
            rows: vec![Row::new(
                written(context, "Kind"),
                Value::Text(written(context, "notice")),
            )],
        },
    }]
}

/// The registration of the test app's English `sources` under `bidi`, opened.
fn registered(sources: Vec<String>, bidi: Bidi) -> Registration<Cursor<Vec<u8>>> {
    let base = Base::load(
        tag("en"),
        AllOf::one(tag("en")),
        bidi,
        render::formatters().expect("the test app's formatters"),
        AllOf::new(sources).expect("sources"),
    )
    .expect("the sources load");
    let blob = write(&base, &Keyed::empty()).expect("written");
    Registration::open(
        Cursor::new(blob),
        render::formatters().expect("the test app's formatters"),
    )
    .expect("opened")
}

/// The test app's English sources.
fn english() -> Vec<String> {
    Language::English
        .sources()
        .iter()
        .map(|source| (*source).to_owned())
        .collect()
}

/// The `Env` of a registration's priority list.
fn env_of(registration: &Registration<Cursor<Vec<u8>>>) -> Env {
    Env::new(
        registration.base().priority().items().to_vec(),
        Vec::new(),
        siros_openid4vp::rows::Choice::First,
    )
    .expect("env")
}

/// The wallet's code path: the matcher's context, built from the registration, resolves what
/// the wallet's own context resolves under either bidi choice, so the matcher emits the wallet's
/// display, every choice under its id, the empty choice with the wallet's icon and its wording.
#[test]
fn the_matcher_emits_the_wallets_display() {
    let mut nothing = 0;
    for bidi in [Bidi::Default, Bidi::None] {
        let wallet_context =
            render::loaded(bidi, Language::English.sources()).expect("the wallet's context");
        for case in cases() {
            let mut registration = registered(english(), bidi);
            let env = env_of(&registration);
            let matcher = case.emitted(
                |request| {
                    registration
                        .context(request)
                        .expect("the matcher's context")
                },
                notice,
                &env,
            );
            let wallet = case.emitted(|_| wallet_context.clone(), notice, &env);
            assert_eq!(matcher.emission, wallet.emission, "{}", case.parameters);
            let emission = matcher.emission.expect("every choice emits");
            assert_eq!(emitted_ids(&emission), matcher.ids);
            for emitted in emission.sets().iter().flatten().flatten() {
                if let Emitted::Nothing { id, icon, title } = emitted {
                    assert_eq!(id.as_str(), "none");
                    assert_eq!(icon.icon(), &Icon::NONE);
                    assert_eq!(title, "None", "the test app's wording");
                    nothing += 1;
                }
            }
        }
    }
    assert!(nothing > 0, "a case offers the empty choice");
}

/// The empty choice, its title unworded in the context, fails the emission, which names the choice
/// and why.
#[test]
fn a_choice_that_does_not_emit_fails_the_emission() {
    let unworded = ENGLISH_OPENID4VP.replacen("\nnone = None\n", "\n", 1);
    assert_ne!(
        unworded, ENGLISH_OPENID4VP,
        "the test app words the empty choice"
    );
    let without_none: Vec<String> = english()
        .into_iter()
        .map(|source| {
            if source == ENGLISH_OPENID4VP {
                unworded.clone()
            } else {
                source
            }
        })
        .collect();
    let [_, _, optional] = cases();
    let mut registration = registered(without_none, Bidi::None);
    let env = env_of(&registration);
    let emitting = optional.emitted(
        |request| {
            registration
                .context(request)
                .expect("the matcher's context")
        },
        notice,
        &env,
    );
    assert!(
        emitting
            .ids
            .iter()
            .flatten()
            .flatten()
            .any(|shown| shown == "none"),
        "the display holds the empty choice"
    );
    let refused = emitting
        .emission
        .expect_err("the empty choice does not emit");
    let cause = Unshown::Resolve(ResolveError::Unknown {
        id: "openid4vp.wallet.none".to_owned(),
    });
    assert_eq!((refused.entry.as_str(), &refused.cause), ("none", &cause));
}

/// android-credman-sys ABI.md §5: Credential Manager decodes a PNG or a JPEG, and drops an entry
/// without an icon, so an icon of another media type gives way to the wallet's card icon.
#[test]
fn an_icon_credential_manager_does_not_draw_gives_way_to_the_wallets() {
    let context = Language::English.shared().expect("the test app");
    for (media, drawn) in [
        ("image/png", true),
        ("image/jpeg", true),
        ("image/svg+xml", false),
        ("image/webp", false),
    ] {
        let logo = Icon {
            reference: IconReference::Logo("logo".into()),
            media: ImageMedia::parse(media).expect("an image media type"),
            ..Icon::DEFAULT
        };
        let entry = CredmanEntry::of_static(&StaticEntry {
            id: StaticEntryId::parse("notice").expect("an id"),
            card: Card {
                icon: logo.clone(),
                title: written(context, "Notice"),
                subtitle: None,
                rows: Vec::new(),
            },
        });
        let want = if drawn { logo } else { Icon::DEFAULT };
        assert_eq!(*entry.icon().icon(), want, "{media}");
    }
}
