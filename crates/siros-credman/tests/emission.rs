//! The matcher's emission over its registration: the context it builds from the registration's
//! sources resolves what the wallet's resolves, so it emits the entries of the wallet's display;
//! an entry that does not show ends the emission or stays out of its slot, as the registration's
//! on-error choice states; an icon Credential Manager does not draw gives way to the wallet's.

use std::io::Cursor;

use siros_credman::register::write;
use siros_credman::{
    Base, CredmanEntry, Emission, Emitted, NoName, NotEmitted, OnRenderError, Registration, emit,
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
use siros_testkit::render::{ENGLISH_OPENID4VP, Language};
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
    emission: Emission,
}

impl Case {
    /// The display of the request matched over the wallet under the context `context_of` gives
    /// for the request, the static entries `statics` resolves opening every set, and its
    /// emission under `on_error`.
    fn emitted(
        &self,
        context_of: impl FnOnce(&Request<'_>) -> Context,
        statics: impl Fn(&Context) -> Vec<StaticEntry>,
        env: &Env,
        on_error: OnRenderError,
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
            emission: emit(&shown, &context, on_error),
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

/// The wallet's static entry `notice`, with `rows`.
fn notice(context: &Context, rows: &[(&str, &str)]) -> Vec<StaticEntry> {
    vec![StaticEntry {
        id: StaticEntryId::parse("notice").expect("an id"),
        card: Card {
            icon: Icon::DEFAULT,
            title: written(context, "Notice"),
            subtitle: None,
            rows: rows
                .iter()
                .map(|(label, value)| {
                    Row::new(
                        written(context, label),
                        Value::Text(written(context, value)),
                    )
                })
                .collect(),
        },
    }]
}

/// The registration of the test app's English `sources` under `bidi` and `on_error`, opened.
fn registered(
    sources: Vec<String>,
    bidi: Bidi,
    on_error: OnRenderError,
) -> Registration<Cursor<Vec<u8>>> {
    let base = Base {
        locale: tag("en"),
        priority: AllOf::one(tag("en")),
        bidi,
        on_error,
        sources: AllOf::new(sources).expect("sources"),
    };
    let blob = write(&base, &Keyed::empty()).expect("written");
    Registration::open(Cursor::new(blob)).expect("opened")
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
        registration.base().priority.items().to_vec(),
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
        let wallet_context = Language::English
            .sources()
            .into_iter()
            .try_fold(Context::new().bidi(bidi), Context::module)
            .expect("the wallet's context");
        for case in cases() {
            let mut registration = registered(english(), bidi, OnRenderError::Rendered);
            let env = env_of(&registration);
            let on_error = registration.base().on_error;
            let statics = |context: &Context| notice(context, &[("Kind", "notice")]);
            let matcher = case.emitted(
                |request| {
                    registration
                        .context(request)
                        .expect("the matcher's context")
                },
                statics,
                &env,
                on_error,
            );
            let wallet = case.emitted(|_| wallet_context.clone(), statics, &env, on_error);
            assert_eq!(matcher.emission, wallet.emission, "{}", case.parameters);
            assert!(
                matcher.emission.refused().is_empty(),
                "{:?}",
                matcher.emission.refused()
            );
            assert_eq!(emitted_ids(&matcher.emission), matcher.ids);
            for emitted in matcher.emission.sets().iter().flatten().flatten() {
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

/// An entry that does not show: the request, the registration's sources and the static entries
/// that make it, its id, and why it does not show.
struct Fixture<'f> {
    case: &'f str,
    request: &'f Case,
    sources: Vec<String>,
    statics: &'f dyn Fn(&Context) -> Vec<StaticEntry>,
    id: &'f str,
    reason: NotEmitted,
}

/// The registration's on-error choice: an entry whose row label is white space alone, or the
/// empty choice whose title the context does not word, ends the emission (`NoEntry`) or stays
/// out of its slot (`Rendered`), and the emission names it with its reason.
#[test]
fn an_entry_that_does_not_show_ends_the_emission_or_stays_out() {
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
    let [plain, _, optional] = cases();
    let unnamed = |context: &Context| notice(context, &[(" \t", "unnamed")]);
    let named = |context: &Context| notice(context, &[("Kind", "notice")]);
    let fixtures = [
        Fixture {
            case: "a row named by white space alone",
            request: &plain,
            sources: english(),
            statics: &unnamed,
            id: "notice",
            reason: NotEmitted::Field(NoName),
        },
        Fixture {
            case: "an empty choice the context does not word",
            request: &optional,
            sources: without_none,
            statics: &named,
            id: "none",
            reason: NotEmitted::Resolve {
                cause: ResolveError::Unknown {
                    id: "openid4vp.wallet.none".to_owned(),
                },
            },
        },
    ];
    for Fixture {
        case,
        request,
        sources,
        statics,
        id,
        reason,
    } in fixtures
    {
        for on_error in [OnRenderError::NoEntry, OnRenderError::Rendered] {
            let mut registration = registered(sources.clone(), Bidi::None, on_error);
            let env = env_of(&registration);
            let on_error = registration.base().on_error;
            let emitting = request.emitted(
                |request| {
                    registration
                        .context(request)
                        .expect("the matcher's context")
                },
                statics,
                &env,
                on_error,
            );
            let occurrences = emitting
                .ids
                .iter()
                .flatten()
                .flatten()
                .filter(|shown| *shown == id)
                .count();
            assert!(occurrences > 0, "{case}: the display holds the entry");
            let refused: Vec<(&str, &NotEmitted)> = emitting
                .emission
                .refused()
                .iter()
                .map(|refused| (refused.id.as_str(), &refused.reason))
                .collect();
            assert_eq!(refused, vec![(id, &reason); occurrences], "{case}");
            match on_error {
                OnRenderError::NoEntry => {
                    assert!(emitting.emission.sets().is_empty(), "{case}");
                }
                OnRenderError::Rendered => {
                    let kept: Vec<Vec<Vec<String>>> = emitting
                        .ids
                        .iter()
                        .map(|set| {
                            set.iter()
                                .map(|slot| {
                                    slot.iter().filter(|shown| *shown != id).cloned().collect()
                                })
                                .collect()
                        })
                        .collect();
                    assert_eq!(emitted_ids(&emitting.emission), kept, "{case}");
                }
            }
        }
    }
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
