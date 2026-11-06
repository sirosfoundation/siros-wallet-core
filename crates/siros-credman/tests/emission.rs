//! I37 inside the workspace: the matcher renders through the registration's package only what the
//! request decides. Its emission reads each card's texts as held and renders each transaction's
//! from the package's compiled messages; every held text equals what a package compiled from the
//! live modules renders (I38); an entry that does not render ends the emission or stays out of
//! its slot, as `RenderOptions::on_error` states. The emission refuses a renderer whose inputs
//! differ from its record's, a card text the package does not hold, and a package registered
//! under other lists.

use siros_credman::register::{Registered, Registration, package};
use siros_credman::{EmitError, Emitted, NotEmitted, Shown, emit, held};
use siros_explain::{DeclaredModule, ModuleId, RequestText, Text};
use siros_i18n::{BuiltPackage, Formats, Module, Package};
use siros_openid4vp::consent::{Card, ConsentEntry, Header};
use siros_openid4vp::ids::TransactionType;
use siros_openid4vp::matching::{
    Accepted, Consent, Display, Match, StaticEntry, Views, display, offer,
};
use siros_openid4vp::plugins::Registry;
use siros_openid4vp::rendering::Rendering;
use siros_openid4vp::rows::{Bidi, Choice, Env, Icon, OnRenderError, RenderOptions, Row, Value};
use siros_openid4vp::wallet::Wallet;
use siros_testkit::fixtures::{Held, OPTIONS, parameters, request_of, unsigned};
use siros_testkit::render::{App, CrateSource, MainModule, TestkitModule, compilers, main_sources};
use siros_testkit::{Binds, TestFormat, TestHost, TestProfile};

const QUERY: &str = r#"{"credentials":[{"id":"q","format":"test"}]}"#;

fn registry() -> Registry<TestHost> {
    let mut builder = Registry::<TestHost>::builder();
    siros_testkit::fixtures::openid4vp(&mut builder);
    builder.format(TestFormat::new().expect("test format"));
    let profile = builder.profile(TestProfile::new(Binds::First));
    builder.exact(TransactionType::parse("t1").expect("type"), profile);
    builder.build().expect("registry")
}

fn held_credential(id: &str) -> Held {
    let mut held = Held::new(id, "test", r#"{"answers":["q"],"alg":"A"}"#);
    held.documents.push((
        "test".to_owned(),
        br#"{"supports":["t1"],"nonconforming":[]}"#.to_vec(),
    ));
    held
}

/// The requests: one without a transaction, one with.
fn requests() -> Vec<String> {
    let entry =
        siros_testkit::verifier::encode(r#"{"type":"t1","credential_ids":["q"]}"#).expect("entry");
    vec![
        parameters(QUERY, ""),
        parameters(QUERY, &format!(r#""transaction_data":["{entry}"]"#)),
    ]
}

/// A source whose `@locale` line names `tag` in place of the language its file serves.
fn retagged(source: &str, tags: &[(&str, &str)]) -> String {
    source
        .lines()
        .map(|line| {
            tags.iter()
                .find(|(from, _)| line.trim() == format!("@locale {from}"))
                .map_or_else(|| line.to_owned(), |(_, to)| format!("@locale {to}"))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The wallet's modules: the main module, the test app's and the core's, each source's tag
/// rewritten by `tags`.
fn modules(tags: &[(&str, &str)]) -> Vec<Module> {
    let [en, de] = main_sources();
    let main = Module::load(
        ModuleId::Main,
        &siros_i18n::Declaration::new(Vec::new()).expect("a declaration"),
        &[&retagged(&en, tags), &retagged(&de, tags)],
        siros_i18n::LanguagePolicy::Any,
        &compilers().expect("compilers"),
    )
    .expect("the main module");
    let mut out = vec![main];
    for source in [CrateSource::testkit(), CrateSource::openid4vp()] {
        let english = retagged(source.english, tags);
        let german = retagged(source.german, tags);
        out.push(
            Module::load(
                source.id,
                &siros_i18n::Declaration::new(source.messages.clone()).expect("a declaration"),
                &[&english, &german],
                siros_i18n::LanguagePolicy::Any,
                &compilers().expect("compilers"),
            )
            .expect("a crate module"),
        );
    }
    out
}

/// Every text an entry shows that a request decides: its overlay's and its header's.
fn request_texts<'e>(entry: &'e ConsentEntry, header: Option<&'e Header>) -> Vec<&'e Text> {
    let mut out: Vec<&Text> = Vec::new();
    if let Some(overlay) = entry.overlay() {
        out.extend(overlay.hint.iter().map(RequestText::text));
        for row in overlay
            .rows
            .iter()
            .chain(overlay.header.iter().flat_map(|h| &h.rows))
        {
            out.push(row.label.text());
            out.extend(
                row.value
                    .as_ref()
                    .and_then(Value::text)
                    .map(RequestText::text),
            );
            out.extend(row.section.iter().map(RequestText::text));
        }
        if let Some(transaction) = &overlay.header {
            out.extend([transaction.counterparty.text(), transaction.amount.text()]);
        }
    }
    if let Some(header) = header {
        out.extend([&header.title, &header.confirm, &header.cancel]);
    }
    out
}

/// The wallet's configuration under these lists and options.
fn env_of(priority: &[&str], options: RenderOptions) -> Env {
    let tag = |t: &&str| siros_i18n::LocaleTag::parse(t).expect("a tag");
    Env::new(
        priority.iter().map(tag).collect(),
        Vec::new(),
        options,
        Vec::new(),
        Choice::First,
    )
    .expect("env")
}

/// A module of the test app with its type's request messages.
fn declared(module: &Module) -> Registered<'_> {
    match module.id() {
        ModuleId::Main => Registered::of::<MainModule>(module),
        id if id == TestkitModule::ID => Registered::of::<TestkitModule>(module),
        _ => Registered::of::<siros_openid4vp::CrateModule>(module),
    }
    .expect("a declared module")
}

/// The registration's package of `modules` for these credentials' cards and the static cards,
/// under `env`.
fn registered(
    modules: &[Module],
    credentials: &[(&str, &Card)],
    statics: &[&Card],
    env: &Env,
) -> BuiltPackage {
    let own: Vec<ModuleId> = modules.iter().map(Module::id).collect();
    let formats = siros_testkit::render::formats().expect("the render halves");
    package(
        &Registration {
            modules: &modules.iter().map(declared).collect::<Vec<_>>(),
            own: &own,
            credentials,
            statics,
            transactions: &[],
        },
        env,
        &formats,
    )
    .expect("a package")
}

/// Each view's credential and card.
fn cards<'v>(views: &'v Views<'_>) -> Vec<(&'v str, &'v Card)> {
    views
        .iter()
        .map(|view| (view.record.credential.as_str(), view.entry.card()))
        .collect()
}

/// A request matched over the live modules: the request's acceptance and the wallet.
struct Case {
    registry: Registry<TestHost>,
    held: Held,
    parameters: String,
}

impl Case {
    fn new(parameters: String) -> Self {
        Self {
            registry: registry(),
            held: held_credential("c"),
            parameters,
        }
    }

    /// The display of the request matched over `rendering` under `env`, with the static entries,
    /// handed to `then` with the views.
    fn shown<T>(
        &self,
        rendering: &Rendering<'_>,
        env: &Env,
        statics: &[StaticEntry],
        then: impl FnOnce(&Views<'_>, &Display<'_>) -> T,
    ) -> T {
        let received = unsigned(&self.parameters).expect("received");
        let request = request_of(&received).expect("request");
        let wallet =
            Wallet::new(vec![self.held.credential().expect("credential")]).expect("wallet");
        let accepted = Accepted::new(&request, &self.registry).expect("accepted");
        let matched = Match::run(&accepted, &wallet, env, rendering).expect("match");
        let consent = Consent::of(&matched).expect("consent");
        let views = Views::of(&matched, env).expect("views");
        let sets = offer(&matched, &consent, env.choice());
        let shown = display(&sets, &views, statics).expect("display");
        then(&views, &shown)
    }
}

/// I37 over modules tagged by language and over modules tagged by region beside a list of
/// languages (section 4.14: `en` matches `en-GB`): every card text reads as held in the language
/// its screen shows, every request text renders from the compiled messages, each byte-equal to
/// the live package's rendering, and every entry is emitted.
#[test]
fn the_matcher_renders_what_the_request_decides_and_reads_the_rest_as_held() {
    let statics = [StaticEntry {
        id: "notice".to_owned(),
        card: Card {
            icon: Icon::DEFAULT,
            title: Text::Raw("Notice".to_owned()),
            subtitle: None,
            rows: Vec::new(),
        },
    }];
    let formats: Formats = siros_testkit::render::formats().expect("the render halves");
    let tagged: [&[(&str, &str)]; 2] = [&[], &[("en", "en-GB"), ("de", "de-DE")]];
    let (mut held_texts, mut rendered_texts) = (0, 0);
    for tags in tagged {
        let modules = modules(tags);
        let own: Vec<ModuleId> = modules.iter().map(Module::id).collect();
        let live =
            App::new(&modules.iter().collect::<Vec<_>>(), &[]).expect("the live modules' app");
        let live_rendering = live.rendering().expect("the live rendering");
        for priority in [&["en"][..], &["de", "en"]] {
            let env = env_of(priority, OPTIONS);
            for parameters in requests() {
                let case = Case::new(parameters);
                // The registration: the cards a first match draws, which no request changes.
                let built = case.shown(&live_rendering, &env, &statics, |views, _| {
                    registered(&modules, &cards(views), &[&statics[0].card], &env)
                });
                let package = Package::read(built.bytes(), built.root()).expect("the package");
                let rendering = Rendering::new(package, &formats, &own).expect("a registration");
                case.shown(&rendering, &env, &statics, |views, shown| {
                    let emission = emit(shown, &rendering, &env).expect("no fault");
                    assert!(emission.refused().is_empty(), "{:?}", emission.refused());
                    for view in views.iter() {
                        let credential = Some(view.record.credential.as_str());
                        let renderer = rendering
                            .renderer(view.selected, credential, &env)
                            .expect("no fault")
                            .expect("a language");
                        let wallet = live_rendering
                            .renderer(view.selected, None, &env)
                            .expect("no fault")
                            .expect("a language");
                        assert_eq!(renderer.inputs(), *view.record.inputs);
                        assert_eq!(renderer.inputs(), wallet.inputs());
                        for text in held(view.entry.card()) {
                            assert!(renderer.holds(text).expect("reads"), "{tags:?}: held");
                            assert_eq!(renderer.formatted(text), wallet.formatted(text));
                            held_texts += 1;
                        }
                        for text in request_texts(&view.entry, view.header) {
                            assert!(!renderer.holds(text).expect("reads"), "a request's text");
                            assert_eq!(renderer.formatted(text), wallet.formatted(text));
                            rendered_texts += 1;
                        }
                    }
                    // Every entry of every slot is emitted, its texts plain.
                    for (set, emitted) in shown.sets().iter().zip(emission.sets()) {
                        for (slot, choices) in set.iter().zip(emitted) {
                            assert_eq!(slot.len(), choices.len());
                            for (choice, emitted) in slot.iter().zip(choices) {
                                match emitted {
                                    Emitted::Entry { id, shown } => {
                                        assert_eq!(id, choice.id());
                                        let title = match shown {
                                            Shown::Standard(entry) => &entry.title,
                                            Shown::Payment(entry) => &entry.method_name,
                                        };
                                        assert!(!title.is_empty());
                                    }
                                    Emitted::Nothing => assert_eq!(choice.id(), "none"),
                                }
                            }
                        }
                    }
                });
            }
        }
    }
    assert!(
        held_texts > 0 && rendered_texts > 0,
        "{held_texts} held, {rendered_texts} rendered"
    );
}

/// `RenderOptions::on_error`: a static entry whose row label is white space alone ends the
/// emission or stays out of its slot.
#[test]
fn an_entry_that_does_not_render_ends_the_emission_or_stays_out() {
    let modules = modules(&[]);
    let own: Vec<ModuleId> = modules.iter().map(Module::id).collect();
    let formats = siros_testkit::render::formats().expect("the render halves");
    let live = App::new(&modules.iter().collect::<Vec<_>>(), &[]).expect("the live modules' app");
    let live_rendering = live.rendering().expect("the live rendering");
    let statics = [StaticEntry {
        id: "notice".to_owned(),
        card: Card {
            icon: Icon::DEFAULT,
            title: Text::Raw("Notice".to_owned()),
            subtitle: None,
            rows: vec![Row::new(
                Text::Raw(" \t".to_owned()),
                siros_openid4vp::rows::Value::Text(Text::Raw("unnamed".to_owned())),
            )],
        },
    }];
    let case = Case::new(requests().swap_remove(0));
    for on_error in [OnRenderError::NoEntry, OnRenderError::Rendered] {
        let env = env_of(
            &["en"],
            RenderOptions {
                on_error,
                ..OPTIONS
            },
        );
        let built = case.shown(&live_rendering, &env, &statics, |views, _| {
            registered(&modules, &cards(views), &[&statics[0].card], &env)
        });
        let package = Package::read(built.bytes(), built.root()).expect("the package");
        let rendering = Rendering::new(package, &formats, &own).expect("a registration");
        let emission = case.shown(&rendering, &env, &statics, |_, shown| {
            emit(shown, &rendering, &env).expect("no fault")
        });
        assert!(
            matches!(emission.refused(), [(id, NotEmitted::Field(_))] if id == "notice"),
            "{:?}",
            emission.refused()
        );
        let emitted: Vec<&Emitted> = emission.sets().iter().flatten().flatten().collect();
        match on_error {
            OnRenderError::NoEntry => assert!(emission.sets().is_empty()),
            OnRenderError::Rendered => {
                assert!(emitted.iter().any(|e| matches!(e, Emitted::Entry { .. })));
                assert!(
                    emitted
                        .iter()
                        .all(|e| !matches!(e, Emitted::Entry { id, .. } if id == "notice"))
                );
            }
        }
    }
}

/// The emission's refusals, one fixture each: a record whose rendering inputs differ from the
/// renderer's (`Inputs`), a card the registration's package holds no text of (`NotHeld`), and a
/// package registered under other lists than the matcher's (`Fault`).
#[test]
fn the_emission_refuses_other_inputs_unheld_cards_and_other_lists() {
    let modules = modules(&[]);
    let own: Vec<ModuleId> = modules.iter().map(Module::id).collect();
    let formats = siros_testkit::render::formats().expect("the render halves");
    let live = App::new(&modules.iter().collect::<Vec<_>>(), &[]).expect("the live modules' app");
    let live_rendering = live.rendering().expect("the live rendering");
    let case = Case::new(requests().swap_remove(0));
    let env = env_of(&["en"], OPTIONS);
    let other = Card {
        icon: Icon::DEFAULT,
        title: Text::Raw("Another card".to_owned()),
        subtitle: None,
        rows: Vec::new(),
    };
    fn read<'p>(
        built: &'p BuiltPackage,
        formats: &'p Formats,
        own: &'p [ModuleId],
    ) -> Rendering<'p> {
        Package::read(built.bytes(), built.root())
            .and_then(|package| Rendering::new(package, formats, own))
            .expect("a registration")
    }
    // The honest registration emits.
    let honest = case.shown(&live_rendering, &env, &[], |views, _| {
        registered(&modules, &cards(views), &[], &env)
    });
    let rendering = read(&honest, &formats, &own);
    let emitted = case.shown(&rendering, &env, &[], |_, shown| {
        emit(shown, &rendering, &env).map(|emission| emission.refused().len())
    });
    assert!(matches!(emitted, Ok(0)), "{emitted:?}");
    // A record matched under another bidi strategy than the registration's.
    let bidi = env_of(
        &["en"],
        RenderOptions {
            bidi: Bidi::Default,
            ..OPTIONS
        },
    );
    let inputs = case.shown(&live_rendering, &bidi, &[], |views, shown| {
        let id = views.iter().next().expect("a view").record.id().clone();
        (emit(shown, &rendering, &env), id)
    });
    assert!(
        matches!(&inputs, (Err(EmitError::Inputs(entry)), id) if entry == id.as_str()),
        "{:?}",
        inputs.0
    );
    // The credential registered with another card.
    let unheld = case.shown(&live_rendering, &env, &[], |views, _| {
        let credentials: Vec<(&str, &Card)> = cards(views)
            .into_iter()
            .map(|(id, _)| (id, &other))
            .collect();
        registered(&modules, &credentials, &[], &env)
    });
    let rendering = read(&unheld, &formats, &own);
    let refused = case.shown(&rendering, &env, &[], |_, shown| {
        emit(shown, &rendering, &env).map(|emission| emission.refused().len())
    });
    assert!(matches!(refused, Err(EmitError::NotHeld(_))), "{refused:?}");
    // A registration under another priority list.
    let german = env_of(&["de"], OPTIONS);
    let stale = case.shown(&live_rendering, &german, &[], |views, _| {
        registered(&modules, &cards(views), &[], &german)
    });
    let rendering = read(&stale, &formats, &own);
    let faulted = case.shown(&live_rendering, &env, &[], |_, shown| {
        emit(shown, &rendering, &env).map(|emission| emission.refused().len())
    });
    assert!(matches!(faulted, Err(EmitError::Fault(_))), "{faulted:?}");
}

/// The array-order index of the root of a subtree of `size` leaves whose nodes start at `base`:
/// RFC 9162 §2.1.1's tree walked in order, a tree of more than one leaf split at the largest
/// power of two below its size.
fn subtree_root(size: usize, base: usize) -> usize {
    if size == 1 {
        return base;
    }
    let split = size.next_power_of_two() / 2;
    base + 2 * split - 1
}

/// RFC 9162 §2.1.3.1's audit path of leaf `leaf` in a subtree of `size` leaves at `base`, as
/// array-order indices: each level's sibling subtree's root.
fn audit_path(leaf: usize, size: usize, base: usize) -> Vec<usize> {
    if size == 1 {
        return Vec::new();
    }
    let split = size.next_power_of_two() / 2;
    let right = base + 2 * split;
    let (mut path, sibling) = if leaf < split {
        (
            audit_path(leaf, split, base),
            subtree_root(size - split, right),
        )
    } else {
        (
            audit_path(leaf - split, size - split, right),
            subtree_root(split, base),
        )
    };
    path.push(sibling);
    path
}

/// I37's read clause: a request reads of the registration's package its header, the root's node,
/// and each entry it reads whole with its RFC 9162 §2.1.3.1 audit path, at most ⌈log2 n⌉ nodes
/// of 32 bytes for n entries. A byte is read when altering it changes what the matcher emits.
#[test]
fn a_request_reads_whole_entries_and_their_audit_paths() {
    let registry = registry();
    let env = env_of(&["en"], OPTIONS);
    let parameters = requests();
    let received = unsigned(&parameters[1]).expect("received");
    let request = request_of(&received).expect("request");
    let credential = held_credential("c");
    let wallet = Wallet::new(vec![credential.credential().expect("credential")]).expect("wallet");
    let accepted = Accepted::new(&request, &registry).expect("accepted");
    let modules = modules(&[]);
    let own: Vec<ModuleId> = modules.iter().map(Module::id).collect();
    let live = App::new(&modules.iter().collect::<Vec<_>>(), &[]).expect("the live modules' app");
    let live_rendering = live.rendering().expect("the live rendering");
    let matched = Match::run(&accepted, &wallet, &env, &live_rendering).expect("match");
    let views = Views::of(&matched, &env).expect("views");
    let built = registered(&modules, &cards(&views), &[], &env);
    let formats = siros_testkit::render::formats().expect("the render halves");
    let emitted = |bytes: &[u8]| -> String {
        let rendering = match Package::read(bytes, built.root())
            .and_then(|package| Rendering::new(package, &formats, &own))
        {
            Ok(rendering) => rendering,
            Err(refused) => return format!("{refused:?}"),
        };
        let matched = match Match::run(&accepted, &wallet, &env, &rendering) {
            Ok(matched) => matched,
            Err(fault) => return format!("{fault:?}"),
        };
        let Some(consent) = Consent::of(&matched) else {
            return "no consent".to_owned();
        };
        let views = Views::of(&matched, &env).expect("views");
        let sets = offer(&matched, &consent, env.choice());
        let shown = display(&sets, &views, &[]).expect("display");
        format!("{:?}", emit(&shown, &rendering, &env))
    };
    let honest = emitted(built.bytes());
    let read = |at: usize| {
        let mut bytes = built.bytes().to_vec();
        bytes[at] ^= 0xff;
        emitted(&bytes) != honest
    };
    let spans = Package::read(built.bytes(), built.root())
        .expect("the package")
        .spans()
        .expect("the spans");
    let n = spans.len();
    let (header, node) = (8 + 2 + 32 + 8 + 8, 32);
    let mut entries_read = Vec::new();
    for (index, span) in spans.iter().enumerate() {
        let (first, last) = (read(span.start), read(span.end - 1));
        assert_eq!(first, last, "entry {index} is read whole or not at all");
        if first {
            entries_read.push(index);
        }
    }
    let nodes_read: Vec<usize> = (0..2 * n - 1).filter(|j| read(header + node * j)).collect();
    let depth = usize::try_from(n.next_power_of_two().trailing_zeros()).expect("a depth");
    let mut want: Vec<usize> = vec![subtree_root(n, 0)];
    for &index in &entries_read {
        let path = audit_path(index, n, 0);
        assert!(path.len() <= depth, "entry {index}: {} nodes", path.len());
        want.extend(path);
    }
    want.sort_unstable();
    want.dedup();
    assert_eq!(
        nodes_read, want,
        "the nodes read are the root and the audit paths"
    );
    let bytes: usize = header
        + node * nodes_read.len()
        + entries_read.iter().map(|&e| spans[e].len()).sum::<usize>();
    assert!(
        entries_read.len() < n,
        "a request reads part of the package"
    );
    println!(
        "{} of {n} entries read, {} nodes, {bytes} of {} bytes",
        entries_read.len(),
        nodes_read.len(),
        built.bytes().len()
    );
}
