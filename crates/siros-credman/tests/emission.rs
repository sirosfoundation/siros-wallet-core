//! I37 inside the workspace: the matcher renders through the registration's package only what the
//! request decides. Its emission reads each card's texts as held and renders each transaction's
//! from the package's compiled messages; every held text equals what a package compiled from the
//! live modules renders (I38); an entry that does not render ends the emission or stays out of
//! its slot, as `RenderOptions::on_error` states.

use siros_credman::register::{held, package};
use siros_credman::{Emitted, Shown, emit};
use siros_explain::Text;
use siros_i18n::{BuiltPackage, Formats, Module, Package};
use siros_openid4vp::consent::{ConsentEntry, Header};
use siros_openid4vp::ids::TransactionType;
use siros_openid4vp::matching::{Accepted, Consent, Match, StaticEntry, Views, display, offer};
use siros_openid4vp::plugins::Registry;
use siros_openid4vp::rendering::Rendering;
use siros_openid4vp::rows::{Env, OnRenderError, RenderOptions, Value};
use siros_openid4vp::wallet::Wallet;
use siros_testkit::fixtures::{Held, OPTIONS, env, parameters, request_of, unsigned};
use siros_testkit::render::{App, CrateSource, main_module};
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

/// The wallet's modules: the main module, the test app's and the core's.
fn modules() -> Vec<Module> {
    vec![
        main_module().expect("the main module"),
        CrateSource::testkit()
            .load()
            .expect("the test app's module"),
        CrateSource::openid4vp().load().expect("the core's module"),
    ]
}

/// Every text an entry shows that a request decides: its overlay's and its header's.
fn request_texts<'e>(entry: &'e ConsentEntry, header: Option<&'e Header>) -> Vec<&'e Text> {
    let mut out: Vec<&Text> = Vec::new();
    if let Some(overlay) = entry.overlay() {
        out.extend(&overlay.hint);
        for row in overlay
            .rows
            .iter()
            .chain(overlay.header.iter().flat_map(|h| &h.rows))
        {
            out.push(&row.label);
            out.extend(row.value.as_ref().and_then(Value::text));
            out.extend(&row.section);
        }
        if let Some(transaction) = &overlay.header {
            out.extend([&transaction.counterparty, &transaction.amount]);
        }
    }
    if let Some(header) = header {
        out.extend([&header.title, &header.confirm, &header.cancel]);
    }
    out
}

/// The registration's package for a request's views: the modules, each card's texts held.
fn registered(views: &Views<'_>, statics: &[StaticEntry], options: RenderOptions) -> BuiltPackage {
    let modules = modules();
    let mut texts: Vec<&Text> = views
        .iter()
        .flat_map(|view| held(view.entry.card()))
        .collect();
    texts.extend(statics.iter().flat_map(|entry| held(&entry.card)));
    let formats = siros_testkit::render::formats().expect("the render halves");
    package(
        &modules.iter().collect::<Vec<_>>(),
        &texts,
        &formats,
        options,
    )
    .expect("a package")
}

#[test]
fn the_matcher_renders_what_the_request_decides_and_reads_the_rest_as_held() {
    let registry = registry();
    let env = env(&["en"], Vec::new()).expect("env");
    let statics = [StaticEntry {
        id: "notice".to_owned(),
        card: siros_openid4vp::consent::Card {
            icon: siros_openid4vp::rows::Icon::DEFAULT,
            title: Text::Raw("Notice".to_owned()),
            subtitle: None,
            rows: Vec::new(),
        },
    }];
    let live = App::of(&[CrateSource::openid4vp()]).expect("the live modules' app");
    let live_rendering = live.rendering().expect("the live rendering");
    let formats: Formats = siros_testkit::render::formats().expect("the render halves");
    let own = live_rendering.own().to_vec();
    let (mut held_texts, mut rendered_texts) = (0, 0);
    for parameters in requests() {
        let received = unsigned(&parameters).expect("received");
        let request = request_of(&received).expect("request");
        let credential = held_credential("c");
        let wallet =
            Wallet::new(vec![credential.credential().expect("credential")]).expect("wallet");
        let accepted = Accepted::new(&request, &registry).expect("accepted");
        // The registration: the views a first match draws give the cards no request changes.
        let matched = Match::run(&accepted, &wallet, &env, &live_rendering).expect("match");
        let views = Views::of(&matched, &env).expect("views");
        let built = registered(&views, &statics, env.options());
        let package = Package::read(built.bytes(), built.root()).expect("the package");
        let rendering = Rendering::new(package, &formats, &own);
        let matched = Match::run(&accepted, &wallet, &env, &rendering).expect("match");
        let consent = Consent::of(&matched).expect("consent");
        let views = Views::of(&matched, &env).expect("views");
        let sets = offer(&matched, &consent, env.choice());
        let shown = display(&sets, &views, &statics).expect("display");
        let emission = emit(&shown, &rendering, &env).expect("no fault");
        assert!(emission.refused().is_empty(), "{:?}", emission.refused());
        for view in views.iter() {
            let renderer = rendering
                .renderer(view.selected, &env)
                .expect("no fault")
                .expect("a language");
            let live = live_rendering
                .renderer(view.selected, &env)
                .expect("no fault")
                .expect("a language");
            assert_eq!(
                renderer.inputs(),
                *view.record.inputs,
                "the record's inputs"
            );
            for text in held(view.entry.card()) {
                assert!(renderer.holds(text).expect("reads"), "a card text is held");
                assert_eq!(
                    renderer.formatted(text),
                    live.formatted(text),
                    "held = live"
                );
                held_texts += 1;
            }
            for text in request_texts(&view.entry, view.header) {
                assert!(
                    !renderer.holds(text).expect("reads"),
                    "a request's text renders"
                );
                assert_eq!(
                    renderer.formatted(text),
                    live.formatted(text),
                    "compiled = live"
                );
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
    }
    assert!(
        held_texts > 0 && rendered_texts > 0,
        "{held_texts} held, {rendered_texts} rendered"
    );
}

/// `RenderOptions::on_error`: a static entry naming a module the package does not hold ends the
/// emission or stays out of its slot.
#[test]
fn an_entry_that_does_not_render_ends_the_emission_or_stays_out() {
    let registry = registry();
    let parameters = requests();
    let received = unsigned(&parameters[0]).expect("received");
    let request = request_of(&received).expect("request");
    let credential = held_credential("c");
    let wallet = Wallet::new(vec![credential.credential().expect("credential")]).expect("wallet");
    let accepted = Accepted::new(&request, &registry).expect("accepted");
    let modules = modules();
    let formats = siros_testkit::render::formats().expect("the render halves");
    let built =
        package(&modules.iter().collect::<Vec<_>>(), &[], &formats, OPTIONS).expect("a package");
    let package = Package::read(built.bytes(), built.root()).expect("the package");
    let own: Vec<_> = modules.iter().map(Module::id).collect();
    let rendering = Rendering::new(package, &formats, &own);
    let absent = siros_explain::DefinedModule::new(
        siros_explain::checked!(siros_explain::Domain, "absent"),
        [0; 32],
    );
    let key = siros_explain::DefinedKey::parse("title".to_owned()).expect("a key");
    let statics = [StaticEntry {
        id: "notice".to_owned(),
        card: siros_openid4vp::consent::Card {
            icon: siros_openid4vp::rows::Icon::DEFAULT,
            title: Text::Query(siros_explain::Query::defined(
                absent,
                key,
                siros_explain::Keyed::empty(),
            )),
            subtitle: None,
            rows: Vec::new(),
        },
    }];
    for on_error in [OnRenderError::NoEntry, OnRenderError::Rendered] {
        let env = Env::new(
            env(&["en"], Vec::new()).expect("env").priority().to_vec(),
            Vec::new(),
            RenderOptions {
                on_error,
                ..OPTIONS
            },
            Vec::new(),
            siros_openid4vp::rows::Choice::First,
        )
        .expect("env");
        let matched = Match::run(&accepted, &wallet, &env, &rendering).expect("match");
        let consent = Consent::of(&matched).expect("consent");
        let views = Views::of(&matched, &env).expect("views");
        let sets = offer(&matched, &consent, env.choice());
        let shown = display(&sets, &views, &statics).expect("display");
        let emission = emit(&shown, &rendering, &env).expect("no fault");
        let refused: Vec<&str> = emission
            .refused()
            .iter()
            .map(|(id, _)| id.as_str())
            .collect();
        assert!(refused.iter().all(|id| *id == "notice") && !refused.is_empty());
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
    let env = env(&["en"], Vec::new()).expect("env");
    let parameters = requests();
    let received = unsigned(&parameters[1]).expect("received");
    let request = request_of(&received).expect("request");
    let credential = held_credential("c");
    let wallet = Wallet::new(vec![credential.credential().expect("credential")]).expect("wallet");
    let accepted = Accepted::new(&request, &registry).expect("accepted");
    let live = App::of(&[CrateSource::openid4vp()]).expect("the live modules' app");
    let live_rendering = live.rendering().expect("the live rendering");
    let matched = Match::run(&accepted, &wallet, &env, &live_rendering).expect("match");
    let views = Views::of(&matched, &env).expect("views");
    let built = registered(&views, &[], env.options());
    let formats = siros_testkit::render::formats().expect("the render halves");
    let own = live_rendering.own().to_vec();
    let emitted = |bytes: &[u8]| -> String {
        let package = match Package::read(bytes, built.root()) {
            Ok(package) => package,
            Err(refused) => return format!("{refused:?}"),
        };
        let rendering = Rendering::new(package, &formats, &own);
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
