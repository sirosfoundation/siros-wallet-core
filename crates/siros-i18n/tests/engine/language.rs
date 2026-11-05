//! I33: one language per presentation, by RFC 4647 basic filtering over the priority list headed by
//! the locale a profile selected for its own module.

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use siros_explain::{
    DefinedKey, DefinedModule, Domain, Keyed, Message, MessageId, ModuleId, Query, Text, checked,
    names,
};
use siros_i18n::{
    Bidi, Compilers, Declaration, Formats, Language, LanguagePolicy, LocaleTag, Module, NoLanguage,
    Package, PackageError, Screen, Selected,
};

use crate::{options, package, tag};

/// A defined module, the `n`-th, whose one message in each of `tags` is that tag.
fn module(n: u8, tags: &[&str], policy: LanguagePolicy) -> Module {
    let id = checked!(MessageId, "lang.entry");
    let declaration =
        Declaration::new(vec![Message::new(id, None, names!(), [])]).expect("a declaration");
    let sources: Vec<String> = tags
        .iter()
        .map(|tag| format!("@locale {tag}\n---\nlang.entry = {tag}\n"))
        .collect();
    let sources: Vec<&str> = sources.iter().map(String::as_str).collect();
    let id = ModuleId::Defined(DefinedModule::new(checked!(Domain, "lang"), [n; 32]));
    Module::load(
        id,
        &declaration,
        &sources,
        policy,
        &Compilers::new(&[]).expect("compilers"),
    )
    .expect("a module")
}

/// The text of a module's one message.
fn entry(module: &Module) -> Text {
    let ModuleId::Defined(defined) = module.id() else {
        panic!("a defined module")
    };
    let key = DefinedKey::parse("lang.entry".to_owned()).expect("a key");
    Text::Query(Query::defined(defined, key, Keyed::empty()))
}

/// The language of modules of these tags over the lists, and the entry each module's text came
/// from.
fn locate(
    modules: &[(&[&str], LanguagePolicy)],
    priority: &[&str],
    fallback: &[&str],
) -> Result<(Language, Vec<String>), NoLanguage> {
    locate_selected(modules, None, priority, fallback)
}

/// [`locate`] with the first module shown in the locale its profile selected.
fn locate_selected(
    modules: &[(&[&str], LanguagePolicy)],
    selected: Option<&str>,
    priority: &[&str],
    fallback: &[&str],
) -> Result<(Language, Vec<String>), NoLanguage> {
    let modules: Vec<Module> = modules
        .iter()
        .zip(0..)
        .map(|((tags, policy), n)| module(n, tags, *policy))
        .collect();
    let built = package(&modules.iter().collect::<Vec<_>>());
    let package = Package::read(built.bytes(), built.root()).expect("a package");
    let mut screen =
        Screen::new(&package, modules.iter().map(Module::id).collect()).expect("a screen");
    if let (Some(locale), Some(first)) = (selected, modules.first()) {
        screen = screen
            .selecting(Selected::new(first.id(), tag(locale)))
            .expect("a module of the screen");
    }
    let tags = |list: &[&str]| list.iter().map(|t| tag(t)).collect::<Vec<LocaleTag>>();
    let located = screen.locale(&tags(priority), &tags(fallback))?;
    let language = located.language().clone();
    let formats = Formats::new(&[]).expect("formats");
    let renderer = located
        .renderer(&formats, options(Bidi::None))
        .expect("a renderer");
    let texts = modules
        .iter()
        .map(|module| renderer.plain(&entry(module)).expect("a text"))
        .collect();
    Ok((language, texts))
}

#[test]
fn known_answers() {
    let any = LanguagePolicy::Any;
    let understood = |t: &str| Language::Understood(tag(t));
    let one = |tags: &'static [&'static str], range: &str| locate(&[(tags, any)], &[range], &[]);
    assert_eq!(
        one(&["en-GB"], "en").expect("en-GB"),
        (understood("en"), vec!["en-GB".to_owned()])
    );
    assert_eq!(
        one(&["en-US", "en-GB"], "en").expect("en-US"),
        (understood("en"), vec!["en-US".to_owned()])
    );
    assert_eq!(
        one(&["en-GB", "en"], "en").expect("en"),
        (understood("en"), vec!["en".to_owned()])
    );
    for (tags, range) in [
        (&["en"][..], "en-US"),
        (&["en-GB"], "en-US"),
        (&["en"], "en-GB"),
    ] {
        assert_eq!(
            one(tags, range).expect_err("none"),
            NoLanguage::NoFallback,
            "{range} over {tags:?}"
        );
    }
    // WE BUILD's TS12 example: claim labels in en-GB, action labels in en.
    let ts12 = [
        (&["en-GB"][..], LanguagePolicy::Understood),
        (&["en"][..], LanguagePolicy::Understood),
    ];
    let both = vec!["en-GB".to_owned(), "en".to_owned()];
    assert_eq!(
        locate(&ts12, &["en-US", "en"], &[]).expect("en"),
        (understood("en"), both.clone())
    );
    assert_eq!(
        locate(&ts12, &["en-GB", "en"], &[]).expect("en"),
        (understood("en"), both)
    );
    let enforced = locate(&ts12, &["en-US"], &["en"]).expect_err("excluded");
    assert!(
        matches!(enforced, NoLanguage::NotUnderstood(_)),
        "{enforced:?}"
    );
    // No module enforcing: the fallback list, marked.
    let mixed = [(&["de"][..], any), (&["en", "de"][..], any)];
    let fallback = locate(&mixed, &["fr"], &["en", "de"]).expect("de");
    assert_eq!(
        fallback,
        (
            Language::Fallback(tag("de")),
            vec!["de".to_owned(), "de".to_owned()]
        )
    );
    assert_eq!(
        locate(&mixed, &["fr"], &[]).expect_err("none"),
        NoLanguage::NoFallback
    );
}

/// What a screen gives: whether the language fell back, the language, and each module's entry;
/// or why it has none.
type Outcome = Result<(bool, String, Vec<String>), Refused>;

/// Why a screen has no language, its module by its index among the screen's modules.
#[derive(Debug, PartialEq, Eq)]
enum Refused {
    /// The selected module holds no entry of its locale.
    Selected,
    /// No tag of the list serves every other module, and this one, the first enforcing, enforces.
    NotUnderstood(u8),
    /// No tag of the fallback list serves every other module.
    NoFallback,
}

/// The language by the rule's words: the first module, when a locale is selected for it, shows
/// its entry equal to that locale, and is refused without one; every other module takes the
/// first tag of the list headed by the selected locale for which it has an entry equal to the
/// tag or extending it; each module's entry the equal one, else its first match. With none, the
/// first module enforcing understood languages refuses, else the fallback list decides.
fn oracle(
    modules: &[(Vec<&'static str>, LanguagePolicy)],
    selected: Option<&str>,
    priority: &[&str],
    fallback: &[&str],
) -> Outcome {
    let extends = |entry: &str, range: &str| {
        entry == range
            || entry
                .strip_prefix(range)
                .is_some_and(|rest| rest.starts_with('-'))
    };
    let pinned = match selected {
        None => None,
        Some(locale) => Some(
            modules
                .first()
                .and_then(|first| first.0.iter().find(|t| **t == locale))
                .map(|t| (*t).to_owned())
                .ok_or(Refused::Selected)?,
        ),
    };
    let skipped = usize::from(selected.is_some());
    let others = &modules[skipped..];
    let serve = |range: &str| -> Option<Vec<String>> {
        let rest: Option<Vec<String>> = others
            .iter()
            .map(|(tags, _)| {
                let equal = tags.iter().find(|t| **t == range);
                equal
                    .or_else(|| tags.iter().find(|t| extends(t, range)))
                    .map(|t| (*t).to_owned())
            })
            .collect();
        rest.map(|rest| pinned.iter().cloned().chain(rest).collect())
    };
    let headed: Vec<&str> = selected
        .into_iter()
        .chain(priority.iter().copied())
        .collect();
    if let Some((range, entries)) = headed.iter().find_map(|r| serve(r).map(|e| (*r, e))) {
        return Ok((false, range.to_owned(), entries));
    }
    if let Some(enforcing) = others
        .iter()
        .position(|(_, policy)| *policy == LanguagePolicy::Understood)
    {
        let index = u8::try_from(enforcing + skipped).expect("three modules at most");
        return Err(Refused::NotUnderstood(index));
    }
    fallback
        .iter()
        .find_map(|r| serve(r).map(|e| (true, (*r).to_owned(), e)))
        .ok_or(Refused::NoFallback)
}

#[test]
fn the_language_is_the_first_tag_every_module_serves() {
    const POOL: [&str; 8] = [
        "en",
        "en-US",
        "en-GB",
        "de",
        "de-CH",
        "fr",
        "zh-Hant",
        "zh-Hant-TW",
    ];
    let mut rng = ChaCha8Rng::seed_from_u64(33);
    let pick = |rng: &mut ChaCha8Rng, most: usize, least: usize| -> Vec<&'static str> {
        let mut tags: Vec<&'static str> = Vec::new();
        for _ in 0..rng.random_range(least..=most) {
            let tag = POOL[rng.random_range(0..POOL.len())];
            if !tags.contains(&tag) {
                tags.push(tag);
            }
        }
        tags
    };
    for _ in 0..200 {
        let count = rng.random_range(1..=3);
        let modules: Vec<(Vec<&str>, LanguagePolicy)> = (0..count)
            .map(|_| {
                let policy = if rng.random_bool(0.3) {
                    LanguagePolicy::Understood
                } else {
                    LanguagePolicy::Any
                };
                (pick(&mut rng, 3, 1), policy)
            })
            .collect();
        let (priority, fallback) = (pick(&mut rng, 3, 0), pick(&mut rng, 2, 0));
        let selected = rng
            .random_bool(0.4)
            .then(|| POOL[rng.random_range(0..POOL.len())]);
        let borrowed: Vec<(&[&str], LanguagePolicy)> = modules
            .iter()
            .map(|(tags, policy)| (tags.as_slice(), *policy))
            .collect();
        let got = locate_selected(&borrowed, selected, &priority, &fallback)
            .map(|(language, entries)| match language {
                Language::Understood(tag) => (false, tag.to_string(), entries),
                Language::Fallback(tag) => (true, tag.to_string(), entries),
            })
            .map_err(|refused| match refused {
                NoLanguage::Selected { .. } => Refused::Selected,
                NoLanguage::NotUnderstood(module) => match module.id() {
                    ModuleId::Defined(defined) => Refused::NotUnderstood(defined.digest()[0]),
                    other => panic!("a test module: {other:?}"),
                },
                NoLanguage::NoFallback => Refused::NoFallback,
            });
        assert_eq!(
            got,
            oracle(&modules, selected, &priority, &fallback),
            "{modules:?} {selected:?} {priority:?} {fallback:?}"
        );
    }
}

#[test]
fn a_selection_the_screen_cannot_show_is_refused() {
    let any = LanguagePolicy::Any;
    let modules = [
        (&["de-CH"][..], LanguagePolicy::Understood),
        (&["en", "de"][..], any),
    ];
    let missing = locate_selected(&modules, Some("fr"), &["fr", "en"], &[]).expect_err("no fr");
    assert!(
        matches!(&missing, NoLanguage::Selected { locale, .. } if *locale == tag("fr")),
        "{missing:?}"
    );
    let one = module(0, &["en"], any);
    let built = package(&[&one]);
    let package = Package::read(built.bytes(), built.root()).expect("a package");
    let absent = ModuleId::Defined(DefinedModule::new(checked!(Domain, "lang"), [9; 32]));
    let refused = Screen::new(&package, vec![one.id()])
        .expect("a screen")
        .selecting(Selected::new(absent, tag("en")))
        .expect_err("a module outside the screen");
    assert!(
        matches!(&refused, PackageError::Module(module) if module.id() == absent),
        "{refused:?}"
    );
}
