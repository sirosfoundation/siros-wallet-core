//! I33: one language per presentation, by RFC 4647 basic filtering over the priority list.

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use siros_explain::{
    DefinedKey, DefinedModule, Domain, Keyed, Message, MessageId, ModuleId, Query, Text, checked,
    names,
};
use siros_i18n::{
    Bidi, Compilers, Declaration, Formats, Language, LanguagePolicy, LocaleTag, Module, NoLanguage,
    Package, Screen,
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
    let modules: Vec<Module> = modules
        .iter()
        .zip(0..)
        .map(|((tags, policy), n)| module(n, tags, *policy))
        .collect();
    let built = package(&modules.iter().collect::<Vec<_>>());
    let package = Package::read(built.bytes(), built.root()).expect("a package");
    let screen = Screen::new(&package, modules.iter().map(Module::id).collect()).expect("a screen");
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

/// The language by the rule's words: the first tag of the list for which every module has an
/// entry equal to it or extending it; each module's entry the equal one, else its first match.
fn oracle(
    modules: &[(Vec<&'static str>, LanguagePolicy)],
    priority: &[&str],
    fallback: &[&str],
) -> Option<(bool, String, Vec<String>)> {
    let extends = |entry: &str, range: &str| {
        entry == range
            || entry
                .strip_prefix(range)
                .is_some_and(|rest| rest.starts_with('-'))
    };
    let serve = |range: &str| -> Option<Vec<String>> {
        modules
            .iter()
            .map(|(tags, _)| {
                let equal = tags.iter().find(|t| **t == range);
                equal
                    .or_else(|| tags.iter().find(|t| extends(t, range)))
                    .map(|t| (*t).to_owned())
            })
            .collect()
    };
    if let Some((range, entries)) = priority.iter().find_map(|r| serve(r).map(|e| (*r, e))) {
        return Some((false, range.to_owned(), entries));
    }
    if modules
        .iter()
        .any(|(_, policy)| *policy == LanguagePolicy::Understood)
    {
        return None;
    }
    fallback
        .iter()
        .find_map(|r| serve(r).map(|e| (true, (*r).to_owned(), e)))
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
        let borrowed: Vec<(&[&str], LanguagePolicy)> = modules
            .iter()
            .map(|(tags, policy)| (tags.as_slice(), *policy))
            .collect();
        let got = locate(&borrowed, &priority, &fallback)
            .ok()
            .map(|(language, entries)| match language {
                Language::Understood(tag) => (false, tag.to_string(), entries),
                Language::Fallback(tag) => (true, tag.to_string(), entries),
            });
        assert_eq!(
            got,
            oracle(&modules, &priority, &fallback),
            "{modules:?} {priority:?} {fallback:?}"
        );
    }
}
