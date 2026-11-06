//! A package serializes, reads back and renders the same whatever it holds; an altered byte is
//! refused when its entry is read (a module altered after its digest was taken is refused when it
//! loads); each refusal rule refuses its fixture.

use siros_explain::{Count, Domain, Message, ModuleId, Text, Value, checked};
use siros_i18n::{
    Bidi, BuiltPackage, Compilers, Declaration, FORMAT, Formats, Formatted, LanguagePolicy, Module,
    Package, PackageBuilder, PackageError, RegistrationBuilder, RenderError, Screen,
};

use crate::{BODY, FIXTURE, Host, Inner, PROBE, formats, load, options, source, tag};

/// The main module: the probe's options, for bare counts.
fn main_module(locales: &[&str]) -> Module {
    let sources: Vec<String> = locales
        .iter()
        .map(|locale| format!("@locale {locale}\n---\n[formats.number]\ndigits = 3\n"))
        .collect();
    let sources: Vec<&str> = sources.iter().map(String::as_str).collect();
    Module::load(
        ModuleId::Main,
        &Declaration::new(Vec::<Message>::new()).expect("empty"),
        &sources,
        LanguagePolicy::Any,
        &Compilers::new(&[&PROBE]).expect("compilers"),
    )
    .expect("a main module")
}

/// The fixture module in English and German.
fn fixture() -> Module {
    let german = BODY
        .replace("Hello", "Hallo")
        .replace("} asks", "} fragt")
        .replace("items", "Dinge");
    load(&[&source("en", BODY), &source("de", &german)]).expect("a module")
}

/// A text of every key of the fixture module, and bare values the main module formats.
fn texts() -> Vec<Text> {
    vec![
        Text::of(&Host::Hello),
        Text::of(&Host::Asks {
            name: "Ada".to_owned(),
        }),
        Text::of(&Host::Counted { count: 3 }),
        Text::of(&Host::Nested {
            reason: Inner::Code { code: "x1" },
        }),
        Text::of(&Host::Maybe {
            note: Some("kept".to_owned()),
        }),
        Text::of(&Inner::Code { code: "y2" }),
        Text::Value(Value::Count(Count::of(42))),
    ]
}

/// A package of the modules in `locales`, the keys given of the fixture, and `held` precomputed.
fn build(
    modules: &[&Module],
    locales: &[&str],
    keys: Option<&[&str]>,
    held: &[Text],
    bidi: Bidi,
) -> BuiltPackage {
    let mut builder =
        PackageBuilder::new(locales.iter().map(|t| tag(t)).collect()).expect("a builder");
    for module in modules {
        let keys = keys.filter(|_| module.id() == FIXTURE);
        builder.module(module, keys).expect("a module");
    }
    let formats = formats();
    let mut texts = builder.texts(&formats);
    for text in held {
        texts
            .precompute(text, options(bidi))
            .expect("a precomputed text");
    }
    texts.finish()
}

/// Every text in `language`, through the package's screen of `ids`.
fn render(
    built: &BuiltPackage,
    bytes: &[u8],
    ids: &[ModuleId],
    language: &str,
    texts: &[Text],
    bidi: Bidi,
) -> Result<Vec<Formatted>, RenderError> {
    let formats = formats();
    let package = Package::read(bytes, built.root())?;
    let screen = Screen::new(&package, ids.to_vec())?;
    let located = screen
        .locale(&[tag(language)], &[])
        .map_err(|_| RenderError::Unknown)?;
    let renderer = located.renderer(&formats, options(bidi))?;
    renderer.render(texts)
}

#[test]
fn packages_write_read_back_and_render_the_same() {
    let (main, module) = (main_module(&["en", "de"]), fixture());
    let texts = texts();
    let ids = [ModuleId::Main, FIXTURE];
    let keys = [
        "fixture.host.hello",
        "fixture.host.asks",
        "fixture.host.counted",
        "fixture.host.nested",
        "fixture.host.maybe",
        "fixture.inner.code",
    ];
    let mut compared = 0;
    for bidi in [Bidi::Default, Bidi::None] {
        let precomputed = build(&[&main, &module], &["en", "de"], None, &texts, bidi);
        // Another order of the locales, the modules and the texts gives the same bytes.
        let reversed: Vec<Text> = texts.iter().rev().cloned().collect();
        let again = build(&[&module, &main], &["de", "en"], None, &reversed, bidi);
        assert_eq!(precomputed, again);
        let compiled = build(&[&main, &module], &["en", "de"], Some(&keys), &[], bidi);
        let live = build(&[&main, &module], &["en", "de"], None, &[], bidi);
        // Texts precomputed over keys the package does not hold.
        let restricted = build(
            &[&main, &module],
            &["en", "de"],
            Some(&keys[..1]),
            &texts,
            bidi,
        );
        for built in [&precomputed, &compiled, &live, &restricted] {
            let package = Package::read(built.bytes(), built.root()).expect("a package");
            assert_eq!(&package.rewrite().expect("written again"), built);
        }
        assert_ne!(precomputed.bytes(), live.bytes());
        for language in ["en", "de"] {
            let through = |built: &BuiltPackage| {
                render(built, built.bytes(), &ids, language, &texts, bidi).expect("the texts")
            };
            let held = through(&precomputed);
            assert_eq!(held, through(&compiled));
            assert_eq!(held, through(&live));
            assert_eq!(held, through(&restricted));
            compared += held.len();
        }
    }
    println!("{compared} texts byte-equal through precomputed, compiled and live packages");
}

/// What one read of an altered package gave.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Read {
    Refused(PackageError),
    Equal,
    Altered,
}

#[test]
fn an_altered_byte_is_refused_when_its_entry_is_read() {
    let (main, module) = (main_module(&["en", "de"]), fixture());
    let texts = texts();
    let ids = [ModuleId::Main, FIXTURE];
    let built = build(&[&main, &module], &["en"], None, &texts[..2], Bidi::Default);
    // Every entry read: the held texts under their options, and every message without them.
    let read = |bytes: &[u8]| -> Result<Vec<Vec<Formatted>>, RenderError> {
        [Bidi::Default, Bidi::None]
            .into_iter()
            .map(|bidi| render(&built, bytes, &ids, "en", &texts, bidi))
            .collect()
    };
    let honest = read(built.bytes()).expect("the honest package");
    // The layout: a 58-byte header whose entry count is at byte 42, the nodes, then the entries.
    let count: [u8; 8] = built.bytes()[42..50].try_into().expect("a count");
    let entries = usize::try_from(u64::from_be_bytes(count)).expect("a count");
    let first_entry = 58 + 32 * (2 * entries - 1);
    let mut tally: Vec<(Read, usize)> = Vec::new();
    for at in 0..built.bytes().len() {
        let mut bytes = built.bytes().to_vec();
        bytes[at] ^= 0xff;
        let outcome = match read(&bytes) {
            Ok(texts) if texts == honest => Read::Equal,
            Ok(_) => Read::Altered,
            Err(RenderError::Package(error)) => Read::Refused(error),
            Err(error) => panic!("byte {at}: refused with {error}, no package error"),
        };
        if at >= first_entry {
            assert!(
                matches!(outcome, Read::Refused(PackageError::Integrity { .. })),
                "byte {at} of an entry: {outcome:?}"
            );
        }
        let kind = match &outcome {
            Read::Refused(PackageError::Integrity { .. }) => {
                Read::Refused(PackageError::Integrity { entry: 0 })
            }
            Read::Refused(PackageError::Bounds { .. }) => {
                Read::Refused(PackageError::Bounds { entry: 0 })
            }
            other => other.clone(),
        };
        match tally.iter_mut().find(|(seen, _)| *seen == kind) {
            Some((_, n)) => *n += 1,
            None => tally.push((kind, 1)),
        }
    }
    println!(
        "{} bytes, {entries} entries, entries from byte {first_entry}: {tally:?}",
        built.bytes().len()
    );
    assert!(
        tally
            .iter()
            .all(|(read, _)| matches!(read, Read::Refused(_)))
    );
}

#[test]
fn each_package_rule_refuses_its_fixture() {
    let module = fixture();
    let refused = PackageBuilder::new(vec![tag("en"), tag("de"), tag("en")]).expect_err("twice");
    assert_eq!(refused, PackageError::RepeatedLocale(tag("en")));
    assert_eq!(
        PackageBuilder::new(Vec::new()).expect_err("none"),
        PackageError::NoLocale
    );
    let mut builder = PackageBuilder::new(vec![tag("en")]).expect("a builder");
    let refused = builder
        .module(&module, Some(&["fixture.host.absent"]))
        .expect_err("no such key");
    assert!(matches!(
        &refused,
        PackageError::Key { module, key } if module.id() == FIXTURE && key == "fixture.host.absent"
    ));
    let refused = builder
        .module(&module, Some(&["fixture.host.hello", "fixture.host.hello"]))
        .expect_err("a key twice");
    assert!(matches!(
        &refused,
        PackageError::RepeatedKey { module, key } if module.id() == FIXTURE && key == "fixture.host.hello"
    ));
    builder.module(&module, None).expect("a module");
    assert!(matches!(
        builder.module(&module, None).expect_err("twice"),
        PackageError::RepeatedModule(module) if module.id() == FIXTURE
    ));
    let built = builder.finish();
    let package = Package::read(built.bytes(), built.root()).expect("a package");
    assert!(matches!(
        Screen::new(&package, vec![FIXTURE, FIXTURE]).expect_err("twice"),
        PackageError::RepeatedModule(module) if module.id() == FIXTURE
    ));
    let absent = ModuleId::Crate(checked!(Domain, "absent"));
    assert!(matches!(
        Screen::new(&package, vec![FIXTURE, absent]).expect_err("absent"),
        PackageError::Module(module) if module.id() == absent
    ));
    let mut longer = built.bytes().to_vec();
    longer.push(0);
    let package = Package::read(&longer, built.root()).expect("the header");
    assert_eq!(
        Screen::new(&package, vec![FIXTURE]).expect_err("a byte past the last entry"),
        PackageError::Length
    );
    assert_eq!(
        Formats::new(&[&PROBE, &PROBE]).err(),
        Some(RenderError::Registered("number"))
    );
    let mut other = built.bytes().to_vec();
    other[8..10].copy_from_slice(&(FORMAT + 1).to_be_bytes());
    assert_eq!(
        Package::read(&other, built.root()).expect_err("another version"),
        PackageError::Version
    );
    let mut root = built.root();
    root[0] ^= 1;
    assert_eq!(
        Package::read(built.bytes(), root).expect_err("another root"),
        PackageError::Root
    );
    let mut registering =
        RegistrationBuilder::new(vec![tag("en")], Vec::new(), options(Bidi::None))
            .expect("a registration");
    assert_eq!(
        RegistrationBuilder::new(Vec::new(), vec![tag("en")], options(Bidi::None))
            .expect_err("no priority list"),
        PackageError::NoLocale
    );
    assert!(matches!(
        registering.credential("c", &[FIXTURE]).expect_err("not added"),
        PackageError::Module(module) if module.id() == FIXTURE
    ));
    registering.module(&module, None).expect("a module");
    registering
        .credential("c", &[FIXTURE])
        .expect("a credential");
    assert_eq!(
        registering
            .credential("c", &[FIXTURE])
            .expect_err("a credential twice"),
        PackageError::RepeatedCredential("c".to_owned())
    );
    registering
        .transaction("t", FIXTURE)
        .expect("a transaction type");
    assert_eq!(
        registering
            .transaction("t", FIXTURE)
            .expect_err("a transaction type twice"),
        PackageError::RepeatedTransaction("t".to_owned())
    );
}

/// A registration's package records its lists, its options, its transaction types and each
/// credential's candidate languages: the tags of each list that every module of its card matches
/// by RFC 4647 §3.3.1 basic filtering, in the list's order.
#[test]
fn a_registration_records_its_inputs_and_each_credentials_candidates() {
    let fixture = fixture();
    let main = main_module(&["en-GB", "de"]);
    let priority = vec![tag("en-US"), tag("en"), tag("fr"), tag("de")];
    let fallback = vec![tag("en-GB"), tag("de")];
    let mut builder =
        RegistrationBuilder::new(priority.clone(), fallback.clone(), options(Bidi::Default))
            .expect("a registration");
    builder.module(&fixture, None).expect("a module");
    builder.module(&main, None).expect("a module");
    builder
        .credential("both", &[FIXTURE, ModuleId::Main])
        .expect("a credential");
    builder
        .credential("main", &[ModuleId::Main])
        .expect("a credential");
    builder
        .transaction("t", FIXTURE)
        .expect("a transaction type");
    let built = builder.finish();
    let package = Package::read(built.bytes(), built.root()).expect("a package");
    let registration = package
        .registration()
        .expect("a manifest")
        .expect("a registration");
    assert_eq!(registration.priority(), priority.as_slice());
    assert_eq!(registration.fallback(), fallback.as_slice());
    assert_eq!(registration.options(), options(Bidi::Default));
    assert!(registration.transacts(FIXTURE) && !registration.transacts(ModuleId::Main));
    let both = registration.credential("both").expect("registered");
    assert!(both.draws_from(&[ModuleId::Main, FIXTURE]) && !both.draws_from(&[FIXTURE]));
    assert_eq!(both.candidates().understood(), &[tag("en"), tag("de")]);
    assert_eq!(both.candidates().fallback(), &[tag("de")]);
    let main = registration.credential("main").expect("registered");
    assert_eq!(main.candidates().understood(), &[tag("en"), tag("de")]);
    assert_eq!(main.candidates().fallback(), &[tag("en-GB"), tag("de")]);
    assert!(registration.credential("absent").is_none());
    let live = PackageBuilder::new(vec![tag("en")])
        .expect("a builder")
        .finish();
    let live = Package::read(live.bytes(), live.root()).expect("a package");
    assert_eq!(live.registration(), Ok(None));
}

#[test]
fn a_text_no_package_locale_serves_is_refused() {
    let english = fixture();
    let main = main_module(&["de"]);
    let mut builder = PackageBuilder::new(vec![tag("en")]).expect("a builder");
    builder.module(&english, None).expect("a module");
    builder.module(&main, None).expect("a module");
    let formats = formats();
    let mut texts = builder.texts(&formats);
    let bare = Text::Value(Value::Count(Count::of(1)));
    assert_eq!(
        texts
            .precompute(&bare, options(Bidi::None))
            .expect_err("main serves no package locale"),
        RenderError::Outside {
            module: "main".to_owned()
        }
    );
}
