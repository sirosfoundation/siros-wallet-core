//! A package serializes, reads back and renders the same whatever it holds; an altered byte is
//! refused when its entry is read (a module altered after its digest was taken is refused when it
//! loads); each refusal rule refuses its fixture.

use sha2::{Digest, Sha256};
use siros_explain::{
    Count, DefinedKey, DefinedModule, Domain, Entry, Keyed, Message, MessageId, MetadataDigest,
    ModuleId, Text, Value, checked,
};
use siros_i18n::{
    Bidi, BuiltPackage, CURRENCY, Call, Compilers, CredentialName, Declaration, DeclaredId, FORMAT,
    FormatCompiler, FormatId, Formats, Formatted, LanguageFormats, LanguagePolicy, Module, Package,
    PackageBuilder, PackageError, PackageRoot, ParsedFormats, RENDERER, Refusal, RefusedOption,
    RegistrationBuilder, RenderError, Screen, TransactionKind,
};

use crate::{
    BODY, FIXTURE, Host, Inner, PROBE, declaration, formats, load, options, renderer, source, tag,
};

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
    keys: Option<&[DeclaredId]>,
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
    let keys: [DeclaredId; 6] = [
        checked!(MessageId, "fixture.host.hello").into(),
        checked!(MessageId, "fixture.host.asks").into(),
        checked!(MessageId, "fixture.host.counted").into(),
        checked!(MessageId, "fixture.host.nested").into(),
        checked!(MessageId, "fixture.host.maybe").into(),
        checked!(MessageId, "fixture.inner.code").into(),
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
    let absent = DeclaredId::from(checked!(MessageId, "fixture.host.absent"));
    let hello = DeclaredId::from(checked!(MessageId, "fixture.host.hello"));
    let refused = builder
        .module(&module, Some(std::slice::from_ref(&absent)))
        .expect_err("no such key");
    assert!(matches!(
        &refused,
        PackageError::Key { module, key } if module.id() == FIXTURE && *key == absent
    ));
    let refused = builder
        .module(&module, Some(&[hello.clone(), hello.clone()]))
        .expect_err("a key twice");
    assert!(matches!(
        &refused,
        PackageError::RepeatedKey { module, key } if module.id() == FIXTURE && *key == hello
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
    let mut other = built.bytes().to_vec();
    other[8..10].copy_from_slice(&(FORMAT + 1).to_be_bytes());
    assert_eq!(
        Package::read(&other, built.root()).expect_err("another version"),
        PackageError::Version
    );
    let mut root = *built.root().bytes();
    root[0] ^= 1;
    assert_eq!(
        Package::read(built.bytes(), PackageRoot::new(root)).expect_err("another root"),
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
        registering.credential(CredentialName::new("c".to_owned()), &[FIXTURE]).expect_err("not added"),
        PackageError::Module(module) if module.id() == FIXTURE
    ));
    registering.module(&module, None).expect("a module");
    registering
        .credential(CredentialName::new("c".to_owned()), &[FIXTURE])
        .expect("a credential");
    assert_eq!(
        registering
            .credential(CredentialName::new("c".to_owned()), &[FIXTURE])
            .expect_err("a credential twice"),
        PackageError::RepeatedCredential(CredentialName::new("c".to_owned()))
    );
    registering
        .transaction(TransactionKind::new("t".to_owned()), FIXTURE)
        .expect("a transaction type");
    assert_eq!(
        registering
            .transaction(TransactionKind::new("t".to_owned()), FIXTURE)
            .expect_err("a transaction type twice"),
        PackageError::RepeatedTransaction(TransactionKind::new("t".to_owned()))
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
        .credential(
            CredentialName::new("both".to_owned()),
            &[FIXTURE, ModuleId::Main],
        )
        .expect("a credential");
    builder
        .credential(CredentialName::new("main".to_owned()), &[ModuleId::Main])
        .expect("a credential");
    builder
        .transaction(TransactionKind::new("t".to_owned()), FIXTURE)
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
    let both = registration
        .credential(&CredentialName::new("both".to_owned()))
        .expect("registered");
    assert!(both.draws_from(&[ModuleId::Main, FIXTURE]) && !both.draws_from(&[FIXTURE]));
    assert_eq!(both.candidates().understood(), &[tag("en"), tag("de")]);
    assert_eq!(both.candidates().fallback(), &[tag("de")]);
    let main = registration
        .credential(&CredentialName::new("main".to_owned()))
        .expect("registered");
    assert_eq!(main.candidates().understood(), &[tag("en"), tag("de")]);
    assert_eq!(main.candidates().fallback(), &[tag("en-GB"), tag("de")]);
    assert!(
        registration
            .credential(&CredentialName::new("absent".to_owned()))
            .is_none()
    );
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

/// The package of one entry, `manifest`, as the format's layout writes it: under RFC 9162 §2.1.1's
/// hash of one leaf, `SHA-256(0x00 || manifest)`, which is also the tree's one node.
fn one_entry(manifest: &[u8]) -> (Vec<u8>, PackageRoot) {
    let leaf: [u8; 32] = Sha256::new()
        .chain_update([0])
        .chain_update(manifest)
        .finalize()
        .into();
    let mut bytes = b"SIROSPKG".to_vec();
    bytes.extend(FORMAT.to_be_bytes());
    bytes.extend(leaf);
    bytes.extend(1_u64.to_be_bytes());
    bytes.extend((manifest.len() as u64).to_be_bytes());
    bytes.extend(leaf);
    bytes.extend(manifest);
    (bytes, PackageRoot::new(leaf))
}

/// The refusal of a screen over the package of one entry, `manifest`.
fn screen_of(manifest: &[u8]) -> PackageError {
    let (bytes, root) = one_entry(manifest);
    let package = Package::read(&bytes, root).expect("the root's node matches");
    Screen::new(&package, Vec::new()).expect_err("refused")
}

#[test]
fn a_manifest_under_its_root_is_read_before_it_is_trusted() {
    // A count whose continuation bit runs past the entry's end.
    assert_eq!(screen_of(&[0x80]), PackageError::Malformed { entry: 0 });
    // The manifest starts with the renderer's version, as a varint.
    let built = PackageBuilder::new(vec![tag("en")])
        .expect("a builder")
        .finish();
    let manifest_at = built.bytes().len()
        - usize::try_from(u64::from_be_bytes(
            built.bytes()[50..58].try_into().expect("eight bytes"),
        ))
        .expect("a length");
    let mut manifest = built.bytes()[manifest_at..].to_vec();
    manifest[0] ^= 1;
    assert!(matches!(
        screen_of(&manifest),
        PackageError::Renderer { built } if built != RENDERER
    ));
}

/// A module holding a key of one token, which only a converter's declaration gives.
#[test]
fn a_package_selects_a_defined_modules_key() {
    let label = DefinedKey::parse("label".to_owned()).expect("a key");
    let defined = DefinedModule::new(checked!(Domain, "fixture"), MetadataDigest::new([7; 32]));
    let declared =
        Declaration::defined(Keyed::first_of([Entry::new(label.clone(), Keyed::empty())]));
    let module = Module::load(
        ModuleId::Defined(defined),
        &declared,
        &[&source("en", "label = Pay\n")],
        LanguagePolicy::Any,
        &Compilers::new(&[]).expect("compilers"),
    )
    .expect("a module");
    let mut builder = PackageBuilder::new(vec![tag("en")]).expect("a builder");
    builder
        .module(&module, Some(&[label.into()]))
        .expect("the key the module holds");
}

/// A load half that writes nothing for its render half to read.
struct Empty;

/// The load half a build registers beside [`CURRENCY`]'s render half.
static EMPTY: Empty = Empty;

impl FormatCompiler for Empty {
    fn id(&self) -> FormatId {
        checked!(FormatId, "currency")
    }

    fn functions(&self) -> &'static [&'static str] {
        &["currency"]
    }

    fn options(&self) -> &'static [&'static str] {
        &[]
    }

    fn parse(
        &self,
        _language: &LanguageFormats<'_>,
    ) -> Result<Box<dyn ParsedFormats>, RefusedOption> {
        Ok(Box::new(Empty))
    }
}

impl ParsedFormats for Empty {
    fn compile(&self, _call: &Call<'_>) -> Result<Vec<u8>, Refusal> {
        Ok(Vec::new())
    }
}

#[test]
fn a_compiled_placeholder_its_render_half_cannot_read_is_refused() {
    let body = BODY
        .replace(":number", ":currency")
        .replace("[formats.number]\ndigits = 3\n", "");
    let module = Module::load(
        FIXTURE,
        &declaration(),
        &[&source("en", &body)],
        LanguagePolicy::Any,
        &Compilers::new(&[&EMPTY]).expect("compilers"),
    )
    .expect("a module");
    let built = crate::package(&[&module]);
    let formats = Formats::new(&[&CURRENCY]).expect("formats");
    let renderer = renderer(&built, &[&module], &["en"], &formats, Bidi::None);
    assert_eq!(
        renderer
            .plain(&Text::of(&Host::Counted { count: 1 }))
            .expect_err("refused"),
        RenderError::Compiled(checked!(FormatId, "currency"))
    );
}
