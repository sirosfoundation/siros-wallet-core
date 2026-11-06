//! I30: each crate module's declaration loads whole with the test app's English and German sources.

use siros_i18n::ModuleError;
use siros_openid4vp::ids::LocaleTag;
use siros_testkit::render::{CrateSource, ENGLISH_PASO, ENGLISH_QES, GERMAN_PASO, GERMAN_QES};

fn paso() -> CrateSource {
    CrateSource::of::<siros_paso::CrateModule>(ENGLISH_PASO, GERMAN_PASO)
}

fn qes() -> CrateSource {
    CrateSource::of::<siros_qes::CrateModule>(ENGLISH_QES, GERMAN_QES)
}

/// Catches a crate module that misses a message, or a text its declaration refuses, in either
/// language.
#[test]
fn each_crate_module_loads_whole_in_english_and_german() {
    for source in [CrateSource::openid4vp(), paso(), qes()] {
        let module = source.load().expect("the module loads");
        let tags: Vec<&str> = module.locales().map(LocaleTag::as_str).collect();
        assert_eq!(tags, ["en", "de"], "{:?}", source.id());
        let lines: Vec<&str> = source.german().lines().collect();
        let at = lines
            .iter()
            .position(|line| line.contains(" = "))
            .expect("a message");
        let key = lines[at].split(" =").next().expect("a key").to_owned();
        let kept: Vec<&str> = [&lines[..at], &lines[at + 1..]].concat();
        let short = source.with_german(Box::leak(kept.join("\n").into_boxed_str()));
        match short.load() {
            Err(ModuleError::Missing {
                key: missing,
                locale,
            }) => {
                assert!(
                    missing.as_str().ends_with(&key) && locale.as_str() == "de",
                    "{missing} in {locale}"
                );
            }
            other => panic!("a German source without {key}: {other:?}"),
        }
    }
}
