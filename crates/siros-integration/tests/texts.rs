//! The crate modules: each loads whole in English and in the test app's German.

use siros_explain::Messages;
use siros_i18n::ModuleError;
use siros_openid4vp::ids::LocaleTag;
use siros_testkit::render::{CrateSource, GERMAN_PASO, GERMAN_QES};

fn paso() -> CrateSource {
    CrateSource {
        id: siros_paso::CrateModule::ID,
        messages: siros_paso::CrateModule::messages(),
        english: siros_paso::CrateModule::ENGLISH,
        german: GERMAN_PASO,
    }
}

fn qes() -> CrateSource {
    CrateSource {
        id: siros_qes::CrateModule::ID,
        messages: siros_qes::CrateModule::messages(),
        english: siros_qes::CrateModule::ENGLISH,
        german: GERMAN_QES,
    }
}

/// Catches a crate module that misses a message, or a text its declaration refuses, in either
/// language; the German source short of its first key shows the check is whole.
#[test]
fn each_crate_module_loads_whole_in_english_and_german() {
    for source in [CrateSource::openid4vp(), paso(), qes()] {
        let module = source.load().expect("the module loads");
        let tags: Vec<&str> = module.locales().map(LocaleTag::as_str).collect();
        assert_eq!(tags, ["en", "de"], "{:?}", source.id);
        let lines: Vec<&str> = source.german.lines().collect();
        let at = lines
            .iter()
            .position(|line| line.contains(" = "))
            .expect("a message");
        let key = lines[at].split(" =").next().expect("a key").to_owned();
        let kept: Vec<&str> = [&lines[..at], &lines[at + 1..]].concat();
        let short = CrateSource {
            german: Box::leak(kept.join("\n").into_boxed_str()),
            ..source
        };
        match short.load() {
            Err(ModuleError::Missing {
                key: missing,
                locale,
            }) => {
                assert!(
                    missing.ends_with(&key) && locale == "de",
                    "{missing} in {locale}"
                );
            }
            other => panic!("a German source without {key}: {other:?}"),
        }
    }
}
