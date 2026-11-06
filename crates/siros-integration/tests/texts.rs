//! I30: each crate module's declaration loads whole with the test app's English and German sources.

use siros_explain::Messages;
use siros_openid4vp::ids::LocaleTag;
use siros_testkit::render::{CrateSource, ENGLISH_PASO, ENGLISH_QES, GERMAN_PASO, GERMAN_QES};

fn paso() -> CrateSource {
    CrateSource {
        id: siros_paso::CrateModule::ID,
        messages: siros_paso::CrateModule::messages(),
        english: ENGLISH_PASO,
        german: GERMAN_PASO,
    }
}

fn qes() -> CrateSource {
    CrateSource {
        id: siros_qes::CrateModule::ID,
        messages: siros_qes::CrateModule::messages(),
        english: ENGLISH_QES,
        german: GERMAN_QES,
    }
}

/// Catches a crate module that misses a message, or a text its declaration refuses, in either
/// language.
#[test]
fn each_crate_module_loads_whole_in_english_and_german() {
    for source in [CrateSource::openid4vp(), paso(), qes()] {
        let module = source.load().expect("the module loads");
        let tags: Vec<&str> = module.locales().map(LocaleTag::as_str).collect();
        assert_eq!(tags, ["en", "de"], "{:?}", source.id);
    }
}
