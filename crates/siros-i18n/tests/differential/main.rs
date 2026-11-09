//! The functions with the CLDR tool's options format as ICU4X 2.4 formats over its compiled data
//! of the same CLDR release, 49.0.0, for the test app's languages, en and de: plural categories
//! and number texts, amounts in every ISO 4217 currency, and dates and times at every length.

#[path = "../support/cldr.rs"]
mod cldr;
mod dates;
mod numbers;

use siros_i18n::{Bidi, Context, Message};

siros_i18n::scope!("probe");

/// The test app's languages.
pub const LANGUAGES: [&str; 2] = ["en", "de"];

/// A context of `language` with the tool's formats and a module of `messages`, without bidi
/// isolation.
pub fn context(language: &str, messages: &str) -> Context {
    cldr::context(language, Bidi::None, messages).expect("the modules load")
}

/// A message resolved as plain text.
pub fn plain(context: &Context, message: &dyn Message) -> String {
    context
        .resolve(message)
        .expect("the message resolves")
        .to_string()
}

/// Counts differences, printing the first few of each check.
#[derive(Default)]
pub struct Differences {
    count: usize,
    compared: usize,
}

impl Differences {
    /// Compares one text with ICU4X's.
    pub fn check(&mut self, what: &str, ours: &str, theirs: &str) {
        self.compared += 1;
        if ours != theirs {
            self.count += 1;
            if self.count <= 20 {
                println!("{what}: ours {ours:?}, ICU4X {theirs:?}");
            }
        }
    }

    /// Reports the counts and fails on a difference.
    pub fn assert_none(&self, check: &str) {
        println!(
            "{check}: {} compared, {} differences",
            self.compared, self.count
        );
        assert_eq!(self.count, 0, "{check}: differences from ICU4X");
        assert!(self.compared > 0, "{check}: nothing compared");
    }
}
