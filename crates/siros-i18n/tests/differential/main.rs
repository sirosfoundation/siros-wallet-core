//! The format modules with the CLDR tool's options render as ICU4X 2.4 renders over
//! its compiled data of the same CLDR release, 49.0.0, for the languages the wallet ships, en and
//! de: plural categories and number texts, amounts in every ISO 4217 currency, and- and
//! or-lists, and dates and times at every length. Spanish and Hebrew add the list patterns'
//! special cases.

#[path = "../support/cldr.rs"]
mod cldr;
mod dates;
mod lists;
mod numbers;

use siros_explain::{Explain, Messages, ModuleId, Text};
use siros_i18n::{
    Amounts, Bidi, BuiltPackage, Declaration, Formats, LocaleTag, OnRenderError, Package,
    PackageBuilder, RenderOptions, Renderer, Screen,
};

/// The languages the wallet ships.
pub const SHIPPED: [&str; 2] = ["en", "de"];

/// A package of a main module of `messages` in `language`, its declaration `M`'s, with every
/// format's options.
pub fn module<M: Messages>(language: &str, messages: &str) -> BuiltPackage {
    let declaration = Declaration::new(M::messages()).expect("a declaration");
    let compilers = cldr::compilers(&[]);
    let module = cldr::load(ModuleId::Main, &declaration, language, messages, &compilers)
        .expect("the module loads");
    let tag = LocaleTag::parse(language).expect("a tag");
    let mut builder = PackageBuilder::new(vec![tag]).expect("a builder");
    builder.module(&module, None).expect("the module");
    builder.finish()
}

/// The renderer of a package's main module in its language, without bidi isolation.
pub fn renderer<'m>(built: &'m BuiltPackage, language: &str, formats: &'m Formats) -> Renderer<'m> {
    let package = Package::read(built.bytes(), built.root()).expect("a package");
    let screen = Screen::new(&package, vec![ModuleId::Main]).expect("a screen");
    let tag = LocaleTag::parse(language).expect("a tag");
    let located = screen.locale(&[tag], &[]).expect("the language");
    let options = RenderOptions {
        amounts: Amounts::Formatted,
        bidi: Bidi::None,
        on_error: OnRenderError::NoEntry,
    };
    located.renderer(formats, options).expect("a renderer")
}

/// A message rendered as plain text.
pub fn plain(renderer: &Renderer<'_>, message: &dyn Explain) -> String {
    renderer
        .plain(&Text::of(message))
        .expect("the text renders")
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
