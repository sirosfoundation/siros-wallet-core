//! The wallet core's i18n engine. Its definitions are modules: a module has an identity, the
//! locales it supports, and a declaration, siros-explain's [`Messages`](siros_explain::Messages)
//! of its keys and each argument's kind. Each locale's source is a `.mf2` resource whose entries
//! are Unicode MessageFormat 2 messages, and whose `[formats.<format>]` sections define the
//! options of the formats its messages use.
//!
//! Feature `load`, the wallet's, parses a module whole and checks it against its declaration and
//! its format options: [`Module::load`] refuses it with the [`ModuleError`] of the first rule it
//! breaks, in the order its documentation lists the rules, and compiles every message into its
//! render form. A [`PackageBuilder`] writes the compiled modules in a set of locales, and texts
//! rendered now over all of them ([`PackageTexts`]), into a package whose identity is the RFC
//! 9162 Merkle tree root of its entries.
//!
//! Feature `render`, the matcher's, reads a [`Package`] under its root, checking each entry
//! when it reads it: a [`Screen`] of the package's modules takes one [`Language`] for every text
//! ([`Screen::locale`]), and its [`Renderer`] writes a [`Text`](siros_explain::Text) into a sink,
//! as [`Formatted`] spans or as plain text, returning a text the package holds rendered as held.
//!
//! Each MF2 function family is a format module, with a load half ([`FormatCompiler`]) and a
//! render half ([`FormatRenderer`]); `:string` is built in, and a build registers the others in
//! [`Compilers`] and [`Formats`]. The crate's format modules are each a feature: `number`
//! ([`NUMBER`]: `:number`, `:integer`), `currency` ([`CURRENCY`]: `:currency`, `:percent`),
//! `offset` ([`OFFSET`]: `:offset`), `date` ([`DATE`]: `:siros:date`, `:siros:time`,
//! `:siros:datetime`, with `length` `short`, `medium`, `long` or `full`) and `list` ([`LIST`]:
//! `:siros:list`). A placeholder without a function calls the one its argument's kind implies:
//! counts and decimals `:number`, amounts and currencies `:currency`, dates, times and lists the
//! `siros` functions, texts `:string`.
//!
//! A module defines each used format's options in each of its languages. `siros-cldr` writes
//! them from CLDR 49.0.0 for a language: a resource head with `@locale` and `@dir`, the
//! language's text direction, and one `[formats.<format>]` section per format module.
//!
//! ```
//! use siros_explain::{Domain, Explain, Messages, ModuleId, Text, checked};
//! use siros_i18n::{
//!     Amounts, Bidi, Compilers, Declaration, Formats, LanguagePolicy, LocaleTag, Module,
//!     OnRenderError, Package, PackageBuilder, RenderOptions, Screen,
//! };
//!
//! #[derive(Debug, thiserror::Error, Explain)]
//! #[explain(domain = "example.host")]
//! enum Host {
//!     #[error("the Verifier {name} asks for your **age**")]
//!     Asks { name: String },
//! }
//!
//! let source = "@locale en\n---\n[host]\nasks = {$name} asks for your {#strong}age{/strong}\n";
//! let id = ModuleId::Crate(checked!(Domain, "example"));
//! let module = Module::load(
//!     id,
//!     &Declaration::new(Host::messages())?,
//!     &[source],
//!     LanguagePolicy::Any,
//!     &Compilers::new(&[])?,
//! )?;
//! let formats = Formats::new(&[])?;
//! let options = RenderOptions {
//!     amounts: Amounts::Formatted,
//!     bidi: Bidi::None,
//!     on_error: OnRenderError::NoEntry,
//! };
//! let text = Text::of(&Host::Asks { name: "Example Bank".to_owned() });
//! let mut builder = PackageBuilder::new(vec![LocaleTag::parse("en")?])?;
//! builder.module(&module, None)?;
//! let mut texts = builder.texts(&formats);
//! texts.precompute(&text, options)?;
//! let built = texts.finish();
//!
//! let package = Package::read(built.bytes(), built.root())?;
//! let screen = Screen::new(&package, vec![id])?;
//! let located = screen.locale(&[LocaleTag::parse("en-GB")?, LocaleTag::parse("en")?], &[])?;
//! let renderer = located.renderer(&formats, options)?;
//! assert_eq!(renderer.plain(&text)?, "Example Bank asks for your age");
//! assert_eq!(renderer.formatted(&text)?.spans().len(), 2);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs, unused_must_use, unused_results)]
#![deny(
    clippy::let_underscore_must_use,
    clippy::let_underscore_untyped,
    clippy::disallowed_types
)]
#![cfg_attr(
    not(test),
    deny(
        clippy::panic,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::indexing_slicing,
        clippy::disallowed_methods
    )
)]

#[cfg(feature = "render")]
mod bytes;
#[cfg(feature = "load")]
mod compile;
#[cfg(feature = "currency")]
mod currency;
#[cfg(feature = "date")]
mod date;
#[cfg(feature = "render")]
mod defined;
mod error;
#[cfg(feature = "render")]
mod eval;
#[cfg(feature = "render")]
mod form;
mod format;
#[cfg(feature = "list")]
mod list;
mod locale;
#[cfg(feature = "load")]
mod mf2;
#[cfg(feature = "load")]
mod module;
#[cfg(feature = "number")]
mod number;
#[cfg(any(feature = "number", feature = "currency", feature = "offset"))]
mod numeric;
#[cfg(feature = "offset")]
mod offset;
#[cfg(feature = "render")]
mod package;
#[cfg(feature = "render")]
mod render;
#[cfg(feature = "load")]
mod resource;
#[cfg(feature = "render")]
mod screen;
mod sink;
#[cfg(feature = "render")]
mod string;

#[cfg(feature = "currency")]
pub use currency::{CURRENCY, CurrencyFormat};
#[cfg(feature = "date")]
pub use date::{DATE, DateFormat};
#[cfg(feature = "render")]
pub use defined::{Body, DefinedBuilder, DefinedError, DefinedForm, MainLocale, Part, Variant};
#[cfg(feature = "load")]
pub use error::{ModuleError, OptionRefusal, Refusal, RefusedOption, ResourceRule, Validity};
#[cfg(feature = "render")]
pub use error::{ModuleName, NoLanguage, PackageError, RenderError};
#[cfg(feature = "render")]
pub use form::{BareKind, LanguagePolicy};
#[cfg(feature = "load")]
pub use format::{
    Call, Compilers, FormatCompiler, FormatOption, LanguageFormats, Operand, ParsedFormats, Uses,
};
pub use format::{Direction, FormatId};
#[cfg(feature = "render")]
pub use format::{FormatRenderer, Formats, Input, VariantKey, VariantKeys};
#[cfg(feature = "list")]
pub use list::{LIST, ListFormat};
pub use locale::{InvalidTag, LocaleTag};
#[cfg(feature = "load")]
pub use module::{Declaration, Module};
#[cfg(feature = "number")]
pub use number::{NUMBER, NumberFormat};
#[cfg(feature = "offset")]
pub use offset::{OFFSET, OffsetFormat};
#[cfg(feature = "load")]
pub use package::{BuiltPackage, PackageBuilder, PackageTexts, RegistrationBuilder};
#[cfg(feature = "render")]
pub use package::{Candidates, CredentialRecord, FORMAT, Package, Registration};
#[cfg(feature = "render")]
pub use render::{
    Amounts, Bidi, OnRenderError, RENDERER, RenderOptions, Renderer, RenderingInputs,
};
#[cfg(feature = "render")]
pub use screen::{Language, Located, Screen, Selected};
pub use sink::Style;
#[cfg(feature = "render")]
pub use sink::{Formatted, Sink, Span};

/// The messages the crate's error types declare in this build.
pub struct CrateMessages;

impl siros_explain::Messages for CrateMessages {
    fn messages() -> Vec<siros_explain::Message> {
        let declared: &[fn() -> Vec<siros_explain::Message>] = &[
            InvalidTag::messages,
            #[cfg(feature = "load")]
            ModuleError::messages,
            #[cfg(feature = "load")]
            ResourceRule::messages,
            #[cfg(feature = "load")]
            Validity::messages,
            #[cfg(feature = "load")]
            Refusal::messages,
            #[cfg(feature = "load")]
            RefusedOption::messages,
            #[cfg(feature = "render")]
            RenderError::messages,
            #[cfg(feature = "render")]
            DefinedError::messages,
            #[cfg(feature = "render")]
            NoLanguage::messages,
            #[cfg(feature = "render")]
            PackageError::messages,
        ];
        declared.iter().flat_map(|messages| messages()).collect()
    }
}
