//! The test app's texts, as a wallet app loads and renders them: its main module of siros-cldr's
//! en and de format options, each crate module in the crate's English and the test app's German,
//! and a renderer over a package of the modules for a screen and an [`Env`].

use siros_explain::{Message, Messages, ModuleId};
use siros_i18n::{
    BuiltPackage, CURRENCY, Compilers, DATE, Declaration, FormatCompiler, FormatRenderer, Formats,
    LIST, LanguagePolicy, LocaleTag, Module, ModuleError, NUMBER, NoLanguage, Package,
    PackageBuilder, PackageError, RenderError, Renderer, Screen,
};
use siros_openid4vp::rows::Env;

/// The test app's German source of the `openid4vp` module.
pub const GERMAN_OPENID4VP: &str = include_str!("../locales/de/openid4vp.mf2");
/// The test app's German source of the `paso` module.
pub const GERMAN_PASO: &str = include_str!("../locales/de/paso.mf2");
/// The test app's German source of the `qes` module.
pub const GERMAN_QES: &str = include_str!("../locales/de/qes.mf2");

/// siros-cldr's en options, which siros-i18n ships.
const CLDR_EN: &str = include_str!("../../siros-i18n/cldr/en.mf2");
/// siros-cldr's de options, which siros-i18n ships.
const CLDR_DE: &str = include_str!("../../siros-i18n/cldr/de.mf2");

/// The format modules the test app registers: the main module's and the crate modules'.
const COMPILERS: [&dyn FormatCompiler; 4] = [&NUMBER, &CURRENCY, &DATE, &LIST];
/// Their render halves.
const RENDERERS: [&dyn FormatRenderer; 4] = [&NUMBER, &CURRENCY, &DATE, &LIST];

/// A text the test app cannot load or render.
#[derive(Debug, thiserror::Error, siros_explain::Explain)]
#[explain(domain = "testkit.render")]
pub enum AppError {
    /// A module does not load.
    #[error(transparent)]
    Module(#[from] ModuleError),
    /// The package refuses a module or a screen.
    #[error(transparent)]
    Package(#[from] PackageError),
    /// No language serves the screen.
    #[error(transparent)]
    Language(#[from] NoLanguage),
    /// A text does not render.
    #[error(transparent)]
    Render(#[from] RenderError),
}

/// A crate's module as the test app loads it: its identity, its declaration, the crate's English
/// source and the test app's German.
pub struct CrateSource {
    /// The module's identity.
    pub id: ModuleId,
    /// Its declaration.
    pub messages: Vec<Message>,
    /// The crate's English source.
    pub english: &'static str,
    /// The test app's German source.
    pub german: &'static str,
}

impl CrateSource {
    /// The `openid4vp` module.
    #[must_use]
    pub fn openid4vp() -> Self {
        Self {
            id: siros_openid4vp::CrateModule::ID,
            messages: siros_openid4vp::CrateModule::messages(),
            english: siros_openid4vp::CrateModule::ENGLISH,
            german: GERMAN_OPENID4VP,
        }
    }

    /// The module, loaded whole in English and German.
    ///
    /// # Errors
    ///
    /// The [`ModuleError`] of the first rule the module breaks.
    pub fn load(&self) -> Result<Module, ModuleError> {
        Module::load(
            self.id,
            &Declaration::new(self.messages.clone())?,
            &[self.english, self.german],
            LanguagePolicy::Any,
            &compilers()?,
        )
    }
}

/// The test app's load halves.
///
/// # Errors
///
/// [`ModuleError::Compiler`] when two share a function.
pub fn compilers() -> Result<Compilers, ModuleError> {
    Compilers::new(&COMPILERS)
}

/// A resource of siros-cldr's options without the offset format, which no build calls.
fn without_offset(cldr: &str) -> String {
    let mut out = String::with_capacity(cldr.len());
    let mut skipping = false;
    for line in cldr.split_inclusive('\n') {
        if line.starts_with('[') {
            skipping = line.trim_end() == "[formats.offset]";
        }
        if !skipping {
            out.push_str(line);
        }
    }
    out
}

/// The test app's main module: no message of its own, the format options of its bare values in
/// en and de.
///
/// # Errors
///
/// The [`ModuleError`] of the first rule the module breaks.
pub fn main_module() -> Result<Module, ModuleError> {
    let (en, de) = (without_offset(CLDR_EN), without_offset(CLDR_DE));
    Module::load(
        ModuleId::Main,
        &Declaration::new(Vec::new())?,
        &[&en, &de],
        LanguagePolicy::Any,
        &compilers()?,
    )
}

/// The test app's package of its modules, in every locale one of them supports, and its render
/// halves.
pub struct App {
    built: BuiltPackage,
    formats: Formats,
}

impl App {
    /// The package of `modules`, every key of each.
    ///
    /// # Errors
    ///
    /// The [`PackageError`] of a module the builder refuses; [`RenderError::Registered`] for two
    /// render halves of one format.
    pub fn new(modules: &[&Module]) -> Result<Self, AppError> {
        let mut locales: Vec<LocaleTag> = modules
            .iter()
            .flat_map(|module| module.locales().cloned())
            .collect();
        locales.sort();
        locales.dedup();
        let mut builder = PackageBuilder::new(locales)?;
        for module in modules {
            builder.module(module, None)?;
        }
        Ok(Self {
            built: builder.finish(),
            formats: Formats::new(&RENDERERS)?,
        })
    }

    /// The renderer of a screen of the package's modules, in the language `env`'s lists choose,
    /// with `env`'s rendering options.
    ///
    /// # Errors
    ///
    /// [`AppError`]: the package refuses the screen, no language serves it, or a module calls a
    /// format the app does not register.
    pub fn renderer(&self, screen: Vec<ModuleId>, env: &Env) -> Result<Renderer<'_>, AppError> {
        let package = Package::read(self.built.bytes(), self.built.root())?;
        let located = Screen::new(&package, screen)?.locale(env.priority(), env.fallback())?;
        Ok(located.renderer(&self.formats, env.options())?)
    }
}
