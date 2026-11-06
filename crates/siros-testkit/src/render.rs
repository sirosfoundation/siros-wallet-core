//! The test app's texts, as a wallet app loads and renders them: its main module of siros-cldr's
//! en and de format options, each crate module in the test app's English and German, and a
//! renderer over a package of the modules for a screen and an [`Env`].

use siros_explain::{DeclaredModule, Message, Messages, ModuleId, Text};
use siros_i18n::{
    BuiltPackage, CURRENCY, Compilers, DATE, Declaration, DefinedForm, FormatCompiler,
    FormatRenderer, Formats, Formatted, LIST, LanguagePolicy, LocaleTag, MainLocale, Module,
    ModuleError, ModuleName, NUMBER, NoLanguage, Package, PackageBuilder, PackageError,
    RenderError, Renderer, Selected,
};
use siros_openid4vp::plugins::Fault;
use siros_openid4vp::rendering::{Rendering, Unrendered};
use siros_openid4vp::rows::Env;

/// The test app's English source of the `openid4vp` module.
const ENGLISH_OPENID4VP: &str = include_str!("../locales/en/openid4vp.mf2");
/// The test app's German source of the `openid4vp` module.
const GERMAN_OPENID4VP: &str = include_str!("../locales/de/openid4vp.mf2");
/// The test app's English source of the `paso` module.
pub const ENGLISH_PASO: &str = include_str!("../locales/en/paso.mf2");
/// The test app's German source of the `paso` module.
pub const GERMAN_PASO: &str = include_str!("../locales/de/paso.mf2");
/// The test app's English source of the `qes` module.
pub const ENGLISH_QES: &str = include_str!("../locales/en/qes.mf2");
/// The test app's German source of the `qes` module.
pub const GERMAN_QES: &str = include_str!("../locales/de/qes.mf2");
/// The test app's own module's English source.
const ENGLISH_TESTKIT: &str = include_str!("../locales/en/testkit.mf2");
/// The test app's own module's German source.
const GERMAN_TESTKIT: &str = include_str!("../locales/de/testkit.mf2");

/// siros-cldr's en options.
const CLDR_EN: &str = include_str!("../locales/cldr/en.mf2");
/// siros-cldr's de options.
const CLDR_DE: &str = include_str!("../locales/cldr/de.mf2");

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
    /// The entry's texts cannot render: the core excludes it.
    #[error(transparent)]
    Unrendered(#[from] Unrendered),
    /// The core's screen faults.
    #[error(transparent)]
    Fault(#[from] Fault),
}

/// The test app's main module: the format options of its bare values, no message of its own.
pub struct MainModule;

impl DeclaredModule for MainModule {
    const ID: ModuleId = ModuleId::Main;
    type Requested = ();
}

/// The test app's own module, `testkit`: the test doubles' texts, which no overlay shows.
pub struct TestkitModule;

impl DeclaredModule for TestkitModule {
    const ID: ModuleId = ModuleId::Crate(siros_explain::checked!(siros_explain::Domain, "testkit"));
    type Requested = ();
}

impl Messages for TestkitModule {
    fn messages() -> Vec<Message> {
        crate::DoubleText::messages()
    }
}

/// A crate's module as the test app loads it: its identity, its declaration, and the test app's
/// English and German sources.
pub struct CrateSource {
    id: ModuleId,
    messages: Vec<Message>,
    english: &'static str,
    german: &'static str,
}

impl CrateSource {
    /// The module `M` declares, in the test app's English and German sources.
    #[must_use]
    pub fn of<M: DeclaredModule + Messages>(english: &'static str, german: &'static str) -> Self {
        Self {
            id: M::ID,
            messages: M::messages(),
            english,
            german,
        }
    }

    /// The `openid4vp` module.
    #[must_use]
    pub fn openid4vp() -> Self {
        Self::of::<siros_openid4vp::CrateModule>(ENGLISH_OPENID4VP, GERMAN_OPENID4VP)
    }

    /// The test app's own module, `testkit`: the test doubles' texts.
    #[must_use]
    pub fn testkit() -> Self {
        Self::of::<TestkitModule>(ENGLISH_TESTKIT, GERMAN_TESTKIT)
    }

    /// The module with another German source.
    #[must_use]
    pub fn with_german(self, german: &'static str) -> Self {
        Self { german, ..self }
    }

    /// The module's identity.
    #[must_use]
    pub const fn id(&self) -> ModuleId {
        self.id
    }

    /// Its declaration.
    #[must_use]
    pub fn messages(&self) -> &[Message] {
        &self.messages
    }

    /// The test app's English source.
    #[must_use]
    pub const fn english(&self) -> &'static str {
        self.english
    }

    /// The test app's German source.
    #[must_use]
    pub const fn german(&self) -> &'static str {
        self.german
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

/// A text an issuer, a Verifier or a credential wrote, as written; `None` for a text of a module
/// or a typed value.
#[must_use]
pub fn written(text: &Text) -> Option<&str> {
    match text {
        Text::Raw(written) => Some(written),
        _ => None,
    }
}

/// The test app's render halves.
///
/// # Errors
///
/// [`RenderError::Registered`] when two share a format.
pub fn formats() -> Result<Formats, RenderError> {
    Formats::new(&RENDERERS)
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

/// The test app's main module's sources, en then de: siros-cldr's options of the formats the
/// app registers.
#[must_use]
pub fn main_sources() -> [String; 2] {
    [without_offset(CLDR_EN), without_offset(CLDR_DE)]
}

/// The test app's languages, its main module's: en and de.
#[must_use]
pub fn languages() -> Vec<LocaleTag> {
    ["en", "de"]
        .into_iter()
        .filter_map(|tag| LocaleTag::parse(tag).ok())
        .collect()
}

/// The test app's main module: no message of its own, the format options of its bare values in
/// en and de.
///
/// # Errors
///
/// The [`ModuleError`] of the first rule the module breaks.
pub fn main_module() -> Result<Module, ModuleError> {
    let [en, de] = main_sources();
    Module::load(
        ModuleId::Main,
        &Declaration::new(Vec::new())?,
        &[&en, &de],
        LanguagePolicy::Any,
        &compilers()?,
    )
}

/// The test app's main module's locale entries, which the defined modules it converts format
/// their typed arguments with.
///
/// # Errors
///
/// [`AppError::Module`]: the main module does not load.
pub fn main_locales() -> Result<Vec<MainLocale>, AppError> {
    main_module()?
        .main_locales()
        .ok_or_else(|| PackageError::Module(ModuleName::of(ModuleId::Main)).into())
}

/// The test app's package of its modules, in every locale one of them supports, its render
/// halves, and the module a profile selected a locale for.
pub struct App {
    built: BuiltPackage,
    formats: Formats,
    own: Vec<ModuleId>,
    selected: Option<Selected>,
}

impl App {
    /// The package of `modules` and the converted `defined` modules, every key of each.
    ///
    /// # Errors
    ///
    /// The [`PackageError`] of a module the builder refuses; [`RenderError::Registered`] for two
    /// render halves of one format.
    pub fn new(modules: &[&Module], defined: &[&DefinedForm]) -> Result<Self, AppError> {
        let mut locales: Vec<LocaleTag> = modules
            .iter()
            .flat_map(|module| module.locales().cloned())
            .chain(defined.iter().flat_map(|form| form.locales().cloned()))
            .collect();
        locales.sort();
        locales.dedup();
        let mut builder = PackageBuilder::new(locales)?;
        for module in modules {
            builder.module(module, None)?;
        }
        for form in defined {
            builder.defined(form)?;
        }
        Ok(Self {
            built: builder.finish(),
            formats: formats()?,
            own: modules
                .iter()
                .map(|module| module.id())
                .filter(|id| !matches!(id, ModuleId::Defined(_)))
                .collect(),
            selected: None,
        })
    }

    /// What the core renders with: the package, the render halves, and the app's modules beside
    /// the defined ones.
    ///
    /// # Errors
    ///
    /// [`AppError::Package`]: the package's header or manifest does not read.
    pub fn rendering(&self) -> Result<Rendering<'_>, AppError> {
        let package = Package::read(self.built.bytes(), self.built.root())?;
        Ok(Rendering::new(package, &self.formats, &self.own)?)
    }

    /// The modules every entry draws from: the app's main module and its crate modules.
    #[must_use]
    pub fn own(&self) -> &[ModuleId] {
        &self.own
    }

    /// The app showing a module in the locale its profile selected.
    #[must_use]
    pub fn selecting(mut self, selected: Selected) -> Self {
        self.selected = Some(selected);
        self
    }

    /// The package of the main module, the test app's own module and the crates' modules, each
    /// loaded whole.
    ///
    /// # Errors
    ///
    /// [`AppError`]: a module does not load, or the package refuses one.
    pub fn of(crates: &[CrateSource]) -> Result<Self, AppError> {
        let mut modules = vec![main_module()?, CrateSource::testkit().load()?];
        for source in crates {
            modules.push(source.load()?);
        }
        Self::new(&modules.iter().collect::<Vec<_>>(), &[])
    }

    /// The language of an entry's texts, as the core's renderer of the entry chooses it.
    ///
    /// # Errors
    ///
    /// [`AppError`]: no language serves the entry's modules.
    pub fn language(&self, env: &Env) -> Result<LocaleTag, AppError> {
        self.language_at(self.selected.as_ref(), env)
    }

    /// A text as plain text, as the core's renderer of an entry renders it: the app's modules
    /// beside the defined ones and the selected module, in its profile's locale, the others in
    /// the language `env`'s lists choose.
    ///
    /// # Errors
    ///
    /// [`AppError`]: no language serves the entry's modules, or the text does not render.
    pub fn plain(&self, env: &Env, text: &Text) -> Result<String, AppError> {
        self.plain_at(self.selected.as_ref(), env, text)
    }

    /// A text as formatted text, as [`App::plain`] renders it.
    ///
    /// # Errors
    ///
    /// [`AppError`]: no language serves the entry's modules, or the text does not render.
    pub fn formatted(&self, env: &Env, text: &Text) -> Result<Formatted, AppError> {
        self.formatted_at(self.selected.as_ref(), env, text)
    }

    /// [`App::language`] with `selected` in place of the app's selection.
    ///
    /// # Errors
    ///
    /// [`AppError`]: no language serves the entry's modules.
    pub fn language_at(
        &self,
        selected: Option<&Selected>,
        env: &Env,
    ) -> Result<LocaleTag, AppError> {
        let renderer = self.renderer(selected, env)?;
        Ok(renderer.inputs().language().tag().clone())
    }

    /// [`App::plain`] with `selected` in place of the app's selection.
    ///
    /// # Errors
    ///
    /// [`AppError`]: no language serves the entry's modules, or the text does not render.
    pub fn plain_at(
        &self,
        selected: Option<&Selected>,
        env: &Env,
        text: &Text,
    ) -> Result<String, AppError> {
        Ok(self.renderer(selected, env)?.plain(text)?)
    }

    /// [`App::formatted`] with `selected` in place of the app's selection.
    ///
    /// # Errors
    ///
    /// [`AppError`]: no language serves the entry's modules, or the text does not render.
    pub fn formatted_at(
        &self,
        selected: Option<&Selected>,
        env: &Env,
        text: &Text,
    ) -> Result<Formatted, AppError> {
        Ok(self.renderer(selected, env)?.formatted(text)?)
    }

    /// The core's renderer of an entry whose profile selected `selected`.
    ///
    /// # Errors
    ///
    /// [`AppError`]: the package refuses the screen, no language serves it, or a module calls a
    /// format the app does not register.
    pub fn renderer(
        &self,
        selected: Option<&Selected>,
        env: &Env,
    ) -> Result<Renderer<'_>, AppError> {
        Ok(self.rendering()?.renderer(selected, None, env)??)
    }
}
