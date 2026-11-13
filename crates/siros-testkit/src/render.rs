//! The test app's texts, as a wallet app loads them: per language, siros-cldr's options of its
//! formats, then its wording of every crate's statements and of the errors a test shows, each
//! module a resource whose keys are full ids, its arguments taking the app's [`formatters`].

use siros_explain::Explain;
use siros_i18n::{Bidi, Context, Formatters, LoadError, RegisterError};
use siros_openid4vp::rows::ExactNumber;
use siros_qes::DocumentNumber;
use siros_syntax::{Count, Date, DateTime, Decimal, OffsetTime};

/// siros-cldr's en options.
const CLDR_EN: &str = include_str!("../locales/cldr/en.mf2");
/// siros-cldr's de options.
const CLDR_DE: &str = include_str!("../locales/cldr/de.mf2");

/// The test app's English wording of siros-openid4vp.
pub const ENGLISH_OPENID4VP: &str = include_str!("../locales/en/openid4vp.mf2");
/// The test app's German wording of siros-openid4vp.
pub const GERMAN_OPENID4VP: &str = include_str!("../locales/de/openid4vp.mf2");
/// The test app's English wording of siros-paso.
pub const ENGLISH_PASO: &str = include_str!("../locales/en/paso.mf2");
/// The test app's German wording of siros-paso.
pub const GERMAN_PASO: &str = include_str!("../locales/de/paso.mf2");
/// The test app's English wording of siros-qes.
pub const ENGLISH_QES: &str = include_str!("../locales/en/qes.mf2");
/// The test app's German wording of siros-qes.
pub const GERMAN_QES: &str = include_str!("../locales/de/qes.mf2");
/// The test app's English wording of the test doubles.
pub const ENGLISH_TESTKIT: &str = include_str!("../locales/en/testkit.mf2");
/// The test app's German wording of the test doubles.
pub const GERMAN_TESTKIT: &str = include_str!("../locales/de/testkit.mf2");

thread_local! {
    /// The English context, loaded once per thread.
    static ENGLISH: Result<&'static Context, AppError> = Language::English.context().map(leak);
    /// The German context, loaded once per thread.
    static GERMAN: Result<&'static Context, AppError> = Language::German.context().map(leak);
}

/// Why the test app's context does not load.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
pub enum AppError {
    /// A formatter the build refuses.
    #[error(transparent)]
    Register(#[from] RegisterError),
    /// A source the context refuses.
    #[error(transparent)]
    Load(#[from] LoadError),
}

/// The test app's formatters: a date, a time and a date and time take `:siros:date`,
/// `:siros:time` and `:siros:datetime`, an exact number `:number` and a count `:integer`, each
/// by default; an amount's number takes `:currency`, and a document number `:integer`.
///
/// # Errors
///
/// The [`RegisterError`] of a function the build lacks.
pub fn formatters() -> Result<Formatters, RegisterError> {
    Formatters::new()
        .default_formatter::<Date>("siros:date")?
        .default_formatter::<OffsetTime>("siros:time")?
        .default_formatter::<DateTime>("siros:datetime")?
        .default_formatter::<ExactNumber>("number")?
        .default_formatter::<Count>("integer")?
        .formatter::<Decimal>("currency")?
        .formatter::<DocumentNumber>("integer")
}

/// The test app's context of `sources`, loaded in their order under `bidi`.
///
/// # Errors
///
/// [`AppError::Register`] for the app's formatters, and the [`LoadError`] of the first source
/// the context refuses.
pub fn loaded<S: AsRef<str>>(
    bidi: Bidi,
    sources: impl IntoIterator<Item = S>,
) -> Result<Context, AppError> {
    let context = Context::new().bidi(bidi).formatters(formatters()?);
    Ok(sources
        .into_iter()
        .try_fold(context, |context, source| context.module(source.as_ref()))?)
}

/// The context, for the rest of the thread's tests.
fn leak(context: Context) -> &'static Context {
    Box::leak(Box::new(context))
}

/// A language the test app speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    /// `en`.
    English,
    /// `de`.
    German,
}

impl Language {
    /// Both, English first.
    pub const ALL: [Self; 2] = [Self::English, Self::German];

    /// Its tag.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::English => "en",
            Self::German => "de",
        }
    }

    /// The test app's sources in the language, in load order: siros-cldr's options of its
    /// formats, then its wording of each crate.
    #[must_use]
    pub const fn sources(self) -> [&'static str; 5] {
        match self {
            Self::English => [
                CLDR_EN,
                ENGLISH_OPENID4VP,
                ENGLISH_PASO,
                ENGLISH_QES,
                ENGLISH_TESTKIT,
            ],
            Self::German => [
                CLDR_DE,
                GERMAN_OPENID4VP,
                GERMAN_PASO,
                GERMAN_QES,
                GERMAN_TESTKIT,
            ],
        }
    }

    /// The test app's context in the language: its [`sources`](Self::sources) [`loaded`] without
    /// bidi isolation.
    ///
    /// # Errors
    ///
    /// The [`AppError`] of [`loaded`].
    pub fn context(self) -> Result<Context, AppError> {
        loaded(Bidi::None, self.sources())
    }

    /// The test app's context in the language, loaded once per thread.
    ///
    /// # Errors
    ///
    /// The [`AppError`] of [`loaded`].
    pub fn shared(self) -> Result<&'static Context, AppError> {
        match self {
            Self::English => ENGLISH.with(Clone::clone),
            Self::German => GERMAN.with(Clone::clone),
        }
    }
}

/// The test app: its context in each language it speaks.
#[derive(Debug, Clone)]
pub struct App {
    english: Context,
    german: Context,
}

impl App {
    /// The app, its contexts loaded.
    ///
    /// # Errors
    ///
    /// The [`AppError`] of [`loaded`].
    pub fn new() -> Result<Self, AppError> {
        Ok(Self {
            english: Language::English.context()?,
            german: Language::German.context()?,
        })
    }

    /// The context in `language`.
    #[must_use]
    pub const fn context(&self, language: Language) -> &Context {
        match language {
            Language::English => &self.english,
            Language::German => &self.german,
        }
    }
}
