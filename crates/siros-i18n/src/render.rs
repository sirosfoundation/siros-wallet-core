//! The renderer: a screen's texts in its language, read from its package or rendered from the
//! package's compiled messages through the build's format modules, written into a sink when
//! they are sent to the display.

use siros_explain::{Keyed, ModuleId, Text};

use crate::error::{PackageError, RenderError};
use crate::eval::Trail;
use crate::format::Formats;
use crate::package::{Manifest, Package, TextKey, replay};
use crate::screen::{ChosenForm, Language};
use crate::sink::{Formatted, FormattedSink, Sink};

/// The renderer's version: its compiled form's and its formatting's. A record commits to it.
pub const RENDERER: u16 = 1;

/// How an amount shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Amounts {
    /// Through its format module, in the locale's currency format.
    Formatted,
    /// The digits as written, a space, and the ISO 4217 code.
    Written,
}

/// MF2's bidi strategies (spec/formatting.md "Handling Bidirectional Text"), among which the app
/// chooses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bidi {
    /// The Default Bidi Strategy: each placeholder isolated, U+2066, U+2067 or U+2068 before it by
    /// its direction and U+2069 after it.
    Default,
    /// No isolation characters.
    None,
}

/// What the matcher emits when a text of its entries does not render.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnRenderError {
    /// No entry.
    NoEntry,
    /// The entries whose texts rendered.
    Rendered,
}

/// The app's rendering choices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenderOptions {
    /// How amounts show.
    pub amounts: Amounts,
    /// The bidi strategy.
    pub bidi: Bidi,
    /// The app's choice for a rendering error in the matcher, which the registration carries.
    pub on_error: OnRenderError,
}

/// What a rendering depends on beside the text: what a record commits to. Only
/// [`Renderer::inputs`] makes one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderingInputs {
    language: Language,
    modules: Keyed<ModuleId, [u8; 32]>,
    options: RenderOptions,
    renderer: u16,
}

impl RenderingInputs {
    /// The presentation's language, and whether it fell back.
    #[must_use]
    pub const fn language(&self) -> &Language {
        &self.language
    }

    /// Each module's digest, under its identity.
    #[must_use]
    pub const fn modules(&self) -> &Keyed<ModuleId, [u8; 32]> {
        &self.modules
    }

    /// The rendering options.
    #[must_use]
    pub const fn options(&self) -> RenderOptions {
        self.options
    }

    /// The renderer's version.
    #[must_use]
    pub const fn renderer(&self) -> u16 {
        self.renderer
    }
}

/// A screen's renderer in its language, which reads its messages from the screen's package. Only
/// `Located::renderer` makes one.
pub struct Renderer<'m> {
    pub(crate) package: Package<'m>,
    pub(crate) manifest: Manifest,
    pub(crate) chosen: Keyed<ModuleId, ChosenForm>,
    language: Language,
    pub(crate) formats: &'m Formats,
    pub(crate) options: RenderOptions,
}

/// A text rendered, and the modules its rendering drew from.
#[cfg(feature = "load")]
pub(crate) struct Drawn {
    pub(crate) formatted: Formatted,
    pub(crate) modules: Vec<ModuleId>,
}

impl<'m> Renderer<'m> {
    pub(crate) const fn new(
        package: Package<'m>,
        manifest: Manifest,
        chosen: Keyed<ModuleId, ChosenForm>,
        language: Language,
        formats: &'m Formats,
        options: RenderOptions,
    ) -> Self {
        Self {
            package,
            manifest,
            chosen,
            language,
            formats,
            options,
        }
    }

    /// The inputs a record commits to: the language and its fallback flag, each module's digest,
    /// the rendering options, and the renderer's version.
    #[must_use]
    pub fn inputs(&self) -> RenderingInputs {
        RenderingInputs {
            language: self.language.clone(),
            modules: self.chosen.map(|chosen| chosen.digest),
            options: self.options,
            renderer: RENDERER,
        }
    }

    /// Every text of the screen.
    ///
    /// # Errors
    ///
    /// The first text's [`RenderError`].
    pub fn render(&self, texts: &[Text]) -> Result<Vec<Formatted>, RenderError> {
        texts.iter().map(|text| self.formatted(text)).collect()
    }

    /// The text, written into a sink: as the package holds it, or rendered now.
    ///
    /// # Errors
    ///
    /// A [`RenderError`] when the text does not render; the sink then holds part of it.
    pub fn render_into(&self, text: &Text, sink: &mut dyn Sink) -> Result<(), RenderError> {
        match self.precomputed(text)? {
            Some(held) => {
                for span in held.spans() {
                    replay(sink, span.text(), span.styles());
                }
                Ok(())
            }
            None => self.text(text, sink, &mut Trail::default()),
        }
    }

    /// The text as formatted text: as the package holds it, or rendered now from the package's
    /// compiled messages, which give the same spans. A function of the text, the modules, the
    /// language and the options alone.
    ///
    /// # Errors
    ///
    /// A [`RenderError`] for a formatting error; no fallback text reaches the End-User.
    pub fn formatted(&self, text: &Text) -> Result<Formatted, RenderError> {
        match self.precomputed(text)? {
            Some(held) => Ok(held),
            None => {
                let mut sink = FormattedSink::default();
                self.text(text, &mut sink, &mut Trail::default())?;
                Ok(sink.finish())
            }
        }
    }

    /// The text as plain text: [`Renderer::formatted`]'s, its styles dropped.
    ///
    /// # Errors
    ///
    /// [`Renderer::formatted`]'s.
    pub fn plain(&self, text: &Text) -> Result<String, RenderError> {
        self.formatted(text).map(|formatted| formatted.plain())
    }

    /// The text as the package holds it precomputed in the renderer's language and options, when
    /// every module its rendering drew from is the screen's.
    fn precomputed(&self, text: &Text) -> Result<Option<Formatted>, RenderError> {
        if self.manifest.held.is_empty() {
            return Ok(None);
        }
        let key = TextKey::of(text, self.language.tag(), self.options);
        let Some(entry) = self.manifest.held(&key.digest()) else {
            return Ok(None);
        };
        let held = self.package.held(&self.manifest, entry)?;
        if held.key != key {
            return Err(PackageError::Malformed { entry }.into());
        }
        let drawn = held.reached.iter().all(|module| {
            self.chosen
                .entries()
                .iter()
                .any(|chosen| module.is(*chosen.key()))
        });
        Ok(drawn.then_some(held.formatted))
    }

    /// The text rendered now from the compiled messages, and the modules its rendering drew
    /// from.
    #[cfg(feature = "load")]
    pub(crate) fn drawn(&self, text: &Text) -> Result<Drawn, RenderError> {
        let mut sink = FormattedSink::default();
        let mut trail = Trail::default();
        self.text(text, &mut sink, &mut trail)?;
        Ok(Drawn {
            formatted: sink.finish(),
            modules: trail.into_modules(),
        })
    }
}
