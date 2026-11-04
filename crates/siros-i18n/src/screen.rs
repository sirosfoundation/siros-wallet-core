//! One language per presentation: a screen's modules, read from a package, and the one language
//! [`Screen::locale`] chooses for all of them.

use siros_explain::{Entry, Keyed, ModuleId};

use crate::error::{ModuleName, NoLanguage, PackageError, RenderError};
use crate::form::LanguagePolicy;
use crate::format::Formats;
use crate::locale::LocaleTag;
use crate::package::{LocaleIndex, LocaleRef, Manifest, ModuleRecord, Package};
use crate::render::{RENDERER, RenderOptions, Renderer};

/// The modules of a package a screen draws its texts from, each once. Only [`Screen::new`] makes
/// one.
#[derive(Debug)]
pub struct Screen<'m> {
    package: Package<'m>,
    manifest: Manifest,
    modules: Keyed<ModuleId, usize>,
}

/// The language of a presentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Language {
    /// The first tag of the priority list that every module matches.
    Understood(LocaleTag),
    /// No tag of the priority list serves every module and none of them enforces: the first tag
    /// of the app's fallback list that every module matches.
    Fallback(LocaleTag),
}

impl Language {
    /// The tag.
    #[must_use]
    pub const fn tag(&self) -> &LocaleTag {
        match self {
            Self::Understood(tag) | Self::Fallback(tag) => tag,
        }
    }
}

/// A module none of whose entries a tag matches.
struct Unserved;

/// A module's digest, and the locale entry a language chose.
#[derive(Debug, Clone)]
struct Chosen {
    digest: [u8; 32],
    entry: usize,
    tag: LocaleTag,
}

/// The locale entries a tag chose, and the language it is.
struct Choice {
    chosen: Keyed<ModuleId, Chosen>,
    language: Language,
}

/// A screen and the language [`Screen::locale`] chose for it. Only `locale` makes one.
#[derive(Debug)]
pub struct Located<'m> {
    package: Package<'m>,
    manifest: Manifest,
    chosen: Keyed<ModuleId, Chosen>,
    language: Language,
}

/// A module's locale entry that the range `tag` matches by RFC 4647 basic filtering: the one equal
/// to the tag, else the first in the module's order.
fn locale_entry<'r>(module: &'r ModuleRecord, tag: &LocaleTag) -> Option<&'r LocaleRef> {
    let locales = &module.locales;
    let equal = locales.iter().find(|locale| locale.tag == *tag);
    equal.or_else(|| locales.iter().find(|locale| tag.filters(&locale.tag)))
}

impl<'m> Screen<'m> {
    /// The screen of these modules of `package`.
    ///
    /// # Errors
    ///
    /// The [`PackageError`] of the package's manifest; [`PackageError::Renderer`] for a package
    /// another version of the renderer built; [`PackageError::Module`] for a module the package
    /// does not hold, and [`PackageError::RepeatedModule`] for one given twice.
    pub fn new(package: &Package<'m>, modules: Vec<ModuleId>) -> Result<Self, PackageError> {
        let manifest = package.manifest()?;
        if manifest.renderer != RENDERER {
            return Err(PackageError::Renderer {
                built: manifest.renderer,
            });
        }
        let entries = modules.into_iter().map(|id| {
            let index = manifest.modules.iter().position(|module| module.id.is(id));
            index
                .map(|index| Entry::new(id, index))
                .ok_or_else(|| PackageError::Module(ModuleName::of(id)))
        });
        let modules = Keyed::new(entries.collect::<Result<_, _>>()?)
            .map_err(|repeated| PackageError::RepeatedModule(ModuleName::of(repeated.0)))?;
        Ok(Self {
            package: *package,
            manifest,
            modules,
        })
    }

    /// The screen of the modules among `modules` that `tag` serves, located at `tag`; `None`
    /// when a module it holds does not serve `tag`.
    #[cfg(feature = "load")]
    pub(crate) fn serving(
        package: &Package<'m>,
        modules: &[ModuleId],
        tag: &LocaleTag,
    ) -> Result<Option<Located<'m>>, PackageError> {
        let all = Self::new(package, modules.to_vec())?;
        let served = all.modules.entries().iter().filter(|entry| {
            all.record(*entry.value())
                .is_some_and(|module| locale_entry(module, tag).is_some())
        });
        let screen = Self::new(package, served.map(|entry| *entry.key()).collect())?;
        Ok(screen
            .first(std::slice::from_ref(tag), Language::Understood)
            .map(|choice| Located {
                package: screen.package,
                manifest: screen.manifest,
                chosen: choice.chosen,
                language: choice.language,
            }))
    }

    /// The module of the manifest at `index`.
    fn record(&self, index: usize) -> Option<&ModuleRecord> {
        self.manifest.modules.get(index)
    }

    /// The presentation's language over the End-User's priority list and the app's fallback
    /// list: the first tag of the priority list every module matches; with none, and no module
    /// enforcing understood languages, the first tag of the fallback list every module matches.
    ///
    /// # Errors
    ///
    /// [`NoLanguage::NotUnderstood`], naming the first enforcing module, when no tag of the
    /// priority list serves every module and a module enforces; [`NoLanguage::NoFallback`] when
    /// no tag of the fallback list serves every module.
    pub fn locale(
        self,
        priority: &[LocaleTag],
        fallback: &[LocaleTag],
    ) -> Result<Located<'m>, NoLanguage> {
        let choice = match self.first(priority, Language::Understood) {
            Some(choice) => choice,
            None => {
                let enforcing = self.modules.entries().iter().find(|entry| {
                    self.record(*entry.value())
                        .is_some_and(|module| module.policy == LanguagePolicy::Understood)
                });
                if let Some(enforcing) = enforcing {
                    return Err(NoLanguage::NotUnderstood(ModuleName::of(*enforcing.key())));
                }
                self.first(fallback, Language::Fallback)
                    .ok_or(NoLanguage::NoFallback)?
            }
        };
        Ok(Located {
            package: self.package,
            manifest: self.manifest,
            chosen: choice.chosen,
            language: choice.language,
        })
    }

    /// The locale entries the first tag of `tags` every module matches chose.
    fn first(&self, tags: &[LocaleTag], language: fn(LocaleTag) -> Language) -> Option<Choice> {
        tags.iter().find_map(|tag| {
            let chosen = self.modules.try_map(|&module| {
                let record = self.record(module).ok_or(Unserved)?;
                let locale = locale_entry(record, tag).ok_or(Unserved)?;
                Ok::<_, Unserved>(Chosen {
                    digest: record.digest,
                    entry: locale.entry,
                    tag: locale.tag.clone(),
                })
            });
            Some(Choice {
                chosen: chosen.ok()?,
                language: language(tag.clone()),
            })
        })
    }
}

impl<'m> Located<'m> {
    /// The language.
    #[must_use]
    pub const fn language(&self) -> &Language {
        &self.language
    }

    /// The tag of each module's entry the language chose, in the screen's order.
    pub fn entries(&self) -> impl Iterator<Item = &LocaleTag> {
        self.chosen.entries().iter().map(|entry| &entry.value().tag)
    }

    /// The screen's renderer in its language, over the build's format modules and the app's
    /// rendering options. It reads each module's locale entry.
    ///
    /// # Errors
    ///
    /// [`RenderError::Package`] for a locale entry the package refuses;
    /// [`RenderError::Format`] when a module's locale entry calls a format module the build
    /// does not register.
    pub fn renderer(
        self,
        formats: &'m Formats,
        options: RenderOptions,
    ) -> Result<Renderer<'m>, RenderError> {
        let forms = self.chosen.try_map(|chosen| {
            let index: LocaleIndex = self.package.locale_index(&self.manifest, chosen.entry)?;
            if let Some(format) = index.formats.iter().find(|f| formats.get(f).is_none()) {
                return Err(RenderError::Format(format.clone()));
            }
            Ok(ChosenForm {
                digest: chosen.digest,
                index,
            })
        })?;
        Ok(Renderer::new(
            self.package,
            self.manifest,
            forms,
            self.language,
            formats,
            options,
        ))
    }
}

/// A module's digest and the locale entry its language chose, read.
#[derive(Debug)]
pub(crate) struct ChosenForm {
    pub(crate) digest: [u8; 32],
    pub(crate) index: LocaleIndex,
}
