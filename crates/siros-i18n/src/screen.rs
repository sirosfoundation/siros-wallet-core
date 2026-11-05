//! One language per presentation: a screen's modules, read from a package, the locale a profile
//! selected for its own module, and the one language [`Screen::locale`] chooses for the others.

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
    modules: Keyed<ModuleId, ModuleRecord>,
    selected: Option<Selected>,
}

/// A module whose texts show in a locale its profile selected, as PaSO View §4 selects a
/// transaction's: the module's entry of that locale renders, and the locale heads the priority
/// list the screen's other modules take their language from.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Selected {
    module: ModuleId,
    locale: LocaleTag,
}

impl Selected {
    /// `module` shown in `locale`.
    #[must_use]
    pub const fn new(module: ModuleId, locale: LocaleTag) -> Self {
        Self { module, locale }
    }

    /// The module.
    #[must_use]
    pub const fn module(&self) -> ModuleId {
        self.module
    }

    /// The locale.
    #[must_use]
    pub const fn locale(&self) -> &LocaleTag {
        &self.locale
    }
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

/// A module's digest, and the locale entry a language chose.
#[derive(Debug, Clone)]
struct Chosen {
    digest: [u8; 32],
    entry: usize,
    tag: LocaleTag,
}

/// A module as the language decision reads it: its identity, the tags of its locale entries in
/// its order, and its language policy.
#[derive(Debug, Clone, Copy)]
struct Served<'t> {
    /// The module.
    id: ModuleId,
    /// Its locale entries' tags.
    tags: &'t [LocaleTag],
    /// Its language policy.
    policy: LanguagePolicy,
}

/// The entry among `entries` the range `tag` matches by RFC 4647 basic filtering: the one whose
/// tag equals the range, else the first in the module's order whose tag extends it.
fn matching<'e, E>(
    entries: &'e [E],
    tag_of: impl Fn(&E) -> &LocaleTag,
    tag: &LocaleTag,
) -> Option<&'e E> {
    let equal = entries.iter().find(|entry| tag_of(entry) == tag);
    equal.or_else(|| entries.iter().find(|entry| tag.filters(tag_of(entry))))
}

/// The presentation's language over its modules, the End-User's priority list and the app's
/// fallback list: the first tag of the priority list every module matches; with none, and no
/// module enforcing understood languages, the first tag of the fallback list every module
/// matches.
///
/// # Errors
///
/// [`NoLanguage::NotUnderstood`], naming the first enforcing module, when no tag of the priority
/// list serves every module and a module enforces; [`NoLanguage::NoFallback`] when no tag of the
/// fallback list serves every module.
fn decide(
    modules: &[Served<'_>],
    priority: &[LocaleTag],
    fallback: &[LocaleTag],
) -> Result<Language, NoLanguage> {
    let first = |tags: &[LocaleTag]| {
        tags.iter()
            .find(|tag| {
                modules
                    .iter()
                    .all(|module| matching(module.tags, |tag| tag, tag).is_some())
            })
            .cloned()
    };
    if let Some(tag) = first(priority) {
        return Ok(Language::Understood(tag));
    }
    if let Some(enforcing) = modules
        .iter()
        .find(|module| module.policy == LanguagePolicy::Understood)
    {
        return Err(NoLanguage::NotUnderstood(ModuleName::of(enforcing.id)));
    }
    first(fallback)
        .map(Language::Fallback)
        .ok_or(NoLanguage::NoFallback)
}

/// A screen and the language [`Screen::locale`] chose for it. Only `locale` makes one.
#[derive(Debug)]
pub struct Located<'m> {
    package: Package<'m>,
    manifest: Manifest,
    chosen: Keyed<ModuleId, Chosen>,
    selected: Option<Selected>,
    language: Language,
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
            let record = manifest.modules.iter().find(|module| module.id.is(id));
            record
                .map(|record| Entry::new(id, record.clone()))
                .ok_or_else(|| PackageError::Module(ModuleName::of(id)))
        });
        let modules = Keyed::new(entries.collect::<Result<_, _>>()?)
            .map_err(|repeated| PackageError::RepeatedModule(ModuleName::of(repeated.0)))?;
        Ok(Self {
            package: *package,
            manifest,
            modules,
            selected: None,
        })
    }

    /// The screen with one of its modules shown in the locale its profile selected.
    ///
    /// # Errors
    ///
    /// [`PackageError::Module`] for a module the screen does not hold, and
    /// [`PackageError::RepeatedModule`] for a second selection.
    pub fn selecting(mut self, selected: Selected) -> Result<Self, PackageError> {
        if self.selected.is_some() {
            return Err(PackageError::RepeatedModule(ModuleName::of(
                selected.module,
            )));
        }
        if self.modules.get(&selected.module).is_none() {
            return Err(PackageError::Module(ModuleName::of(selected.module)));
        }
        self.selected = Some(selected);
        Ok(self)
    }

    /// The screen of the modules among `modules` that `tag` serves, located at `tag`.
    #[cfg(feature = "load")]
    pub(crate) fn serving(
        package: &Package<'m>,
        modules: &[ModuleId],
        tag: &LocaleTag,
    ) -> Result<Located<'m>, PackageError> {
        let all = Self::new(package, modules.to_vec())?;
        let chosen = all.modules.entries().iter().filter_map(|entry| {
            let record = entry.value();
            matching(&record.locales, |locale| &locale.tag, tag)
                .map(|locale| Entry::new(*entry.key(), Chosen::of(record, locale)))
        });
        Ok(Located {
            package: all.package,
            chosen: Keyed::first_of(chosen),
            manifest: all.manifest,
            selected: None,
            language: Language::Understood(tag.clone()),
        })
    }

    /// The presentation's language over the End-User's priority list and the app's fallback
    /// list, by [`decide`] over the screen's modules. A selected module shows its entry of the
    /// locale its profile selected, and the others decide over the priority list headed by that
    /// locale.
    ///
    /// # Errors
    ///
    /// [`NoLanguage::Selected`] when the selected module holds no entry of its locale;
    /// [`NoLanguage::NotUnderstood`], naming the first enforcing module, when no tag of the
    /// priority list serves every other module and one of them enforces;
    /// [`NoLanguage::NoFallback`] when no tag of the fallback list serves every other module.
    pub fn locale(
        self,
        priority: &[LocaleTag],
        fallback: &[LocaleTag],
    ) -> Result<Located<'m>, NoLanguage> {
        let selected = match &self.selected {
            None => None,
            Some(selected) => {
                let record = self
                    .modules
                    .get(&selected.module)
                    .ok_or_else(|| NoLanguage::selected(selected))?;
                let locale = record
                    .locales
                    .iter()
                    .find(|locale| locale.tag == selected.locale)
                    .ok_or_else(|| NoLanguage::selected(selected))?;
                Some(Entry::new(selected.module, Chosen::of(record, locale)))
            }
        };
        let others: Vec<&Entry<ModuleId, ModuleRecord>> = self
            .modules
            .entries()
            .iter()
            .filter(|entry| Some(*entry.key()) != self.selected.as_ref().map(|s| s.module))
            .collect();
        let tags: Vec<Vec<LocaleTag>> = others
            .iter()
            .map(|entry| {
                entry
                    .value()
                    .locales
                    .iter()
                    .map(|l| l.tag.clone())
                    .collect()
            })
            .collect();
        let served: Vec<Served<'_>> = others
            .iter()
            .zip(&tags)
            .map(|(entry, tags)| Served {
                id: *entry.key(),
                tags,
                policy: entry.value().policy,
            })
            .collect();
        let headed: Vec<LocaleTag> = self
            .selected
            .iter()
            .map(|selected| selected.locale.clone())
            .chain(priority.iter().cloned())
            .collect();
        let language = decide(&served, &headed, fallback)?;
        let chosen = self.modules.entries().iter().filter_map(|entry| {
            let record = entry.value();
            match &selected {
                Some(selected) if selected.key() == entry.key() => Some(selected.clone()),
                _ => matching(&record.locales, |locale| &locale.tag, language.tag())
                    .map(|locale| Entry::new(*entry.key(), Chosen::of(record, locale))),
            }
        });
        Ok(Located {
            package: self.package,
            chosen: Keyed::first_of(chosen),
            manifest: self.manifest,
            selected: self.selected,
            language,
        })
    }
}

impl Chosen {
    /// A module's locale entry.
    fn of(record: &ModuleRecord, locale: &LocaleRef) -> Self {
        Self {
            digest: record.digest,
            entry: locale.entry,
            tag: locale.tag.clone(),
        }
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
            Shown {
                selected: self.selected,
                language: self.language,
            },
            formats,
            options,
        ))
    }
}

/// The locales a screen shows: the selected module's, and the others' language.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Shown {
    pub(crate) selected: Option<Selected>,
    pub(crate) language: Language,
}

/// A module's digest and the locale entry its language chose, read.
#[derive(Debug)]
pub(crate) struct ChosenForm {
    pub(crate) digest: [u8; 32],
    pub(crate) index: LocaleIndex,
}
