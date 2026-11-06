//! One language per presentation: a screen's modules, read from a package, the locale a profile
//! selected for its own module, and the one language [`Screen::locale`] chooses for the others.

use siros_explain::{Entry, Keyed, ModuleId};

use crate::defined::{DefinedForm, DefinedLocale};
use crate::error::{ModuleName, NoLanguage, PackageError, RenderError};
use crate::form::{BareCalls, LanguagePolicy};
use crate::format::{Direction, Formats};
use crate::locale::LocaleTag;
use crate::package::{LocaleIndex, Manifest, ModuleRecord, Package};
use crate::render::{ModuleDigest, RENDERER, RenderOptions, Renderer};

/// The modules a screen draws its texts from, each once: a package's, and defined modules carried
/// beside it. Only [`Screen::new`] and [`Screen::carrying`] make one.
#[derive(Debug)]
pub struct Screen<'m> {
    package: Package<'m>,
    manifest: Manifest,
    modules: Keyed<ModuleId, Source<'m>>,
    selected: Option<Selected>,
}

/// Where a screen's module lies: in its package, or carried beside it.
#[derive(Debug, Clone)]
enum Source<'m> {
    /// The package's module.
    Package(ModuleRecord),
    /// A defined module carried beside the package.
    Carried(&'m DefinedForm),
}

impl<'m> Source<'m> {
    /// Its digest.
    const fn digest(&self) -> ModuleDigest {
        match self {
            Self::Package(record) => record.digest,
            Self::Carried(form) => form.digest,
        }
    }

    /// Its language policy.
    const fn policy(&self) -> LanguagePolicy {
        match self {
            Self::Package(record) => record.policy,
            Self::Carried(form) => form.policy,
        }
    }

    /// The tags of its locale entries, in its order.
    fn tags(&self) -> Vec<LocaleTag> {
        match self {
            Self::Package(record) => record.locales.iter().map(|l| l.tag.clone()).collect(),
            Self::Carried(form) => form.locales().cloned().collect(),
        }
    }

    /// Its locale entry of tag `tag`, which `pick` finds among the tags.
    fn chosen(&self, pick: impl Fn(&[LocaleTag]) -> Option<usize>) -> Option<Chosen<'m>> {
        let tags = self.tags();
        let at = pick(&tags)?;
        let tag = tags.get(at)?.clone();
        let place = match self {
            Self::Package(record) => Place::Entry(record.locales.get(at)?.entry),
            Self::Carried(form) => Place::Carried(form.locales.get(at)?),
        };
        Some(Chosen {
            digest: self.digest(),
            place,
            tag,
        })
    }
}

/// A module whose texts show in a locale its profile selected, as PaSO View §4 selects a
/// transaction's: the module's entry of that locale renders, and the locale and its RFC 4647
/// §3.4 truncations head the priority list the screen's other modules take their language from.
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
struct Chosen<'m> {
    digest: ModuleDigest,
    place: Place<'m>,
    tag: LocaleTag,
}

/// Where a chosen locale entry lies: the package's entry, or a carried module's locale.
#[derive(Debug, Clone, Copy)]
enum Place<'m> {
    /// The package's entry of this index.
    Entry(usize),
    /// A carried module's locale.
    Carried(&'m DefinedLocale),
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

/// The position among `tags` the range `tag` matches by RFC 4647 basic filtering: the tag equal
/// to the range, else the first in the module's order that extends it.
fn matching(tags: &[LocaleTag], tag: &LocaleTag) -> Option<usize> {
    let equal = tags.iter().position(|known| known == tag);
    equal.or_else(|| tags.iter().position(|known| tag.filters(known)))
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
                    .all(|module| matching(module.tags, tag).is_some())
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
    chosen: Keyed<ModuleId, Chosen<'m>>,
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
        Self::carrying(package, modules, &[])
    }

    /// The screen of these modules, each the package's, else one of `carried`: the defined modules
    /// carried beside the package, such as those of metadata that arrives with a request.
    ///
    /// # Errors
    ///
    /// [`Screen::new`]'s, [`PackageError::Module`] naming a module neither the package nor
    /// `carried` holds.
    pub fn carrying(
        package: &Package<'m>,
        modules: Vec<ModuleId>,
        carried: &'m [DefinedForm],
    ) -> Result<Self, PackageError> {
        let manifest = package.manifest()?;
        if manifest.renderer != RENDERER {
            return Err(PackageError::Renderer {
                built: manifest.renderer,
            });
        }
        let entries = modules.into_iter().map(|id| {
            let record = manifest.modules.iter().find(|module| module.id.is(id));
            let source = record
                .map(|record| Source::Package(record.clone()))
                .or_else(|| {
                    carried
                        .iter()
                        .find(|form| ModuleId::Defined(form.id) == id)
                        .map(Source::Carried)
                });
            source
                .map(|source| Entry::new(id, source))
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
            entry
                .value()
                .chosen(|tags| matching(tags, tag))
                .map(|chosen| Entry::new(*entry.key(), chosen))
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
    /// list: the first tag of the priority list every module of the screen matches; with none,
    /// and no module enforcing understood languages, the first tag of the fallback list every
    /// module matches. A selected module shows its entry of the locale its profile selected, and
    /// the others decide over the priority list headed by that locale and its RFC 4647 §3.4
    /// truncations ([`LocaleTag::truncations`]): `de-CH` selected heads the list with `de-CH`,
    /// `de`.
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
                let chosen = self
                    .modules
                    .get(&selected.module)
                    .and_then(|source| {
                        source.chosen(|tags| tags.iter().position(|tag| *tag == selected.locale))
                    })
                    .ok_or_else(|| NoLanguage::selected(selected))?;
                Some(Entry::new(selected.module, chosen))
            }
        };
        let others: Vec<&Entry<ModuleId, Source<'m>>> = self
            .modules
            .entries()
            .iter()
            .filter(|entry| Some(*entry.key()) != self.selected.as_ref().map(|s| s.module))
            .collect();
        let tags: Vec<Vec<LocaleTag>> = others.iter().map(|entry| entry.value().tags()).collect();
        let served: Vec<Served<'_>> = others
            .iter()
            .zip(&tags)
            .map(|(entry, tags)| Served {
                id: *entry.key(),
                tags,
                policy: entry.value().policy(),
            })
            .collect();
        let headed: Vec<LocaleTag> = self
            .selected
            .iter()
            .flat_map(|selected| selected.locale.truncations())
            .chain(priority.iter().cloned())
            .collect();
        let language = decide(&served, &headed, fallback)?;
        let chosen = self
            .modules
            .entries()
            .iter()
            .filter_map(|entry| match &selected {
                Some(selected) if selected.key() == entry.key() => Some(selected.clone()),
                _ => entry
                    .value()
                    .chosen(|tags| matching(tags, language.tag()))
                    .map(|chosen| Entry::new(*entry.key(), chosen)),
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
            let form = match chosen.place {
                Place::Entry(entry) => ChosenForm::Package {
                    digest: chosen.digest,
                    index: Box::new(self.package.locale_index(&self.manifest, entry)?),
                },
                Place::Carried(locale) => ChosenForm::Carried {
                    digest: chosen.digest,
                    locale,
                },
            };
            if let Some(format) = form
                .formats()
                .into_iter()
                .find(|f| formats.get(f).is_none())
            {
                return Err(RenderError::Format(format));
            }
            Ok(form)
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

/// A module's digest and the locale entry its language chose, read: the package's, or a carried
/// module's.
#[derive(Debug)]
pub(crate) enum ChosenForm<'m> {
    /// A package's locale entry.
    Package {
        /// The module's digest.
        digest: ModuleDigest,
        /// The entry.
        index: Box<LocaleIndex>,
    },
    /// A carried module's locale.
    Carried {
        /// The module's digest.
        digest: ModuleDigest,
        /// The locale.
        locale: &'m DefinedLocale,
    },
}

impl ChosenForm<'_> {
    /// The module's digest.
    pub(crate) const fn digest(&self) -> ModuleDigest {
        match self {
            Self::Package { digest, .. } | Self::Carried { digest, .. } => *digest,
        }
    }

    /// The locale entry's direction.
    pub(crate) const fn direction(&self) -> Direction {
        match self {
            Self::Package { index, .. } => index.direction,
            Self::Carried { locale, .. } => locale.direction,
        }
    }

    /// The locale entry's formats of bare values; a carried module has none.
    pub(crate) const fn bare(&self) -> Option<&BareCalls> {
        match self {
            Self::Package { index, .. } => Some(&index.bare),
            Self::Carried { .. } => None,
        }
    }

    /// The format modules its messages and bare formats call.
    fn formats(&self) -> Vec<String> {
        match self {
            Self::Package { index, .. } => index.formats.clone(),
            Self::Carried { locale, .. } => locale.formats(),
        }
    }
}
