//! The package builder, the wallet's: compiled modules in the package's locales, then texts
//! rendered now over all of them, and the bytes, the same for the same content whatever the
//! order of the calls.

use std::fmt;

use siros_explain::{ModuleId, Text};

use super::codec::write_message;
use super::held::{Held, TextKey};
use super::manifest::{
    HeldRef, LocaleIndex, LocaleRef, Manifest, MessageRef, ModuleRecord, StoredId,
};
use super::registration::{Candidates, CredentialRecord, Registration, TransactionRecord};
use super::{FORMAT, HEADER, Location, MAGIC, Package, merkle};
use crate::bytes::Writer;
use crate::error::{ModuleName, PackageError, RenderError};
use crate::form::{CompiledModule, LocaleForm, MessageForm};
use crate::format::Formats;
use crate::locale::LocaleTag;
use crate::module::Module;
use crate::render::{RENDERER, RenderOptions};
use crate::screen::Screen;

/// A package under construction for its locales, each once, sorted: its modules.
/// [`PackageBuilder::texts`] closes the module set and renders texts over it. Only
/// [`PackageBuilder::new`] makes one.
#[derive(Debug)]
pub struct PackageBuilder {
    locales: Vec<LocaleTag>,
    modules: Vec<Added>,
    registration: Option<Registration>,
}

/// A registration's package under construction (section 4.14 of the design, "DC API
/// precomputation"): its locales the tags of the End-User's priority list and the app's fallback
/// list, its modules, the credentials and transaction types it serves, and the lists and options
/// it records. Only [`RegistrationBuilder::new`] makes one.
#[derive(Debug)]
pub struct RegistrationBuilder {
    builder: PackageBuilder,
    priority: Vec<LocaleTag>,
    fallback: Vec<LocaleTag>,
    options: RenderOptions,
    credentials: Vec<Recorded>,
    transactions: Vec<TransactionRecord>,
}

/// A credential a registration serves: its name, and its card's modules with the tags of the
/// locale entries the package holds of each.
#[derive(Debug)]
struct Recorded {
    name: String,
    modules: Vec<(ModuleId, Vec<LocaleTag>)>,
}

/// A module added to a package: its locale entries that the package's locales choose, with
/// every key, and the keys the package holds of them, all when `None`.
#[derive(Debug)]
struct Added {
    whole: CompiledModule,
    keys: Option<Vec<String>>,
}

impl Added {
    /// The module as the package holds it: its locale entries with the kept keys.
    fn held(&self) -> CompiledModule {
        let kept = |message: &MessageForm| {
            self.keys
                .as_ref()
                .is_none_or(|keys| keys.contains(&message.id))
        };
        let locales = self.whole.locales.iter().map(|locale| LocaleForm {
            messages: locale
                .messages
                .iter()
                .filter(|m| kept(m))
                .cloned()
                .collect(),
            ..locale.clone()
        });
        CompiledModule {
            locales: locales.collect(),
            ..self.whole.clone()
        }
    }
}

/// A package whose module set is closed: texts rendered now through `formats` over every key of
/// every module, then the bytes. Only [`PackageBuilder::texts`] makes one.
pub struct PackageTexts<'f> {
    builder: PackageBuilder,
    whole: BuiltPackage,
    formats: &'f Formats,
    held: Vec<Held>,
}

impl fmt::Debug for PackageTexts<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PackageTexts")
            .field("builder", &self.builder)
            .field("whole", &self.whole)
            .field("held", &self.held)
            .finish_non_exhaustive()
    }
}

/// A package's bytes and its root, which a reader reads it under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltPackage {
    bytes: Vec<u8>,
    root: [u8; 32],
}

impl BuiltPackage {
    /// The bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The root: the package's identity, which [`Package::read`] takes.
    #[must_use]
    pub const fn root(&self) -> [u8; 32] {
        self.root
    }

    /// The bytes, taken.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// The locale entry of `module` that the range `tag` chooses: the one equal to it, else the first
/// that extends it.
fn chosen<'m>(module: &'m CompiledModule, tag: &LocaleTag) -> Option<&'m LocaleForm> {
    let equal = module.locales.iter().find(|form| form.locale == *tag);
    equal.or_else(|| module.locales.iter().find(|form| tag.filters(&form.locale)))
}

impl PackageBuilder {
    /// A builder for these locales.
    ///
    /// # Errors
    ///
    /// [`PackageError::NoLocale`] for no locale, [`PackageError::RepeatedLocale`] for one given
    /// twice.
    pub fn new(mut locales: Vec<LocaleTag>) -> Result<Self, PackageError> {
        locales.sort();
        if let Some(repeated) = locales.windows(2).find_map(|pair| match pair {
            [a, b] if a == b => Some(a),
            _ => None,
        }) {
            return Err(PackageError::RepeatedLocale(repeated.clone()));
        }
        if locales.is_empty() {
            return Err(PackageError::NoLocale);
        }
        Ok(Self {
            locales,
            modules: Vec::new(),
            registration: None,
        })
    }

    /// Adds a module's compiled form in the package's locales: for each locale, the module's
    /// entry it chooses by RFC 4647 basic filtering, with every key, or with the keys given.
    ///
    /// # Errors
    ///
    /// [`PackageError::RepeatedModule`] for a module added twice; [`PackageError::RepeatedKey`]
    /// for a key given twice; [`PackageError::Key`] for a key the module does not hold.
    pub fn module(&mut self, module: &Module, keys: Option<&[&str]>) -> Result<(), PackageError> {
        let form = module.form();
        if self.modules.iter().any(|added| added.whole.id == form.id) {
            return Err(PackageError::RepeatedModule(ModuleName::of(form.id)));
        }
        let keys = keys.map(|keys| kept_keys(form, keys)).transpose()?;
        let locales = form.locales.iter().filter(|locale| {
            self.locales
                .iter()
                .any(|tag| chosen(form, tag).is_some_and(|entry| entry.locale == locale.locale))
        });
        let whole = CompiledModule {
            locales: locales.cloned().collect(),
            ..form.clone()
        };
        self.modules.push(Added { whole, keys });
        Ok(())
    }

    /// Closes the module set: the texts [`PackageTexts::precompute`] renders through `formats`
    /// draw from every key of every module added.
    #[must_use]
    pub fn texts(self, formats: &Formats) -> PackageTexts<'_> {
        let whole = assemble(self.entries(self.modules.iter().map(|m| m.whole.clone()), &[]));
        PackageTexts {
            builder: self,
            whole,
            formats,
            held: Vec::new(),
        }
    }

    /// The package of the modules, with no text rendered in advance: its bytes and its root.
    #[must_use]
    pub fn finish(self) -> BuiltPackage {
        assemble(self.entries(self.modules.iter().map(Added::held), &[]))
    }

    /// The entries of the package of `modules` and `held`, which the caller sorted by their
    /// keys' SHA-256: the manifest, then each module's locale entries, each followed by its
    /// messages, in the order of the modules' stored identities, then the precomputed texts.
    fn entries(
        &self,
        modules: impl Iterator<Item = CompiledModule>,
        held: &[Held],
    ) -> Vec<Vec<u8>> {
        let mut modules: Vec<CompiledModule> = modules.collect();
        modules.sort_by_cached_key(|module| StoredId::of(module.id).encoded().to_vec());
        let mut entries = vec![Vec::new()];
        let mut records = Vec::with_capacity(modules.len());
        for module in &modules {
            let mut locales = Vec::with_capacity(module.locales.len());
            for form in &module.locales {
                let entry = entries.len();
                locales.push(LocaleRef {
                    tag: form.locale.clone(),
                    entry,
                });
                entries.push(locale_index(form, entry).encode());
                entries.extend(form.messages.iter().map(encode_message));
            }
            records.push(ModuleRecord {
                id: StoredId::of(module.id),
                digest: module.digest,
                policy: module.policy,
                locales,
            });
        }
        let held_refs = held.iter().map(|held| {
            entries.push(held.encode());
            HeldRef {
                digest: held.key.digest(),
                entry: entries.len() - 1,
            }
        });
        let held_refs: Vec<HeldRef> = held_refs.collect();
        let manifest = Manifest {
            renderer: RENDERER,
            locales: self.locales.clone(),
            modules: records,
            held: held_refs,
            registration: self.registration.clone(),
            locations: locations(&entries),
        };
        if let Some(first) = entries.first_mut() {
            *first = manifest.encode();
        }
        entries
    }
}

impl RegistrationBuilder {
    /// A builder for a registration under the End-User's priority list, the app's fallback list
    /// and its rendering options: the package's locales are the lists' tags, so each text it
    /// precomputes is held under the tag a screen's language names.
    ///
    /// # Errors
    ///
    /// [`PackageError::NoLocale`] for an empty priority list.
    pub fn new(
        priority: Vec<LocaleTag>,
        fallback: Vec<LocaleTag>,
        options: RenderOptions,
    ) -> Result<Self, PackageError> {
        if priority.is_empty() {
            return Err(PackageError::NoLocale);
        }
        let mut locales: Vec<LocaleTag> = priority.iter().chain(&fallback).cloned().collect();
        locales.sort();
        locales.dedup();
        Ok(Self {
            builder: PackageBuilder::new(locales)?,
            priority,
            fallback,
            options,
            credentials: Vec::new(),
            transactions: Vec::new(),
        })
    }

    /// Adds a module, as [`PackageBuilder::module`] does.
    ///
    /// # Errors
    ///
    /// [`PackageBuilder::module`]'s.
    pub fn module(&mut self, module: &Module, keys: Option<&[&str]>) -> Result<(), PackageError> {
        self.builder.module(module, keys)
    }

    /// Records a credential the registration serves, by its name, and the modules its card draws
    /// from, each added before.
    ///
    /// # Errors
    ///
    /// [`PackageError::RepeatedCredential`] for a name given twice; [`PackageError::Module`] for a
    /// module not added, and [`PackageError::RepeatedModule`] for one given twice.
    pub fn credential(&mut self, name: &str, modules: &[ModuleId]) -> Result<(), PackageError> {
        if self.credentials.iter().any(|known| known.name == name) {
            return Err(PackageError::RepeatedCredential(name.to_owned()));
        }
        let mut tagged = Vec::with_capacity(modules.len());
        for (index, module) in modules.iter().enumerate() {
            if modules.iter().take(index).any(|earlier| earlier == module) {
                return Err(PackageError::RepeatedModule(ModuleName::of(*module)));
            }
            let tags = self.added(*module)?.locales.iter();
            tagged.push((*module, tags.map(|l| l.locale.clone()).collect()));
        }
        self.credentials.push(Recorded {
            name: name.to_owned(),
            modules: tagged,
        });
        Ok(())
    }

    /// Records a transaction type the registration serves and the module its metadata converts
    /// to, added before.
    ///
    /// # Errors
    ///
    /// [`PackageError::RepeatedTransaction`] for a type given twice; [`PackageError::Module`] for
    /// a module not added.
    pub fn transaction(&mut self, kind: &str, module: ModuleId) -> Result<(), PackageError> {
        if self.transactions.iter().any(|known| known.kind == kind) {
            return Err(PackageError::RepeatedTransaction(kind.to_owned()));
        }
        let added = self.added(module)?.id;
        self.transactions.push(TransactionRecord {
            kind: kind.to_owned(),
            module: StoredId::of(added),
        });
        Ok(())
    }

    /// The added module of identity `id`.
    fn added(&self, id: ModuleId) -> Result<&CompiledModule, PackageError> {
        self.builder
            .modules
            .iter()
            .find(|added| added.whole.id == id)
            .map(|added| &added.whole)
            .ok_or_else(|| PackageError::Module(ModuleName::of(id)))
    }

    /// The package builder with the registration's record: each credential's candidate
    /// languages over the locale entries the package holds of its modules.
    fn recorded(mut self) -> PackageBuilder {
        let mut credentials: Vec<CredentialRecord> = self
            .credentials
            .iter()
            .map(|credential| {
                let tags: Vec<&[LocaleTag]> = credential
                    .modules
                    .iter()
                    .map(|(_, tags)| tags.as_slice())
                    .collect();
                CredentialRecord {
                    name: credential.name.clone(),
                    modules: credential
                        .modules
                        .iter()
                        .map(|(id, _)| StoredId::of(*id))
                        .collect(),
                    candidates: Candidates::of(&tags, &self.priority, &self.fallback),
                }
            })
            .collect();
        credentials.sort_by(|a, b| a.name.cmp(&b.name));
        let mut transactions = std::mem::take(&mut self.transactions);
        transactions.sort_by(|a, b| a.kind.cmp(&b.kind));
        self.builder.registration = Some(Registration {
            priority: self.priority,
            fallback: self.fallback,
            options: self.options,
            credentials,
            transactions,
        });
        self.builder
    }

    /// Closes the module set, as [`PackageBuilder::texts`] does.
    #[must_use]
    pub fn texts(self, formats: &Formats) -> PackageTexts<'_> {
        self.recorded().texts(formats)
    }

    /// The package with no text rendered in advance, as [`PackageBuilder::finish`] gives it.
    #[must_use]
    pub fn finish(self) -> BuiltPackage {
        self.recorded().finish()
    }
}

/// `keys`, each once and each a key that every locale of `form` holds.
fn kept_keys(form: &CompiledModule, keys: &[&str]) -> Result<Vec<String>, PackageError> {
    keys.iter()
        .enumerate()
        .map(|(index, key)| {
            let module = || ModuleName::of(form.id);
            let key = (*key).to_owned();
            if keys.iter().take(index).any(|earlier| *earlier == key) {
                return Err(PackageError::RepeatedKey {
                    module: module(),
                    key,
                });
            }
            let held = !form.locales.is_empty()
                && form
                    .locales
                    .iter()
                    .all(|locale| locale.message(&key).is_some());
            if held {
                Ok(key)
            } else {
                Err(PackageError::Key {
                    module: module(),
                    key,
                })
            }
        })
        .collect()
}

/// The locale entry of `form` at index `entry`, its messages in the entries after it.
fn locale_index(form: &LocaleForm, entry: usize) -> LocaleIndex {
    let mut formats: Vec<String> = form
        .messages
        .iter()
        .flat_map(|message| message.expressions.iter().map(|e| &e.call))
        .chain(form.bare.calls())
        .map(|call| call.format.clone())
        .collect();
    formats.sort();
    formats.dedup();
    let messages = form
        .messages
        .iter()
        .enumerate()
        .map(|(index, message)| MessageRef {
            key: message.id.clone(),
            entry: entry + 1 + index,
        });
    LocaleIndex {
        locale: form.locale.clone(),
        direction: form.direction,
        formats,
        bare: form.bare.clone(),
        messages: messages.collect(),
    }
}

impl PackageTexts<'_> {
    /// Renders `text` now in each package locale whose modules serve it, over every key of every
    /// module, and keeps its formatted spans: a renderer over the package returns them as kept,
    /// and `plain` of them drops the styles. A text given again renders to the spans it keeps.
    ///
    /// # Errors
    ///
    /// The [`RenderError`] of a locale whose modules serve the text; [`RenderError::Outside`]
    /// when no package locale serves every module the text draws from.
    pub fn precompute(&mut self, text: &Text, options: RenderOptions) -> Result<(), RenderError> {
        let package = Package::read(self.whole.bytes(), self.whole.root())?;
        let ids: Vec<ModuleId> = self.builder.modules.iter().map(|m| m.whole.id).collect();
        let mut kept = Vec::new();
        let mut outside = None;
        for tag in &self.builder.locales {
            let located = Screen::serving(&package, &ids, tag)?;
            let renderer = located.renderer(self.formats, options)?;
            match renderer.drawn(text) {
                Ok(drawn) => kept.push(Held {
                    key: TextKey::of(text, tag, options),
                    reached: drawn.modules.into_iter().map(StoredId::of).collect(),
                    formatted: drawn.formatted,
                }),
                Err(error @ RenderError::Outside { .. }) => outside = Some(error),
                Err(error) => return Err(error),
            }
        }
        if kept.is_empty()
            && let Some(outside) = outside
        {
            return Err(outside);
        }
        for held in kept {
            if self.held.iter().all(|earlier| earlier.key != held.key) {
                self.held.push(held);
            }
        }
        Ok(())
    }

    /// The package: its bytes and its root.
    #[must_use]
    pub fn finish(mut self) -> BuiltPackage {
        self.held.sort_by_key(|held| held.key.digest());
        let modules = self.builder.modules.iter().map(Added::held);
        assemble(self.builder.entries(modules, &self.held))
    }
}

/// A compiled message's bytes.
fn encode_message(message: &MessageForm) -> Vec<u8> {
    let mut writer = Writer::default();
    write_message(&mut writer, message);
    writer.finish()
}

/// Where each entry after the manifest lies: one after the other.
fn locations(entries: &[Vec<u8>]) -> Vec<Location> {
    let mut offset = 0;
    entries
        .iter()
        .skip(1)
        .map(|entry| {
            let location = Location {
                offset,
                length: entry.len(),
            };
            offset += entry.len();
            location
        })
        .collect()
}

/// The package of `entries`, the manifest first: the header, the tree's nodes, the entries.
fn assemble(entries: Vec<Vec<u8>>) -> BuiltPackage {
    let tree = merkle::tree(&entries);
    let manifest = entries.first().map_or(0, Vec::len);
    let mut bytes = Vec::with_capacity(HEADER);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&FORMAT.to_be_bytes());
    bytes.extend_from_slice(&tree.root);
    bytes.extend_from_slice(&(entries.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&(manifest as u64).to_be_bytes());
    for node in &tree.nodes {
        bytes.extend_from_slice(node);
    }
    for entry in &entries {
        bytes.extend_from_slice(entry);
    }
    BuiltPackage {
        bytes,
        root: tree.root,
    }
}

impl Package<'_> {
    /// The package written again from its entries, each read, checked against the root,
    /// decoded and encoded: the same bytes for a package this crate wrote.
    ///
    /// # Errors
    ///
    /// The [`PackageError`] of an entry the package refuses; [`PackageError::Malformed`] for an
    /// entry the manifest and the locale entries do not each name once.
    pub fn rewrite(&self) -> Result<BuiltPackage, PackageError> {
        let manifest = self.manifest()?;
        let mut entries: Vec<Option<Vec<u8>>> = vec![None; manifest.locations.len() + 1];
        let mut place = |entry: usize, bytes: Vec<u8>| match entries.get_mut(entry) {
            Some(slot @ None) => {
                *slot = Some(bytes);
                Ok(())
            }
            Some(Some(_)) | None => Err(PackageError::Malformed { entry }),
        };
        place(0, manifest.encode())?;
        for locale in manifest.modules.iter().flat_map(|module| &module.locales) {
            let index = self.locale_index(&manifest, locale.entry)?;
            for message in &index.messages {
                place(
                    message.entry,
                    encode_message(&self.message(&manifest, message.entry)?),
                )?;
            }
            place(locale.entry, index.encode())?;
        }
        for held in &manifest.held {
            place(held.entry, self.held(&manifest, held.entry)?.encode())?;
        }
        let entries = entries
            .into_iter()
            .enumerate()
            .map(|(entry, bytes)| bytes.ok_or(PackageError::Malformed { entry }))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(assemble(entries))
    }
}
