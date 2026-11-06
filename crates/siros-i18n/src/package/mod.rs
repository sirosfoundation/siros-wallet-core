//! Packages: compiled modules for a set of locales and texts rendered in advance, under the RFC
//! 9162 Merkle tree root of their entries, which is the package's identity.
//!
//! The layout, integers big-endian:
//!
//! | Bytes | Content |
//! | :-- | :-- |
//! | 8 | `SIROSPKG` |
//! | 2 | the format version, [`FORMAT`] |
//! | 32 | the root: RFC 9162 §2.1.1's MTH over the entries, SHA-256, leaf prefix 0x00, node prefix 0x01 |
//! | 8 | the entry count `n`, one or more |
//! | 8 | the manifest's length |
//! | 32·(2n − 1) | the tree's nodes in RFC 9420 Appendix C's array order: leaf `i` at `2i`, the root at 2^⌈log2 n⌉ − 1 |
//! | | the manifest, entry 0 |
//! | | the other entries, one after the other, each as long as the manifest says; the bytes end with the last |
//!
//! The manifest records the renderer's version, the package's locales, each module's identity,
//! digest, language policy and locale entries, the precomputed texts' digests, a registration's
//! inputs (its lists, its rendering options, each credential with its candidate languages, each
//! transaction type with its module), and each other entry's length. A locale entry holds a module's direction, formats, bare formats and message
//! index in one locale; a message entry one compiled message; a held entry one precomputed text
//! with its key, the modules it drew from and its formatted spans.
//!
//! A reader takes an entry and its audit path, RFC 9162 §2.1.3.1's, alone: the entry's bytes and
//! at most ⌈log2 n⌉ nodes of 32 bytes. It checks the entry against the root before it decodes it,
//! as fs-verity checks a block when it reads it. [`Package::read`] checks the root's node against
//! the root, and the manifest's read checks that the bytes end with the last entry, so a root
//! reads one byte string.

#[cfg(feature = "load")]
mod builder;
mod codec;
mod held;
mod manifest;
mod merkle;
mod registration;

#[cfg(feature = "load")]
pub use builder::{BuiltPackage, PackageBuilder, PackageTexts, RegistrationBuilder};
pub(crate) use codec::{replay, write_direction, write_message};
pub(crate) use held::{Held, TextKey};
pub(crate) use manifest::{LocaleIndex, Manifest, ModuleRecord, StoredKind, module_name};
pub use registration::{
    Candidates, CredentialName, CredentialRecord, Registration, TransactionKind,
};

use crate::defined::MainLocale;
use crate::error::PackageError;
use crate::form::MessageForm;

/// The package format's version, which the header names.
pub const FORMAT: u16 = 1;

/// The header's first bytes.
const MAGIC: &[u8; 8] = b"SIROSPKG";

/// The header's length: the magic, the version, the root, the entry count and the manifest's
/// length.
const HEADER: usize = 8 + 2 + 32 + 8 + 8;

/// A node's length.
const NODE: usize = 32;

/// Where an entry lies, after the manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Location {
    pub(crate) offset: usize,
    pub(crate) length: usize,
}

/// A package's RFC 9162 Merkle tree root: its identity, which its holder keeps beside its bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackageRoot([u8; 32]);

impl PackageRoot {
    /// The root a holder kept as these bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The root's bytes.
    #[must_use]
    pub const fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A package over its serialized bytes, its header read. Each entry is checked against the root
/// when it is read. Only [`Package::read`] makes one.
#[derive(Debug, Clone, Copy)]
pub struct Package<'p> {
    bytes: &'p [u8],
    root: PackageRoot,
    entries: usize,
    manifest: usize,
}

/// A big-endian `u64` at `at`, as a `usize`.
fn word(bytes: &[u8], at: usize) -> Option<usize> {
    let word: [u8; 8] = bytes.get(at..at + 8)?.try_into().ok()?;
    usize::try_from(u64::from_be_bytes(word)).ok()
}

impl<'p> Package<'p> {
    /// The package of `bytes`: its header and the root's node read alone.
    ///
    /// # Errors
    ///
    /// [`PackageError::Version`] for bytes that are no package of format version [`FORMAT`],
    /// [`PackageError::Root`] for a header or a root node whose root is not `root`, and
    /// [`PackageError::Bounds`] for a manifest the bytes cannot hold.
    pub fn read(bytes: &'p [u8], root: PackageRoot) -> Result<Self, PackageError> {
        let header = bytes.get(..HEADER).ok_or(PackageError::Version)?;
        if header.get(..8) != Some(MAGIC.as_slice())
            || header.get(8..10) != Some(FORMAT.to_be_bytes().as_slice())
        {
            return Err(PackageError::Version);
        }
        if header.get(10..42) != Some(root.bytes().as_slice()) {
            return Err(PackageError::Root);
        }
        let bounds = PackageError::Bounds { entry: 0 };
        let entries = word(header, 42).filter(|&n| n > 0).ok_or(bounds.clone())?;
        let manifest = word(header, 50).ok_or(bounds.clone())?;
        let package = Self {
            bytes,
            root,
            entries,
            manifest,
        };
        let end = package
            .data()
            .and_then(|data| data.checked_add(manifest))
            .ok_or(bounds.clone())?;
        if end > bytes.len() {
            return Err(bounds);
        }
        let root_node = merkle::root_index(entries)
            .ok_or(PackageError::Bounds { entry: 0 })
            .and_then(|index| package.node(0, index))?;
        if root_node != *root.bytes() {
            return Err(PackageError::Root);
        }
        Ok(package)
    }

    /// Where each entry lies in the bytes, entry 0 the manifest: what a reader reads of an entry
    /// beside its audit path, which an auditor of the bytes a reader reads takes.
    ///
    /// # Errors
    ///
    /// The [`PackageError`] of the manifest.
    pub fn spans(&self) -> Result<Vec<std::ops::Range<usize>>, PackageError> {
        let manifest = self.manifest()?;
        let bounds = PackageError::Bounds { entry: 0 };
        let start = self.data().ok_or(bounds.clone())?;
        let data = start.checked_add(self.manifest).ok_or(bounds.clone())?;
        let mut spans = Vec::with_capacity(self.entries);
        spans.push(start..data);
        for entry in 1..self.entries {
            let location = manifest.location(entry)?;
            let begin = data.checked_add(location.offset).ok_or(bounds.clone())?;
            let end = begin.checked_add(location.length).ok_or(bounds.clone())?;
            spans.push(begin..end);
        }
        Ok(spans)
    }

    /// The identifiers of the compiled messages its main and crate modules hold, each once,
    /// sorted. A defined module's keys are its converter's.
    ///
    /// # Errors
    ///
    /// The [`PackageError`] of the manifest or of a locale entry.
    pub fn keys(&self) -> Result<Vec<String>, PackageError> {
        let manifest = self.manifest()?;
        let mut keys = Vec::new();
        let named = manifest
            .modules
            .iter()
            .filter(|module| !matches!(module.id.kind(), StoredKind::Defined { .. }));
        for locale in named.flat_map(|module| &module.locales) {
            let index = self.locale_index(&manifest, locale.entry)?;
            keys.extend(index.messages.into_iter().map(|message| message.key));
        }
        keys.sort();
        keys.dedup();
        Ok(keys)
    }

    /// What a registration's package was built from beside its modules; `None` for a package
    /// built without a registration.
    ///
    /// # Errors
    ///
    /// The [`PackageError`] of the manifest.
    pub fn registration(&self) -> Result<Option<Registration>, PackageError> {
        Ok(self.manifest()?.registration)
    }

    /// The main module's locale entries, in its order: what a defined module converted with no
    /// loader formats its typed arguments with ([`DefinedForm`](crate::DefinedForm)). None for a
    /// package without a main module.
    ///
    /// # Errors
    ///
    /// The [`PackageError`] of the manifest or of a locale entry.
    pub fn main_locales(&self) -> Result<Vec<MainLocale>, PackageError> {
        let manifest = self.manifest()?;
        let main = manifest
            .modules
            .iter()
            .find(|module| *module.id.kind() == StoredKind::Main);
        main.iter()
            .flat_map(|main| &main.locales)
            .map(|locale| {
                let index = self.locale_index(&manifest, locale.entry)?;
                Ok(MainLocale {
                    locale: index.locale,
                    direction: index.direction,
                    bare: index.bare,
                })
            })
            .collect()
    }

    /// Its RFC 9162 Merkle tree root: its identity.
    #[must_use]
    pub const fn root(&self) -> PackageRoot {
        self.root
    }

    /// Where the manifest starts: after the header and the nodes.
    fn data(&self) -> Option<usize> {
        let nodes = self.entries.checked_mul(2)?.checked_sub(1)?;
        nodes.checked_mul(NODE)?.checked_add(HEADER)
    }

    /// The node at `index` of the array order.
    fn node(&self, entry: usize, index: u64) -> Result<[u8; 32], PackageError> {
        let bounds = PackageError::Bounds { entry };
        let at = usize::try_from(index)
            .ok()
            .and_then(|index| index.checked_mul(NODE)?.checked_add(HEADER))
            .ok_or(bounds.clone())?;
        let end = at.checked_add(NODE).ok_or(bounds.clone())?;
        let node = self.bytes.get(at..end).ok_or(bounds)?;
        node.try_into().map_err(|_| PackageError::Bounds { entry })
    }

    /// Entry `index` at `location` after the manifest, checked against the root.
    pub(crate) fn entry(&self, index: usize, location: Location) -> Result<&'p [u8], PackageError> {
        let bounds = PackageError::Bounds { entry: index };
        let start = self
            .data()
            .and_then(|data| {
                data.checked_add(self.manifest)?
                    .checked_add(location.offset)
            })
            .ok_or(bounds.clone())?;
        let end = start.checked_add(location.length).ok_or(bounds.clone())?;
        let bytes = self.bytes.get(start..end).ok_or(bounds)?;
        self.verify(index, bytes)
    }

    /// The manifest, checked against the root and decoded; refused unless the bytes end where
    /// its last entry ends.
    pub(crate) fn manifest(&self) -> Result<Manifest, PackageError> {
        let bounds = PackageError::Bounds { entry: 0 };
        let start = self.data().ok_or(bounds.clone())?;
        let end = start.checked_add(self.manifest).ok_or(bounds.clone())?;
        let bytes = self.bytes.get(start..end).ok_or(bounds)?;
        let manifest = Manifest::decode(self.verify(0, bytes)?, self.entries)?;
        if manifest.end().and_then(|last| last.checked_add(end)) == Some(self.bytes.len()) {
            Ok(manifest)
        } else {
            Err(PackageError::Length)
        }
    }

    /// Locale entry `entry`.
    pub(crate) fn locale_index(
        &self,
        manifest: &Manifest,
        entry: usize,
    ) -> Result<LocaleIndex, PackageError> {
        LocaleIndex::decode(self.entry(entry, manifest.location(entry)?)?, entry)
    }

    /// Message entry `entry`.
    pub(crate) fn message(
        &self,
        manifest: &Manifest,
        entry: usize,
    ) -> Result<MessageForm, PackageError> {
        let mut reader = codec::reader(self.entry(entry, manifest.location(entry)?)?, entry);
        let message = codec::message(&mut reader)?;
        if reader.is_empty() {
            Ok(message)
        } else {
            Err(reader.malformed())
        }
    }

    /// Held entry `entry`.
    pub(crate) fn held(&self, manifest: &Manifest, entry: usize) -> Result<Held, PackageError> {
        Held::decode(self.entry(entry, manifest.location(entry)?)?, entry)
    }

    /// `bytes` as entry `index`, once its audit path leads to the root.
    fn verify(&self, index: usize, bytes: &'p [u8]) -> Result<&'p [u8], PackageError> {
        let path = merkle::path(self.entries, index)
            .ok_or(PackageError::Bounds { entry: index })?
            .into_iter()
            .map(|node| self.node(index, node))
            .collect::<Result<Vec<_>, _>>()?;
        if merkle::includes(*self.root.bytes(), self.entries, index, bytes, &path) {
            Ok(bytes)
        } else {
            Err(PackageError::Integrity { entry: index })
        }
    }
}
