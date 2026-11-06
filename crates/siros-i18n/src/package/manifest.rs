//! A package's manifest, entry 0, and its locale entries: what a screen reads before any message.

use siros_explain::ModuleId;

use super::Location;
use super::codec::{EntryReader, bare, digest, direction, list, reader, tag, text};
#[cfg(feature = "load")]
use super::codec::{write_bare, write_direction, write_list};
use super::registration::Registration;
use crate::bytes::Writer;
use crate::error::PackageError;
use crate::form::{BareCalls, LanguagePolicy};
use crate::format::Direction;
use crate::locale::LocaleTag;
use crate::render::{ModuleDigest, RendererVersion};

/// What a module's identity is, as a package stores it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StoredKind {
    /// The main module.
    Main,
    /// A crate module, under its domain.
    Crate(String),
    /// A defined module: the converting plug-in's domain and the metadata's SHA-256.
    Defined {
        /// The plug-in's domain.
        plugin: String,
        /// The metadata's SHA-256.
        digest: [u8; 32],
    },
}

/// A module's identity as a package stores it: its bytes, which a caller's [`ModuleId`] is
/// compared by, and what they hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoredId {
    encoded: Vec<u8>,
    kind: StoredKind,
}

impl StoredId {
    /// The stored form of `id`.
    pub(crate) fn of(id: ModuleId) -> Self {
        Self::from_kind(match id {
            ModuleId::Main => StoredKind::Main,
            ModuleId::Crate(domain) => StoredKind::Crate(domain.as_str().to_owned()),
            ModuleId::Defined(defined) => StoredKind::Defined {
                plugin: defined.plugin().as_str().to_owned(),
                digest: defined.digest().bytes(),
            },
        })
    }

    /// The stored form of what `kind` holds.
    fn from_kind(kind: StoredKind) -> Self {
        let mut writer = Writer::default();
        match &kind {
            StoredKind::Main => writer.byte(0),
            StoredKind::Crate(domain) => {
                writer.byte(1);
                writer.text(domain);
            }
            StoredKind::Defined { plugin, digest } => {
                writer.byte(2);
                writer.text(plugin);
                writer.raw(digest);
            }
        }
        Self {
            encoded: writer.finish(),
            kind,
        }
    }

    /// Its bytes.
    #[cfg(feature = "load")]
    pub(crate) fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// What it holds.
    pub(crate) const fn kind(&self) -> &StoredKind {
        &self.kind
    }

    /// Whether it is `id`'s.
    pub(crate) fn is(&self, id: ModuleId) -> bool {
        self.encoded == Self::of(id).encoded
    }

    /// The module's name, as an error names it: `main`, a crate's domain, or a defined module's
    /// plug-in and digest in hexadecimal.
    pub(crate) fn name(&self) -> String {
        match &self.kind {
            StoredKind::Main => "main".to_owned(),
            StoredKind::Crate(domain) => domain.clone(),
            StoredKind::Defined { plugin, digest } => {
                let digest: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
                format!("{plugin}:{digest}")
            }
        }
    }

    /// A stored identity.
    pub(super) fn decode(reader: &mut EntryReader<'_>) -> Result<Self, PackageError> {
        let kind = match reader.byte()? {
            0 => StoredKind::Main,
            1 => StoredKind::Crate(text(reader)?),
            2 => StoredKind::Defined {
                plugin: text(reader)?,
                digest: digest(reader)?,
            },
            _ => return Err(reader.malformed()),
        };
        Ok(Self::from_kind(kind))
    }
}

/// A module's name, as an error names it.
pub(crate) fn module_name(id: ModuleId) -> String {
    StoredId::of(id).name()
}

/// One of a module's locales in the package, and its locale entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LocaleRef {
    pub(crate) tag: LocaleTag,
    pub(crate) entry: usize,
}

/// A module of the package: its identity, its digest, its language policy and its locales.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ModuleRecord {
    pub(crate) id: StoredId,
    pub(crate) digest: ModuleDigest,
    pub(crate) policy: LanguagePolicy,
    pub(crate) locales: Vec<LocaleRef>,
}

/// A precomputed text: its key's SHA-256, and its entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HeldRef {
    pub(crate) digest: [u8; 32],
    pub(crate) entry: usize,
}

/// The manifest: the renderer that built the package, its locales, its modules, its precomputed
/// texts by their keys' SHA-256 in ascending order, a registration's inputs, and where each other
/// entry lies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Manifest {
    pub(crate) renderer: RendererVersion,
    pub(crate) locales: Vec<LocaleTag>,
    pub(crate) modules: Vec<ModuleRecord>,
    pub(crate) held: Vec<HeldRef>,
    pub(crate) registration: Option<Registration>,
    pub(crate) locations: Vec<Location>,
}

const fn policy_byte(policy: LanguagePolicy) -> u8 {
    match policy {
        LanguagePolicy::Understood => 0,
        LanguagePolicy::Any => 1,
    }
}

impl Manifest {
    /// The manifest of a package of `entries` entries: refused when it places another number of
    /// entries, names an entry outside them, holds a module twice, or lists its texts out of
    /// order.
    pub(super) fn decode(bytes: &[u8], entries: usize) -> Result<Self, PackageError> {
        let mut reader = reader(bytes, 0);
        let reader = &mut reader;
        let renderer =
            RendererVersion::read(u16::try_from(reader.number()?).map_err(|_| reader.malformed())?);
        let locales = list(reader, tag)?;
        let entry = |reader: &mut EntryReader<'_>| {
            let entry = reader.count()?;
            if (1..entries).contains(&entry) {
                Ok(entry)
            } else {
                Err(reader.malformed())
            }
        };
        let modules = list(reader, |reader| {
            let id = StoredId::decode(reader)?;
            let digest = ModuleDigest::new(digest(reader)?);
            let byte = reader.byte()?;
            let policy = [LanguagePolicy::Understood, LanguagePolicy::Any]
                .into_iter()
                .find(|policy| policy_byte(*policy) == byte)
                .ok_or(reader.malformed())?;
            let locales = list(reader, |reader| {
                Ok(LocaleRef {
                    tag: tag(reader)?,
                    entry: entry(reader)?,
                })
            })?;
            Ok(ModuleRecord {
                id,
                digest,
                policy,
                locales,
            })
        })?;
        let held = list(reader, |reader| {
            Ok(HeldRef {
                digest: digest(reader)?,
                entry: entry(reader)?,
            })
        })?;
        let registration = if reader.flag()? {
            Some(Registration::decode(reader, &modules)?)
        } else {
            None
        };
        let lengths = list(reader, EntryReader::count)?;
        let mut offset = Some(0_usize);
        let locations = lengths.into_iter().map(|length| {
            let start = offset?;
            offset = start.checked_add(length);
            Some(Location {
                offset: start,
                length,
            })
        });
        let locations = locations
            .collect::<Option<Vec<_>>>()
            .ok_or(reader.malformed())?;
        let repeated = modules.iter().enumerate().any(|(index, module)| {
            modules
                .iter()
                .take(index)
                .any(|earlier| earlier.id == module.id)
        });
        let unordered = held.windows(2).any(|pair| match pair {
            [a, b] => a.digest >= b.digest,
            _ => false,
        });
        if repeated || unordered || locations.len() + 1 != entries || !reader.is_empty() {
            return Err(reader.malformed());
        }
        Ok(Self {
            renderer,
            locales,
            modules,
            held,
            registration,
            locations,
        })
    }

    /// Where entry `entry` lies, one of the entries after the manifest; [`PackageError::Bounds`]
    /// for an entry the manifest does not place.
    pub(crate) fn location(&self, entry: usize) -> Result<Location, PackageError> {
        entry
            .checked_sub(1)
            .and_then(|index| self.locations.get(index))
            .copied()
            .ok_or(PackageError::Bounds { entry })
    }

    /// Where the last entry ends, after the manifest; `None` past `usize`.
    pub(crate) fn end(&self) -> Option<usize> {
        self.locations
            .last()
            .map_or(Some(0), |last| last.offset.checked_add(last.length))
    }

    /// The precomputed text whose key has SHA-256 `digest`.
    pub(crate) fn held(&self, digest: &[u8; 32]) -> Option<usize> {
        let index = self
            .held
            .binary_search_by(|held| held.digest.cmp(digest))
            .ok()?;
        self.held.get(index).map(|held| held.entry)
    }

    /// The manifest's bytes.
    #[cfg(feature = "load")]
    pub(super) fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::default();
        writer.number(u64::from(self.renderer.number()));
        write_list(&mut writer, &self.locales, |writer, tag| {
            writer.text(tag.as_str());
        });
        write_list(&mut writer, &self.modules, |writer, module| {
            writer.raw(module.id.encoded());
            writer.raw(module.digest.bytes());
            writer.byte(policy_byte(module.policy));
            write_list(writer, &module.locales, |writer, locale| {
                writer.text(locale.tag.as_str());
                writer.count(locale.entry);
            });
        });
        write_list(&mut writer, &self.held, |writer, held| {
            writer.raw(&held.digest);
            writer.count(held.entry);
        });
        writer.flag(self.registration.is_some());
        if let Some(registration) = &self.registration {
            registration.encode(&mut writer);
        }
        write_list(&mut writer, &self.locations, |writer, location| {
            writer.count(location.length);
        });
        writer.finish()
    }
}

/// A message of a locale entry: its key and its entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MessageRef {
    pub(crate) key: String,
    pub(crate) entry: usize,
}

/// A module's locale entry: its tag, its direction, the formats its messages and bare formats
/// call, its bare formats, and its messages by key in ascending order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LocaleIndex {
    pub(crate) locale: LocaleTag,
    pub(crate) direction: Direction,
    pub(crate) formats: Vec<String>,
    pub(crate) bare: BareCalls,
    pub(crate) messages: Vec<MessageRef>,
}

impl LocaleIndex {
    /// Locale entry `index`: refused when its messages are out of order.
    pub(crate) fn decode(bytes: &[u8], index: usize) -> Result<Self, PackageError> {
        let mut reader = reader(bytes, index);
        let reader = &mut reader;
        let locale = tag(reader)?;
        let direction = direction(reader)?;
        let formats = list(reader, text)?;
        let bare = bare(reader)?;
        let messages = list(reader, |reader| {
            Ok(MessageRef {
                key: text(reader)?,
                entry: reader.count()?,
            })
        })?;
        let unordered = messages.windows(2).any(|pair| match pair {
            [a, b] => a.key >= b.key,
            _ => false,
        });
        if unordered || !reader.is_empty() {
            return Err(reader.malformed());
        }
        Ok(Self {
            locale,
            direction,
            formats,
            bare,
            messages,
        })
    }

    /// The entry of the message `key`.
    pub(crate) fn message(&self, key: &str) -> Option<usize> {
        let index = self
            .messages
            .binary_search_by(|message| message.key.as_str().cmp(key))
            .ok()?;
        self.messages.get(index).map(|message| message.entry)
    }

    /// The locale entry's bytes.
    #[cfg(feature = "load")]
    pub(super) fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::default();
        writer.text(self.locale.as_str());
        write_direction(&mut writer, self.direction);
        write_list(&mut writer, &self.formats, |writer, format| {
            writer.text(format)
        });
        write_bare(&mut writer, &self.bare);
        write_list(&mut writer, &self.messages, |writer, message| {
            writer.text(&message.key);
            writer.count(message.entry);
        });
        writer.finish()
    }
}
