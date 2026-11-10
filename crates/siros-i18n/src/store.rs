//! A context's messages under their ids. A message's id is its section's name, a dot and its
//! key, or its key alone before a resource's first section head. The store holds a section's name
//! once for all its messages, and finds an id by its text's hash: a section's name is hashed once,
//! and each of its keys from that hash.

use std::fmt;

use rustc_hash::FxHashMap;

use crate::compile::Compiled;
use crate::error::{Defect, LoadError};
use crate::resource::{Entry, MessageSection};

/// A message's id: its section's name, `None` before a resource's first section head, and its
/// key.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Id<'a> {
    section: Option<&'a str>,
    key: &'a str,
}

impl Id<'_> {
    /// Its text's bytes.
    fn bytes(self) -> impl Iterator<Item = u8> {
        self.section
            .into_iter()
            .flat_map(|name| name.bytes().chain(*b"."))
            .chain(self.key.bytes())
    }

    /// Its text's length in bytes.
    fn len(self) -> usize {
        self.section.map_or(0, |name| name.len() + 1) + self.key.len()
    }

    /// Whether `other` has its text.
    fn is(self, other: Id<'_>) -> bool {
        self.len() == other.len() && self.bytes().eq(other.bytes())
    }
}

impl fmt::Display for Id<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.section {
            Some(name) => write!(f, "{name}.{}", self.key),
            None => f.write_str(self.key),
        }
    }
}

/// `hash` continued over `bytes` by FxHash's step (rustc-hash 1's `FxHasher`) on each byte: a
/// text hashes the same whatever parts it is fed in.
fn hash(hash: u64, bytes: impl IntoIterator<Item = u8>) -> u64 {
    bytes.into_iter().fold(hash, |hash, byte| {
        (hash.rotate_left(5) ^ u64::from(byte)).wrapping_mul(0x517c_c1b7_2722_0a95)
    })
}

/// A section's name, and the hash of the name and a dot, which its ids' hashes continue.
#[derive(Debug, Clone)]
struct Section {
    name: String,
    hash: u64,
}

impl Section {
    fn named(name: String) -> Self {
        Self {
            hash: hash(hash(0, name.bytes()), *b"."),
            name,
        }
    }
}

/// A message: the index of its section, `None` before a resource's first section head, its key,
/// and the index of the message held before it whose id hashes the same.
#[derive(Debug, Clone)]
struct Held {
    section: Option<usize>,
    key: String,
    message: Compiled,
    next: Option<usize>,
}

/// The messages of a context, each id once.
#[derive(Debug, Clone, Default)]
pub(crate) struct Store {
    sections: Vec<Section>,
    held: Vec<Held>,
    /// The index of the last message held under each hash of an id.
    last: FxHashMap<u64, usize>,
}

impl Store {
    /// The message of `id`; `None` when no module words it.
    ///
    /// # Errors
    ///
    /// [`Defect`] for a held message whose section or hash chain names no entry.
    pub(crate) fn find(&self, id: &str) -> Result<Option<&Compiled>, Defect> {
        let id = Id {
            section: None,
            key: id,
        };
        let found = self.first(hash(0, id.bytes()), |held| Ok(self.id(held, None)?.is(id)))?;
        Ok(found.map(|held| &held.message))
    }

    /// Holds a resource section's messages, each compiled by `compile` under its id. The store
    /// holds the section's name after its messages.
    ///
    /// # Errors
    ///
    /// [`LoadError::Repeated`] for an id a message holds, [`LoadError::Defect`] for a held
    /// message whose section or hash chain names no entry, and the error of `compile`.
    pub(crate) fn hold(
        &mut self,
        section: MessageSection,
        mut compile: impl FnMut(Id<'_>, &Entry) -> Result<Compiled, LoadError>,
    ) -> Result<(), LoadError> {
        let named = section.name.map(Section::named);
        let at = named.as_ref().map(|_| self.sections.len());
        let prefix = named.as_ref().map_or(0, |section| section.hash);
        for entry in section.entries {
            let id = Id {
                section: named.as_ref().map(|section| section.name.as_str()),
                key: &entry.key,
            };
            let hash = hash(prefix, entry.key.bytes());
            let repeated = self
                .first(hash, |held| Ok(self.id(held, named.as_ref())?.is(id)))
                .map_err(|Defect| LoadError::Defect { id: id.to_string() })?;
            if repeated.is_some() {
                return Err(LoadError::Repeated { id: id.to_string() });
            }
            let message = compile(id, &entry)?;
            let next = self.last.insert(hash, self.held.len());
            self.held.push(Held {
                section: at,
                key: entry.key,
                message,
                next,
            });
        }
        self.sections.extend(named);
        Ok(())
    }

    /// The last message held under `hash` that `matches`: the messages held under it are walked
    /// from the last.
    ///
    /// # Errors
    ///
    /// [`Defect`] for a chain that names no held message, and the error of `matches`.
    fn first(
        &self,
        hash: u64,
        mut matches: impl FnMut(&Held) -> Result<bool, Defect>,
    ) -> Result<Option<&Held>, Defect> {
        let mut next = self.last.get(&hash).copied();
        while let Some(at) = next {
            let held = self.held.get(at).ok_or(Defect)?;
            if matches(held)? {
                return Ok(Some(held));
            }
            next = held.next;
        }
        Ok(None)
    }

    /// A held message's id. `pending` is the section [`Store::hold`] holds, whose index is the
    /// count of the held sections.
    ///
    /// # Errors
    ///
    /// [`Defect`] for a section index past the held sections and the pending one.
    fn id<'a>(&'a self, held: &'a Held, pending: Option<&'a Section>) -> Result<Id<'a>, Defect> {
        let section = match held.section {
            None => None,
            Some(at) => {
                let section = match self.sections.get(at) {
                    Some(section) => section,
                    None if at == self.sections.len() => pending.ok_or(Defect)?,
                    None => return Err(Defect),
                };
                Some(section.name.as_str())
            }
        };
        Ok(Id {
            section,
            key: &held.key,
        })
    }
}
