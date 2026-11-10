//! A context's messages under their ids. A message's id is its section's name, a dot and its
//! key, or its key alone before a resource's first section head. The store holds a section's name
//! once for all its messages, and finds an id by its text's hash: a section's name is hashed once,
//! and each of its keys from that hash.

use std::fmt;

use rustc_hash::FxHashMap;

use crate::compile::Compiled;
use crate::error::LoadError;
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
    /// The message of `id`.
    pub(crate) fn find(&self, id: &str) -> Option<&Compiled> {
        let id = Id {
            section: None,
            key: id,
        };
        self.under(hash(0, id.bytes()))
            .find(|held| self.id(held).is_some_and(|held| held.is(id)))
            .map(|held| &held.message)
    }

    /// Holds a resource section's messages, each compiled by `compile` under its id.
    ///
    /// # Errors
    ///
    /// [`LoadError::Repeated`] for an id a message holds, and the error of `compile`.
    pub(crate) fn hold(
        &mut self,
        section: MessageSection,
        compile: impl FnMut(Id<'_>, &Entry) -> Result<Compiled, LoadError>,
    ) -> Result<(), LoadError> {
        let named = section.name.map(Section::named);
        let at = named.as_ref().map(|_| self.sections.len());
        let held = self.entries(at, named.as_ref(), section.entries, compile);
        self.sections.extend(named);
        held
    }

    /// Holds the entries of the section `named` at `at`, which the store holds once they are.
    fn entries(
        &mut self,
        at: Option<usize>,
        named: Option<&Section>,
        entries: Vec<Entry>,
        mut compile: impl FnMut(Id<'_>, &Entry) -> Result<Compiled, LoadError>,
    ) -> Result<(), LoadError> {
        let prefix = named.map_or(0, |section| section.hash);
        for entry in entries {
            let id = Id {
                section: named.map(|section| section.name.as_str()),
                key: &entry.key,
            };
            let hash = hash(prefix, entry.key.bytes());
            if self.under(hash).any(|held| {
                (held.section == at && held.key == entry.key)
                    || self.id(held).is_some_and(|held| held.is(id))
            }) {
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
        Ok(())
    }

    /// The messages whose ids hash to `hash`, the last held first.
    fn under(&self, hash: u64) -> impl Iterator<Item = &Held> {
        let last = self.last.get(&hash).and_then(|&at| self.held.get(at));
        std::iter::successors(last, |held| held.next.and_then(|at| self.held.get(at)))
    }

    /// A held message's id; `None` for a message of the section [`Store::hold`] holds, which
    /// the store holds after its messages.
    fn id<'a>(&'a self, held: &'a Held) -> Option<Id<'a>> {
        let section = match held.section {
            None => None,
            Some(at) => Some(self.sections.get(at)?.name.as_str()),
        };
        Some(Id {
            section,
            key: &held.key,
        })
    }
}
