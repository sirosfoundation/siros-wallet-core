//! A context's messages under their ids. An id is its text, whichever section head and key
//! write it: `[a] b.c` and `[a.b] c` are one id. The messages hold each dot-separated part of an
//! id once under the parts before it, so a section's name is held once for all its messages.

use rustc_hash::FxHashMap;

use crate::compile::Compiled;

/// The parts before one of an id's dots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Prefix(usize);

impl Prefix {
    /// No part: an id's first part is under it.
    pub(crate) const NONE: Self = Self(0);
}

/// A part under a prefix: the prefix it ends, and the message whose id it ends.
#[derive(Debug, Clone)]
struct Part {
    ends: Prefix,
    message: Option<Box<Compiled>>,
}

/// The messages of a context.
#[derive(Debug, Clone, Default)]
pub(crate) struct Messages {
    under: FxHashMap<Prefix, FxHashMap<Box<str>, Part>>,
    /// The count of the parts held, each the end of one prefix.
    parts: usize,
}

/// An id's parts before its last dot, and its last part.
fn split(id: &str) -> (impl Iterator<Item = &str>, &str) {
    let (before, last) = match id.rsplit_once('.') {
        Some((before, last)) => (Some(before), last),
        None => (None, id),
    };
    (
        before.into_iter().flat_map(|before| before.split('.')),
        last,
    )
}

impl Messages {
    /// The message of `id`; `None` when no module words it.
    pub(crate) fn find(&self, id: &str) -> Option<&Compiled> {
        let (before, last) = split(id);
        let mut prefix = Prefix::NONE;
        for part in before {
            prefix = self.under.get(&prefix)?.get(part)?.ends;
        }
        self.under.get(&prefix)?.get(last)?.message.as_deref()
    }

    /// The part `part` under `prefix`, held from now on.
    fn part(&mut self, prefix: Prefix, part: &str) -> &mut Part {
        let parts = &mut self.parts;
        self.under
            .entry(prefix)
            .or_default()
            .entry(part.into())
            .or_insert_with(|| {
                *parts += 1;
                Part {
                    ends: Prefix(*parts),
                    message: None,
                }
            })
    }

    /// The prefix the ids of a section named `name` start with.
    pub(crate) fn section(&mut self, name: &str) -> Prefix {
        name.split('.')
            .fold(Prefix::NONE, |prefix, part| self.part(prefix, part).ends)
    }

    /// Where the message whose id is `key` after `prefix` is held: `None` until a module words
    /// it.
    pub(crate) fn slot(&mut self, prefix: Prefix, key: &str) -> &mut Option<Box<Compiled>> {
        let (before, last) = split(key);
        let prefix = before.fold(prefix, |prefix, part| self.part(prefix, part).ends);
        &mut self.part(prefix, last).message
    }
}
