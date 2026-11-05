//! View §4: the first locale of the End-User's priority list for which every display array has
//! an entry, by RFC 4647 basic filtering over its tagged entries, else its default entry.

use rustc_hash::FxHashSet;
use siros_openid4vp::ids::LocaleTag;
use siros_openid4vp::text::lookup;

use crate::conform::ClaimIndex;
use crate::metadata::{DisplayArray, EntryLocale, Localized, UiKey};

/// A display array by what it labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ArrayKey {
    /// A claim's `display`.
    Claim(ClaimIndex),
    /// A UI label's entries.
    Ui(UiKey),
}

/// The entries a template whose claim is absent discards: they take no part in the selection
/// (View §3 template).
#[derive(Debug, Default)]
pub(crate) struct Discarded(FxHashSet<(ArrayKey, usize)>);

impl Discarded {
    /// Discards an array's entry at a position.
    pub(crate) fn discard(&mut self, key: ArrayKey, position: usize) {
        self.0.extend([(key, position)]);
    }

    fn holds(&self, key: ArrayKey, position: usize) -> bool {
        self.0.contains(&(key, position))
    }
}

/// An entry a locale matched: its position in its array, and the entry.
pub(crate) type Matched<'a, 'm> = (usize, &'a Localized<'m>);

/// The selected locale and the entry it matched in each array.
#[derive(Debug)]
pub(crate) struct Selection<'a, 'm> {
    /// The locale.
    pub(crate) locale: LocaleTag,
    chosen: Vec<(ArrayKey, Matched<'a, 'm>)>,
}

impl<'a, 'm> Selection<'a, 'm> {
    /// The entry matched in an array.
    pub(crate) fn entry(&self, key: ArrayKey) -> Option<Matched<'a, 'm>> {
        self.chosen
            .iter()
            .find(|(known, _)| *known == key)
            .map(|(_, matched)| *matched)
    }
}

/// The first locale of the list for which every array matches: basic filtering over the array's
/// tagged entries not discarded, else its first default entry not discarded. `None` when no
/// locale matches every array.
pub(crate) fn select<'l, 'a, 'm>(
    arrays: &[(ArrayKey, &'a DisplayArray<'m>)],
    locales: impl IntoIterator<Item = &'l LocaleTag>,
    discarded: &Discarded,
) -> Option<Selection<'a, 'm>> {
    locales.into_iter().find_map(|tag| {
        let chosen = arrays
            .iter()
            .map(|(key, array)| matched(*key, array, tag, discarded).map(|entry| (*key, entry)))
            .collect::<Option<Vec<_>>>()?;
        Some(Selection {
            locale: tag.clone(),
            chosen,
        })
    })
}

/// The entry of one array a locale matches, with its position.
fn matched<'a, 'm>(
    key: ArrayKey,
    array: &'a DisplayArray<'m>,
    tag: &LocaleTag,
    discarded: &Discarded,
) -> Option<Matched<'a, 'm>> {
    let live: Vec<Matched<'a, 'm>> = array
        .entries()
        .iter()
        .enumerate()
        .filter(|(position, _)| !discarded.holds(key, *position))
        .collect();
    let tags: Vec<&str> = live
        .iter()
        .filter_map(|(_, entry)| match entry.locale {
            EntryLocale::Tagged(tag) => Some(tag),
            EntryLocale::Default => None,
        })
        .collect();
    let looked_up = lookup(tag, &tags).and_then(|found| {
        live.iter()
            .find(|(_, entry)| entry.locale == EntryLocale::Tagged(found))
            .copied()
    });
    looked_up.or_else(|| {
        live.iter()
            .find(|(_, entry)| entry.locale == EntryLocale::Default)
            .copied()
    })
}
