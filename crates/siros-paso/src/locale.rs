//! View §4 under the core's matching (section 4.14 of the design): the entries of a display array
//! a language takes, by RFC 4647 basic filtering over its tagged entries, then its default entry;
//! and the languages a type's display rules serve among the wallet's.

use rustc_hash::FxHashSet;
use siros_openid4vp::ids::LocaleTag;

use crate::conform::ClaimIndex;
use crate::metadata::{DisplayArray, EntryLocale, LabelForm, Localized, UiKey};

/// A display array by what it labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ArrayKey {
    /// A claim's `display`.
    Claim(ClaimIndex),
    /// A UI label's entries.
    Ui(UiKey),
}

/// The entries a template whose claim is absent discards (View §3 template).
#[derive(Debug, Default)]
pub(crate) struct Discarded(FxHashSet<(ArrayKey, usize)>);

impl Discarded {
    /// Discards an array's entry at a position.
    pub(crate) fn discard(&mut self, key: ArrayKey, position: usize) {
        self.0.extend([(key, position)]);
    }

    /// Whether an array's entry at a position is discarded.
    pub(crate) fn holds(&self, key: ArrayKey, position: usize) -> bool {
        self.0.contains(&(key, position))
    }
}

/// An entry of an array, with its position in the array.
pub(crate) type Placed<'a, 'm> = (usize, &'a Localized<'m>);

/// The entries a language takes from an array, in the order it takes them: the entry whose tag
/// equals the language, then those whose tags extend it, in the array's order, then the default
/// entry; up to the first that no absent claim discards, a label other than a template. A tag
/// outside RFC 4647's grammar matches no language.
pub(crate) fn chain<'a, 'm>(
    array: &'a DisplayArray<'m>,
    language: &LocaleTag,
) -> Vec<Placed<'a, 'm>> {
    let entries: Vec<Placed<'a, 'm>> = array.entries().iter().enumerate().collect();
    let tagged = |(_, entry): &Placed<'a, 'm>| match entry.locale {
        EntryLocale::Tagged(tag) => LocaleTag::parse(tag).ok(),
        EntryLocale::Default => None,
    };
    let equal = entries
        .iter()
        .filter(|entry| tagged(entry).as_ref() == Some(language));
    let extending = entries.iter().filter(|entry| {
        tagged(entry).is_some_and(|tag| tag != *language && language.filters(&tag))
    });
    let default = entries
        .iter()
        .filter(|(_, entry)| entry.locale == EntryLocale::Default);
    let mut out = Vec::new();
    for entry in equal.chain(extending).chain(default) {
        out.push(*entry);
        if !matches!(entry.1.label, LabelForm::Template(_)) {
            break;
        }
    }
    out
}

/// The languages a type's display rules serve among the wallet's languages: each wallet language
/// and each of its shorter subtag prefixes, each once, from which every array takes an entry
/// `discarded` leaves. Every language a presentation can take is one of them: the wallet's
/// modules serve no other.
pub(crate) fn languages(
    arrays: &[(ArrayKey, &DisplayArray<'_>)],
    wallet: &[LocaleTag],
    discarded: &Discarded,
) -> Vec<LocaleTag> {
    let mut out: Vec<LocaleTag> = Vec::new();
    for tag in prefixes(wallet) {
        if arrays.iter().all(|(key, array)| {
            chain(array, &tag)
                .iter()
                .any(|(position, _)| !discarded.holds(*key, *position))
        }) {
            out.push(tag);
        }
    }
    out
}

/// Each tag and each of its shorter subtag prefixes, shortest first, each once.
pub(crate) fn prefixes(tags: &[LocaleTag]) -> Vec<LocaleTag> {
    let mut out: Vec<LocaleTag> = Vec::new();
    for tag in tags {
        let text = tag.as_str();
        let ends = text
            .match_indices('-')
            .map(|(at, _)| at)
            .chain(std::iter::once(text.len()));
        for end in ends {
            if let Some(prefix) = text.get(..end).and_then(|head| LocaleTag::parse(head).ok())
                && !out.contains(&prefix)
            {
                out.push(prefix);
            }
        }
    }
    out
}
