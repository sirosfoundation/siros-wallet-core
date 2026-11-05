//! View §4: the locale of a transaction's texts. For each tag of the End-User's priority list in
//! order, every display array takes the entry RFC 4647 §3.4's Lookup finds with the tag as the
//! range over its tagged entries, else its first entry without a locale; the first tag whose every
//! array matches is selected. An entry a template with an absent claim discards takes no part
//! (View §3).

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

/// The ranges RFC 4647 §3.4's Lookup tries for `range`, in order: the range, then the range
/// progressively truncated from the end, a single-character subtag removed together with the
/// subtag after it.
fn truncations(range: &LocaleTag) -> Vec<&str> {
    let text = range.as_str();
    let mut ends: Vec<usize> = vec![text.len()];
    let subtags: Vec<(usize, &str)> = text
        .match_indices('-')
        .map(|(at, _)| at)
        .zip(text.split('-').skip(1))
        .collect();
    let mut kept = subtags.len();
    while kept > 0 {
        kept -= 1;
        while kept > 0 && subtags.get(kept - 1).is_some_and(|(_, s)| s.len() == 1) {
            kept -= 1;
        }
        ends.extend(subtags.get(kept).map(|(at, _)| *at));
    }
    ends.into_iter().filter_map(|end| text.get(..end)).collect()
}

/// The entries View §4 tries for `tag` in an array, in order: for each range Lookup tries, the
/// entries whose tag equals it, compared case-insensitively, in the array's order; then the
/// entries without a locale. The list ends with the first label other than a template, which no
/// absent claim discards.
pub(crate) fn chain<'a, 'm>(array: &'a DisplayArray<'m>, tag: &LocaleTag) -> Vec<Placed<'a, 'm>> {
    let entries: Vec<Placed<'a, 'm>> = array.entries().iter().enumerate().collect();
    let looked_up = truncations(tag).into_iter().flat_map(|range| {
        entries.iter().filter(move |(_, entry)| match entry.locale {
            EntryLocale::Tagged(written) => written.eq_ignore_ascii_case(range),
            EntryLocale::Default => false,
        })
    });
    let default = entries
        .iter()
        .filter(|(_, entry)| entry.locale == EntryLocale::Default);
    let mut out = Vec::new();
    for entry in looked_up.chain(default) {
        out.push(*entry);
        if !matches!(entry.1.label, LabelForm::Template(_)) {
            break;
        }
    }
    out
}

/// The entry View §4 matches for `tag` in an array: the first of its [`chain`] that `discarded`
/// leaves.
pub(crate) fn matched<'a, 'm>(
    key: ArrayKey,
    array: &'a DisplayArray<'m>,
    tag: &LocaleTag,
    discarded: &Discarded,
) -> Option<Placed<'a, 'm>> {
    chain(array, tag)
        .into_iter()
        .find(|(position, _)| !discarded.holds(key, *position))
}

/// View §4: the first tag of the priority list for which every array matches.
pub(crate) fn select(
    arrays: &[(ArrayKey, &DisplayArray<'_>)],
    priority: &[LocaleTag],
    discarded: &Discarded,
) -> Option<LocaleTag> {
    priority
        .iter()
        .find(|tag| {
            arrays
                .iter()
                .all(|(key, array)| matched(*key, array, tag, discarded).is_some())
        })
        .cloned()
}

/// The tags of the priority list View §4 can select, each once: those for which every array
/// matches while no entry is discarded.
pub(crate) fn selectable(
    arrays: &[(ArrayKey, &DisplayArray<'_>)],
    priority: &[LocaleTag],
) -> Vec<LocaleTag> {
    let mut out: Vec<LocaleTag> = Vec::new();
    for tag in priority {
        if !out.contains(tag)
            && arrays
                .iter()
                .all(|(_, array)| !chain(array, tag).is_empty())
        {
            out.push(tag.clone());
        }
    }
    out
}

/// The tag among `tags` RFC 4647 §3.4's Lookup finds for `range`.
pub(crate) fn lookup<'t>(range: &LocaleTag, tags: &'t [LocaleTag]) -> Option<&'t LocaleTag> {
    truncations(range).into_iter().find_map(|truncated| {
        tags.iter()
            .find(|tag| tag.as_str().eq_ignore_ascii_case(truncated))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4647 §3.4's example range, and a range whose singleton ends a truncation.
    #[test]
    fn lookup_truncates_as_rfc_4647_3_4_writes() {
        let tag = |text: &str| LocaleTag::parse(text).expect("a tag");
        assert_eq!(
            truncations(&tag("zh-Hant-CN-x-private1-private2")),
            [
                "zh-hant-cn-x-private1-private2",
                "zh-hant-cn-x-private1",
                "zh-hant-cn",
                "zh-hant",
                "zh"
            ]
            .map(|range| tag(range).as_str().to_owned())
        );
        assert_eq!(truncations(&tag("de-CH")), ["de-CH", "de"]);
        assert_eq!(truncations(&tag("en")), ["en"]);
    }
}
