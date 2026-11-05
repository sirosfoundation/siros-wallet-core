//! RFC 4647 §3.3.1 basic filtering for one language range over received tags.

use crate::ids::LocaleTag;

/// The tag a range matches among `tags` by [`LocaleTag::filters`]: the tag equal to it, else the
/// first tag that extends it by further subtags. A text outside the language tag grammar matches
/// no range.
#[must_use]
pub fn lookup<'t, T: AsRef<str>>(range: &LocaleTag, tags: &'t [T]) -> Option<&'t T> {
    let parsed: Vec<(LocaleTag, &'t T)> = tags
        .iter()
        .filter_map(|tag| {
            LocaleTag::parse(tag.as_ref())
                .ok()
                .map(|parsed| (parsed, tag))
        })
        .collect();
    let equal = parsed.iter().find(|(tag, _)| tag == range);
    equal
        .or_else(|| parsed.iter().find(|(tag, _)| range.filters(tag)))
        .map(|(_, tag)| *tag)
}
