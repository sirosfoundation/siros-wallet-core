//! RFC 4647 §3.3.1 basic filtering for one language range.

use crate::ids::LocaleTag;

/// The tag a range matches among `tags`: the tag equal to it, else the first tag that extends it
/// by further subtags; compared case-insensitively. `en` matches `en`, `en-US` and `en-GB`;
/// `en-US` matches `en-US` and its extensions, and never `en` or `en-GB`.
#[must_use]
pub fn lookup<'t, T: AsRef<str>>(range: &LocaleTag, tags: &'t [T]) -> Option<&'t T> {
    let range = range.as_str();
    let equal = tags
        .iter()
        .find(|tag| tag.as_ref().eq_ignore_ascii_case(range));
    equal.or_else(|| {
        tags.iter().find(|tag| {
            let tag = tag.as_ref();
            tag.get(..range.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(range))
                && tag.as_bytes().get(range.len()) == Some(&b'-')
        })
    })
}
