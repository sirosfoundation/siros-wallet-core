//! RFC 4647 §3.4 Lookup for one language range.

use crate::ids::LocaleTag;

/// The ranges Lookup tries, in order: the range progressively truncated from the end, a
/// single-character subtag removed together with the subtag after it.
#[must_use]
pub fn lookup_chain(range: &str) -> Vec<String> {
    let subtags: Vec<&str> = range.split('-').collect();
    let mut chain = Vec::new();
    let mut end = subtags.len();
    while let Some(kept) = subtags.get(..end).filter(|kept| !kept.is_empty()) {
        chain.push(kept.join("-"));
        end -= 1;
        while end > 0
            && subtags
                .get(end - 1)
                .is_some_and(|subtag| subtag.chars().count() == 1)
        {
            end -= 1;
        }
    }
    chain
}

/// The tag Lookup selects among `tags` for one range, compared case-insensitively.
#[must_use]
pub fn lookup<'t, T: AsRef<str>>(range: &LocaleTag<'_>, tags: &'t [T]) -> Option<&'t T> {
    lookup_chain(range.as_str())
        .into_iter()
        .find_map(|candidate| {
            tags.iter()
                .find(|tag| tag.as_ref().to_lowercase() == candidate.to_lowercase())
        })
}
