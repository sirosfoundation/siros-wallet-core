//! Language tags, RFC 4647 basic filtering and Lookup's truncations.

use std::fmt;

use siros_explain::{IntoArg, kind};

/// A language tag, as a module's locale or an entry of a priority list: RFC 4647 §2.1's
/// `1*8ALPHA *("-" 1*8alphanum)`, held in RFC 5646 §2.1.1's case: the language in lowercase, a
/// four-letter script in title case, a two-letter region in uppercase, everything after a
/// singleton in lowercase. Tags that differ in case alone are one tag. Only [`LocaleTag::parse`]
/// makes one.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LocaleTag(Box<str>);

/// A text that is no language tag.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, siros_explain::Explain)]
#[explain(domain = "i18n.locale")]
#[error("{tag} is no language tag")]
pub struct InvalidTag {
    /// The text.
    pub tag: String,
}

impl LocaleTag {
    /// The tag `text` writes.
    ///
    /// # Errors
    ///
    /// [`InvalidTag`] for a text outside the grammar.
    pub fn parse(text: &str) -> Result<Self, InvalidTag> {
        let invalid = || InvalidTag {
            tag: text.to_owned(),
        };
        let mut canonical = String::with_capacity(text.len());
        let mut after_singleton = false;
        for (index, subtag) in text.split('-').enumerate() {
            let bytes = subtag.as_bytes();
            let first = index == 0;
            let fits = (1..=8).contains(&bytes.len())
                && if first {
                    bytes.iter().all(u8::is_ascii_alphabetic)
                } else {
                    bytes.iter().all(u8::is_ascii_alphanumeric)
                };
            if !fits {
                return Err(invalid());
            }
            if !first {
                canonical.push('-');
            }
            let lower = subtag.to_ascii_lowercase();
            if first || after_singleton {
                canonical.push_str(&lower);
            } else if bytes.len() == 2 {
                canonical.push_str(&subtag.to_ascii_uppercase());
            } else if bytes.len() == 4 && bytes.iter().all(u8::is_ascii_alphabetic) {
                let mut chars = lower.chars();
                canonical.extend(chars.next().map(|c| c.to_ascii_uppercase()));
                canonical.extend(chars);
            } else {
                canonical.push_str(&lower);
            }
            after_singleton |= !first && bytes.len() == 1;
        }
        Ok(Self(canonical.into_boxed_str()))
    }

    /// Its text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The ranges RFC 4647 §3.4's Lookup tries for this tag as the range, in order: the tag, then
    /// the tag truncated from the end one subtag at a time, a single-character subtag dropped
    /// with the subtag after it. `de-CH` gives `de-CH`, `de`; `zh-Hant-CN-x-private1-private2`
    /// gives it, `zh-Hant-CN-x-private1`, `zh-Hant-CN`, `zh-Hant`, `zh`.
    #[must_use]
    pub fn truncations(&self) -> Vec<Self> {
        let mut out = vec![self.clone()];
        let mut rest: &str = &self.0;
        while let Some((kept, _)) = rest.rsplit_once('-') {
            rest = kept;
            while let Some((kept, last)) = rest.rsplit_once('-')
                && last.len() == 1
            {
                rest = kept;
            }
            out.push(Self(rest.into()));
        }
        out
    }

    /// Whether this tag, as a basic language range, matches `tag` by RFC 4647 §3.3.1 basic
    /// filtering: `tag` equals it or extends it by further subtags. `en` matches `en`, `en-US`
    /// and `en-GB`; `en-US` matches neither `en` nor `en-GB`.
    #[must_use]
    pub fn filters(&self, tag: &Self) -> bool {
        tag.0
            .strip_prefix(&*self.0)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('-'))
    }
}

impl fmt::Display for LocaleTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl IntoArg for LocaleTag {
    type Kind = kind::Raw;

    fn arg(&self) -> &str {
        &self.0
    }
}
