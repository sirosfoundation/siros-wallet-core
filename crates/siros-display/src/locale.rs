//! Language tags and the locale function (D2): RFC 4647 Lookup with the wallet's language, then
//! the entry without a locale (PaSO View, Section 4).

use std::fmt;
use std::hash::{Hash, Hasher};

/// A well-formed BCP 47 language tag (RFC 5646, Section 2.1).
///
/// Tags compare without regard to ASCII case (RFC 5646, Section 2.1.1).
#[derive(Debug, Clone)]
pub struct Locale(String);

/// The irregular grandfathered tags, which no other production of RFC 5646, Section 2.1
/// matches.
const IRREGULAR: [&str; 17] = [
    "en-GB-oed",
    "i-ami",
    "i-bnn",
    "i-default",
    "i-enochian",
    "i-hak",
    "i-klingon",
    "i-lux",
    "i-mingo",
    "i-navajo",
    "i-pwn",
    "i-tao",
    "i-tay",
    "i-tsu",
    "sgn-BE-FR",
    "sgn-BE-NL",
    "sgn-CH-DE",
];

impl Locale {
    /// The tag `tag`.
    ///
    /// # Errors
    ///
    /// [`LocaleError::Malformed`] when `tag` matches no production of `Language-Tag`.
    pub fn parse(tag: &str) -> Result<Self, LocaleError> {
        let irregular = IRREGULAR.iter().any(|g| g.eq_ignore_ascii_case(tag));
        let subtags: Vec<&str> = tag.split('-').collect();
        if irregular || well_formed(&subtags) {
            Ok(Self(tag.to_owned()))
        } else {
            Err(LocaleError::Malformed)
        }
    }

    /// The tag as given.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl PartialEq for Locale {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(&other.0)
    }
}

impl Eq for Locale {}

impl Hash for Locale {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0
            .bytes()
            .for_each(|b| b.to_ascii_lowercase().hash(state));
    }
}

impl fmt::Display for Locale {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The unread subtags of a tag.
struct Subtags<'a>(&'a [&'a str]);

impl Subtags<'_> {
    /// Reads the next subtag when `accept` accepts it.
    fn skip(&mut self, accept: impl Fn(&str) -> bool) {
        if let Some((first, rest)) = self.0.split_first() {
            if accept(first) {
                self.0 = rest;
            }
        }
    }

    /// Reads the next subtag when `accept` accepts it, and says whether it did.
    fn eat(&mut self, accept: impl Fn(&str) -> bool) -> bool {
        let before = self.0.len();
        self.skip(accept);
        self.0.len() < before
    }
}

fn alpha(s: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphabetic())
}

fn alnum(s: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric())
}

fn private_use_prefix(s: &str) -> bool {
    s.eq_ignore_ascii_case("x")
}

/// `langtag / privateuse`. The regular grandfathered tags match `langtag`.
fn well_formed(subtags: &[&str]) -> bool {
    let mut rest = Subtags(subtags);
    if !rest.eat(private_use_prefix) {
        if !language(&mut rest) {
            return false;
        }
        // script = 4ALPHA; region = 2ALPHA / 3DIGIT
        rest.skip(|s| alpha(s, 4, 4));
        rest.skip(|s| alpha(s, 2, 2) || (s.len() == 3 && s.bytes().all(|b| b.is_ascii_digit())));
        // variant = 5*8alphanum / (DIGIT 3alphanum)
        while rest.eat(|s| {
            alnum(s, 5, 8)
                || (alnum(s, 4, 4) && s.bytes().next().is_some_and(|b| b.is_ascii_digit()))
        }) {}
        if !extensions(&mut rest) {
            return false;
        }
        if rest.0.is_empty() {
            return true;
        }
        if !rest.eat(private_use_prefix) {
            return false;
        }
    }
    // privateuse = "x" 1*("-" (1*8alphanum))
    !rest.0.is_empty() && rest.0.iter().all(|s| alnum(s, 1, 8))
}

/// language = 2*3ALPHA ["-" extlang] / 4ALPHA / 5*8ALPHA; extlang = 3ALPHA *2("-" 3ALPHA)
fn language(rest: &mut Subtags<'_>) -> bool {
    let short = rest.0.first().is_some_and(|s| alpha(s, 2, 3));
    if !rest.eat(|s| alpha(s, 2, 8)) {
        return false;
    }
    if short {
        for _ in 0..3 {
            rest.skip(|s| alpha(s, 3, 3));
        }
    }
    true
}

/// *("-" extension); extension = singleton 1*("-" (2*8alphanum)), a singleton being any
/// alphanumeric but "x".
fn extensions(rest: &mut Subtags<'_>) -> bool {
    while rest.eat(|s| alnum(s, 1, 1) && !private_use_prefix(s)) {
        if !rest.eat(|s| alnum(s, 2, 8)) {
            return false;
        }
        while rest.eat(|s| alnum(s, 2, 8)) {}
    }
    true
}

/// Why text is no language tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}", self.code())]
pub enum LocaleError {
    /// The text is no well-formed BCP 47 language tag (RFC 5646, Section 2.1).
    Malformed,
}

impl LocaleError {
    /// A stable identifier.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Malformed => "locale_malformed",
        }
    }
}

/// An entry of display metadata for one locale, or for an unstated one.
pub trait Localized {
    /// The entry's locale. `None` when the entry states none.
    fn locale(&self) -> Option<&Locale>;
}

impl<T: Localized + ?Sized> Localized for &T {
    fn locale(&self) -> Option<&Locale> {
        (**self).locale()
    }
}

/// The entry of `entries` to show in the wallet's `language` (D2; PaSO View, Section 4): the
/// entry RFC 4647 Lookup (Section 3.4) finds with `language` as the language range and the
/// entries' locales as the available tags, else the first entry without a locale. `None` when
/// neither exists.
///
/// Lookup tries the range whole, then truncated one subtag at a time from the end. Tags compare
/// without regard to ASCII case.
pub fn lookup<'a, T: Localized>(language: &Locale, entries: &'a [T]) -> Option<&'a T> {
    language
        .lookup_ranges()
        .find_map(|range| {
            entries.iter().find(|entry| {
                entry
                    .locale()
                    .is_some_and(|tag| tag.as_str().eq_ignore_ascii_case(range))
            })
        })
        .or_else(|| entries.iter().find(|entry| entry.locale().is_none()))
}

impl Locale {
    /// The language ranges RFC 4647 Lookup tries for this tag, longest first (Section 3.4).
    fn lookup_ranges(&self) -> impl Iterator<Item = &str> {
        let tag = self.0.as_str();
        let mut next = Some(tag);
        std::iter::from_fn(move || {
            let range = next?;
            next = truncated(range);
            Some(range)
        })
    }
}

/// `range` without its last subtag; `None` for a range of one subtag. RFC 4647 also drops a
/// singleton the cut leaves at the end; no well-formed tag ends in one, so that range matches
/// nothing either way.
fn truncated(range: &str) -> Option<&str> {
    range.rsplit_once('-').map(|(rest, _)| rest)
}
