//! The characters and constructs CommonMark's inline parsing distinguishes: whitespace and
//! punctuation (CommonMark §2.1), and the constructs that take precedence over emphasis and
//! render literally in `mini_markdown`.

use icu_properties::CodePointMapData;
use icu_properties::props::{GeneralCategory, GeneralCategoryGroup};
use siros_openid4vp::text::python_space;

/// A Unicode whitespace character, or no character (CommonMark §2.1).
pub(super) fn space(c: Option<char>) -> bool {
    c.is_none_or(|c| {
        matches!(c, '\t' | '\n' | '\u{c}' | '\r') || category(c) == GeneralCategory::SpaceSeparator
    })
}

/// A Unicode punctuation character: general category P or S (CommonMark §2.1).
pub(super) fn punctuation(c: Option<char>) -> bool {
    c.is_some_and(|c| {
        let category = category(c);
        GeneralCategoryGroup::Punctuation.contains(category)
            || GeneralCategoryGroup::Symbol.contains(category)
    })
}

fn category(c: char) -> GeneralCategory {
    CodePointMapData::<GeneralCategory>::new().get(c)
}

/// The end of the construct at `i` that takes precedence over emphasis and renders literally
/// (a backslash escape, a code span, raw HTML other than `<u>` and `</u>`, an autolink), or `i`.
pub(super) fn atom(chars: &[char], i: usize) -> usize {
    match chars.get(i) {
        Some('\\') if chars.get(i + 1).is_some_and(char::is_ascii_punctuation) => i + 2,
        Some('`') => code_span(chars, i),
        Some('<') => match raw_html(chars, i).or_else(|| autolink(chars, i)) {
            Some(end)
                if !matches!(
                    chars.get(i..end),
                    Some(['<', 'u', '>'] | ['<', '/', 'u', '>'])
                ) =>
            {
                end
            }
            _ => i,
        },
        _ => i,
    }
}

/// A backtick run closes only on a run of its length; unclosed, the run is literal text.
fn code_span(chars: &[char], i: usize) -> usize {
    let run_at = |k: usize| {
        chars
            .get(k..)
            .unwrap_or_default()
            .iter()
            .take_while(|&&c| c == '`')
            .count()
    };
    let run = run_at(i);
    let mut k = i + run;
    while let Some(&c) = chars.get(k) {
        if c == '`' {
            let closing = run_at(k);
            if closing == run {
                return k + closing;
            }
            k += closing;
        } else {
            k += 1;
        }
    }
    i + run
}

/// `</?[A-Za-z][A-Za-z0-9-]*(?:\s[^<>]*)?/?>` at `i`: the end of the tag.
fn raw_html(chars: &[char], i: usize) -> Option<usize> {
    let mut k = i + 1;
    if chars.get(k) == Some(&'/') {
        k += 1;
    }
    if !chars.get(k).is_some_and(char::is_ascii_alphabetic) {
        return None;
    }
    k += 1;
    while chars
        .get(k)
        .is_some_and(|c| c.is_ascii_alphanumeric() || *c == '-')
    {
        k += 1;
    }
    match chars.get(k) {
        Some(&c) if python_space(c) => {
            let stop = chars.get(k..)?.iter().position(|&c| c == '<' || c == '>')?;
            (chars.get(k + stop) == Some(&'>')).then_some(k + stop + 1)
        }
        Some('>') => Some(k + 1),
        Some('/') if chars.get(k + 1) == Some(&'>') => Some(k + 2),
        _ => None,
    }
}

/// `<[A-Za-z][A-Za-z0-9+.-]{1,31}:[^\s<>]*>` at `i`: the end of the autolink.
fn autolink(chars: &[char], i: usize) -> Option<usize> {
    if !chars.get(i + 1).is_some_and(char::is_ascii_alphabetic) {
        return None;
    }
    let scheme = chars
        .get(i + 2..)?
        .iter()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'))
        .count();
    let colon = i + 2 + scheme;
    if !(1..=31).contains(&scheme) || chars.get(colon) != Some(&':') {
        return None;
    }
    let body = chars
        .get(colon + 1..)?
        .iter()
        .take_while(|&&c| !python_space(c) && c != '<' && c != '>')
        .count();
    (chars.get(colon + 1 + body) == Some(&'>')).then_some(colon + body + 2)
}
