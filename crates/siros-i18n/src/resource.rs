//! The `.mf2` resource format: the W3C i18n-discuss message resource syntax
//! (`explainers/message-resource.abnf`). A resource names its locale in `@locale` metadata, and its
//! text direction in `@dir` metadata when it is known, before its `---` frontmatter; then
//! `[section]` heads prefix the keys of the `key = message` entries after them, an indented line
//! continues a message, and the sections `[formats.<format>]` hold a format's options.

use crate::error::{ModuleError, ResourceRule};
use crate::format::Direction;
use crate::locale::LocaleTag;

/// The section prefix of a format's options.
const FORMATS: &str = "formats";

/// A resource, parsed: its locale, its messages and its formats' options, each in source order.
#[derive(Debug)]
pub(crate) struct Resource {
    pub(crate) locale: LocaleTag,
    pub(crate) direction: Direction,
    pub(crate) messages: Vec<Entry>,
    pub(crate) formats: Vec<FormatSection>,
}

/// A message under its key: the section's id path, then the entry's.
#[derive(Debug)]
pub(crate) struct Entry {
    pub(crate) key: String,
    pub(crate) value: String,
}

/// One format's options, as `[formats.<format>]` sections give them.
#[derive(Debug)]
pub(crate) struct FormatSection {
    pub(crate) format: String,
    pub(crate) options: Vec<Entry>,
}

/// Where the parser stands: before the frontmatter, then in a section.
enum Place {
    Head,
    Body(Section),
}

/// The section entries belong to.
enum Section {
    Root,
    Messages(String),
    Format(String),
}

/// Parses the resource `text`, the `index`-th source given.
pub(crate) fn parse(index: usize, text: &str) -> Result<Resource, ModuleError> {
    let refuse = |line: usize, rule: ResourceRule| ModuleError::Resource {
        source_index: index,
        line,
        rule,
    };
    let lines: Vec<&str> = text.split('\n').collect();
    let mut locale: Option<LocaleTag> = None;
    let mut direction: Option<Direction> = None;
    let mut place = Place::Head;
    let mut messages = Vec::new();
    let mut formats: Vec<FormatSection> = Vec::new();
    let mut at = 0;
    while let Some(&raw) = lines.get(at) {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        let number = at + 1;
        if !line.chars().all(allowed) {
            return Err(refuse(number, ResourceRule::Line));
        }
        at += 1;
        if line.trim_matches(is_ws).is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with(is_ws) {
            return Err(refuse(number, ResourceRule::Line));
        }
        if line.trim_end_matches(is_ws) == "---" {
            match (&place, &locale) {
                (Place::Head, Some(_)) => place = Place::Body(Section::Root),
                (Place::Head, None) => return Err(refuse(number, ResourceRule::NoLocale)),
                (Place::Body(_), _) => return Err(refuse(number, ResourceRule::Frontmatter)),
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix('@') {
            let (name, value, next) =
                metadata(&lines, at, rest).ok_or(refuse(number, ResourceRule::Line))?;
            at = next;
            let value = value.map_err(|rule| refuse(number, rule))?;
            match (&place, name.as_str()) {
                (Place::Head, "locale") if locale.is_none() => {
                    let tag = LocaleTag::parse(&value)
                        .map_err(|_| refuse(number, ResourceRule::Tag { tag: value }))?;
                    locale = Some(tag);
                }
                (Place::Head, "locale") => return Err(refuse(number, ResourceRule::NoLocale)),
                (Place::Head, "dir") if direction.is_none() => {
                    direction = Some(match value.as_str() {
                        "ltr" => Direction::Ltr,
                        "rtl" => Direction::Rtl,
                        _ => {
                            let rule = ResourceRule::Direction { direction: value };
                            return Err(refuse(number, rule));
                        }
                    });
                }
                _ => return Err(refuse(number, ResourceRule::Metadata { name })),
            }
            continue;
        }
        let Place::Body(section) = &mut place else {
            return Err(refuse(number, ResourceRule::Order));
        };
        if let Some(rest) = line.strip_prefix('[') {
            *section = head(rest).map_err(|rule| refuse(number, rule))?;
            continue;
        }
        let (key, rest) = id(line).map_err(|rule| refuse(number, rule))?;
        let Some(first) = rest.trim_start_matches(is_ws).strip_prefix('=') else {
            return Err(refuse(number, ResourceRule::Line));
        };
        let (value, next) = value(&lines, at, first);
        at = next;
        let entry = Entry {
            key: String::new(),
            value: value.map_err(|rule| refuse(number, rule))?,
        };
        match section {
            Section::Root => messages.push(Entry { key, ..entry }),
            Section::Messages(prefix) => messages.push(Entry {
                key: format!("{prefix}.{key}"),
                ..entry
            }),
            Section::Format(format) => {
                let option = Entry { key, ..entry };
                match formats.iter_mut().find(|section| section.format == *format) {
                    Some(section) => section.options.push(option),
                    None => formats.push(FormatSection {
                        format: format.clone(),
                        options: vec![option],
                    }),
                }
            }
        }
    }
    match (place, locale) {
        (Place::Body(_), Some(locale)) => Ok(Resource {
            locale,
            direction: direction.unwrap_or(Direction::Unknown),
            messages,
            formats,
        }),
        (Place::Head, _) | (_, None) => Err(refuse(lines.len(), ResourceRule::Frontmatter)),
    }
}

/// A section head after its `[`.
fn head(rest: &str) -> Result<Section, ResourceRule> {
    let (path, after) = id(rest.trim_start_matches(is_ws))?;
    let Some(tail) = after.trim_start_matches(is_ws).strip_prefix(']') else {
        return Err(ResourceRule::Line);
    };
    if !tail.trim_start_matches(is_ws).is_empty() {
        return Err(ResourceRule::Line);
    }
    Ok(
        match path
            .strip_prefix(FORMATS)
            .and_then(|format| format.strip_prefix('.'))
        {
            Some(format) => Section::Format(format.to_owned()),
            None => Section::Messages(path),
        },
    )
}

/// A metadata line after its `@`: its name, its value, and the line after it.
fn metadata(
    lines: &[&str],
    next: usize,
    rest: &str,
) -> Option<(String, Result<String, ResourceRule>, usize)> {
    let end = rest.find(|c: char| is_ws(c)).unwrap_or(rest.len());
    let (name, after) = (rest.get(..end)?, rest.get(end..)?);
    let (name, left) = part(name).ok()?;
    if !left.is_empty() {
        return None;
    }
    let (value, next) = value(lines, next, after);
    Some((name, value, next))
}

/// An id at the start of `text`: its parts joined by `.`, and the text after it.
fn id(text: &str) -> Result<(String, &str), ResourceRule> {
    if text.starts_with("---") {
        return Err(ResourceRule::Line);
    }
    let (mut path, mut rest) = part(text)?;
    loop {
        let after = rest.trim_start_matches(is_ws);
        let Some(dotted) = after.strip_prefix('.') else {
            return Ok((path, rest));
        };
        let (next, left) = part(dotted.trim_start_matches(is_ws))?;
        path.push('.');
        path.push_str(&next);
        rest = left;
    }
}

/// One id part: `1*(id-char / "-")`, its escapes resolved.
fn part(text: &str) -> Result<(String, &str), ResourceRule> {
    let mut out = String::new();
    let mut chars = text.char_indices().peekable();
    while let Some((_, c)) = chars.next_if(|&(_, c)| c == '\\' || id_safe(c) || c == '-') {
        if c == '\\' {
            let escaped = chars.next().ok_or(ResourceRule::Escape)?.1;
            match escape(escaped, &mut chars)? {
                Some(c) => out.push(c),
                None if symbol(escaped) => out.push(escaped),
                None => return Err(ResourceRule::Escape),
            }
        } else {
            out.push(c);
        }
    }
    if out.is_empty() {
        return Err(ResourceRule::Line);
    }
    let rest = chars
        .peek()
        .map_or("", |&(at, _)| text.get(at..).unwrap_or_default());
    Ok((out, rest))
}

/// One character of a value: escaped, and so kept from trimming, or as written.
#[derive(Clone, Copy)]
enum Char {
    Escaped(char),
    Written(char),
    Break,
}

/// A value from `first`, the rest of its first line, through its continuation lines: each line
/// trimmed, empty lines trimmed from both ends, lines joined by LF. MF2's escapes `\\`, `\{`,
/// `\|` and `\}` pass through intact. Returns the line after it.
fn value(lines: &[&str], mut next: usize, first: &str) -> (Result<String, ResourceRule>, usize) {
    let mut text = first.to_owned();
    let mut end = next;
    while let Some(&raw) = lines.get(end) {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if line.trim_matches(is_ws).is_empty() {
            end += 1;
        } else if line.starts_with(is_ws) {
            for empty in lines.get(next..end).unwrap_or_default() {
                text.push('\n');
                text.push_str(empty.strip_suffix('\r').unwrap_or(empty));
            }
            text.push('\n');
            text.push_str(line);
            end += 1;
            next = end;
        } else {
            break;
        }
    }
    (resolve(&text), next)
}

/// The value's text, its escapes resolved and its lines trimmed.
fn resolve(text: &str) -> Result<String, ResourceRule> {
    let mut chars = text.char_indices().peekable();
    let mut out: Vec<Char> = Vec::new();
    while let Some((_, c)) = chars.next() {
        match c {
            '\n' => out.push(Char::Break),
            '\\' => {
                let escaped = chars.next().ok_or(ResourceRule::Escape)?.1;
                if matches!(escaped, '\\' | '{' | '|' | '}') {
                    out.extend([Char::Escaped('\\'), Char::Escaped(escaped)]);
                } else if escaped == '\n' {
                    while chars.next_if(|&(_, c)| is_ws(c)).is_some() {}
                } else {
                    out.push(Char::Escaped(
                        escape(escaped, &mut chars)?.ok_or(ResourceRule::Escape)?,
                    ));
                }
            }
            c => out.push(Char::Written(c)),
        }
    }
    let lines: Vec<&[Char]> = out
        .split(|c| matches!(c, Char::Break))
        .map(|line| {
            let blank = |c: &Char| matches!(c, Char::Written(c) if is_ws(*c));
            let start = line.iter().position(|c| !blank(c)).unwrap_or(line.len());
            let end = line
                .iter()
                .rposition(|c| !blank(c))
                .map_or(start, |end| end + 1);
            line.get(start..end).unwrap_or_default()
        })
        .collect();
    let first = lines
        .iter()
        .position(|line| !line.is_empty())
        .unwrap_or(lines.len());
    let last = lines
        .iter()
        .rposition(|line| !line.is_empty())
        .map_or(first, |last| last + 1);
    let kept = lines.get(first..last).unwrap_or_default();
    let mut value = String::new();
    for (index, line) in kept.iter().enumerate() {
        if index > 0 {
            value.push('\n');
        }
        value.extend(line.iter().filter_map(|c| match c {
            Char::Escaped(c) | Char::Written(c) => Some(*c),
            Char::Break => None,
        }));
    }
    Ok(value)
}

/// The character an escape after its backslash stands for, reading its hex digits from `chars`;
/// `None` for a character that starts no escape of `escaped`.
fn escape<I: Iterator<Item = (usize, char)>>(
    escaped: char,
    chars: &mut std::iter::Peekable<I>,
) -> Result<Option<char>, ResourceRule> {
    let digits = match escaped {
        '\\' => return Ok(Some('\\')),
        ' ' | '\t' => return Ok(Some(escaped)),
        'n' => return Ok(Some('\n')),
        'r' => return Ok(Some('\r')),
        't' => return Ok(Some('\t')),
        'x' => 2,
        'u' => 4,
        'U' => 6,
        _ => return Ok(None),
    };
    let mut code = 0u32;
    for _ in 0..digits {
        let digit = chars
            .next()
            .and_then(|(_, c)| c.to_digit(16))
            .ok_or(ResourceRule::Escape)?;
        code = code * 16 + digit;
    }
    char::from_u32(code).map(Some).ok_or(ResourceRule::Escape)
}

/// `symbols`: the characters an id escapes.
const fn symbol(c: char) -> bool {
    matches!(c, '\u{21}'..='\u{2F}' | '\u{3A}'..='\u{40}' | '\u{5B}'..='\u{60}' | '\u{7B}'..='\u{7E}'
        | '\u{A1}'..='\u{BF}' | '\u{D7}' | '\u{F7}' | '\u{2010}'..='\u{2027}' | '\u{2030}'..='\u{205E}'
        | '\u{2190}'..='\u{2BFF}')
}

/// `id-safe`.
const fn id_safe(c: char) -> bool {
    matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '_' | '\u{A1}'..='\u{1FFF}' | '\u{200C}'..='\u{200D}'
        | '\u{2030}'..='\u{205E}' | '\u{2070}'..='\u{2FEF}' | '\u{3001}'..='\u{D7FF}'
        | '\u{F900}'..='\u{FDCF}' | '\u{FDF0}'..='\u{FFFD}' | '\u{10000}'..='\u{EFFFF}')
}

/// `ws`.
const fn is_ws(c: char) -> bool {
    matches!(c, ' ' | '\t')
}

/// A character a line may hold: `content`, a backslash, or a line's CR.
const fn allowed(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\u{21}'..='\u{7E}' | '\u{A0}'..='\u{2027}' | '\u{202A}'..='\u{10FFFF}')
}
