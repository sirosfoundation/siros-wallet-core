//! The `.mf2` resource format: the W3C i18n-discuss message resource syntax
//! (`explainers/message-resource.abnf`). A resource names its locale in `@locale` metadata, and its
//! text direction in `@dir` metadata when it is known, before its `---` frontmatter; then
//! `[section]` heads prefix the keys of the `key = message` entries after them, an indented line
//! continues a message, and the sections `[formats.<format>]` hold a format's options. A parsed
//! resource borrows from its source each id and each value written without an escape on one line.

use std::borrow::Cow;

use crate::error::{LoadError, SyntaxRule};
use crate::format::Direction;
use crate::locale::LocaleTag;

/// The section prefix of a format's options.
const FORMATS: &str = "formats";

/// A resource, parsed: its locale, its direction, its message sections and its formats' options,
/// each in source order.
#[derive(Debug)]
pub(crate) struct Resource<'s> {
    pub(crate) locale: Option<LocaleTag>,
    pub(crate) direction: Direction,
    pub(crate) sections: Vec<MessageSection<'s>>,
    pub(crate) formats: Vec<FormatSection<'s>>,
}

/// The message entries under one `[section]` head, whose name and a dot prefix each entry's key in
/// its id; or those before the first head, whose ids are their keys.
#[derive(Debug)]
pub(crate) struct MessageSection<'s> {
    pub(crate) name: Option<Cow<'s, str>>,
    pub(crate) entries: Vec<Entry<'s>>,
}

/// A message or an option under its key, and the line, from 1, where the entry starts.
#[derive(Debug)]
pub(crate) struct Entry<'s> {
    pub(crate) key: Cow<'s, str>,
    pub(crate) value: Cow<'s, str>,
    pub(crate) line: usize,
}

/// One format's options, as its `[formats.<format>]` sections give them.
#[derive(Debug)]
pub(crate) struct FormatSection<'s> {
    pub(crate) format: Cow<'s, str>,
    pub(crate) options: Vec<Entry<'s>>,
}

/// Where the parser stands: before the frontmatter, then in a section.
enum Place<'s> {
    Head,
    Body(Section<'s>),
}

/// The section the parser adds entries to.
enum Section<'s> {
    Messages(MessageSection<'s>),
    Format(FormatSection<'s>),
}

/// The sections the parser has left: the message sections, and each format's options, the
/// formats in the order of their first sections.
#[derive(Default)]
struct Left<'s> {
    sections: Vec<MessageSection<'s>>,
    formats: Vec<FormatSection<'s>>,
}

impl<'s> Left<'s> {
    /// Adds a section the parser leaves: its options to its format's.
    fn leave(&mut self, section: Section<'s>) {
        match section {
            Section::Messages(messages) => self.sections.push(messages),
            Section::Format(section) => {
                match self
                    .formats
                    .iter_mut()
                    .find(|held| held.format == section.format)
                {
                    Some(held) => held.options.extend(section.options),
                    None => self.formats.push(section),
                }
            }
        }
    }
}

/// Parses the resource `text`.
pub(crate) fn parse(text: &str) -> Result<Resource<'_>, LoadError> {
    let refuse = |line: usize, rule: SyntaxRule| LoadError::Syntax { line, rule };
    // `newline = CRLF / LF`: a line an LF ends drops the CR before it; the last line keeps one.
    let lines: Vec<&str> = match text.rsplit_once('\n') {
        Some((ended, last)) => ended
            .split('\n')
            .map(|line| line.strip_suffix('\r').unwrap_or(line))
            .chain([last])
            .collect(),
        None => vec![text],
    };
    if let Some(at) = lines.iter().position(|line| !line.chars().all(allowed)) {
        return Err(refuse(at + 1, SyntaxRule::Line));
    }
    let mut locale: Option<LocaleTag> = None;
    let mut direction: Option<Direction> = None;
    let mut place = Place::Head;
    let mut left = Left::default();
    let mut at = 0;
    while let Some(&line) = lines.get(at) {
        let number = at + 1;
        at += 1;
        if line.trim_matches(is_ws).is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with(is_ws) {
            return Err(refuse(number, SyntaxRule::Line));
        }
        if line.trim_end_matches(is_ws) == "---" {
            match place {
                Place::Head => {
                    place = Place::Body(Section::Messages(MessageSection {
                        name: None,
                        entries: Vec::new(),
                    }));
                }
                Place::Body(_) => return Err(refuse(number, SyntaxRule::Frontmatter)),
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix('@') {
            let (name, value, next) =
                metadata(&lines, at, rest).map_err(|rule| refuse(number, rule))?;
            at = next;
            let value = value.map_err(|rule| refuse(number, rule))?;
            match (&place, name.as_ref()) {
                (Place::Head, "locale") if locale.is_none() => {
                    let tag = LocaleTag::parse(&value).map_err(|_| {
                        let tag = value.to_string();
                        refuse(number, SyntaxRule::Tag { tag })
                    })?;
                    locale = Some(tag);
                }
                (Place::Head, "dir") if direction.is_none() => {
                    direction = Some(match value.as_ref() {
                        "ltr" => Direction::Ltr,
                        "rtl" => Direction::Rtl,
                        _ => {
                            let direction = value.into_owned();
                            return Err(refuse(number, SyntaxRule::Direction { direction }));
                        }
                    });
                }
                _ => {
                    let name = name.into_owned();
                    return Err(refuse(number, SyntaxRule::Metadata { name }));
                }
            }
            continue;
        }
        let Place::Body(section) = &mut place else {
            return Err(refuse(number, SyntaxRule::Order));
        };
        if let Some(rest) = line.strip_prefix('[') {
            let next = head(rest).map_err(|rule| refuse(number, rule))?;
            left.leave(std::mem::replace(section, next));
            continue;
        }
        let (key, rest) = id(line).map_err(|rule| refuse(number, rule))?;
        let Some(first) = rest.trim_start_matches(is_ws).strip_prefix('=') else {
            return Err(refuse(number, SyntaxRule::Line));
        };
        let (value, next) = value(&lines, at, first);
        at = next;
        let value = value.map_err(|rule| refuse(number, rule))?;
        let entry = Entry {
            key,
            value,
            line: number,
        };
        match section {
            Section::Messages(messages) => messages.entries.push(entry),
            Section::Format(format) => format.options.push(entry),
        }
    }
    match place {
        Place::Body(section) => {
            left.leave(section);
            Ok(Resource {
                locale,
                direction: direction.unwrap_or(Direction::Unknown),
                sections: left.sections,
                formats: left.formats,
            })
        }
        Place::Head => Err(refuse(lines.len(), SyntaxRule::Frontmatter)),
    }
}

/// A section head after its `[`.
fn head(rest: &str) -> Result<Section<'_>, SyntaxRule> {
    let (path, after) = id(rest.trim_start_matches(is_ws))?;
    let Some(tail) = after.trim_start_matches(is_ws).strip_prefix(']') else {
        return Err(SyntaxRule::Line);
    };
    if !tail.trim_start_matches(is_ws).is_empty() {
        return Err(SyntaxRule::Line);
    }
    fn format(path: &str) -> Option<&str> {
        path.strip_prefix(FORMATS)?.strip_prefix('.')
    }
    let format = match &path {
        Cow::Borrowed(path) => format(path).map(Cow::Borrowed),
        Cow::Owned(path) => format(path).map(|format| Cow::Owned(format.to_owned())),
    };
    Ok(match format {
        Some(format) => Section::Format(FormatSection {
            format,
            options: Vec::new(),
        }),
        None => Section::Messages(MessageSection {
            name: Some(path),
            entries: Vec::new(),
        }),
    })
}

/// A metadata line after its `@` (`id-part [ws value]`): its name, its value, and the line after
/// it.
#[expect(
    clippy::type_complexity,
    reason = "the name, the value or its refusal, and the next line"
)]
fn metadata<'s>(
    lines: &[&'s str],
    next: usize,
    rest: &'s str,
) -> Result<(Cow<'s, str>, Result<Cow<'s, str>, SyntaxRule>, usize), SyntaxRule> {
    let (name, after) = part(rest)?;
    if !after.is_empty() && !after.starts_with(is_ws) {
        return Err(SyntaxRule::Line);
    }
    let (value, next) = value(lines, next, after);
    Ok((name, value, next))
}

/// The longest prefix of `text` whose characters `admitted` admits, and the text after it.
fn run(text: &str, admitted: impl Fn(char) -> bool) -> (&str, &str) {
    let run = text
        .split_once(|c| !admitted(c))
        .map_or(text, |(run, _)| run);
    (run, text.trim_start_matches(admitted))
}

/// An id at the start of `text`: its parts joined by `.`, and the text after it.
fn id(text: &str) -> Result<(Cow<'_, str>, &str), SyntaxRule> {
    if text.starts_with("---") {
        return Err(SyntaxRule::Line);
    }
    // An id written without an escape or a space around its dots is a slice of the line.
    let (plain, after) = run(text, |c| id_safe(c) || c == '-' || c == '.');
    if !plain.is_empty()
        && plain.split('.').all(|part| !part.is_empty())
        && !after.starts_with('\\')
        && !after.trim_start_matches(is_ws).starts_with('.')
    {
        return Ok((Cow::Borrowed(plain), after));
    }
    let (mut path, mut rest) = part(text)?;
    loop {
        let after = rest.trim_start_matches(is_ws);
        let Some(dotted) = after.strip_prefix('.') else {
            return Ok((path, rest));
        };
        let (next, left) = part(dotted.trim_start_matches(is_ws))?;
        let path = path.to_mut();
        path.push('.');
        path.push_str(&next);
        rest = left;
    }
}

/// One id part: `1*(id-char / "-")`, its escapes resolved.
fn part(text: &str) -> Result<(Cow<'_, str>, &str), SyntaxRule> {
    let written = |c| id_safe(c) || c == '-';
    let (first, mut rest) = run(text, written);
    let mut out = Cow::Borrowed(first);
    while let Some(after) = rest.strip_prefix('\\') {
        let mut chars = after.chars();
        let escaped = chars.next().ok_or(SyntaxRule::Escape)?;
        let c = match escape(escaped, &mut chars)? {
            Some(c) => c,
            None if symbol(escaped) => escaped,
            None => return Err(SyntaxRule::Escape),
        };
        let (next, left) = run(chars.as_str(), written);
        let out = out.to_mut();
        out.push(c);
        out.push_str(next);
        rest = left;
    }
    if out.is_empty() {
        Err(SyntaxRule::Line)
    } else {
        Ok((out, rest))
    }
}

/// One character of a value's line: escaped, and so kept from trimming, or as written.
#[derive(Clone, Copy)]
enum Char {
    Escaped(char),
    Written(char),
}

/// A value from `first`, the rest of its first line, through its continuation lines: each line
/// trimmed, empty lines trimmed from both ends, lines joined by LF. MF2's escapes `\\`, `\{`,
/// `\|` and `\}` pass through intact. Returns the line after it.
fn value<'s>(
    lines: &[&'s str],
    mut next: usize,
    first: &'s str,
) -> (Result<Cow<'s, str>, SyntaxRule>, usize) {
    let mut text = Cow::Borrowed(first);
    let mut blank = 0;
    for &line in lines.iter().skip(next) {
        if line.trim_matches(is_ws).is_empty() {
            blank += 1;
        } else if line.starts_with(is_ws) {
            let text = text.to_mut();
            text.extend(std::iter::repeat_n('\n', blank + 1));
            text.push_str(line);
            next += blank + 1;
            blank = 0;
        } else {
            break;
        }
    }
    let value = match text {
        Cow::Borrowed(line) if !line.contains('\\') => Ok(Cow::Borrowed(line.trim_matches(is_ws))),
        text => resolve(&text).map(Cow::Owned),
    };
    (value, next)
}

/// The value's text, its escapes resolved and its lines trimmed.
fn resolve(text: &str) -> Result<String, SyntaxRule> {
    let mut chars = text.chars().peekable();
    let mut lines: Vec<Vec<Char>> = Vec::new();
    let mut line: Vec<Char> = Vec::new();
    while let Some(c) = chars.next() {
        match c {
            '\n' => lines.push(std::mem::take(&mut line)),
            '\\' => {
                let escaped = chars.next().ok_or(SyntaxRule::Escape)?;
                if matches!(escaped, '\\' | '{' | '|' | '}') {
                    line.extend([Char::Escaped('\\'), Char::Escaped(escaped)]);
                } else if escaped == '\n' {
                    while chars.next_if(|&c| is_ws(c)).is_some() {}
                } else {
                    line.push(Char::Escaped(
                        escape(escaped, &mut chars)?.ok_or(SyntaxRule::Escape)?,
                    ));
                }
            }
            c => line.push(Char::Written(c)),
        }
    }
    lines.push(line);
    let blank = |c: &Char| matches!(c, Char::Written(c) if is_ws(*c));
    let lines: Vec<&[Char]> = lines.iter().map(|line| trim(line, blank)).collect();
    let mut value = String::new();
    for (index, line) in trim(&lines, |line| line.is_empty()).iter().enumerate() {
        if index > 0 {
            value.push('\n');
        }
        value.extend(line.iter().map(|c| match *c {
            Char::Escaped(c) | Char::Written(c) => c,
        }));
    }
    Ok(value)
}

/// `items` without the blank items at either end.
fn trim<T>(mut items: &[T], blank: impl Fn(&T) -> bool) -> &[T] {
    while let [first, rest @ ..] = items
        && blank(first)
    {
        items = rest;
    }
    while let [rest @ .., last] = items
        && blank(last)
    {
        items = rest;
    }
    items
}

/// The character an escape after its backslash stands for, reading its hex digits from `chars`;
/// `None` for a character that starts no escape of `escaped`.
fn escape(
    escaped: char,
    chars: &mut impl Iterator<Item = char>,
) -> Result<Option<char>, SyntaxRule> {
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
            .and_then(|c| c.to_digit(16))
            .ok_or(SyntaxRule::Escape)?;
        code = code * 16 + digit;
    }
    char::from_u32(code).map(Some).ok_or(SyntaxRule::Escape)
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

/// A character a line may hold before its line ending: `content` or a backslash.
const fn allowed(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\u{21}'..='\u{7E}' | '\u{A0}'..='\u{2027}' | '\u{202A}'..='\u{10FFFF}')
}
