//! The `.mf2` resource format: the W3C i18n-discuss message resource syntax
//! (`explainers/message-resource.abnf`). A resource names its locale in `@locale` metadata, and its
//! text direction in `@dir` metadata when it is known, before its `---` frontmatter; then
//! `[section]` heads prefix the keys of the `key = message` entries after them, an indented line
//! continues a message, and the sections `[formats.<format>]` hold a format's options.

use rustc_hash::FxHashMap;

use crate::error::{LoadError, SyntaxRule};
use crate::format::Direction;
use crate::locale::LocaleTag;

/// The section prefix of a format's options.
const FORMATS: &str = "formats";

/// A resource, parsed: its locale, its direction, its message sections and its formats' options,
/// each in source order.
#[derive(Debug)]
pub(crate) struct Resource {
    pub(crate) locale: Option<LocaleTag>,
    pub(crate) direction: Direction,
    pub(crate) sections: Vec<MessageSection>,
    pub(crate) formats: Vec<FormatSection>,
}

/// The message entries under one `[section]` head, whose name and a dot prefix each entry's key in
/// its id; or those before the first head, whose ids are their keys.
#[derive(Debug)]
pub(crate) struct MessageSection {
    pub(crate) name: Option<String>,
    pub(crate) entries: Vec<Entry>,
}

/// A message or an option under its key, and the line, from 1, where the entry starts.
#[derive(Debug)]
pub(crate) struct Entry {
    pub(crate) key: String,
    pub(crate) value: String,
    pub(crate) line: usize,
}

/// One format's options, as its `[formats.<format>]` sections give them.
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

/// The section the parser adds entries to.
enum Section {
    Messages(MessageSection),
    Format(FormatSection),
}

/// The sections the parser has left: the message sections, and each format's options with the
/// index of its format among them.
#[derive(Default)]
struct Left {
    sections: Vec<MessageSection>,
    formats: Vec<FormatSection>,
    format_at: FxHashMap<String, usize>,
}

impl Left {
    /// Adds a section the parser leaves: its options to the format's options, which it adds when
    /// absent.
    fn leave(&mut self, section: Section) {
        match section {
            Section::Messages(messages) => self.sections.push(messages),
            Section::Format(options) => match self
                .format_at
                .get(&options.format)
                .and_then(|&at| self.formats.get_mut(at))
            {
                Some(earlier) => earlier.options.extend(options.options),
                None => {
                    self.format_at
                        .extend([(options.format.clone(), self.formats.len())]);
                    self.formats.push(options);
                }
            },
        }
    }
}

/// Parses the resource `text`.
pub(crate) fn parse(text: &str) -> Result<Resource, LoadError> {
    let refuse = |line: usize, rule: SyntaxRule| LoadError::Syntax { line, rule };
    let lines: Vec<&str> = text
        .split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .collect();
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
            match (&place, name.as_str()) {
                (Place::Head, "locale") if locale.is_none() => {
                    let tag = LocaleTag::parse(&value)
                        .map_err(|_| refuse(number, SyntaxRule::Tag { tag: value }))?;
                    locale = Some(tag);
                }
                (Place::Head, "dir") if direction.is_none() => {
                    direction = Some(match value.as_str() {
                        "ltr" => Direction::Ltr,
                        "rtl" => Direction::Rtl,
                        _ => {
                            let rule = SyntaxRule::Direction { direction: value };
                            return Err(refuse(number, rule));
                        }
                    });
                }
                _ => return Err(refuse(number, SyntaxRule::Metadata { name })),
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
fn head(rest: &str) -> Result<Section, SyntaxRule> {
    let (path, after) = id(rest.trim_start_matches(is_ws))?;
    let Some(tail) = after.trim_start_matches(is_ws).strip_prefix(']') else {
        return Err(SyntaxRule::Line);
    };
    if !tail.trim_start_matches(is_ws).is_empty() {
        return Err(SyntaxRule::Line);
    }
    Ok(
        match path
            .strip_prefix(FORMATS)
            .and_then(|format| format.strip_prefix('.'))
        {
            Some(format) => Section::Format(FormatSection {
                format: format.to_owned(),
                options: Vec::new(),
            }),
            None => Section::Messages(MessageSection {
                name: Some(path),
                entries: Vec::new(),
            }),
        },
    )
}

/// A metadata line after its `@` (`id-part [ws value]`): its name, its value, and the line after
/// it.
fn metadata(
    lines: &[&str],
    next: usize,
    rest: &str,
) -> Result<(String, Result<String, SyntaxRule>, usize), SyntaxRule> {
    let (name, after) = part(rest)?;
    if !after.is_empty() && !after.starts_with(is_ws) {
        return Err(SyntaxRule::Line);
    }
    let (value, next) = value(lines, next, after);
    Ok((name, value, next))
}

/// An id at the start of `text`: its parts joined by `.`, and the text after it.
fn id(text: &str) -> Result<(String, &str), SyntaxRule> {
    if text.starts_with("---") {
        return Err(SyntaxRule::Line);
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
fn part(text: &str) -> Result<(String, &str), SyntaxRule> {
    let mut out = String::new();
    let mut chars = text.chars();
    loop {
        let rest = chars.as_str();
        match chars.next() {
            Some('\\') => {
                let escaped = chars.next().ok_or(SyntaxRule::Escape)?;
                match escape(escaped, &mut chars)? {
                    Some(c) => out.push(c),
                    None if symbol(escaped) => out.push(escaped),
                    None => return Err(SyntaxRule::Escape),
                }
            }
            Some(c) if id_safe(c) || c == '-' => out.push(c),
            Some(_) | None if out.is_empty() => return Err(SyntaxRule::Line),
            Some(_) | None => return Ok((out, rest)),
        }
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
fn value(lines: &[&str], mut next: usize, first: &str) -> (Result<String, SyntaxRule>, usize) {
    let mut text = first.to_owned();
    let mut blank = 0;
    for &line in lines.iter().skip(next) {
        if line.trim_matches(is_ws).is_empty() {
            blank += 1;
        } else if line.starts_with(is_ws) {
            text.extend(std::iter::repeat_n('\n', blank + 1));
            text.push_str(line);
            next += blank + 1;
            blank = 0;
        } else {
            break;
        }
    }
    (resolve(&text), next)
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
