//! The condition of a list pattern's special case (Unicode TR35 Part 2, "List Patterns": Spanish
//! `e` before /i/, `u` before /o/, Hebrew `ו-` before a non-Hebrew word): a regular expression
//! matched at the start of the item that follows the conjunction. The grammar is the subset ICU4X
//! writes for these cases: alternation, groups, classes with ranges, nested classes and negation,
//! `.`, `^`, `$`, escapes, and the quantifiers `?`, `*`, `+` and `{n,m}`.

use crate::bytes::Reader;
#[cfg(feature = "load")]
use crate::bytes::Writer;
use crate::error::RenderError;

/// A node of the expression.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Node {
    Char(char),
    Class {
        negated: bool,
        ranges: Vec<(char, char)>,
    },
    Any,
    Start,
    End,
    Group(Vec<Vec<Piece>>),
}

/// A node and how many times it repeats: `min` to `max`, `None` for no bound.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Piece {
    node: Node,
    min: u32,
    max: Option<u32>,
}

/// A condition, read from a compiled placeholder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Condition {
    alternatives: Vec<Vec<Piece>>,
}

impl Condition {
    /// Whether the condition matches at the start of `text`.
    pub(crate) fn matches(&self, text: &str) -> bool {
        let chars: Vec<char> = text.chars().collect();
        alternatives(&self.alternatives, &chars, 0, &mut |_| true)
    }

    pub(crate) fn read(reader: &mut Reader<'_>) -> Result<Self, RenderError> {
        Ok(Self {
            alternatives: read_alternatives(reader)?,
        })
    }

    #[cfg(feature = "load")]
    pub(crate) fn write(&self, writer: &mut Writer) {
        write_alternatives(&self.alternatives, writer);
    }

    /// The condition a text writes; `None` outside the grammar.
    #[cfg(feature = "load")]
    pub(crate) fn parse(text: &str) -> Option<Self> {
        let chars: Vec<char> = text.chars().collect();
        let (alternatives, at) = parse_alternatives(&chars, 0)?;
        (at == chars.len()).then_some(Self { alternatives })
    }
}

fn alternatives(
    alternatives: &[Vec<Piece>],
    text: &[char],
    at: usize,
    then: &mut dyn FnMut(usize) -> bool,
) -> bool {
    alternatives
        .iter()
        .any(|sequence| pieces(sequence, text, at, then))
}

fn pieces(
    sequence: &[Piece],
    text: &[char],
    at: usize,
    then: &mut dyn FnMut(usize) -> bool,
) -> bool {
    let Some((piece, rest)) = sequence.split_first() else {
        return then(at);
    };
    repeat(piece, 0, text, at, &mut |next| {
        pieces(rest, text, next, then)
    })
}

/// Matches `piece` `count` times so far, then more, greedily, before `then`. A repetition past
/// the minimum consumes text.
fn repeat(
    piece: &Piece,
    count: u32,
    text: &[char],
    at: usize,
    then: &mut dyn FnMut(usize) -> bool,
) -> bool {
    if count < piece.min {
        return node(&piece.node, text, at, &mut |next| {
            repeat(piece, count + 1, text, next, then)
        });
    }
    let more = piece.max.is_none_or(|max| count < max);
    let advanced = more
        && node(&piece.node, text, at, &mut |next| {
            next != at && repeat(piece, count + 1, text, next, then)
        });
    advanced || then(at)
}

fn node(node: &Node, text: &[char], at: usize, then: &mut dyn FnMut(usize) -> bool) -> bool {
    let next = text.get(at).copied();
    match node {
        Node::Char(c) => next == Some(*c) && then(at + 1),
        Node::Class { negated, ranges } => {
            next.is_some_and(|c| {
                ranges.iter().any(|&(low, high)| (low..=high).contains(&c)) != *negated
            }) && then(at + 1)
        }
        Node::Any => next.is_some() && then(at + 1),
        Node::Start => at == 0 && then(at),
        Node::End => at == text.len() && then(at),
        Node::Group(inner) => alternatives(inner, text, at, then),
    }
}

fn read_alternatives(reader: &mut Reader<'_>) -> Result<Vec<Vec<Piece>>, RenderError> {
    (0..reader.count()?)
        .map(|_| {
            (0..reader.count()?)
                .map(|_| {
                    let min = u32::try_from(reader.number()?).map_err(|_| reader.malformed())?;
                    let max = match reader.number()? {
                        0 => None,
                        bound => Some(u32::try_from(bound - 1).map_err(|_| reader.malformed())?),
                    };
                    Ok(Piece {
                        node: read_node(reader)?,
                        min,
                        max,
                    })
                })
                .collect()
        })
        .collect()
}

fn read_char(reader: &mut Reader<'_>) -> Result<char, RenderError> {
    let code = u32::try_from(reader.number()?).map_err(|_| reader.malformed())?;
    char::from_u32(code).ok_or(reader.malformed())
}

fn read_node(reader: &mut Reader<'_>) -> Result<Node, RenderError> {
    Ok(match reader.byte()? {
        0 => Node::Char(read_char(reader)?),
        1 => {
            let negated = reader.flag()?;
            let ranges = (0..reader.count()?)
                .map(|_| Ok((read_char(reader)?, read_char(reader)?)))
                .collect::<Result<_, RenderError>>()?;
            Node::Class { negated, ranges }
        }
        2 => Node::Any,
        3 => Node::Start,
        4 => Node::End,
        5 => Node::Group(read_alternatives(reader)?),
        _ => return Err(reader.malformed()),
    })
}

#[cfg(feature = "load")]
fn write_alternatives(alternatives: &[Vec<Piece>], writer: &mut Writer) {
    writer.count(alternatives.len());
    for sequence in alternatives {
        writer.count(sequence.len());
        for piece in sequence {
            writer.number(u64::from(piece.min));
            writer.number(piece.max.map_or(0, |max| u64::from(max) + 1));
            match &piece.node {
                Node::Char(c) => {
                    writer.byte(0);
                    writer.number(u64::from(u32::from(*c)));
                }
                Node::Class { negated, ranges } => {
                    writer.byte(1);
                    writer.flag(*negated);
                    writer.count(ranges.len());
                    for (low, high) in ranges {
                        writer.number(u64::from(u32::from(*low)));
                        writer.number(u64::from(u32::from(*high)));
                    }
                }
                Node::Any => writer.byte(2),
                Node::Start => writer.byte(3),
                Node::End => writer.byte(4),
                Node::Group(inner) => {
                    writer.byte(5);
                    write_alternatives(inner, writer);
                }
            }
        }
    }
}

#[cfg(feature = "load")]
fn parse_alternatives(chars: &[char], mut at: usize) -> Option<(Vec<Vec<Piece>>, usize)> {
    let mut alternatives = vec![Vec::new()];
    while let Some(&c) = chars.get(at) {
        match c {
            ')' => break,
            '|' => {
                alternatives.push(Vec::new());
                at += 1;
            }
            _ => {
                let (node, next) = parse_node(chars, at)?;
                let (min, max, next) = parse_quantifier(chars, next)?;
                alternatives.last_mut()?.push(Piece { node, min, max });
                at = next;
            }
        }
    }
    Some((alternatives, at))
}

#[cfg(feature = "load")]
fn parse_node(chars: &[char], at: usize) -> Option<(Node, usize)> {
    Some(match *chars.get(at)? {
        '(' => {
            let start = if chars.get(at + 1) == Some(&'?') && chars.get(at + 2) == Some(&':') {
                at + 3
            } else {
                at + 1
            };
            let (inner, end) = parse_alternatives(chars, start)?;
            (chars.get(end) == Some(&')')).then_some((Node::Group(inner), end + 1))?
        }
        '[' => parse_class(chars, at + 1)?,
        '.' => (Node::Any, at + 1),
        '^' => (Node::Start, at + 1),
        '$' => (Node::End, at + 1),
        '\\' => {
            let (c, end) = parse_escape(chars, at + 1)?;
            (Node::Char(c), end)
        }
        '*' | '+' | '?' | '{' | '}' | ']' => return None,
        c => (Node::Char(c), at + 1),
    })
}

/// A class after its `[`, and the index after its `]`.
#[cfg(feature = "load")]
fn parse_class(chars: &[char], mut at: usize) -> Option<(Node, usize)> {
    let negated = chars.get(at) == Some(&'^');
    if negated {
        at += 1;
    }
    let mut ranges = Vec::new();
    loop {
        let (low, next) = match *chars.get(at)? {
            ']' if !ranges.is_empty() => return Some((Node::Class { negated, ranges }, at + 1)),
            '[' => {
                let (
                    Node::Class {
                        negated: false,
                        ranges: inner,
                    },
                    next,
                ) = parse_class(chars, at + 1)?
                else {
                    return None;
                };
                ranges.extend(inner);
                at = next;
                continue;
            }
            '\\' => parse_escape(chars, at + 1)?,
            c => (c, at + 1),
        };
        at = next;
        if chars.get(at) == Some(&'-') && chars.get(at + 1).is_some_and(|&c| c != ']') {
            let (high, next) = match *chars.get(at + 1)? {
                '\\' => parse_escape(chars, at + 2)?,
                c => (c, at + 2),
            };
            if high < low {
                return None;
            }
            ranges.push((low, high));
            at = next;
        } else {
            ranges.push((low, low));
        }
    }
}

/// An escape after its backslash: `\u{…}`, `\uXXXX`, or a character as itself.
#[cfg(feature = "load")]
fn parse_escape(chars: &[char], at: usize) -> Option<(char, usize)> {
    match *chars.get(at)? {
        'u' if chars.get(at + 1) == Some(&'{') => {
            let end = (at + 2..chars.len()).find(|&i| chars.get(i) == Some(&'}'))?;
            let hex: String = chars.get(at + 2..end)?.iter().collect();
            Some((
                char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?,
                end + 1,
            ))
        }
        'u' => {
            let hex: String = chars.get(at + 1..at + 5)?.iter().collect();
            Some((char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?, at + 5))
        }
        c if c.is_ascii_alphanumeric() => None,
        c => Some((c, at + 1)),
    }
}

#[cfg(feature = "load")]
fn parse_quantifier(chars: &[char], at: usize) -> Option<(u32, Option<u32>, usize)> {
    Some(match chars.get(at) {
        Some('?') => (0, Some(1), at + 1),
        Some('*') => (0, None, at + 1),
        Some('+') => (1, None, at + 1),
        Some('{') => {
            let end = (at + 1..chars.len()).find(|&i| chars.get(i) == Some(&'}'))?;
            let inner: String = chars.get(at + 1..end)?.iter().collect();
            let (min, max) = match inner.split_once(',') {
                Some((min, "")) => (min.parse().ok()?, None),
                Some((min, max)) => (min.parse().ok()?, Some(max.parse().ok()?)),
                None => {
                    let n = inner.parse().ok()?;
                    (n, Some(n))
                }
            };
            if max.is_some_and(|max| max < min) {
                return None;
            }
            (min, max, end + 1)
        }
        _ => (1, Some(1), at),
    })
}
