//! CommonMark 0.31.2 §6.2 emphasis and strong emphasis, `<u>` underline (§6.6), every other
//! construct literal (PaSO View §3 `mini_markdown`). Backslash escapes, code spans, raw HTML
//! and autolinks keep their precedence over emphasis and render literally. Each line is its own
//! block: emphasis pairs within a line.

use super::atoms::{atom, punctuation, space};

/// The styles a span carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Style(u8);

impl Style {
    /// No style.
    pub const PLAIN: Self = Self(0);
    /// Emphasis.
    pub const EM: Self = Self(1);
    /// Strong emphasis.
    pub const STRONG: Self = Self(2);
    /// Underline.
    pub const UNDERLINE: Self = Self(4);

    /// The union of two styles.
    #[must_use]
    pub const fn with(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Whether the style holds all of `other`.
    #[must_use]
    pub const fn has(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

/// A run of text in one style.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Span {
    /// The text.
    pub text: String,
    /// Its style.
    pub style: Style,
}

/// One line's emphasis tree as CommonMark 0.31.2 HTML: a paragraph of `<em>` and `<strong>`
/// elements, text escaped, `<u>` and `</u>` as written. CommonMark's own examples state their
/// expected output in this form.
#[must_use]
pub fn commonmark_html(line: &str) -> String {
    format!("<p>{}</p>\n", Tree::parse(line).html(None))
}

/// The text as styled spans, adjacent spans of one style merged.
#[must_use]
pub fn spans(text: &str) -> Vec<Span> {
    let mut out = Vec::new();
    for (k, line) in text.split('\n').enumerate() {
        if k > 0 {
            push(&mut out, "\n", Style::PLAIN);
        }
        for span in line_spans(line) {
            push(&mut out, &span.text, span.style);
        }
    }
    out
}

fn push(out: &mut Vec<Span>, text: &str, style: Style) {
    match out.last_mut() {
        Some(last) if last.style == style => last.text.push_str(text),
        _ => out.push(Span {
            text: text.to_owned(),
            style,
        }),
    }
}

/// One line's spans: emphasis by its tree, then `<u>` and `</u>` paired in order across it.
fn line_spans(line: &str) -> Vec<Span> {
    let tree = Tree::parse(line);
    let mut flat = Vec::new();
    tree.flatten(ROOT_CHILDREN, Style::PLAIN, &mut flat);
    let mut open = Vec::new();
    let mut pairs = Vec::new();
    for (k, item) in flat.iter().enumerate() {
        match item.piece {
            Piece::Open => open.push(k),
            Piece::Close => {
                if let Some(start) = open.pop() {
                    pairs.push((start, k));
                }
            }
            Piece::Text(_) => {}
        }
    }
    let paired = |k: usize| pairs.iter().any(|&(a, b)| a == k || b == k);
    let underlined = |k: usize| pairs.iter().any(|&(a, b)| a < k && k < b);
    let mut out = Vec::new();
    for (k, item) in flat.iter().enumerate() {
        let text = match item.piece {
            Piece::Open | Piece::Close if paired(k) => continue,
            Piece::Open => "<u>",
            Piece::Close => "</u>",
            Piece::Text(node) => tree.nodes.get(node).map_or("", |n| n.text.as_str()),
        };
        let style = if underlined(k) {
            item.style.with(Style::UNDERLINE)
        } else {
            item.style
        };
        push(&mut out, text, style);
    }
    out
}

/// What a flattened inline item holds.
#[derive(Clone, Copy)]
enum Piece {
    Text(usize),
    Open,
    Close,
}

struct Flat {
    piece: Piece,
    style: Style,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Head,
    Text,
    Em,
    Strong,
    OpenU,
    CloseU,
}

struct Node {
    kind: Kind,
    text: String,
    children: Vec<usize>,
    prev: Option<usize>,
    next: Option<usize>,
}

struct Delimiter {
    ch: char,
    node: usize,
    count: usize,
    original: usize,
    can_open: bool,
    can_close: bool,
}

/// The inline nodes of a line: a doubly linked list from the head node, emphasis nodes holding
/// the nodes they enclose.
struct Tree {
    nodes: Vec<Node>,
}

const HEAD: usize = 0;
/// Flattening starts from the head's successors.
const ROOT_CHILDREN: Option<usize> = None;

impl Tree {
    fn parse(line: &str) -> Self {
        let mut tree = Tree {
            nodes: vec![Node::new(Kind::Head, String::new())],
        };
        let mut tail = HEAD;
        let mut delimiters = Vec::new();
        let chars: Vec<char> = line.chars().collect();
        let mut text = String::new();
        let mut i = 0;
        while let Some(&c) = chars.get(i) {
            let end = atom(&chars, i);
            if end > i {
                text.extend(chars.get(i..end).unwrap_or_default());
                i = end;
                continue;
            }
            if let Some((kind, len)) = underline_tag(&chars, i) {
                tree.flush(&mut tail, &mut text);
                tree.append(&mut tail, kind, String::new());
                i += len;
                continue;
            }
            if c == '*' || c == '_' {
                tree.flush(&mut tail, &mut text);
                let delimiter = Delimiter::run(&chars, i, c);
                tree.append(&mut tail, Kind::Text, c.to_string().repeat(delimiter.count));
                i += delimiter.count;
                delimiters.push(Delimiter {
                    node: tail,
                    ..delimiter
                });
                continue;
            }
            text.push(c);
            i += 1;
        }
        tree.flush(&mut tail, &mut text);
        tree.process_emphasis(delimiters);
        tree
    }

    /// Appends a node after `tail`, which becomes the new node.
    fn append(&mut self, tail: &mut usize, kind: Kind, text: String) {
        let index = self.nodes.len();
        let mut node = Node::new(kind, text);
        node.prev = Some(*tail);
        self.nodes.push(node);
        if let Some(previous) = self.nodes.get_mut(*tail) {
            previous.next = Some(index);
        }
        *tail = index;
    }

    /// Appends the pending text as a text node.
    fn flush(&mut self, tail: &mut usize, text: &mut String) {
        if !text.is_empty() {
            self.append(tail, Kind::Text, std::mem::take(text));
        }
    }

    /// CommonMark's "process emphasis" over the whole delimiter stack. The search runs to the
    /// stack bottom: `openers_bottom` only bounds a search that would find nothing below it.
    fn process_emphasis(&mut self, mut stack: Vec<Delimiter>) {
        let mut pos = 0;
        while let Some(closer) = stack.get(pos) {
            if !closer.can_close {
                pos += 1;
                continue;
            }
            let opener = stack
                .get(..pos)
                .unwrap_or_default()
                .iter()
                .enumerate()
                .rev()
                .find(|(_, opener)| {
                    opener.ch == closer.ch && opener.can_open && !odd_match(opener, closer)
                });
            match opener {
                None if closer.can_open => pos += 1,
                None => stack.cut(pos, pos + 1),
                Some((found, opener)) => {
                    let used = if opener.count >= 2 && closer.count >= 2 {
                        2
                    } else {
                        1
                    };
                    let nodes = (opener.node, closer.node);
                    pos = self.pair(&mut stack, (found, pos), nodes, used);
                }
            }
        }
    }

    /// Encloses the nodes between the opener at `found` and the closer at `pos` in emphasis of
    /// `used` delimiters, drops the delimiters between them and those spent; the position to
    /// continue from.
    fn pair(
        &mut self,
        stack: &mut Vec<Delimiter>,
        (found, pos): (usize, usize),
        (open_node, close_node): (usize, usize),
        used: usize,
    ) -> usize {
        self.shorten(open_node, used);
        self.shorten(close_node, used);
        self.enclose(
            open_node,
            close_node,
            if used == 2 { Kind::Strong } else { Kind::Em },
        );
        stack.cut(found + 1, pos);
        let mut pos = found + 1;
        let mut spend = |k: usize| {
            stack.get_mut(k).is_some_and(|d| {
                d.count -= used;
                d.count == 0
            })
        };
        let (opener_spent, closer_spent) = (spend(found), spend(pos));
        if opener_spent {
            self.unlink(open_node);
            stack.cut(found, found + 1);
            pos -= 1;
        }
        if closer_spent {
            self.unlink(close_node);
            stack.cut(pos, pos + 1);
        }
        pos
    }

    fn shorten(&mut self, node: usize, used: usize) {
        if let Some(node) = self.nodes.get_mut(node) {
            let keep = node.text.chars().count().saturating_sub(used);
            node.text = node.text.chars().take(keep).collect();
        }
    }

    /// Moves the nodes strictly between `open` and `close` into a new emphasis node placed there.
    fn enclose(&mut self, open: usize, close: usize, kind: Kind) {
        let emphasis = self.nodes.len();
        self.nodes.push(Node::new(kind, String::new()));
        let mut inner = self.nodes.get(open).and_then(|n| n.next);
        let mut children = Vec::new();
        while let Some(node) = inner.filter(|&n| n != close) {
            inner = self.nodes.get(node).and_then(|n| n.next);
            if let Some(n) = self.nodes.get_mut(node) {
                n.prev = None;
                n.next = None;
            }
            children.push(node);
        }
        if let Some(n) = self.nodes.get_mut(emphasis) {
            n.children = children;
            n.prev = Some(open);
            n.next = Some(close);
        }
        if let Some(n) = self.nodes.get_mut(open) {
            n.next = Some(emphasis);
        }
        if let Some(n) = self.nodes.get_mut(close) {
            n.prev = Some(emphasis);
        }
    }

    fn unlink(&mut self, node: usize) {
        let (prev, next) = self
            .nodes
            .get(node)
            .map_or((None, None), |n| (n.prev, n.next));
        if let Some(p) = prev.and_then(|p| self.nodes.get_mut(p)) {
            p.next = next;
        }
        if let Some(n) = next.and_then(|n| self.nodes.get_mut(n)) {
            n.prev = prev;
        }
    }

    /// The nodes under a node, or the head's successors for `None`.
    fn children(&self, parent: Option<usize>) -> Vec<usize> {
        match parent {
            Some(node) => self
                .nodes
                .get(node)
                .map(|n| n.children.clone())
                .unwrap_or_default(),
            None => std::iter::successors(self.nodes.get(HEAD).and_then(|n| n.next), |&n| {
                self.nodes.get(n).and_then(|node| node.next)
            })
            .collect(),
        }
    }

    /// The nodes under a node as CommonMark HTML.
    fn html(&self, parent: Option<usize>) -> String {
        self.children(parent)
            .into_iter()
            .filter_map(|child| self.nodes.get(child).map(|node| (child, node)))
            .map(|(child, node)| match node.kind {
                Kind::Text => node
                    .text
                    .replace('&', "&amp;")
                    .replace('<', "&lt;")
                    .replace('>', "&gt;")
                    .replace('"', "&quot;"),
                Kind::OpenU => "<u>".to_owned(),
                Kind::CloseU => "</u>".to_owned(),
                Kind::Em => format!("<em>{}</em>", self.html(Some(child))),
                Kind::Strong => format!("<strong>{}</strong>", self.html(Some(child))),
                Kind::Head => String::new(),
            })
            .collect()
    }

    /// The pieces under a node (the head's successors for `None`), each with its styles.
    fn flatten(&self, parent: Option<usize>, style: Style, out: &mut Vec<Flat>) {
        for child in self.children(parent) {
            let Some(node) = self.nodes.get(child) else {
                continue;
            };
            match node.kind {
                Kind::Text => out.push(Flat {
                    piece: Piece::Text(child),
                    style,
                }),
                Kind::OpenU => out.push(Flat {
                    piece: Piece::Open,
                    style,
                }),
                Kind::CloseU => out.push(Flat {
                    piece: Piece::Close,
                    style,
                }),
                Kind::Em => self.flatten(Some(child), style.with(Style::EM), out),
                Kind::Strong => self.flatten(Some(child), style.with(Style::STRONG), out),
                Kind::Head => {}
            }
        }
    }
}

impl Node {
    fn new(kind: Kind, text: String) -> Self {
        Self {
            kind,
            text,
            children: Vec::new(),
            prev: None,
            next: None,
        }
    }
}

impl Delimiter {
    /// The run of `c` at `i`, whether it can open and close emphasis (CommonMark §6.2: left- and
    /// right-flanking runs; `_` also by the punctuation around it). Its node is set on append.
    fn run(chars: &[char], i: usize, c: char) -> Self {
        let count = chars
            .get(i..)
            .unwrap_or_default()
            .iter()
            .take_while(|&&x| x == c)
            .count();
        let before = i.checked_sub(1).and_then(|k| chars.get(k).copied());
        let after = chars.get(i + count).copied();
        let left = !space(after) && (!punctuation(after) || space(before) || punctuation(before));
        let right = !space(before) && (!punctuation(before) || space(after) || punctuation(after));
        let (can_open, can_close) = if c == '*' {
            (left, right)
        } else {
            (
                left && (!right || punctuation(before)),
                right && (!left || punctuation(after)),
            )
        };
        Self {
            ch: c,
            node: HEAD,
            count,
            original: count,
            can_open,
            can_close,
        }
    }
}

/// CommonMark's "rule of 3": a pair one of whose runs can both open and close does not match
/// when the lengths sum to a multiple of 3, unless both are multiples of 3.
fn odd_match(opener: &Delimiter, closer: &Delimiter) -> bool {
    (opener.can_close || closer.can_open)
        && (opener.original + closer.original).is_multiple_of(3)
        && !(opener.original.is_multiple_of(3) && closer.original.is_multiple_of(3))
}

/// Removals from a delimiter stack, each index clamped to the length.
trait Cut {
    /// Removes the items from `start` up to `end`.
    fn cut(&mut self, start: usize, end: usize);
}

impl<T> Cut for Vec<T> {
    fn cut(&mut self, start: usize, end: usize) {
        let end = end.min(self.len());
        let mut tail = Vec::with_capacity(self.len() - end);
        while self.len() > end {
            tail.extend(self.pop());
        }
        self.truncate(start.min(end));
        self.extend(tail.into_iter().rev());
    }
}

/// `<u>` or `</u>` at `i`, with its length.
fn underline_tag(chars: &[char], i: usize) -> Option<(Kind, usize)> {
    let rest = chars.get(i..)?;
    if rest.starts_with(&['<', 'u', '>']) {
        Some((Kind::OpenU, 3))
    } else if rest.starts_with(&['<', '/', 'u', '>']) {
        Some((Kind::CloseU, 4))
    } else {
        None
    }
}
