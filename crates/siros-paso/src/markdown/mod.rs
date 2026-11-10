//! PaSO View §3's `mini_markdown`: CommonMark 0.31.2 §6.2 emphasis and strong emphasis, `<u>`
//! underline (§6.6), every other construct literal. Backslash escapes, code spans, raw HTML
//! and autolinks keep their precedence over emphasis and render literally. Each line is its own
//! block: emphasis pairs within a line.

mod atoms;

use atoms::{atom, punctuation, space};

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
    format!("<p>{}</p>\n", html(&inlines(line)))
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
    let mut flat = Vec::new();
    flatten(inlines(line), Style::PLAIN, &mut flat);
    let mut open = Vec::new();
    let mut pairs = Vec::new();
    for (k, item) in flat.iter().enumerate() {
        match &item.piece {
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
        let text = match &item.piece {
            Piece::Open | Piece::Close if paired(k) => continue,
            Piece::Open => "<u>",
            Piece::Close => "</u>",
            Piece::Text(text) => text.as_str(),
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
enum Piece {
    Text(String),
    Open,
    Close,
}

struct Flat {
    piece: Piece,
    style: Style,
}

/// An underline tag as written.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Tag {
    Open,
    Close,
}

/// An inline of a line: text, an underline tag, the delimiters a run keeps, or emphasis owning
/// the inlines it encloses.
enum Inline {
    Text(String),
    Underline(Tag),
    Run(Run),
    Emphasis { strong: bool, children: Vec<Inline> },
}

/// A delimiter run (CommonMark §6.2): its character, the delimiters it keeps, its length as
/// written, and whether it can open and close emphasis.
struct Run {
    ch: char,
    count: usize,
    original: usize,
    can_open: bool,
    can_close: bool,
}

/// A line's inlines, emphasis processed (CommonMark §6.3 "process emphasis" over the whole
/// line).
fn inlines(line: &str) -> Vec<Inline> {
    let mut done: Vec<Inline> = Vec::new();
    for inline in scan(line) {
        match inline {
            Inline::Run(run) if run.can_close => close(&mut done, run),
            other => done.push(other),
        }
    }
    done
}

/// The line as text, underline tags and delimiter runs, in order.
fn scan(line: &str) -> Vec<Inline> {
    let chars: Vec<char> = line.chars().collect();
    let mut out = Vec::new();
    let mut text = String::new();
    let mut i = 0;
    while let Some(&c) = chars.get(i) {
        let end = atom(&chars, i);
        if end > i {
            text.extend(chars.iter().skip(i).take(end - i));
            i = end;
            continue;
        }
        if let Some((tag, len)) = underline_tag(&chars, i) {
            flush(&mut out, &mut text);
            out.push(Inline::Underline(tag));
            i += len;
            continue;
        }
        if c == '*' || c == '_' {
            flush(&mut out, &mut text);
            let run = Run::at(&chars, i, c);
            i += run.count;
            out.push(Inline::Run(run));
            continue;
        }
        text.push(c);
        i += 1;
    }
    flush(&mut out, &mut text);
    out
}

/// Appends the pending text as a text inline.
fn flush(out: &mut Vec<Inline>, text: &mut String) {
    if !text.is_empty() {
        out.push(Inline::Text(std::mem::take(text)));
    }
}

/// Pairs the closer with the nearest opener before it, again while it keeps delimiters; the
/// inlines between them become the emphasis's children. A closer without an opener stays a
/// possible opener when it can open.
fn close(done: &mut Vec<Inline>, mut closer: Run) {
    while let Some((mut opener, children)) = take_opener(done, &closer) {
        let used = if opener.count >= 2 && closer.count >= 2 {
            2
        } else {
            1
        };
        opener.count -= used;
        closer.count -= used;
        done.push(Inline::Run(opener));
        done.push(Inline::Emphasis {
            strong: used == 2,
            children,
        });
        if closer.count == 0 {
            break;
        }
    }
    done.push(Inline::Run(closer));
}

/// The nearest run of `done` that opens emphasis `closer` closes, taken out with the inlines
/// after it; `done` unchanged when none does.
fn take_opener(done: &mut Vec<Inline>, closer: &Run) -> Option<(Run, Vec<Inline>)> {
    let mut after = Vec::new();
    while let Some(inline) = done.pop() {
        match inline {
            Inline::Run(run) if run.opens(closer) => {
                after.reverse();
                return Some((run, after));
            }
            other => after.push(other),
        }
    }
    done.extend(after.into_iter().rev());
    None
}

/// The inlines as CommonMark HTML.
fn html(inlines: &[Inline]) -> String {
    inlines
        .iter()
        .map(|inline| match inline {
            Inline::Text(text) => text
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
                .replace('"', "&quot;"),
            Inline::Run(run) => run.text(),
            Inline::Underline(Tag::Open) => "<u>".to_owned(),
            Inline::Underline(Tag::Close) => "</u>".to_owned(),
            Inline::Emphasis {
                strong: false,
                children,
            } => format!("<em>{}</em>", html(children)),
            Inline::Emphasis {
                strong: true,
                children,
            } => format!("<strong>{}</strong>", html(children)),
        })
        .collect()
}

/// The inlines' pieces, each with its styles.
fn flatten(inlines: Vec<Inline>, style: Style, out: &mut Vec<Flat>) {
    for inline in inlines {
        let piece = match inline {
            Inline::Text(text) => Piece::Text(text),
            Inline::Run(run) if run.count == 0 => continue,
            Inline::Run(run) => Piece::Text(run.text()),
            Inline::Underline(Tag::Open) => Piece::Open,
            Inline::Underline(Tag::Close) => Piece::Close,
            Inline::Emphasis { strong, children } => {
                let added = if strong { Style::STRONG } else { Style::EM };
                flatten(children, style.with(added), out);
                continue;
            }
        };
        out.push(Flat { piece, style });
    }
}

impl Run {
    /// The run of `c` at `i`, whether it can open and close emphasis (CommonMark §6.2: left- and
    /// right-flanking runs; `_` also by the punctuation around it).
    fn at(chars: &[char], i: usize, c: char) -> Self {
        let count = chars.iter().skip(i).take_while(|&&x| x == c).count();
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
            count,
            original: count,
            can_open,
            can_close,
        }
    }

    /// The delimiters the run keeps, as text.
    fn text(&self) -> String {
        self.ch.to_string().repeat(self.count)
    }

    /// Whether the run opens emphasis `closer` closes: of one character, able to open, holding
    /// delimiters, and no odd match (CommonMark's "rule of 3": a pair one of whose runs can both
    /// open and close does not match when the lengths sum to a multiple of 3, unless both are
    /// multiples of 3).
    fn opens(&self, closer: &Run) -> bool {
        let odd = (self.can_close || closer.can_open)
            && (self.original + closer.original).is_multiple_of(3)
            && !(self.original.is_multiple_of(3) && closer.original.is_multiple_of(3));
        self.ch == closer.ch && self.can_open && self.count > 0 && !odd
    }
}

/// `<u>` or `</u>` at `i`, with its length.
fn underline_tag(chars: &[char], i: usize) -> Option<(Tag, usize)> {
    let starts = |tag: &[char]| chars.iter().skip(i).take(tag.len()).eq(tag);
    if starts(&['<', 'u', '>']) {
        Some((Tag::Open, 3))
    } else if starts(&['<', '/', 'u', '>']) {
        Some((Tag::Close, 4))
    } else {
        None
    }
}
