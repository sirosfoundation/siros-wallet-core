//! A resolved message: styled spans of text, as [`Context::resolve`](crate::Context::resolve)
//! writes them.

use std::fmt;

/// A style that MF2 markup applies: `{#strong}…{/strong}`, `{#emphasis}…{/emphasis}`,
/// `{#underline}…{/underline}`. A module whose markup names another is refused when it loads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Style {
    /// `strong`.
    Strong,
    /// `emphasis`.
    Emphasis,
    /// `underline`.
    Underline,
}

impl Style {
    /// Every style, in the order [`Styles::iter`] gives them.
    const ALL: [Self; 3] = [Self::Strong, Self::Emphasis, Self::Underline];

    /// The style markup of this name applies; `None` for another name.
    pub(crate) fn named(name: &str) -> Option<Self> {
        match name {
            "strong" => Some(Self::Strong),
            "emphasis" => Some(Self::Emphasis),
            "underline" => Some(Self::Underline),
            _ => None,
        }
    }

    /// Its bit in a [`Styles`].
    const fn bit(self) -> u8 {
        match self {
            Self::Strong => 1,
            Self::Emphasis => 2,
            Self::Underline => 4,
        }
    }
}

/// A set of styles: the markup open around a span. Markup nests, so a span can be strong and
/// emphasised at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Styles(u8);

impl Styles {
    /// No style.
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// The set with `style` added.
    #[must_use]
    pub const fn with(self, style: Style) -> Self {
        Self(self.0 | style.bit())
    }

    /// Whether the set holds `style`.
    #[must_use]
    pub const fn contains(self, style: Style) -> bool {
        self.0 & style.bit() != 0
    }

    /// The styles in the set: strong, emphasis, underline, in that order.
    pub fn iter(self) -> impl Iterator<Item = Style> {
        Style::ALL
            .into_iter()
            .filter(move |style| self.contains(*style))
    }

    /// The set with `style` removed.
    const fn without(self, style: Style) -> Self {
        Self(self.0 & !style.bit())
    }
}

/// A run of text and the styles around it. In a [`Text`] no span is empty and no two adjacent
/// spans have the same styles.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Span {
    /// The text, as resolved.
    pub text: String,
    /// The styles the markup around it opened.
    pub styles: Styles,
}

/// A message resolved in a context's locale: its spans, in order. Two texts that read the same
/// with the same styles are equal. Its `Display` writes the spans' text, the styles dropped.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Text(Vec<Span>);

impl Text {
    /// The spans, in order.
    #[must_use]
    pub fn spans(&self) -> &[Span] {
        &self.0
    }
}

impl fmt::Display for Text {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|span| f.write_str(&span.text))
    }
}

/// Where resolution writes: text and markup in order. It merges text under equal styles into one
/// span and drops empty text, so equal texts are equal values. The compiler checks that each
/// pattern opens and closes its styles in nested order.
#[derive(Debug, Default)]
pub(crate) struct Writer {
    spans: Vec<Span>,
    open: Styles,
}

impl Writer {
    /// Text, as given.
    pub(crate) fn text(&mut self, text: &str) {
        if text.is_empty() {
            return;
        }
        match self.spans.last_mut() {
            Some(last) if last.styles == self.open => last.text.push_str(text),
            _ => self.spans.push(Span {
                text: text.to_owned(),
                styles: self.open,
            }),
        }
    }

    /// Markup that opens `style`.
    pub(crate) const fn open(&mut self, style: Style) {
        self.open = self.open.with(style);
    }

    /// Markup that closes `style`.
    pub(crate) const fn close(&mut self, style: Style) {
        self.open = self.open.without(style);
    }

    /// The text written.
    pub(crate) fn finish(self) -> Text {
        Text(self.spans)
    }
}
