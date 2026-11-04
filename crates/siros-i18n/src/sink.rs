//! Where rendering writes: the plain and the formatted sinks, and the styles markup applies.

/// A style that MF2 markup applies: `{#strong}…{/strong}`. A module whose markup names another is
/// refused when it loads.
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
    /// The style markup of this name applies; `None` for another name.
    #[must_use]
    pub fn named(name: &str) -> Option<Self> {
        match name {
            "strong" => Some(Self::Strong),
            "emphasis" => Some(Self::Emphasis),
            "underline" => Some(Self::Underline),
            _ => None,
        }
    }
}

/// Where rendering writes. A compiled message opens and closes its styles in nested order, each
/// once.
#[cfg(feature = "render")]
pub trait Sink {
    /// Text, as given.
    fn text(&mut self, text: &str);
    /// Markup that opens a style.
    fn open(&mut self, style: Style);
    /// Markup that closes the innermost open style, `style`.
    fn close(&mut self, style: Style);
}

/// Formatted text: styled spans, which the frontend renders deterministically, each style with one
/// fixed presentation and each span's text as given. No span is empty and no two adjacent spans
/// have the same styles, so equal texts are equal values. Only the renderer makes one.
#[cfg(feature = "render")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Formatted {
    spans: Vec<Span>,
}

/// A run of text, non-empty, and the styles the markup around it opened, each once, outermost
/// first.
#[cfg(feature = "render")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Span {
    text: String,
    styles: Vec<Style>,
}

#[cfg(feature = "render")]
impl Formatted {
    /// The spans, in order.
    #[must_use]
    pub fn spans(&self) -> &[Span] {
        &self.spans
    }

    /// The plain text: the spans' texts in order, the styles dropped.
    #[must_use]
    pub fn plain(&self) -> String {
        self.spans.iter().map(|span| span.text.as_str()).collect()
    }
}

#[cfg(feature = "render")]
impl Span {
    /// The text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The styles, outermost first.
    #[must_use]
    pub fn styles(&self) -> &[Style] {
        &self.styles
    }
}

/// The sink that makes [`Formatted`] text. The renderer alone writes into it, so its styles nest.
#[cfg(feature = "render")]
#[derive(Debug, Default)]
pub(crate) struct FormattedSink {
    formatted: Formatted,
    open: Vec<Style>,
}

#[cfg(feature = "render")]
impl FormattedSink {
    /// The text written so far.
    #[must_use]
    pub(crate) fn finish(self) -> Formatted {
        self.formatted
    }
}

#[cfg(feature = "render")]
impl Sink for FormattedSink {
    fn text(&mut self, text: &str) {
        if text.is_empty() {
            return;
        }
        match self.formatted.spans.last_mut() {
            Some(last) if last.styles == self.open => last.text.push_str(text),
            _ => self.formatted.spans.push(Span {
                text: text.to_owned(),
                styles: self.open.clone(),
            }),
        }
    }

    fn open(&mut self, style: Style) {
        self.open.push(style);
    }

    fn close(&mut self, style: Style) {
        self.open.retain(|open| *open != style);
    }
}

/// The sink that makes plain text: the text written, the styles dropped.
#[cfg(feature = "render")]
#[derive(Debug, Default)]
pub(crate) struct PlainSink {
    text: String,
}

#[cfg(feature = "render")]
impl PlainSink {
    /// The text written so far.
    #[must_use]
    pub(crate) fn finish(self) -> String {
        self.text
    }
}

#[cfg(feature = "render")]
impl Sink for PlainSink {
    fn text(&mut self, text: &str) {
        self.text.push_str(text);
    }

    fn open(&mut self, _style: Style) {}

    fn close(&mut self, _style: Style) {}
}
