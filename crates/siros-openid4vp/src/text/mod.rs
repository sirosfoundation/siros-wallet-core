//! Text the core displays: RFC 4647 §3.3.1 basic filtering over the wallet's locale tables, and the
//! CommonMark 0.31.2 emphasis (plus `<u>`, everything else literal) a `mini_markdown` label or
//! value shows (PaSO View §3).

pub(crate) mod atoms;
mod lookup;
mod markdown;

pub use atoms::python_space;
pub use lookup::lookup;
pub use markdown::{Span, Style, commonmark_html, spans};
