//! Text the core reads: the characters and lengths a metadata text may hold, RFC 4647 §3.3.1 basic
//! filtering over the language tags of display entries, and Python's whitespace, as the reference
//! model trims a display text.

mod display;
mod lookup;
mod space;

pub use display::{CARD_TEXT_MAX, DisplayText, LABEL_MAX, TEMPLATE_MAX, TextError, VALUE_MAX};
pub use lookup::lookup;
pub use space::python_space;
