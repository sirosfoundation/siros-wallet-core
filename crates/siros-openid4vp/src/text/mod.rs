//! Text the core matches: RFC 4647 §3.3.1 basic filtering over the language tags of display
//! entries, and Python's whitespace, as the reference model trims a display text.

mod lookup;
mod space;

pub use lookup::lookup;
pub use space::python_space;
