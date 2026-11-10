//! MessageFormat 2: its syntax, its data model, and the data model's rules.

pub(crate) mod ast;
#[cfg(any(
    feature = "number",
    feature = "currency",
    feature = "offset",
    feature = "conformance"
))]
pub(crate) mod number;
pub(crate) mod parse;
pub(crate) mod valid;
