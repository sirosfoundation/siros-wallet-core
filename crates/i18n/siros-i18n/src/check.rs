//! The rows of every derived statement the binary links: what [`Context::check`] reads beside
//! siros-explain's rows of errors.
//!
//! [`Context::check`]: crate::Context::check

#[doc(hidden)]
pub use inventory as __inventory;

/// A derived statement's id and its argument keys, in field order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Row {
    /// The id, `<scope>.<id>`.
    pub id: &'static str,
    /// The argument keys.
    pub keys: &'static [&'static str],
}

inventory::collect!(Row);

/// Every row of every crate the binary links, in no set order. rustc keeps each linked crate's
/// rows, those of the statements the binary never builds included.
pub fn rows() -> impl Iterator<Item = &'static Row> {
    inventory::iter::<Row>.into_iter()
}
