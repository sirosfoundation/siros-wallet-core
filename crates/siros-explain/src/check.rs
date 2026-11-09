//! The rows of every derived error the binary links: what the wallet's completeness test reads.

#[doc(hidden)]
pub use inventory as __inventory;

/// A derived error's id and its argument keys, in field order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Row {
    /// The id, `err.<scope>.<id>`.
    pub id: &'static str,
    /// The argument keys.
    pub keys: &'static [&'static str],
}

inventory::collect!(Row);

/// Every row of every crate the binary links, in no set order. rustc keeps each linked crate's
/// rows, those of the errors the binary never builds included.
pub fn rows() -> impl Iterator<Item = &'static Row> {
    inventory::iter::<Row>.into_iter()
}
