//! What breaks the rule of a member of a decoded structure.

crate::position!(
    /// The position of an entry in an array member.
    pub ArrayIndex
);

/// What breaks the rule of a member of a decoded JSON object or CBOR map.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum MemberFault {
    /// The member is absent.
    #[error("the member is absent")]
    Absent,
    /// The member has another type than its rule gives it.
    #[error("the member has another type than its rule gives it")]
    WrongType,
    /// The member is an empty string, array or map.
    #[error("the member is an empty string, array or map")]
    Empty,
    /// The array entry at this position breaks the rule of the entries.
    #[error("the array entry at position {0} breaks the rule of the entries")]
    Entry(ArrayIndex),
}
