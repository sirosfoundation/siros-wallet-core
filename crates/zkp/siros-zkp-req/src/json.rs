//! The member shapes the request rules share.

use serde_json::Value;
use siros_codec::member::{ArrayIndex, MemberFault};

use crate::outcome::IdentifierFault;

/// A non-empty array.
pub(crate) fn non_empty_array(value: Option<&Value>) -> Result<&[Value], MemberFault> {
    match value {
        None => Err(MemberFault::Absent),
        Some(Value::Array(list)) if list.is_empty() => Err(MemberFault::Empty),
        Some(Value::Array(list)) => Ok(list),
        Some(_) => Err(MemberFault::WrongType),
    }
}

/// A non-empty array of strings. One function for every value type, so that `matcher.wasm`
/// holds its code once.
#[inline(never)]
pub(crate) fn non_empty_texts(value: Option<&Value>) -> Result<Vec<&str>, MemberFault> {
    non_empty_array(value)?
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            entry
                .as_str()
                .ok_or(MemberFault::Entry(ArrayIndex::new(index)))
        })
        .collect()
}

/// A non-empty array of strings, each read by `read`.
pub(crate) fn non_empty_strings<T>(
    value: Option<&Value>,
    read: fn(&str) -> T,
) -> Result<Vec<T>, MemberFault> {
    Ok(non_empty_texts(value)?.into_iter().map(read).collect())
}

/// A member that holds an identifier, read by `parse`.
pub(crate) fn identifier<T, E>(
    value: Option<&Value>,
    parse: fn(&str) -> Result<T, E>,
) -> Result<T, IdentifierFault<E>> {
    let text = value
        .ok_or(IdentifierFault::Absent)?
        .as_str()
        .ok_or(IdentifierFault::NotString)?;
    parse(text).map_err(IdentifierFault::Syntax)
}
