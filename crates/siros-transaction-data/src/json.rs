//! The members of the JSON documents transaction data reads, taken one by one against their
//! schema, and the JSON text a projected definition writes. siros-codec's strict reader reads
//! the documents.

use siros_codec::json::{Json, JsonNumber};
use siros_codec::member::MemberFault;

/// The members of an object not taken yet, in their order.
pub(crate) struct Fields(Vec<(String, Json)>);

impl Fields {
    /// The members `members`, all to take.
    pub(crate) fn new(members: Vec<(String, Json)>) -> Self {
        Self(members)
    }

    /// Takes member `name`.
    pub(crate) fn take(&mut self, name: &str) -> Option<Json> {
        let mut taken = None;
        self.0 = std::mem::take(&mut self.0)
            .into_iter()
            .filter_map(|(n, value)| {
                if taken.is_none() && n == name {
                    taken = Some(value);
                    None
                } else {
                    Some((n, value))
                }
            })
            .collect();
        taken
    }

    /// Takes member `name`, which must be present.
    pub(crate) fn require(&mut self, name: &str) -> Result<Json, MemberFault> {
        self.take(name).ok_or(MemberFault::Absent)
    }

    /// Takes member `name` when present, read by `read`.
    pub(crate) fn optional<T>(
        &mut self,
        name: &str,
        read: impl FnOnce(Json) -> Result<T, MemberFault>,
    ) -> Result<Option<T>, MemberFault> {
        self.take(name).map(read).transpose()
    }

    /// The members not taken: those the schema of the object leaves open.
    pub(crate) fn rest(self) -> Vec<(String, Json)> {
        self.0
    }

    /// The name of the first member not taken.
    pub(crate) fn first_left(&self) -> Option<&str> {
        self.0.first().map(|(name, _)| name.as_str())
    }
}

/// `value` as a string.
pub(crate) fn text(value: Json) -> Result<String, MemberFault> {
    match value {
        Json::String(text) => Ok(text),
        _ => Err(MemberFault::WrongType),
    }
}

/// `value` as a boolean.
pub(crate) fn boolean(value: Json) -> Result<bool, MemberFault> {
    match value {
        Json::Bool(b) => Ok(b),
        _ => Err(MemberFault::WrongType),
    }
}

/// `value` as a number.
pub(crate) fn number(value: Json) -> Result<JsonNumber, MemberFault> {
    match value {
        Json::Number(number) => Ok(number),
        _ => Err(MemberFault::WrongType),
    }
}

/// `value` as a JSON Schema `integer`: a number without a fractional part.
pub(crate) fn integer(value: Json) -> Result<JsonNumber, MemberFault> {
    match value {
        Json::Number(number) if number.is_integer() => Ok(number),
        _ => Err(MemberFault::WrongType),
    }
}

/// `value` as the members of an object.
pub(crate) fn object(value: Json) -> Result<Fields, MemberFault> {
    match value {
        Json::Object(members) => Ok(Fields::new(members)),
        _ => Err(MemberFault::WrongType),
    }
}

/// `value` as the elements of an array.
pub(crate) fn array(value: Json) -> Result<Vec<Json>, MemberFault> {
    match value {
        Json::Array(items) => Ok(items),
        _ => Err(MemberFault::WrongType),
    }
}

/// The compact JSON text of `value`: members and elements in their order, numbers as their
/// writer wrote them.
pub(crate) fn write(value: &Json) -> String {
    let mut out = String::new();
    write_into(value, &mut out);
    out
}

fn write_into(value: &Json, out: &mut String) {
    match value {
        Json::Null => out.push_str("null"),
        Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Json::Number(number) => out.push_str(number.text()),
        Json::String(text) => out.push_str(&quoted(text)),
        Json::Array(items) => {
            out.push('[');
            for (at, item) in items.iter().enumerate() {
                if at > 0 {
                    out.push(',');
                }
                write_into(item, out);
            }
            out.push(']');
        }
        Json::Object(members) => {
            out.push('{');
            for (at, (name, item)) in members.iter().enumerate() {
                if at > 0 {
                    out.push(',');
                }
                out.push_str(&quoted(name));
                out.push(':');
                write_into(item, out);
            }
            out.push('}');
        }
    }
}

/// `value` with the members of every object in the order of RFC 8785, Section 3.2.3: by the
/// UTF-16 code units of their names.
pub(crate) fn canonical(value: &Json) -> Json {
    match value {
        Json::Object(members) => Json::Object(canonical_members(members)),
        Json::Array(items) => Json::Array(items.iter().map(canonical).collect()),
        Json::Null | Json::Bool(_) | Json::Number(_) | Json::String(_) => value.clone(),
    }
}

/// `members` in the order of RFC 8785, Section 3.2.3, the members of their values too.
pub(crate) fn canonical_members(members: &[(String, Json)]) -> Vec<(String, Json)> {
    // An allocation that fails aborts: the members already fit in memory, and a wallet that
    // cannot hold their copy has nothing to fall back to.
    let mut sorted: Vec<(String, Json)> = Vec::new();
    for (name, value) in members {
        // After the members that sort before or equal to it: equal names keep their order.
        let (mut before, after): (Vec<_>, Vec<_>) = sorted.into_iter().partition(|(other, _)| {
            other.encode_utf16().cmp(name.encode_utf16()) != std::cmp::Ordering::Greater
        });
        before.push((name.clone(), canonical(value)));
        before.extend(after);
        sorted = before;
    }
    sorted
}

/// The JSON string literal of `text`.
pub(crate) fn quoted(text: &str) -> String {
    serde_json::Value::from(text).to_string()
}
