//! The members of a TS12 payload, each read at its path, and why a payload breaks its schema or
//! TS12's prose.

use siros_codec::json::{Json, JsonNumber};
use siros_codec::member::MemberFault;

use crate::json;
pub(crate) use crate::json::Fields;

/// The path of a member in a TS12 payload, `payee.name` for one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MemberPath(&'static str);

impl MemberPath {
    pub(crate) const fn new(path: &'static str) -> Self {
        Self(path)
    }

    /// The path.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        self.0
    }
}

/// Why a payload breaks the schema of its EC TS12 v1.0.1 type, or a rule of Sections 4.3.1 to
/// 4.3.4.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum Ts12PayloadFault {
    /// A member is absent or has the wrong JSON type.
    Member(MemberPath, #[source] MemberFault),
    /// A member has a value its type does not allow.
    Invalid(MemberPath),
    /// The payload holds this member, which its schema does not define.
    Unknown(String),
    /// A member is present where its type forbids it.
    NotAllowed(MemberPath),
}

impl Ts12PayloadFault {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Member(_, MemberFault::Absent) => "transaction_data_member_missing",
            Self::Member(..) => "transaction_data_member_wrong_type",
            Self::Invalid(_) => "transaction_data_member_invalid",
            Self::Unknown(_) => "transaction_data_member_unknown",
            Self::NotAllowed(_) => "transaction_data_member_not_allowed",
        }
    }
}

/// The members of a payload object, read at their paths.
pub(crate) trait Members {
    /// Takes member `name` at `path`, which must be present.
    fn require_member(&mut self, name: &str, path: MemberPath) -> Result<Json, Ts12PayloadFault>;

    /// Refuses a member not taken.
    fn finish(self) -> Result<(), Ts12PayloadFault>;
}

impl Members for Fields {
    fn require_member(&mut self, name: &str, path: MemberPath) -> Result<Json, Ts12PayloadFault> {
        self.require(name)
            .map_err(|fault| Ts12PayloadFault::Member(path, fault))
    }

    fn finish(self) -> Result<(), Ts12PayloadFault> {
        match self.first_left() {
            Some(name) => Err(Ts12PayloadFault::Unknown(name.to_owned())),
            None => Ok(()),
        }
    }
}

/// The fault of `fault` at `path`.
fn at(path: MemberPath) -> impl Fn(MemberFault) -> Ts12PayloadFault {
    move |fault| Ts12PayloadFault::Member(path, fault)
}

/// `value` at `path` as a string.
pub(crate) fn text(value: Json, path: MemberPath) -> Result<String, Ts12PayloadFault> {
    json::text(value).map_err(at(path))
}

/// `value` at `path` as a boolean.
pub(crate) fn boolean(value: Json, path: MemberPath) -> Result<bool, Ts12PayloadFault> {
    json::boolean(value).map_err(at(path))
}

/// `value` at `path` as a number.
pub(crate) fn number(value: Json, path: MemberPath) -> Result<JsonNumber, Ts12PayloadFault> {
    json::number(value).map_err(at(path))
}

/// `value` at `path` as a JSON Schema `integer`.
pub(crate) fn integer(value: Json, path: MemberPath) -> Result<JsonNumber, Ts12PayloadFault> {
    json::integer(value).map_err(at(path))
}

/// `value` at `path` as the members of an object.
pub(crate) fn object(value: Json, path: MemberPath) -> Result<Fields, Ts12PayloadFault> {
    json::object(value).map_err(at(path))
}

/// Member `name` at `path` of `fields`, read by `read` when present.
pub(crate) fn optional<T>(
    fields: &mut Fields,
    name: &str,
    path: MemberPath,
    read: impl FnOnce(Json, MemberPath) -> Result<T, Ts12PayloadFault>,
) -> Result<Option<T>, Ts12PayloadFault> {
    fields.take(name).map(|value| read(value, path)).transpose()
}
