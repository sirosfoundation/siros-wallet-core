//! Transaction data type identifiers (OpenID4VP 1.0, Section 5.1 `type`), and the types whose
//! rulebook the wallet holds.

use std::fmt;

/// The prefix of a PaSO transaction data type identifier (PaSO Core, Section 5.2).
const PASO_PREFIX: &str = "urn:paso:sca:";

/// A transaction data type identifier: a non-empty string.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TypeId(String);

/// Why text is no transaction data type identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EmptyTypeId;

impl TypeId {
    /// The identifier `text`.
    ///
    /// # Errors
    ///
    /// [`EmptyTypeId`] for the empty string.
    pub fn parse(text: &str) -> Result<Self, EmptyTypeId> {
        if text.is_empty() {
            Err(EmptyTypeId)
        } else {
            Ok(Self(text.to_owned()))
        }
    }

    /// The identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether the entry is PaSO-targeted: its identifier starts with `urn:paso:sca:` (PaSO
    /// Core, Section 5.2).
    #[must_use]
    pub fn family(&self) -> TypeFamily {
        if self.0.starts_with(PASO_PREFIX) {
            TypeFamily::Paso
        } else {
            TypeFamily::Other
        }
    }

    /// The built-in rulebook of the identifier, when it names one.
    #[must_use]
    pub fn rulebook(&self) -> Option<Ts12Type> {
        Ts12Type::ALL
            .into_iter()
            .find(|builtin| builtin.identifier() == self.0)
    }
}

impl fmt::Display for TypeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Whether a type is PaSO-targeted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TypeFamily {
    /// `urn:paso:sca:`.
    Paso,
    /// Any other identifier.
    Other,
}

/// A transaction data type whose rulebook the wallet holds: the four types of EC TS12 v1.0.1
/// (Section 4.3), with their typed payloads and their KB-JWT claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ts12Type {
    /// `urn:eudi:sca:payment:1`.
    Payment,
    /// `urn:eudi:sca:login_risk_transaction:1`.
    LoginRisk,
    /// `urn:eudi:sca:account_access:1`.
    AccountAccess,
    /// `urn:eudi:sca:emandate:1`.
    Emandate,
}

impl Ts12Type {
    pub(crate) const ALL: [Self; 4] = [
        Self::Payment,
        Self::LoginRisk,
        Self::AccountAccess,
        Self::Emandate,
    ];

    /// The `type` value, which also names the type's built-in JSON Schema (Section 4.3).
    #[must_use]
    pub fn identifier(self) -> &'static str {
        match self {
            Self::Payment => "urn:eudi:sca:payment:1",
            Self::LoginRisk => "urn:eudi:sca:login_risk_transaction:1",
            Self::AccountAccess => "urn:eudi:sca:account_access:1",
            Self::Emandate => "urn:eudi:sca:emandate:1",
        }
    }

    /// The type whose built-in schema `name` names (Section 4.3).
    pub(crate) fn schema(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|builtin| builtin.identifier() == name)
    }
}
