//! Why text is not a wallet state the core reads. Each error has a stable code.

use serde_json::error::Category;

/// What breaks the rule of a member of a decoded JSON object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum MemberFault {
    /// The member is absent.
    #[error("the member is absent")]
    Absent,
    /// The member has another type than its rule gives it.
    #[error("the member has another type than its rule gives it")]
    WrongType,
    /// `format` is the empty string.
    #[error("`format` is the empty string")]
    Empty,
}

/// What serde_json found in text that is no JSON value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum JsonTextFault {
    /// Text that breaks the JSON syntax.
    #[error("text that breaks the JSON syntax")]
    Syntax,
    /// A value of another type than its member's, a number beyond a 64-bit float, or a member
    /// name an object repeats.
    #[error("a value of another type than its member's")]
    Value,
    /// The text ends inside a value.
    #[error("the text ends inside a value")]
    Eof,
}

/// Why bytes are no JSON text of the shape read, and where.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{kind:?} at line {line} column {column}")]
pub struct JsonTextError {
    #[source]
    kind: JsonTextFault,
    line: usize,
    column: usize,
}

impl JsonTextError {
    /// What `error` found, and where.
    #[must_use]
    pub fn of(error: &serde_json::Error) -> Self {
        Self {
            kind: match error.classify() {
                Category::Syntax | Category::Io => JsonTextFault::Syntax,
                Category::Data => JsonTextFault::Value,
                Category::Eof => JsonTextFault::Eof,
            },
            line: error.line(),
            column: error.column(),
        }
    }

    /// What breaks the text.
    #[must_use]
    pub fn kind(self) -> JsonTextFault {
        self.kind
    }

    /// The line, from 1.
    #[must_use]
    pub fn line(self) -> usize {
        self.line
    }

    /// The column, from 1, or 0 at the start of a line.
    #[must_use]
    pub fn column(self) -> usize {
        self.column
    }
}

/// Why text is not the `S` of a WalletStateContainer (privatedata 3.1, Section 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}", self.code())]
pub enum WalletStateError {
    /// The text is not a JSON object of the members `S` gives them.
    Malformed(#[source] JsonTextError),
    /// `schemaVersion` is neither 3 nor 4.
    UnsupportedSchemaVersion(FoundVersion),
    /// `credentials` is absent or not an array.
    Credentials(#[source] ArrayFault),
    /// An entry of `credentials` is not an object.
    CredentialEntry(#[source] JsonTextError),
    /// A member of Section 6.0 of a credential entry breaks its rule. The number members are
    /// non-negative integers of 64 bits; the others are strings, `format` a non-empty one.
    #[error("{code}: {member}", code = self.code(), member = .0.name())]
    CredentialMember(Member, #[source] MemberFault),
    /// Two credential entries share a `credentialId`.
    RepeatedCredentialId,
    /// `metadata` is not an array of objects, each with a non-empty string `type` and a
    /// `value`.
    Metadata(#[source] MetadataFault),
    /// `keypairs` is absent or not an array.
    Keypairs(#[source] ArrayFault),
    /// `presentations` is not an array of the records of `new_presentation`.
    Presentations(#[source] PresentationsFault),
}

/// The `schemaVersion` of a state of a version other than 3 and 4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FoundVersion {
    /// The member is absent: version 1.
    Absent,
    /// This version.
    Version(u64),
    /// The member is no non-negative integer of 64 bits.
    NotAVersion,
}

/// A member of a credential entry (privatedata 3.1, Section 6.0).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Member {
    /// `credentialId`.
    CredentialId,
    /// `format`.
    Format,
    /// `data`.
    Data,
    /// `kid`.
    Kid,
    /// `instanceId`.
    InstanceId,
    /// `batchId`.
    BatchId,
    /// `credentialIssuerIdentifier`.
    CredentialIssuerIdentifier,
    /// `credentialConfigurationId`.
    CredentialConfigurationId,
}

impl Member {
    /// The member's name.
    pub fn name(self) -> &'static str {
        match self {
            Self::CredentialId => "credentialId",
            Self::Format => "format",
            Self::Data => "data",
            Self::Kid => "kid",
            Self::InstanceId => "instanceId",
            Self::BatchId => "batchId",
            Self::CredentialIssuerIdentifier => "credentialIssuerIdentifier",
            Self::CredentialConfigurationId => "credentialConfigurationId",
        }
    }
}

/// Why a member that holds an array is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum ArrayFault {
    /// The member is absent.
    #[error("the member is absent")]
    Absent,
    /// The member holds no array.
    #[error("the member holds no array")]
    NotArray(#[source] JsonTextError),
}

/// The rule `metadata` breaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum MetadataFault {
    /// `metadata` is not an array.
    #[error("`metadata` is not an array")]
    NotArray(#[source] JsonTextError),
    /// An entry is not an object.
    #[error("an entry is not an object")]
    EntryNotObject(#[source] JsonTextError),
    /// An entry has no non-empty string `type`.
    #[error("an entry has no non-empty string `type`")]
    Type(#[source] TypeFault),
    /// An entry has no `value`.
    #[error("an entry has no `value`")]
    Value,
}

/// Why a `metadata` entry has no `type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum TypeFault {
    /// The entry has no `type`.
    #[error("the entry has no `type`")]
    Absent,
    /// `type` is not a string.
    #[error("`type` is not a string")]
    NotString(#[source] JsonTextError),
    /// `type` is the empty string.
    #[error("`type` is the empty string")]
    Empty,
}

/// The rule `presentations` breaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum PresentationsFault {
    /// `presentations` is absent or not an array.
    #[error("`presentations` is absent or not an array")]
    NotArray(#[source] ArrayFault),
    /// An entry lacks one of the six members of `new_presentation`, or one of them has the
    /// wrong type: `presentationId` and `transactionId` non-negative integers of 64 bits,
    /// `usedCredentialIds` an array of them, `presentationTimestampSeconds` an integer, and
    /// the strings `data` and `audience`.
    #[error("an entry lacks one of the six members of `new_presentation`, or one of them has the wrong type: `presentationId` and `transactionId` non-negative integers of 64 bits, `usedCredentialIds` an array of them, `presentationTimestampSeconds` an integer, and the strings `data` and `audience`")]
    Record(#[source] JsonTextError),
    /// A `presentationTimestampSeconds` is outside the years 0000 to 9999.
    #[error("a `presentationTimestampSeconds` is outside the years 0000 to 9999")]
    Timestamp,
}

impl WalletStateError {
    /// A stable identifier.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Malformed(_) => "state_malformed",
            Self::UnsupportedSchemaVersion(_) => "schema_version_unsupported",
            Self::Credentials(_) => "credentials_malformed",
            Self::CredentialEntry(_) => "credential_entry_malformed",
            Self::CredentialMember(..) => "credential_member_malformed",
            Self::RepeatedCredentialId => "credential_id_repeated",
            Self::Metadata(_) => "metadata_malformed",
            Self::Keypairs(_) => "keypairs_malformed",
            Self::Presentations(_) => "presentations_malformed",
        }
    }
}
