//! The identifiers of the wallet state.
//!
//! A string identifier the wallet does not know is the empty string in the wallet state, and
//! `None` here.

use std::fmt;

use serde::Serialize;

/// `credentialId`: the identifier of a credential entry, unique within `S.credentials`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct CredentialId(u64);

impl CredentialId {
    /// The identifier `id`, as the wallet state and the credential picker's entries write it.
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    /// The number.
    pub fn value(self) -> u64 {
        self.0
    }
}

/// The decimal form, as JSON writes the number.
impl fmt::Display for CredentialId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// `batchId`: shared by the instances of one issuance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BatchId(u64);

impl BatchId {
    /// The identifier `id`, as the wallet state and a registration projection write it.
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    /// The number.
    pub fn value(self) -> u64 {
        self.0
    }
}

/// `instanceId`: the index of a one-time-use instance within its batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct InstanceId(u64);

impl InstanceId {
    /// The identifier `id`, as the wallet state and a registration projection write it.
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    /// The number.
    pub fn value(self) -> u64 {
        self.0
    }
}

/// The decimal form, as JSON writes the number.
impl fmt::Display for InstanceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// `format`: a credential format identifier, `dc+sd-jwt` for one.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FormatIdentifier(String);

impl FormatIdentifier {
    pub(crate) fn new(format: String) -> Self {
        Self(format)
    }

    /// The identifier as the wallet state writes it.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// `credentialIssuerIdentifier`: the Credential Issuer Identifier of the issuance (OpenID4VCI
/// 1.0, Section 12.2.1). Never empty.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IssuerIdentifier(String);

impl IssuerIdentifier {
    /// The identifier `text`; `None` for the empty string of an unknown one.
    pub(crate) fn known(text: String) -> Option<Self> {
        known(text).map(Self)
    }

    /// The identifier `text`, as issuer metadata writes it.
    ///
    /// # Errors
    ///
    /// [`EmptyIdentifier`] for the empty string.
    pub fn parse(text: &str) -> Result<Self, EmptyIdentifier> {
        Self::known(text.to_owned()).ok_or(EmptyIdentifier)
    }

    /// The identifier as the wallet state writes it.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// `credentialConfigurationId`: the credential configuration of the issuance (OpenID4VCI 1.0,
/// Section 12.2.4). Never empty.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConfigurationId(String);

impl ConfigurationId {
    /// The identifier `text`; `None` for the empty string of an unknown one.
    pub(crate) fn known(text: String) -> Option<Self> {
        known(text).map(Self)
    }

    /// The identifier `text`, as issuer metadata writes it.
    ///
    /// # Errors
    ///
    /// [`EmptyIdentifier`] for the empty string.
    pub fn parse(text: &str) -> Result<Self, EmptyIdentifier> {
        Self::known(text.to_owned()).ok_or(EmptyIdentifier)
    }

    /// The identifier as the wallet state writes it.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// `kid`: the identifier of a key pair of the wallet. Never empty.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyId(String);

impl KeyId {
    /// The identifier `text`; `None` for the empty string of an unknown one.
    pub(crate) fn known(text: String) -> Option<Self> {
        known(text).map(Self)
    }

    /// The identifier as the wallet state writes it.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// `presentationId`: the identifier of a presentation record, drawn at random by the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct PresentationId(u64);

impl PresentationId {
    /// The identifier `id`.
    pub fn new(id: u64) -> Self {
        Self(id)
    }
}

/// `transactionId`: shared by the presentation records of one response, drawn at random by the
/// host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct TransactionId(u64);

impl TransactionId {
    /// The identifier `id`.
    pub fn new(id: u64) -> Self {
        Self(id)
    }
}

/// The empty string, where an identifier is never empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("identifier_empty")]
pub struct EmptyIdentifier;

/// `text`, or `None` for the empty string the wallet writes when it does not know a value.
pub(crate) fn known(text: String) -> Option<String> {
    (!text.is_empty()).then_some(text)
}
