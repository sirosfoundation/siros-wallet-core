//! An entry of `S.credentials` (privatedata 3.1, Section 6.0).

use rustc_hash::FxHashMap;
use serde::de::DeserializeOwned;
use serde_json::value::RawValue;
use siros_codec::json::JsonTextError;
use siros_codec::member::MemberFault;

use crate::error::{Member, MetadataFault, TypeFault, WalletStateError};
use crate::ids::{
    known, BatchId, ConfigurationId, CredentialId, FormatIdentifier, InstanceId, IssuerIdentifier,
    KeyId,
};

/// The members of a JSON object, each as its text. A repeated name keeps its last value, as
/// JavaScript's `JSON.parse` in `wallet-frontend` does.
pub(crate) type Members<'a> = FxHashMap<String, &'a RawValue>;

/// The members of the object `raw` holds.
///
/// # Errors
///
/// [`JsonTextError`]: `raw` holds no object.
pub(crate) fn object(raw: &RawValue) -> Result<Members<'_>, JsonTextError> {
    serde_json::from_str(raw.get()).map_err(|error| JsonTextError::of(&error))
}

/// The elements of the array `raw` holds.
///
/// # Errors
///
/// [`JsonTextError`]: `raw` holds no array.
pub(crate) fn array(raw: &RawValue) -> Result<Vec<&RawValue>, JsonTextError> {
    serde_json::from_str(raw.get()).map_err(|error| JsonTextError::of(&error))
}

/// A credential entry: the eight members of Section 6.0 and its `metadata`.
pub struct CredentialEntry {
    credential_id: CredentialId,
    format: FormatIdentifier,
    data: CredentialData,
    key_id: Option<KeyId>,
    instance_id: InstanceId,
    batch_id: BatchId,
    issuer: Option<IssuerIdentifier>,
    configuration_id: Option<ConfigurationId>,
    metadata: Vec<MetadataEntry>,
}

/// `data`: the stored credential, in the serialization of its format. It holds the claim
/// values (R-G6).
pub struct CredentialData(String);

impl CredentialData {
    /// The serialization.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl CredentialEntry {
    /// The entry `raw` holds: the members of Section 6.0 and `metadata`.
    pub(crate) fn parse(raw: &RawValue) -> Result<Self, WalletStateError> {
        let members = object(raw).map_err(WalletStateError::CredentialEntry)?;
        let text = |name: Member| member::<String>(&members, name);
        Ok(Self {
            credential_id: CredentialId::new(member(&members, Member::CredentialId)?),
            format: FormatIdentifier::new(text(Member::Format)?),
            data: CredentialData(text(Member::Data)?),
            key_id: KeyId::known(text(Member::Kid)?),
            instance_id: InstanceId::new(member(&members, Member::InstanceId)?),
            batch_id: BatchId::new(member(&members, Member::BatchId)?),
            issuer: IssuerIdentifier::known(text(Member::CredentialIssuerIdentifier)?),
            configuration_id: ConfigurationId::known(text(Member::CredentialConfigurationId)?),
            metadata: match members.get("metadata") {
                Some(raw) => metadata(raw)?,
                None => Vec::new(),
            },
        })
    }

    /// `credentialId`.
    pub fn credential_id(&self) -> CredentialId {
        self.credential_id
    }

    /// `format`.
    pub fn format(&self) -> &FormatIdentifier {
        &self.format
    }

    /// `data`.
    pub fn data(&self) -> &CredentialData {
        &self.data
    }

    /// `kid`: the key pair the credential is bound to. `None` when the entry names none.
    pub fn key_id(&self) -> Option<&KeyId> {
        self.key_id.as_ref()
    }

    /// `instanceId`.
    pub fn instance_id(&self) -> InstanceId {
        self.instance_id
    }

    /// `batchId`.
    pub fn batch_id(&self) -> BatchId {
        self.batch_id
    }

    /// `credentialIssuerIdentifier`. `None` when the wallet did not know it.
    pub fn issuer(&self) -> Option<&IssuerIdentifier> {
        self.issuer.as_ref()
    }

    /// `credentialConfigurationId`. `None` when the wallet did not know it.
    pub fn configuration_id(&self) -> Option<&ConfigurationId> {
        self.configuration_id.as_ref()
    }

    /// `metadata`, in its order. An absent member and an empty array both give no entry.
    pub fn metadata(&self) -> &[MetadataEntry] {
        &self.metadata
    }
}

/// The member `name` of `members`, as a `T`.
fn member<T: DeserializeOwned>(members: &Members<'_>, name: Member) -> Result<T, WalletStateError> {
    let fault = |fault| WalletStateError::CredentialMember(name, fault);
    let raw = members
        .get(name.name())
        .ok_or_else(|| fault(MemberFault::Absent))?;
    serde_json::from_str(raw.get()).map_err(|_| fault(MemberFault::WrongType))
}

/// An entry of `metadata`: data a counterparty supplied for this credential entry.
pub struct MetadataEntry {
    kind: MetadataType,
    value: MetadataValue,
}

impl MetadataEntry {
    /// `type`. Its consumer defines the meaning of `value`.
    pub fn kind(&self) -> &MetadataType {
        &self.kind
    }

    /// `value`.
    pub fn value(&self) -> &MetadataValue {
        &self.value
    }
}

/// The `type` of a `metadata` entry. Never empty.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MetadataType(String);

impl MetadataType {
    /// The type as the entry writes it.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl PartialEq<str> for MetadataType {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for MetadataType {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

/// A `metadata` value as the container holds it. It may hold a delivered secret (privatedata
/// 3.1, Section 5A).
#[derive(Clone)]
pub struct MetadataValue(Box<RawValue>);

impl MetadataValue {
    /// The JSON text of the value, exactly as the container holds it.
    pub fn json(&self) -> &str {
        self.0.get()
    }
}

/// The entries of the `metadata` member `raw`.
fn metadata(raw: &RawValue) -> Result<Vec<MetadataEntry>, WalletStateError> {
    let fault = WalletStateError::Metadata;
    let entries = array(raw).map_err(|error| fault(MetadataFault::NotArray(error)))?;
    entries
        .into_iter()
        .map(|entry| {
            let members =
                object(entry).map_err(|error| fault(MetadataFault::EntryNotObject(error)))?;
            let kind = members
                .get("type")
                .ok_or(fault(MetadataFault::Type(TypeFault::Absent)))?;
            let kind = serde_json::from_str::<String>(kind.get()).map_err(|error| {
                fault(MetadataFault::Type(TypeFault::NotString(
                    JsonTextError::of(&error),
                )))
            })?;
            let kind = known(kind)
                .map(MetadataType)
                .ok_or(fault(MetadataFault::Type(TypeFault::Empty)))?;
            let value = members.get("value").ok_or(fault(MetadataFault::Value))?;
            Ok(MetadataEntry {
                kind,
                value: MetadataValue((*value).to_owned()),
            })
        })
        .collect()
}
