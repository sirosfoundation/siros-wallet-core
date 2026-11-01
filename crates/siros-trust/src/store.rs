//! The trust store the host provisions (TR1, TR4): for each authority a Verifier may name, the
//! certificates to which an issuer chain has a path.

use siros_codec::date::DateTime;
use siros_codec::json::{Json, JsonFault};
use siros_codec::member::MemberFault;
use siros_codec::{base64, Base64Error};
use siros_dcql::{AuthorityType, AuthorityValue};

use crate::authority::{KnownAuthorityType, StoreAuthority};
use crate::certificate::{Certificate, CertificateError};
use crate::chain::IssuerChain;
use crate::path::PathRefusal;
use crate::position::{CertificateIndex, EntryIndex};

/// The trust store: its entries, each authority once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustStore {
    entries: Vec<StoreEntry>,
}

/// An entry of the trust store: an authority and its certificates, at least one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreEntry {
    authority: StoreAuthority,
    certificates: Vec<Certificate>,
}

/// Why a record is no trust store (TR1).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    /// The strict reader refuses the record: a member name an object repeats among its faults.
    #[error("{code}: {0}", code = self.code())]
    Json(#[source] JsonFault),
    /// The record is not a JSON array.
    #[error("{}", self.code())]
    NotArray,
    /// An entry breaks a rule.
    #[error("{code} at entry {at}", code = self.code(), at = entry.value())]
    Entry {
        /// The entry's position.
        entry: EntryIndex,
        /// The rule.
        #[source]
        error: EntryError,
    },
    /// An entry repeats the `type` and `value` of an earlier one.
    #[error("{code} at entry {at}", code = self.code(), at = .0.value())]
    Repeated(EntryIndex),
}

/// Why an entry of a trust store record is refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum EntryError {
    /// The entry is not a JSON object.
    NotObject,
    /// The entry has this member, other than `type`, `value` and `certificates`.
    UnknownMember(String),
    /// `type` is absent or not a string.
    Type(#[source] MemberFault),
    /// `type` names this type, other than `etsi_tl` and `openid_federation`.
    UnknownType(AuthorityType),
    /// `value` is absent or not a string.
    Value(#[source] MemberFault),
    /// `certificates` is absent, not an array, or empty.
    Certificates(#[source] MemberFault),
    /// A certificate is not a string.
    CertificateNotString(CertificateIndex),
    /// A certificate is not base64 with padding (the `x5c` encoding, RFC 7515, Section 4.1.6).
    Encoding {
        /// Its position in `certificates`.
        certificate: CertificateIndex,
        /// Why.
        #[source]
        error: Base64Error,
    },
    /// A certificate does not parse.
    Certificate {
        /// Its position in `certificates`.
        certificate: CertificateIndex,
        /// Why.
        #[source]
        error: CertificateError,
    },
}

impl StoreError {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Json(JsonFault::Read(_)) => "trust_store_json",
            Self::Json(JsonFault::RepeatedMember(_)) => "trust_store_member_repeated",
            Self::NotArray => "trust_store_not_array",
            Self::Entry { error, .. } => error.code(),
            Self::Repeated(_) => "trust_store_entry_repeated",
        }
    }
}

impl EntryError {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotObject => "trust_store_entry_not_object",
            Self::UnknownMember(_) => "trust_store_entry_member_unknown",
            Self::Type(_) => "trust_store_entry_type",
            Self::UnknownType(_) => "trust_store_entry_type_unknown",
            Self::Value(_) => "trust_store_entry_value",
            Self::Certificates(_) => "trust_store_entry_certificates",
            Self::CertificateNotString(_) => "trust_store_certificate_not_string",
            Self::Encoding { .. } => "trust_store_certificate_encoding",
            Self::Certificate { error, .. } => error.code(),
        }
    }
}

impl TrustStore {
    /// The trust store of the JSON record `record`: an array of entries `{type, value,
    /// certificates}`, `type` `etsi_tl` or `openid_federation`, `value` the authority's value as
    /// a Verifier sends it, and `certificates` a non-empty array of DER certificates, each in
    /// base64 with padding. No two entries share a `type` and a `value`, and no object repeats
    /// a member name.
    ///
    /// # Errors
    ///
    /// [`StoreError`]: the first rule the record breaks.
    pub fn parse(record: &str) -> Result<Self, StoreError> {
        let Json::Array(entries) =
            Json::parse_unique(record.as_bytes()).map_err(StoreError::Json)?
        else {
            return Err(StoreError::NotArray);
        };
        let mut parsed: Vec<StoreEntry> = Vec::with_capacity(entries.len());
        for (position, entry) in entries.iter().enumerate() {
            let entry_index = EntryIndex::new(position);
            let entry = StoreEntry::parse(entry).map_err(|error| StoreError::Entry {
                entry: entry_index,
                error,
            })?;
            if parsed
                .iter()
                .any(|earlier| earlier.authority == entry.authority)
            {
                return Err(StoreError::Repeated(entry_index));
            }
            parsed.push(entry);
        }
        Ok(Self { entries: parsed })
    }

    /// The entries, in the record's order.
    #[must_use]
    pub fn entries(&self) -> &[StoreEntry] {
        &self.entries
    }

    /// The entry of `authority`.
    #[must_use]
    pub fn entry(&self, authority: &StoreAuthority) -> Option<&StoreEntry> {
        self.entries
            .iter()
            .find(|entry| entry.authority == *authority)
    }

    /// The store certificate at which `chain`'s path ends at `time` (TR3): the anchor of the
    /// first entry, in the record's order, to which the chain has a path.
    ///
    /// # Errors
    ///
    /// [`Unanchored`]: the refusal of each entry, in the record's order.
    pub fn anchor(&self, chain: &IssuerChain, time: DateTime) -> Result<&Certificate, Unanchored> {
        let mut refusals = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            match chain.validate_path(&entry.certificates, time) {
                Ok(anchor) => return Ok(anchor),
                Err(refusal) => refusals.push((entry.authority.clone(), refusal)),
            }
        }
        Err(Unanchored(refusals))
    }
}

/// Why an issuer chain has a path to no certificate of the trust store: the refusal of each
/// entry, in the record's order; none for an empty store.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub struct Unanchored(Vec<(StoreAuthority, PathRefusal)>);

impl Unanchored {
    /// Each entry's authority, with why the chain has no path to its certificates.
    #[must_use]
    pub fn refusals(&self) -> &[(StoreAuthority, PathRefusal)] {
        &self.0
    }

    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        "chain_unanchored"
    }
}

impl StoreEntry {
    fn parse(entry: &Json) -> Result<Self, EntryError> {
        let Json::Object(members) = entry else {
            return Err(EntryError::NotObject);
        };
        if let Some((name, _)) = members
            .iter()
            .find(|(name, _)| !matches!(name.as_str(), "type" | "value" | "certificates"))
        {
            return Err(EntryError::UnknownMember(name.clone()));
        }
        let kind = AuthorityType::new(text(entry, "type").map_err(EntryError::Type)?);
        let kind = match KnownAuthorityType::of(&kind) {
            Some(KnownAuthorityType::Store(store)) => store,
            Some(KnownAuthorityType::Aki) | None => return Err(EntryError::UnknownType(kind)),
        };
        let value = text(entry, "value").map_err(EntryError::Value)?;
        let certificates = match entry.member("certificates") {
            None => return Err(EntryError::Certificates(MemberFault::Absent)),
            Some(Json::Array(certificates)) if certificates.is_empty() => {
                return Err(EntryError::Certificates(MemberFault::Empty))
            }
            Some(Json::Array(certificates)) => certificates,
            Some(_) => return Err(EntryError::Certificates(MemberFault::WrongType)),
        };
        Ok(Self {
            authority: StoreAuthority::new(kind, AuthorityValue::new(value)),
            certificates: certificates
                .iter()
                .enumerate()
                .map(|(position, certificate)| {
                    certificate_of(certificate, CertificateIndex::new(position))
                })
                .collect::<Result<_, _>>()?,
        })
    }

    /// The authority.
    #[must_use]
    pub fn authority(&self) -> &StoreAuthority {
        &self.authority
    }

    /// The certificates, at least one, in the record's order.
    #[must_use]
    pub fn certificates(&self) -> &[Certificate] {
        &self.certificates
    }
}

/// The string member `name` of `entry`.
fn text<'e>(entry: &'e Json, name: &str) -> Result<&'e str, MemberFault> {
    match entry.member(name) {
        None => Err(MemberFault::Absent),
        Some(Json::String(text)) => Ok(text),
        Some(_) => Err(MemberFault::WrongType),
    }
}

/// The certificate at `position` of an entry's `certificates`: base64 with padding of a DER
/// certificate.
fn certificate_of(value: &Json, position: CertificateIndex) -> Result<Certificate, EntryError> {
    let Json::String(text) = value else {
        return Err(EntryError::CertificateNotString(position));
    };
    let der = base64::decode(text).map_err(|error| EntryError::Encoding {
        certificate: position,
        error,
    })?;
    Certificate::parse(&der).map_err(|error| EntryError::Certificate {
        certificate: position,
        error,
    })
}
