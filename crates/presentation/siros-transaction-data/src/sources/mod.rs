//! The sources of a transaction data type's definition, each a parser into the one form
//! ([`Definition`](crate::Definition)), and their precedence for one entry and one credential:
//! the entry's ad-hoc metadata; else the credential's own metadata, its signed credential
//! metadata or its TS12 SCA type metadata, which declares every type the credential supports;
//! else, for a credential without metadata of its own, the host's configuration.

mod adhoc;
mod config;
#[cfg(feature = "wallet")]
mod held;
#[cfg(feature = "wallet")]
mod issuer_keys;
#[cfg(feature = "wallet")]
mod jws;
#[cfg(feature = "wallet")]
mod paso;
#[cfg(feature = "wallet")]
mod signed;
#[cfg(feature = "wallet")]
mod ts12;
#[cfg(feature = "wallet")]
mod ts12_map;

use crate::definition::LabelRules;
use crate::type_id::Ts12Type;

pub use adhoc::AdHocMetadata;
pub use config::{
    Configuration, ConfigurationError, ConfigurationMember, Configured, ConfiguredFault,
    ConfiguredType,
};
#[cfg(feature = "wallet")]
pub use held::{HeldDocument, HeldError, HeldJwt, HeldMetadata, Renewal, Wanted, WantedFault};
#[cfg(feature = "wallet")]
pub use issuer_keys::KeySetFault;
#[cfg(feature = "wallet")]
pub use jws::{JwkFault, JwsFault};
#[cfg(feature = "wallet")]
pub use paso::CredentialMetadataFault;
#[cfg(feature = "wallet")]
pub use signed::{MetadataClaim, SignedFault};
#[cfg(feature = "wallet")]
pub use ts12::{Ts12Fault, Ts12Member};

#[cfg(feature = "wallet")]
pub(crate) use signed::Verifier;

/// Where a definition comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceKind {
    /// The entry's ad-hoc metadata JWT (PaSO Proof Metadata, Section 5).
    AdHoc,
    /// The credential's signed credential metadata JWT (PaSO Proof Metadata, Section 4).
    CredentialMetadata,
    /// The credential's SD-JWT VC Type Metadata (EC TS12 v1.0.1, Section 4.1).
    TypeMetadata,
    /// The host's configuration.
    Configuration,
}

impl SourceKind {
    const ALL: [Self; 4] = [
        Self::AdHoc,
        Self::CredentialMetadata,
        Self::TypeMetadata,
        Self::Configuration,
    ];

    /// Whether the source is PaSO's signed metadata, which a signed request must accompany
    /// (PaSO Core, Section 3).
    #[must_use]
    pub fn is_paso(self) -> bool {
        matches!(self, Self::AdHoc | Self::CredentialMetadata)
    }

    /// The rules the source's labels follow: TS12's for Type Metadata, PaSO's for the others.
    #[must_use]
    pub fn label_rules(self) -> LabelRules {
        match self {
            Self::TypeMetadata => LabelRules::Ts12,
            Self::AdHoc | Self::CredentialMetadata | Self::Configuration => LabelRules::Paso,
        }
    }

    /// The name a projected definition writes.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AdHoc => "ad_hoc",
            Self::CredentialMetadata => "credential_metadata",
            Self::TypeMetadata => "type_metadata",
            Self::Configuration => "configuration",
        }
    }

    /// The source `name` names.
    #[must_use]
    pub fn named(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == name)
    }
}

/// A source of a credential's own definitions, which a registration records: every source but
/// an entry's ad-hoc metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CredentialSource {
    /// The credential's signed credential metadata JWT (PaSO Proof Metadata, Section 4).
    CredentialMetadata,
    /// The credential's SD-JWT VC Type Metadata (EC TS12 v1.0.1, Section 4.1).
    TypeMetadata,
    /// The host's configuration.
    Configuration,
}

impl From<CredentialSource> for SourceKind {
    fn from(source: CredentialSource) -> Self {
        match source {
            CredentialSource::CredentialMetadata => Self::CredentialMetadata,
            CredentialSource::TypeMetadata => Self::TypeMetadata,
            CredentialSource::Configuration => Self::Configuration,
        }
    }
}

/// The rulebook of an entry's payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Rulebook {
    /// A type of EC TS12 v1.0.1: its typed payload, `transaction_data_hashes_alg` required, and
    /// `jti`, `response_mode` and `amr` in the KB-JWT.
    Ts12(Ts12Type),
    /// The definition alone: PaSO payload conformance (PaSO Core, Section 7.4.2).
    Generic,
}

/// The name of [`Rulebook::Generic`] in a projected definition.
const GENERIC: &str = "generic";

impl Rulebook {
    /// The name a projected definition writes: the TS12 schema identifier, or `generic`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ts12(rulebook) => rulebook.identifier(),
            Self::Generic => GENERIC,
        }
    }

    /// The rulebook `name` names.
    #[must_use]
    pub fn named(name: &str) -> Option<Self> {
        match name {
            GENERIC => Some(Self::Generic),
            _ => Ts12Type::schema(name).map(Self::Ts12),
        }
    }

    /// The rulebook of an entry of `type_id` that no TS12 schema names: the built-in one of
    /// the identifier, else the generic one.
    #[must_use]
    pub fn of_type(type_id: &crate::TypeId) -> Self {
        type_id.rulebook().map_or(Self::Generic, Self::Ts12)
    }
}

#[cfg(feature = "wallet")]
mod credential;

#[cfg(feature = "wallet")]
pub(crate) use credential::{CredentialSources, NotServed};
