//! The issuer facts the wallet records for the picker (TR5): what the admission rule reads of a
//! credential, without its chain or the trust store.

use crate::admission::Issuer;
use crate::authority::{KeyIdentifier, StoreAuthority};

/// A credential's issuer facts at the time the wallet registered it: the AuthorityKeyIdentifier
/// keyIdentifiers of its chain, and the trust store entries whose certificates its chain
/// has a path to.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IssuerFacts {
    key_identifiers: Vec<KeyIdentifier>,
    admitting: Vec<StoreAuthority>,
}

/// Why the facts give an authority no admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}", self.code())]
pub enum FactRefusal {
    /// No certificate of the chain names the key.
    KeyIdentifierAbsent,
    /// The store entry of the authority admits no chain of the credential.
    NotAdmitting,
}

impl FactRefusal {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::KeyIdentifierAbsent => "key_identifier_absent",
            Self::NotAdmitting => "store_entry_not_admitting",
        }
    }
}

impl IssuerFacts {
    /// The facts of a credential whose chain names `key_identifiers` and whose chain the store
    /// entries of `admitting` admit.
    #[must_use]
    pub fn new(key_identifiers: Vec<KeyIdentifier>, admitting: Vec<StoreAuthority>) -> Self {
        Self {
            key_identifiers,
            admitting,
        }
    }

    /// The keyIdentifiers of the AuthorityKeyIdentifier extensions of the chain's certificates.
    #[must_use]
    pub fn key_identifiers(&self) -> &[KeyIdentifier] {
        &self.key_identifiers
    }

    /// The authorities whose store entries admit the chain.
    #[must_use]
    pub fn admitting(&self) -> &[StoreAuthority] {
        &self.admitting
    }
}

impl Issuer for IssuerFacts {
    type Refusal = FactRefusal;

    fn names(&self, key_identifier: &KeyIdentifier) -> Result<(), FactRefusal> {
        if self.key_identifiers.contains(key_identifier) {
            Ok(())
        } else {
            Err(FactRefusal::KeyIdentifierAbsent)
        }
    }

    fn admitted_by(&self, authority: &StoreAuthority) -> Result<(), FactRefusal> {
        if self.admitting.contains(authority) {
            Ok(())
        } else {
            Err(FactRefusal::NotAdmitting)
        }
    }
}
