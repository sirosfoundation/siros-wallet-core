//! The wallet's side of TR3 and TR5: the admission witness of a credential's issuer for one
//! query, from its chain and the trust store at a given time, and the facts it records for the
//! picker.

use siros_codec::date::DateTime;
use siros_dcql::QueryId;

use crate::admission::{Ground, Issuer, Unadmitted};
use crate::authority::{KeyIdentifier, QueryAuthorities, StoreAuthority};
use crate::certificate::Certificate;
use crate::chain::IssuerChain;
use crate::facts::IssuerFacts;
use crate::path::PathRefusal;
use crate::store::TrustStore;

/// Why an authority does not admit a credential's issuer, from its chain and the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}", self.code())]
pub enum ChainRefusal {
    /// The credential carries no issuer chain: an SD-JWT VC without `x5c`.
    NoChain,
    /// No certificate of the chain names the key in its AuthorityKeyIdentifier.
    KeyIdentifierAbsent,
    /// The store has no entry of the authority's type and value.
    NoStoreEntry,
    /// The chain has no path to a certificate of the entry.
    Path(#[source] PathRefusal),
}

impl ChainRefusal {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::NoChain => "issuer_chain_absent",
            Self::KeyIdentifierAbsent => "key_identifier_absent",
            Self::NoStoreEntry => "store_entry_absent",
            Self::Path(refusal) => refusal.code(),
        }
    }
}

/// A credential's issuer chain and the trust store, at a time.
struct ChainAt<'a> {
    chain: &'a IssuerChain,
    store: &'a TrustStore,
    time: DateTime,
}

/// A credential without an issuer chain.
struct NoChain;

impl Issuer for ChainAt<'_> {
    type Refusal = ChainRefusal;

    fn names(&self, key_identifier: &KeyIdentifier) -> Result<(), ChainRefusal> {
        if self
            .chain
            .key_identifiers()
            .any(|own| own == key_identifier)
        {
            Ok(())
        } else {
            Err(ChainRefusal::KeyIdentifierAbsent)
        }
    }

    fn admitted_by(&self, authority: &StoreAuthority) -> Result<(), ChainRefusal> {
        let entry = self
            .store
            .entry(authority)
            .ok_or(ChainRefusal::NoStoreEntry)?;
        self.chain
            .validate_path(entry.certificates(), self.time)
            .map(drop)
            .map_err(ChainRefusal::Path)
    }
}

impl Issuer for NoChain {
    type Refusal = ChainRefusal;

    fn names(&self, _: &KeyIdentifier) -> Result<(), ChainRefusal> {
        Err(ChainRefusal::NoChain)
    }

    fn admitted_by(&self, _: &StoreAuthority) -> Result<(), ChainRefusal> {
        Err(ChainRefusal::NoChain)
    }
}

/// The issuer of a credential that the authorities of one query admit (TR3): the authorities,
/// the chain's first certificate, and the ground. A usable nym_auth attestation requires it
/// (N3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedIssuer {
    authorities: QueryAuthorities,
    admitted: Admitted,
}

/// What admits an issuer, with the chain's first certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Admitted {
    /// The query names no authority; the leaf, when the credential carries a chain.
    Unconstrained(Option<Certificate>),
    /// An `aki` value names a key the chain names.
    KeyIdentifier {
        leaf: Certificate,
        key_identifier: KeyIdentifier,
    },
    /// The store entry of the authority admits the chain.
    Store {
        leaf: Certificate,
        authority: StoreAuthority,
    },
}

impl AdmittedIssuer {
    /// The admission, for the query of `authorities`, of the issuer whose chain is `chain`,
    /// against `store` at `time`: the query names no authority, an `aki` value names a key the
    /// chain's AuthorityKeyIdentifier extensions name, or the store entry of an `etsi_tl` or
    /// `openid_federation` value admits the chain (TR3). An entry of another type admits
    /// nothing. A credential without a chain is admitted only by a query that names no
    /// authority.
    ///
    /// # Errors
    ///
    /// [`Unadmitted`] with the refusal of every authority, in the query's order.
    pub fn resolve(
        authorities: &QueryAuthorities,
        chain: Option<&IssuerChain>,
        store: &TrustStore,
        time: DateTime,
    ) -> Result<Self, Unadmitted<ChainRefusal>> {
        let admitted = match chain {
            // The issuer refuses every authority: only a query that names none admits it.
            None => authorities
                .admit(&NoChain)
                .map(|_unconstrained| Admitted::Unconstrained(None))?,
            Some(chain) => {
                let leaf = chain.leaf().clone();
                match authorities.admit(&ChainAt { chain, store, time })? {
                    Ground::Unconstrained => Admitted::Unconstrained(Some(leaf)),
                    Ground::KeyIdentifier(key_identifier) => Admitted::KeyIdentifier {
                        leaf,
                        key_identifier,
                    },
                    Ground::Store(authority) => Admitted::Store { leaf, authority },
                }
            }
        };
        Ok(Self {
            authorities: authorities.clone(),
            admitted,
        })
    }

    /// The query.
    #[must_use]
    pub fn query(&self) -> &QueryId {
        self.authorities.query()
    }

    /// The authorities that admit the issuer: those of the query.
    #[must_use]
    pub fn authorities(&self) -> &QueryAuthorities {
        &self.authorities
    }

    /// The chain's first certificate: the Document Signer's of an mdoc. `None` for a credential
    /// without a chain, which only a query naming no authority admits.
    #[must_use]
    pub fn leaf(&self) -> Option<&Certificate> {
        match &self.admitted {
            Admitted::Unconstrained(leaf) => leaf.as_ref(),
            Admitted::KeyIdentifier { leaf, .. } | Admitted::Store { leaf, .. } => Some(leaf),
        }
    }

    /// Why the issuer is admitted.
    #[must_use]
    pub fn ground(&self) -> Ground {
        match &self.admitted {
            Admitted::Unconstrained(_) => Ground::Unconstrained,
            Admitted::KeyIdentifier { key_identifier, .. } => {
                Ground::KeyIdentifier(key_identifier.clone())
            }
            Admitted::Store { authority, .. } => Ground::Store(authority.clone()),
        }
    }
}

impl IssuerFacts {
    /// The registration facts of the credential whose issuer chain is `chain`, against `store`
    /// at `time` (TR5): the keyIdentifiers its AuthorityKeyIdentifier extensions name, and the
    /// authorities to whose store entries it has a path. A credential without a chain has
    /// none.
    #[must_use]
    pub fn at(chain: Option<&IssuerChain>, store: &TrustStore, time: DateTime) -> Self {
        let Some(chain) = chain else {
            return Self::new(Vec::new(), Vec::new());
        };
        Self::new(
            chain.key_identifiers().cloned().collect(),
            store
                .entries()
                .iter()
                .filter(|entry| chain.validate_path(entry.certificates(), time).is_ok())
                .map(|entry| entry.authority().clone())
                .collect(),
        )
    }
}
