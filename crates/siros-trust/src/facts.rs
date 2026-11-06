//! What the wallet registers about a credential's issuer (TR5): the core's `Facts`, which the
//! matcher and phase 2 read without the chain or the trust store.

use siros_openid4vp::host::Timestamp;
use siros_openid4vp::ids;
use siros_openid4vp::wallet::{Facts, Holder};

use crate::authority::{KeyIdentifier, StoreAuthority, StoreType};
use crate::chain::IssuerChain;
use crate::ids::{AuthorityType, AuthorityValue};
use crate::path::PathRefusal;
use crate::store::TrustStore;

/// A credential's issuer chain resolved against the trust store at a time. An issuer without a
/// chain holds nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerFacts(Option<ChainFacts>);

/// What a chain names and the verdict of each store entry on it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ChainFacts {
    key_identifiers: Vec<KeyIdentifier>,
    admitting: Vec<StoreAuthority>,
    refusing: Vec<(StoreAuthority, PathRefusal)>,
}

/// Why one value of a query's `trusted_authorities` does not admit a credential's issuer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum ChainRefusal {
    /// The authority's `type` is none of `aki`, `etsi_tl` and `openid_federation`.
    Type(AuthorityType),
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
    pub fn code(&self) -> &'static str {
        match self {
            Self::Type(_) => "authority_type_unknown",
            Self::NoChain => "issuer_chain_absent",
            Self::KeyIdentifierAbsent => "key_identifier_absent",
            Self::NoStoreEntry => "store_entry_absent",
            Self::Path(refusal) => refusal.code(),
        }
    }
}

impl IssuerFacts {
    /// The resolution of `chain` against `store` at `time`.
    #[must_use]
    pub fn at(chain: Option<&IssuerChain>, store: &TrustStore, time: Timestamp) -> Self {
        Self(chain.map(|chain| {
            let mut admitting = Vec::new();
            let mut refusing = Vec::new();
            for entry in store.entries() {
                match chain.validate_path(entry.certificates(), time) {
                    Ok(_) => admitting.push(entry.authority().clone()),
                    Err(refusal) => refusing.push((entry.authority().clone(), refusal)),
                }
            }
            ChainFacts {
                key_identifiers: chain.key_identifiers().cloned().collect(),
                admitting,
                refusing,
            }
        }))
    }

    /// The core's facts: one `HeldAuthority` for `aki`, with the chain's keyIdentifiers in
    /// base64url, and one per admitting store type with its values.
    #[must_use]
    pub fn facts(&self, holder: Holder) -> Facts<'static> {
        let Some(chain) = &self.0 else {
            return Facts::of(holder, []);
        };
        let aki = chain
            .key_identifiers
            .iter()
            .map(|key| (AuthorityType::of("aki"), key.aki()));
        let stores = chain
            .admitting
            .iter()
            .map(|authority| (authority.kind().authority_type(), authority.value().clone()));
        Facts::of(holder, aki.chain(stores))
    }

    /// Why the value `value` of type `kind`, which the facts do not hold, admits no issuer.
    pub(crate) fn refusal(
        &self,
        kind: &ids::AuthorityType<'_>,
        value: &ids::AuthorityValue<'_>,
    ) -> ChainRefusal {
        let store = StoreType::named(kind.as_str());
        if store.is_none() && kind.as_str() != "aki" {
            return ChainRefusal::Type(kind.clone().into_owned());
        }
        let Some(chain) = &self.0 else {
            return ChainRefusal::NoChain;
        };
        let Some(store) = store else {
            return ChainRefusal::KeyIdentifierAbsent;
        };
        let wanted = StoreAuthority::new(store, AuthorityValue::of(value.as_str().to_owned()));
        chain
            .refusing
            .iter()
            .find(|(authority, _)| *authority == wanted)
            .map_or(ChainRefusal::NoStoreEntry, |(_, refusal)| {
                ChainRefusal::Path(*refusal)
            })
    }
}
