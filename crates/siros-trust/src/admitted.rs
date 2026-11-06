//! The issuer of a credential the authorities of one query admit, as a usable nym_auth attestation
//! requires it (siros-zkp-catalogues' N3).

use siros_openid4vp::host::Timestamp;
use siros_openid4vp::ids;
use siros_openid4vp::request::{Query, TrustedAuthority};
use siros_openid4vp::wallet::Holder;

use crate::certificate::Certificate;
use crate::chain::IssuerChain;
use crate::facts::{ChainRefusal, IssuerFacts};
use crate::ids::QueryId;
use crate::store::TrustStore;

/// Why no authority of a query admits an issuer: the refusal of each value, in the Verifier's
/// order.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("issuer_not_admitted")]
pub struct Unadmitted {
    refusals: Vec<ChainRefusal>,
}

impl Unadmitted {
    /// The refusal of each value the query names, at least one, in its order.
    #[must_use]
    pub fn refusals(&self) -> &[ChainRefusal] {
        &self.refusals
    }
}

/// The issuer of a credential that the authorities of one query admit: the authorities and the
/// chain's first certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedIssuer {
    query: QueryId,
    authorities: Vec<TrustedAuthority<'static>>,
    leaf: Option<Certificate>,
}

impl AdmittedIssuer {
    /// The admission, for `query`, of the issuer whose chain is `chain`, against `store` at
    /// `time`: the core's rule, `Facts::admits`, over the chain's facts.
    ///
    /// # Errors
    ///
    /// [`Unadmitted`] with the refusal of every value, in the query's order.
    pub fn resolve(
        query: &Query<'_>,
        chain: Option<&IssuerChain>,
        store: &TrustStore,
        time: Timestamp,
    ) -> Result<Self, Unadmitted> {
        let issuer = IssuerFacts::at(chain, store, time);
        // The rule reads the authorities alone.
        if !issuer.facts(Holder::Unbound).admits(query) {
            return Err(Unadmitted {
                refusals: query
                    .trusted_authorities
                    .iter()
                    .flat_map(|entry| {
                        let issuer = &issuer;
                        entry
                            .values
                            .iter()
                            .map(move |value| issuer.refusal(&entry.kind, value))
                    })
                    .collect(),
            });
        }
        Ok(Self {
            query: query.id.clone().into_owned(),
            authorities: query
                .trusted_authorities
                .iter()
                .cloned()
                .map(TrustedAuthority::into_owned)
                .collect(),
            leaf: chain.map(|chain| chain.leaf().clone()),
        })
    }

    /// The query's `id`.
    #[must_use]
    pub fn query(&self) -> &QueryId {
        &self.query
    }

    /// Whether this is the admission for the query `query` with `trusted_authorities`.
    #[must_use]
    pub fn is_for(
        &self,
        query: &ids::QueryId<'_>,
        trusted_authorities: &[TrustedAuthority<'_>],
    ) -> bool {
        self.query == *query && self.authorities == trusted_authorities
    }

    /// The chain's first certificate: the Document Signer's of an mdoc. `None` for a credential
    /// without a chain, which only a query naming no authority admits.
    #[must_use]
    pub fn leaf(&self) -> Option<&Certificate> {
        self.leaf.as_ref()
    }
}
