//! The admission rule of TR3: whether the authorities a Credential Query names admit a
//! credential's issuer. The wallet applies it to the issuer chain and the trust store, the
//! picker to the facts the wallet recorded (TR5).

use siros_dcql::{AuthorityType, QueryId};

use crate::authority::{Authority, KeyIdentifier, QueryAuthorities, StoreAuthority};

/// What the admission rule asks of a credential's issuer.
pub trait Issuer {
    /// Why an authority does not admit the issuer.
    type Refusal;

    /// Whether a certificate of the issuer's chain names `key_identifier` in its
    /// AuthorityKeyIdentifier extension.
    ///
    /// # Errors
    ///
    /// The reason it names no such key.
    fn names(&self, key_identifier: &KeyIdentifier) -> Result<(), Self::Refusal>;

    /// Whether the trust store entry of `authority` admits the issuer: the chain's first
    /// certificate has a path to one of its certificates.
    ///
    /// # Errors
    ///
    /// The reason the entry does not admit it.
    fn admitted_by(&self, authority: &StoreAuthority) -> Result<(), Self::Refusal>;
}

/// Why a credential's issuer is admitted for a query.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Ground {
    /// The query has no `trusted_authorities`.
    Unconstrained,
    /// This `aki` value names the key of a certificate's signer in the chain.
    KeyIdentifier(KeyIdentifier),
    /// The trust store entry of this authority admits the chain.
    Store(StoreAuthority),
}

/// Why one authority of a query does not admit an issuer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refusal<R> {
    /// The authority's `type` is none of `aki`, `etsi_tl` and `openid_federation`.
    #[error("the authority's `type` `{0}` is none of `aki`, `etsi_tl` and `openid_federation`")]
    Type(AuthorityType),
    /// The issuer's reason.
    #[error("the issuer's reason")]
    Issuer(#[source] R),
}

/// Why no authority of a query admits an issuer: the refusal of each, in the Verifier's order.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("issuer_not_admitted")]
pub struct Unadmitted<R> {
    refusals: Vec<Refusal<R>>,
}

impl<R> Unadmitted<R> {
    /// The refusal of each authority the query names, at least one, in its order.
    #[must_use]
    pub fn refusals(&self) -> &[Refusal<R>] {
        &self.refusals
    }
}

/// An issuer the authorities of a query admit, as the picker learns it from the recorded facts
/// (TR5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admission {
    query: QueryId,
    ground: Ground,
}

impl QueryAuthorities {
    /// Whether the authorities admit `issuer` (TR3): the query names none, an `aki` value names
    /// a key the chain's certificates name, or the store entry of an `etsi_tl` or
    /// `openid_federation` value admits the chain. The first authority that admits it, in the
    /// Verifier's order, is the ground.
    ///
    /// # Errors
    ///
    /// [`Unadmitted`] with the refusal of every authority.
    pub fn admit<I: Issuer + ?Sized>(&self, issuer: &I) -> Result<Ground, Unadmitted<I::Refusal>> {
        let Some(authorities) = self.authorities() else {
            return Ok(Ground::Unconstrained);
        };
        let mut refusals = Vec::with_capacity(authorities.len());
        for authority in authorities {
            match ground(authority, issuer) {
                Ok(ground) => return Ok(ground),
                Err(refusal) => refusals.push(refusal),
            }
        }
        Err(Unadmitted { refusals })
    }
}

/// The ground `authority` gives `issuer`, or why it gives none.
fn ground<I: Issuer + ?Sized>(
    authority: &Authority,
    issuer: &I,
) -> Result<Ground, Refusal<I::Refusal>> {
    match authority {
        Authority::KeyIdentifier(key_identifier) => issuer
            .names(key_identifier)
            .map(|()| Ground::KeyIdentifier(key_identifier.clone()))
            .map_err(Refusal::Issuer),
        Authority::Store(store) => issuer
            .admitted_by(store)
            .map(|()| Ground::Store(store.clone()))
            .map_err(Refusal::Issuer),
        Authority::Other(kind) => Err(Refusal::Type(kind.clone())),
    }
}

impl Admission {
    /// The admission of `issuer` for the query of `authorities`.
    ///
    /// # Errors
    ///
    /// [`Unadmitted`] with the refusal of every authority.
    pub fn of<I: Issuer + ?Sized>(
        authorities: &QueryAuthorities,
        issuer: &I,
    ) -> Result<Self, Unadmitted<I::Refusal>> {
        Ok(Self {
            query: authorities.query().clone(),
            ground: authorities.admit(issuer)?,
        })
    }

    /// The query.
    #[must_use]
    pub fn query(&self) -> &QueryId {
        &self.query
    }

    /// Why the issuer is admitted.
    #[must_use]
    pub fn ground(&self) -> &Ground {
        &self.ground
    }
}
