//! The credential the matching reads (K2).

use serde_json::Value;
#[cfg(feature = "wallet")]
use siros_credential::UsableCredential;
use siros_credential::{Format, Instance};
use siros_dcql::{ClaimPath, PathError};
use siros_trust::QueryAuthorities;
#[cfg(feature = "wallet")]
use siros_trust::{AdmittedIssuer, ChainRefusal, TrustStore, Unadmitted};

/// A credential as the matching reads it: a usable credential of the wallet (C4), or a credential
/// of the picker's registration projection.
pub trait MatchCredential: Instance {
    /// The admission of the credential's issuer that a candidate carries: the wallet's
    /// `AdmittedIssuer`, or the picker's [`siros_trust::Admission`] from the TR5 facts.
    type Admission: Clone;

    /// Why a query's authorities refuse the credential's issuer.
    type Unadmitted: Clone;

    /// What resolves a query's `trusted_authorities` beside the credential: the wallet's trust
    /// store, or nothing for a credential of the projection, which carries its TR5 facts.
    type Trust: ?Sized;

    /// The admission of the credential's issuer by `authorities` through `trust` (TR3).
    ///
    /// # Errors
    ///
    /// [`Self::Unadmitted`] when they refuse it, and the credential matches nothing (A1).
    fn admission(
        &self,
        authorities: &QueryAuthorities,
        trust: &Self::Trust,
    ) -> Result<Self::Admission, Self::Unadmitted>;

    /// The format.
    fn format(&self) -> Format;

    /// The type: the SD-JWT VC's `vct`, or the mdoc's `docType`.
    fn credential_type(&self) -> &str;

    /// Whether a presentation of the credential proves holder binding.
    fn key_holding(&self) -> KeyHolding;

    /// The values of the claims `path` selects, as JSON, for the comparison with `values`
    /// (OpenID4VP 1.0, Section 6.3).
    ///
    /// # Errors
    ///
    /// [`PathError`] when the path does not fit the credential or selects nothing.
    fn claim_values(&self, path: &ClaimPath) -> Result<Vec<Value>, PathError>;
}

/// Whether the wallet holds the key a credential is bound to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyHolding {
    /// The credential is bound to a key the wallet holds: a presentation proves holder binding.
    Held,
    /// The credential is bound to no key, or to one the wallet does not hold.
    NotHeld,
}

#[cfg(feature = "wallet")]
impl MatchCredential for UsableCredential<'_> {
    type Admission = AdmittedIssuer;
    type Unadmitted = Unadmitted<ChainRefusal>;
    type Trust = TrustStore;

    /// The admission of the issuer chain against the trust store at the time the credential is
    /// usable at.
    fn admission(
        &self,
        authorities: &QueryAuthorities,
        store: &TrustStore,
    ) -> Result<AdmittedIssuer, Unadmitted<ChainRefusal>> {
        let chain = self.credential().issuer_chain();
        AdmittedIssuer::resolve(authorities, chain, store, self.time())
    }

    fn format(&self) -> Format {
        self.credential().format()
    }

    fn credential_type(&self) -> &str {
        self.credential().credential_type().as_str()
    }

    /// Held for an SD-JWT VC with a P-256 `cnf.jwk`, or an mdoc, whose entry names its key pair.
    fn key_holding(&self) -> KeyHolding {
        let credential = self.credential();
        match (credential.key_id(), credential.holder_key()) {
            (Some(_), Some(_)) => KeyHolding::Held,
            _ => KeyHolding::NotHeld,
        }
    }

    fn claim_values(&self, path: &ClaimPath) -> Result<Vec<Value>, PathError> {
        siros_dcql::Credential::claim(self.credential(), path)
    }
}
