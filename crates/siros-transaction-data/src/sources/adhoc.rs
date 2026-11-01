//! Ad-hoc transaction data metadata (PaSO Proof Metadata, Section 5): a JWT inside a
//! `transaction_data` entry, signed by the Attestation Provider of the targeted credential,
//! that defines the entry's type for that entry alone. The credential picker cannot verify it
//! (K2): the wallet's selection decides an entry that carries one.

#[cfg(feature = "wallet")]
use siros_credential::Credential;

#[cfg(feature = "wallet")]
use super::signed::{self, MetadataClaim, SignedFault, Verifier};
#[cfg(feature = "wallet")]
use crate::definition::{Definition, DefinitionError, LabelRules};
#[cfg(feature = "wallet")]
use crate::type_id::TypeId;

/// The `typ` of an ad-hoc metadata JWT (Section 5.2).
#[cfg(feature = "wallet")]
const TYP: &str = "adhoc-transaction-metadata+jwt";

/// The text of an entry's `metadata` member: the ad-hoc metadata JWT, verified per credential.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AdHocMetadata(String);

impl AdHocMetadata {
    /// The JWT `text`, as the entry carries it.
    pub(crate) fn new(text: String) -> Self {
        Self(text)
    }

    #[cfg(feature = "wallet")]
    /// The definition the JWT gives the entry of type `type_id` for `credential`, verified
    /// (Section 5.3). A verified JWT whose `metadata` breaks Section 3 gives the definition's
    /// error.
    ///
    /// # Errors
    ///
    /// [`SignedFault`]: the first step of Section 5.3 that fails. The entry is then not
    /// compatible for the credential, and no other source serves it (Section 5.3).
    pub(crate) fn verify(
        &self,
        type_id: &TypeId,
        credential: &Credential,
        verifier: Verifier<'_>,
    ) -> Result<Result<Definition, DefinitionError>, SignedFault> {
        let mut claims = signed::verify(&self.0, TYP, credential, verifier)?.claims;
        // Step 7.
        if signed::text_claim(&mut claims, MetadataClaim::TransactionDataType)? != type_id.as_str()
        {
            return Err(SignedFault::TransactionDataType);
        }
        let metadata = claims
            .require(MetadataClaim::Metadata.as_str())
            .map_err(|fault| SignedFault::Claim(MetadataClaim::Metadata, fault))?;
        Ok(Definition::parse(metadata, LabelRules::Paso))
    }
}
