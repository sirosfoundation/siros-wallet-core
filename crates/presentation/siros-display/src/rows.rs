//! Claim rows of a stored credential (D2 to D5).

use siros_credential::Credential;
use siros_dcql::ClaimPath;

use crate::cache::DisplayCache;
use crate::error::DisplayError;
use crate::labels::{ClaimLabels, ClaimRow, DescribedLabel};
use crate::locale::{lookup, Locale};

impl DisplayCache {
    /// The labels of `credential`'s claims in the wallet's `language`.
    ///
    /// [`lookup`] takes a claim's label from the nearest type of the credential's Type Metadata
    /// with a labelled claim description that addresses the claim. Without a type label for the
    /// language it takes it from the claims description of the credential's configuration that
    /// addresses the claim, the fallback (D3, OpenID4VCI 1.0, Section 12.2.4).
    pub fn claim_labels(&self, credential: &Credential, language: &Locale) -> ClaimLabels {
        let types = self
            .types_of(credential)
            .into_iter()
            .flat_map(|metadata| metadata.claims())
            .filter_map(|claim| {
                let labels = claim.labels.as_deref()?;
                let label = lookup(language, labels).map(|label| label.text.clone());
                Some(DescribedLabel::new(claim.path.clone(), label))
            })
            .collect();
        let issuer = self
            .issuer_metadata(credential)
            .map(|metadata| metadata.claims())
            .unwrap_or_default()
            .iter()
            .map(|description| {
                let label = lookup(language, &description.labels).map(|label| label.text.clone());
                DescribedLabel::new(description.path.clone(), label)
            })
            .collect();
        ClaimLabels::new(types, issuer)
    }

    /// The rows of the claims `pointers` select in `credential`, one per pointer, in the
    /// wallet's `language`: [`ClaimLabels::rows`] with [`DisplayCache::claim_labels`]. No
    /// display metadata of the ecosystem declares a claim to be an image, so a byte string shows
    /// its length (D5).
    ///
    /// # Errors
    ///
    /// [`DisplayError`] as [`ClaimLabels::rows`] gives it.
    pub fn claim_rows(
        &self,
        credential: &Credential,
        pointers: &[ClaimPath],
        language: &Locale,
    ) -> Result<Vec<ClaimRow>, DisplayError> {
        self.claim_labels(credential, language)
            .rows(credential, pointers)
    }
}
