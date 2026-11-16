//! The display metadata a host holds, keyed for resolution.

use rustc_hash::FxHashMap;
use siros_dcql::Vct;
use siros_wallet_state::{ConfigurationId, IssuerIdentifier};

use crate::error::DisplayError;
use crate::issuer::IssuerMetadata;
use crate::type_metadata::TypeMetadata;

/// The display metadata a host holds: OpenID4VCI display metadata keyed by Credential Issuer
/// Identifier and credential configuration identifier, and SD-JWT VC Type Metadata keyed by
/// `vct`. Every `extends` names a type the cache holds, and no chain of `extends` returns to
/// its start (SD-JWT VC, Sections 5.4 and 7.4).
#[derive(Debug, Clone, Default)]
pub struct DisplayCache {
    issuers: FxHashMap<IssuerIdentifier, FxHashMap<ConfigurationId, IssuerMetadata>>,
    types: FxHashMap<Vct, TypeMetadata>,
}

impl DisplayCache {
    /// The cache of `issuers` and `types`.
    ///
    /// # Errors
    ///
    /// [`DisplayError::IssuerMetadataRepeated`] for two entries of one configuration,
    /// [`DisplayError::TypeMetadataRepeated`] for two documents of one `vct`,
    /// [`DisplayError::ExtendsUnknown`] for an `extends` the cache lacks, and
    /// [`DisplayError::ExtendsCycle`] for a chain of `extends` that returns to its start.
    pub fn new(
        issuers: Vec<IssuerMetadata>,
        types: Vec<TypeMetadata>,
    ) -> Result<Self, DisplayError> {
        let mut cache = Self::default();
        issuers
            .into_iter()
            .try_for_each(|metadata| cache.hold_issuer(metadata))?;
        types
            .into_iter()
            .try_for_each(|metadata| cache.hold_type(metadata))?;
        cache
            .types
            .values()
            .try_for_each(|start| cache.extends_to_end(start))?;
        Ok(cache)
    }

    /// Holds the display metadata of one configuration.
    fn hold_issuer(&mut self, metadata: IssuerMetadata) -> Result<(), DisplayError> {
        let configurations = self
            .issuers
            .entry(metadata.credential_issuer().clone())
            .or_default();
        match configurations.insert(metadata.configuration_id().clone(), metadata) {
            None => Ok(()),
            Some(_) => Err(DisplayError::IssuerMetadataRepeated),
        }
    }

    /// Holds the Type Metadata of one `vct`.
    fn hold_type(&mut self, metadata: TypeMetadata) -> Result<(), DisplayError> {
        match self.types.insert(metadata.vct().clone(), metadata) {
            None => Ok(()),
            Some(_) => Err(DisplayError::TypeMetadataRepeated),
        }
    }

    /// Follows the `extends` of `start` to a type that extends none: every step names a type
    /// the cache holds, and the chain takes fewer steps than the cache holds types.
    fn extends_to_end(&self, start: &TypeMetadata) -> Result<(), DisplayError> {
        let mut at = start;
        for _ in 0..=self.types.len() {
            let Some(extended) = at.extends() else {
                return Ok(());
            };
            at = self
                .types
                .get(extended)
                .ok_or(DisplayError::ExtendsUnknown)?;
        }
        Err(DisplayError::ExtendsCycle)
    }

    /// The OpenID4VCI display metadata of configuration `configuration_id` of `issuer`.
    pub(crate) fn issuer(
        &self,
        issuer: &IssuerIdentifier,
        configuration_id: &ConfigurationId,
    ) -> Option<&IssuerMetadata> {
        self.issuers.get(issuer)?.get(configuration_id)
    }

    /// The Type Metadata of `vct`, then of each type it extends, in order.
    pub(crate) fn type_chain<'a>(&'a self, vct: &str) -> impl Iterator<Item = &'a TypeMetadata> {
        let mut next = self.types.get(vct);
        std::iter::from_fn(move || {
            let current = next?;
            next = current
                .extends()
                .and_then(|extended| self.types.get(extended.as_str()));
            Some(current)
        })
    }
}
