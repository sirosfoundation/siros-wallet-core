//! The sources of one credential: its own metadata, loaded and verified once, and the entry by
//! entry precedence of the sources.

use siros_credential::{Credential, Format};
use siros_display::{DisplayCache, Locale};

use super::config::Configuration;
use super::paso::{CredentialMetadata, CredentialMetadataFault};
use super::signed::Verifier;
use super::ts12::{Ts12Fault, TypeMetadata};
use super::{CredentialSource, Rulebook, SourceKind};
use crate::definition::{Definition, DefinitionError};
use crate::entry::Entry;
use crate::projection::{Projected, Unmatched};
use crate::select::{Definitions, Incompatibility};
use crate::served::{ServedTypes, Unserved};
use crate::type_id::TypeId;

/// Why a credential's sources serve no definition of a type: the reasons an entry's
/// [`Incompatibility`] and a registration's [`Unserved`] both name.
pub(crate) enum NotServed {
    Format,
    IssuerMetadataNotHeld,
    CredentialMetadata(CredentialMetadataFault),
    TypeMetadata(Ts12Fault),
    TypeUndeclared,
    TypeUnsupported,
    Definition(CredentialSource, DefinitionError),
    Language(Unmatched),
}

impl From<NotServed> for Incompatibility {
    fn from(reason: NotServed) -> Self {
        match reason {
            NotServed::Format => Self::Format,
            NotServed::IssuerMetadataNotHeld => Self::IssuerMetadataNotHeld,
            NotServed::CredentialMetadata(fault) => Self::CredentialMetadata(fault),
            NotServed::TypeMetadata(fault) => Self::TypeMetadata(fault),
            NotServed::TypeUndeclared => Self::TypeUndeclared,
            NotServed::TypeUnsupported => Self::TypeUnsupported,
            NotServed::Definition(source, error) => Self::Definition(source.into(), error),
            NotServed::Language(unmatched) => Self::Language(unmatched),
        }
    }
}

impl NotServed {
    /// The reason as a registration records it.
    pub(crate) fn recorded(&self) -> Unserved {
        match self {
            Self::Format => Unserved::Format,
            Self::IssuerMetadataNotHeld => Unserved::IssuerMetadataNotHeld,
            Self::CredentialMetadata(_) => Unserved::CredentialMetadata,
            Self::TypeMetadata(_) => Unserved::TypeMetadata,
            Self::TypeUndeclared => Unserved::TypeUndeclared,
            Self::TypeUnsupported => Unserved::TypeUnsupported,
            Self::Definition(source, _) => Unserved::Definition(*source),
            Self::Language(_) => Unserved::Language,
        }
    }
}

/// The sources of one credential, its own metadata loaded.
pub(crate) struct CredentialSources<'c> {
    credential: &'c Credential,
    verifier: Verifier<'c>,
    configuration: &'c Configuration,
    language: &'c Locale,
    /// The credential's signed credential metadata, verified, when it is a PaSO Credential.
    paso: Option<CredentialMetadata>,
    /// The credential's SCA type metadata, or why it does not read.
    ts12: Result<Option<TypeMetadata>, Ts12Fault>,
}

impl<'c> CredentialSources<'c> {
    /// The sources of `credential`, read in `language`. A credential whose configuration names
    /// a `credential_metadata_uri` in the issuer metadata `display` holds is a PaSO Credential:
    /// the host holds its signed credential metadata (PaSO Proof Metadata, Section 3).
    ///
    /// # Errors
    ///
    /// The credential takes no entry: [`NotServed::Format`] for a credential other than an
    /// SD-JWT VC, [`NotServed::IssuerMetadataNotHeld`] when the host holds no issuer metadata of
    /// its configuration, and [`NotServed::CredentialMetadata`] for signed credential metadata
    /// that is not held or not valid (Sections 3, 6 and 7).
    pub(crate) fn load(
        credential: &'c Credential,
        verifier: Verifier<'c>,
        display: &DisplayCache,
        configuration: &'c Configuration,
        language: &'c Locale,
    ) -> Result<Self, NotServed> {
        if credential.format() != Format::SdJwtVc {
            return Err(NotServed::Format);
        }
        let issued = display
            .issuer_metadata(credential)
            .ok_or(NotServed::IssuerMetadataNotHeld)?;
        let paso = issued
            .credential_metadata_uri()
            .map(|_| CredentialMetadata::load(credential, verifier))
            .transpose()
            .map_err(NotServed::CredentialMetadata)?;
        Ok(Self {
            credential,
            verifier,
            configuration,
            language,
            paso,
            ts12: TypeMetadata::load(credential, verifier.held),
        })
    }

    /// The definition of `type_id` the credential's own metadata gives; for a credential
    /// without metadata of its own, the one the configuration gives. Signed credential metadata
    /// comes before SCA type metadata.
    ///
    /// # Errors
    ///
    /// [`NotServed`]: why no source serves the type.
    pub(crate) fn served(&self, type_id: &TypeId) -> Result<Projected, NotServed> {
        self.named(type_id).unwrap_or_else(|| Err(self.otherwise()))
    }

    /// What the sources serve for each type they name, and for every other type: what a
    /// registration records (K1).
    pub(crate) fn record(&self) -> ServedTypes<Projected> {
        ServedTypes::collect(
            self.named_types(),
            |type_id| self.served(type_id).map_err(|reason| reason.recorded()),
            self.otherwise().recorded(),
        )
    }

    /// The definition, or why there is none, of a type a source names; `None` for a type no
    /// source names, and for every type the signed credential metadata does not name when the
    /// type metadata does not read: [`Self::otherwise`] gives why.
    fn named(&self, type_id: &TypeId) -> Option<Result<Projected, NotServed>> {
        let rulebook = Rulebook::of_type(type_id);
        if let Some(definition) = self.paso.as_ref().and_then(|paso| paso.definition(type_id)) {
            return Some(self.project(
                definition.clone(),
                CredentialSource::CredentialMetadata,
                rulebook,
            ));
        }
        let ts12 = self.ts12.as_ref().ok()?;
        if let Some(found) = ts12
            .as_ref()
            .and_then(|metadata| metadata.definition(type_id, self.credential, self.verifier.held))
        {
            return Some(match found {
                Ok((definition, schema)) => self.project(
                    Ok(definition),
                    CredentialSource::TypeMetadata,
                    Rulebook::Ts12(schema),
                ),
                Err(fault) => Err(NotServed::TypeMetadata(fault)),
            });
        }
        if self.paso.is_some() || ts12.is_some() {
            return None;
        }
        let definition = self.configuration.definition(type_id, self.credential)?;
        Some(self.project(
            Ok(definition.clone()),
            CredentialSource::Configuration,
            rulebook,
        ))
    }

    /// Why no definition serves a type no source names: type metadata that does not read, a
    /// type the credential's own metadata leaves out, or a type no source defines.
    fn otherwise(&self) -> NotServed {
        match &self.ts12 {
            Err(fault) => NotServed::TypeMetadata(fault.clone()),
            Ok(ts12) if self.paso.is_some() || ts12.is_some() => NotServed::TypeUndeclared,
            Ok(_) => NotServed::TypeUnsupported,
        }
    }

    /// The types the sources name: those of the signed credential metadata and of the type
    /// metadata, or, for a credential without metadata of its own, of the configuration.
    fn named_types(&self) -> Vec<TypeId> {
        let paso = self
            .paso
            .iter()
            .flat_map(CredentialMetadata::types)
            .cloned();
        match &self.ts12 {
            Err(_) => paso.collect(),
            Ok(Some(ts12)) => paso.chain(ts12.types()).collect(),
            Ok(None) if self.paso.is_some() => paso.collect(),
            Ok(None) => self.configuration.types(self.credential).cloned().collect(),
        }
    }

    /// `definition`, of `source`, projected to the wallet's language.
    fn project(
        &self,
        definition: Result<Definition, DefinitionError>,
        source: CredentialSource,
        rulebook: Rulebook,
    ) -> Result<Projected, NotServed> {
        definition
            .map_err(|error| NotServed::Definition(source, error))?
            .project(self.language, source.into(), rulebook)
            .map_err(NotServed::Language)
    }
}

impl Definitions for CredentialSources<'_> {
    /// The entry's ad-hoc metadata when it has one, with no other source after a failed one
    /// (PaSO Proof Metadata, Section 5.3); else [`CredentialSources::served`].
    fn serve(&self, entry: &Entry) -> Result<Projected, Incompatibility> {
        let type_id = entry.type_id();
        match entry.metadata() {
            Some(metadata) => metadata
                .verify(type_id, self.credential, self.verifier)
                .map_err(Incompatibility::AdHoc)?
                .map_err(|error| Incompatibility::Definition(SourceKind::AdHoc, error))?
                .project(self.language, SourceKind::AdHoc, Rulebook::of_type(type_id))
                .map_err(Incompatibility::Language),
            None => self.served(type_id).map_err(Incompatibility::from),
        }
    }
}
